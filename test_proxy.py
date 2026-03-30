import re
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask
import httpx
from urllib.parse import urljoin, urlparse

app = FastAPI()

# follow_redirects=False ensures we intercept redirects to rewrite them
client = httpx.AsyncClient(follow_redirects=False)
TARGET_BASE = "https://neust.edu.ph/"
parsed_target = urlparse(TARGET_BASE)

HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", 
    "proxy-authorization", "te", "trailers", 
    "transfer-encoding", "upgrade", "host", "content-length",
    "content-encoding"
}

# Regex to find and strip the Domain= attribute from cookies
COOKIE_DOMAIN_RE = re.compile(r"(?i);\s*Domain=[^;]+")

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy(request: Request, path: str):
    url = urljoin(TARGET_BASE.rstrip("/") + "/", path)
    
    # We need these strings to rewrite absolute URLs in HTML and headers
    proxy_base = str(request.base_url).rstrip("/")
    target_base_str = TARGET_BASE.rstrip("/")
    
    # 1. Forward Incoming Headers safely
    req_headers = [
        (k, v) for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    ]
    req_headers.append(("accept-encoding", "identity"))
    req_headers.append(("host", parsed_target.netloc))
            
    body = await request.body()
    
    # 2. Dispatch the Request
    try:
        proxy_req = client.build_request(
            method=request.method,
            url=url,
            headers=req_headers,
            content=body,
            params=dict(request.query_params)
        )
        resp = await client.send(proxy_req, stream=True)
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Bad Gateway: {str(exc)}")

    # 3. Process Outgoing Headers (Cookies & Redirects)
    processed_headers = []
    for k, v in resp.headers.multi_items():
        k_lower = k.lower()
        if k_lower in HOP_BY_HOP_HEADERS:
            continue
            
        if k_lower == "location":
            # Rewrite upstream redirects to keep the user on the proxy
            if v.startswith(target_base_str):
                v = v.replace(target_base_str, proxy_base)
            processed_headers.append((k, v))
            
        elif k_lower == "set-cookie":
            # Strip the domain attribute. If the domain attribute is missing, 
            # the browser automatically applies the cookie to the proxy's domain.
            v = COOKIE_DOMAIN_RE.sub("", v)
            processed_headers.append((k, v))
            
        else:
            processed_headers.append((k, v))

    # 4. Body Processing Fork: HTML vs Streaming
    content_type = resp.headers.get("content-type", "").lower()
    
    if "text/html" in content_type:
        # Buffer HTML into memory to manipulate it
        await resp.aread()
        html_body = resp.text 
        
        # A global string replacement is superior to regexing specific tags (like <a href>) 
        # because it successfully catches absolute URLs hidden inside JavaScript variables and JSON config blocks.
        rewritten_body = html_body.replace(target_base_str, proxy_base)
        
        # Re-encode to bytes
        body_bytes = rewritten_body.encode("utf-8")
        final_response = Response(content=body_bytes, status_code=resp.status_code)
    else:
        # Stream non-HTML responses untouched
        final_response = StreamingResponse(
            resp.aiter_bytes(),
            status_code=resp.status_code,
            background=BackgroundTask(resp.aclose)
        )

    # 5. Attach processed headers safely to preserve multi-values
    for k, v in processed_headers:
        final_response.headers.append(k, v)
            
    return final_response