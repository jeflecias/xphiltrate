import re
import httpx
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask
from urllib.parse import urljoin, urlparse

app = FastAPI()

client = httpx.AsyncClient(follow_redirects=False, timeout=60.0)
TARGET_BASE = "https://usa.edu.ph/"
parsed_target = urlparse(TARGET_BASE)
TARGET_DOMAIN = parsed_target.netloc

HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", 
    "proxy-authorization", "te", "trailers", 
    "transfer-encoding", "upgrade", "host", "content-length",
    "content-encoding"
}

COOKIE_DOMAIN_RE = re.compile(r"(?i);\s*Domain=[^;]+")

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy(request: Request, path: str):
    # 1. Build the target URL with Query Params preserved
    query_string = request.url.query
    target_url = urljoin(TARGET_BASE.rstrip("/") + "/", path)
    if query_string:
        target_url += f"?{query_string}"
    
    proxy_base = str(request.base_url).rstrip("/")
    proxy_domain = urlparse(proxy_base).netloc
    
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
            v = COOKIE_DOMAIN_RE.sub("", v)
            processed_headers.append((k, v))
        else:
            processed_headers.append((k, v))

    # 5. Body Fork
    content_type = resp.headers.get("content-type", "").lower()
    
    if any(t in content_type for t in ["text/html", "javascript", "json"]):
        await resp.aread()
        text = resp.text
        
        # Swap raw domain strings to catch subdomains and JS links
        rewritten = text.replace(TARGET_DOMAIN, proxy_domain)
        rewritten = rewritten.replace("https://" + proxy_domain, "http://" + proxy_domain)

        final_response = Response(content=rewritten.encode("utf-8"), status_code=resp.status_code)
        await resp.aclose()
    else:
        final_response = StreamingResponse(
            resp.aiter_bytes(),
            status_code=resp.status_code,
            background=BackgroundTask(resp.aclose)
        )

    # 6. Cleanup & Header Attachment
    if "content-length" in final_response.headers:
        del final_response.headers["content-length"]
    for k, v in processed_headers:
        final_response.headers.append(k, v)
            
    return final_response