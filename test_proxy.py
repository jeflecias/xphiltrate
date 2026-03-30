from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask
import httpx
from urllib.parse import urljoin

app = FastAPI()

# follow_redirects=False ensures we leave redirects untouched
client = httpx.AsyncClient(follow_redirects=False)
TARGET_BASE = "https://example.com"

HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", 
    "proxy-authorization", "te", "trailers", 
    "transfer-encoding", "upgrade", "host", "content-length",
    "content-encoding"
}

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy(request: Request, path: str):
    # 1. Build the target URL
    url = urljoin(TARGET_BASE.rstrip("/") + "/", path)
    
    # 2. Forward Incoming Headers safely & force uncompressed response
    req_headers = [
        (k, v)
        for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    ]
    # Tell the upstream server NOT to compress the response
    req_headers.append(("accept-encoding", "identity"))
            
    body = await request.body()
    
    # 3. Build and send the streaming request
    try:
        # We must build the request explicitly to use stream=True safely
        proxy_req = client.build_request(
            method=request.method,
            url=url,
            headers=req_headers,
            content=body,
            params=dict(request.query_params)
        )
        
        # stream=True prevents httpx from buffering the response in memory
        resp = await client.send(proxy_req, stream=True)
        
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Bad Gateway: {str(exc)}")
        
    # 4. Construct the StreamingResponse
    # We pass resp.aiter_bytes() as the generator and ensure the httpx stream closes via BackgroundTask
    response = StreamingResponse(
        resp.aiter_bytes(),
        status_code=resp.status_code,
        background=BackgroundTask(resp.aclose)
    )
    
    for k, v in resp.headers.items():
        if k.lower() not in HOP_BY_HOP_HEADERS and k.lower() != "set-cookie":
            response.headers.append(k, v)
            
    
    for k, v in resp.headers.multi_items():
        if k.lower() == "set-cookie":
            response.headers.append(k, v)
            
    return response
