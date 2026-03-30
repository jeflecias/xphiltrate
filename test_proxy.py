from fastapi import FastAPI, Request, Response, HTTPException
import httpx
from urllib.parse import urljoin

app = FastAPI()


client = httpx.AsyncClient(follow_redirects=False)
TARGET_BASE = "https://0a1f00e804d373e981fefc0400e5002c.web-security-academy.net/"


HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", 
    "proxy-authorization", "te", "trailers", 
    "transfer-encoding", "upgrade", "host", "content-length",
    "content-encoding"
}

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy(request: Request, path: str):
   
    url = urljoin(TARGET_BASE.rstrip("/") + "/", path)
    
   
    req_headers = [
        (k, v)
        for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    ]
            
    body = await request.body()
    
    
    try:
        resp = await client.request(
            method=request.method,
            url=url,
            headers=req_headers,
            content=body,
            params=request.query_params
        )
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Bad Gateway: {str(exc)}")
        
   
    response = Response(
        content=resp.content,
        status_code=resp.status_code
    )
    
 
    for k, v in resp.headers.multi_items():
        if k.lower() not in HOP_BY_HOP_HEADERS:
            response.headers.append(k, v)
            
    return response
