from fastapi import FastAPI, Request, Response
import httpx
from urllib.parse import urljoin

app = FastAPI(title="Base Proxy")

# change this
TARGET_BASE = "https://example.com"   
PROXY_PORT = 8443

client = httpx.AsyncClient(
    follow_redirects=True,
    timeout=30.0
)

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def proxy(request: Request, path: str):
    # Build target URL properly
    url = urljoin(TARGET_BASE.rstrip("/") + "/", path)
    if request.query_params:
        url += "?" + str(request.query_params)

    # Clean headers
    headers = {k: v for k, v in request.headers.items() 
               if k.lower() not in ["host", "content-length", "transfer-encoding"]}

    headers["Host"] = TARGET_BASE.split("//")[1].split("/")[0]

    body = await request.body()

    # Basic capture
    if request.method == "POST":
        print(f"\n[POST → {path}]")
        print(body.decode(errors="ignore")[:800])

    # Forward request
    resp = await client.request(
        method=request.method,
        url=url,
        headers=headers,
        content=body,
        params=request.query_params
    )

    # Log cookies
    if "set-cookie" in resp.headers:
        print(f"[SET-COOKIE] {resp.headers.get_list('set-cookie')}")

    # Clean response headers
    resp_headers = {k: v for k, v in resp.headers.items() 
                    if k.lower() not in ["content-encoding", "transfer-encoding", "content-length"]}

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers=resp_headers
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8443,
        ssl_keyfile="localhost+2-key.pem",
        ssl_certfile="localhost+2.pem",
        log_level="info"
    )
