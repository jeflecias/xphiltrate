from fastapi import FastAPI, Response, Request, HTTPException
import httpx
from urllib.parse import urljoin

#setup fastapi, httpx
app = FastAPI()
client = httpx.AsyncClient()
TARGET_BASE = "https://example.com"

# match any path and capture
@app.api_route("/{path:path}", methods=["GET","POST","PUT","DELETE"])
async def fetch(request: Request, path: str):
	# build target url
	url = urljoin(TARGET_BASE.rstrip("/") + "/", path)
	
	if not url:
		raise HTTPException(status_code = 400, detail="?")
		
	# append query to orig url
	if request.query_params:
		url += "?" + str(request.query_params)
		
	# request body (in raw)
	body = await request.body()
		
	# incoming headers from client
	headers = {
		k: v for k, v in request.headers.items()
		if k.lower() not in ["host", "content-length"]
	}
	
	# separate, debug
	headers["X-Debug"] = "true"
	headers["User-Agent"] = "Mozilla/5.0"
	
	# manually set host to avoid rejection (ex. https://example.com -> example.com
	headers["Host"] = TARGET_BASE.split("//")[1].split("/")[0]
	
	# actual proxy action
	# recreate original request -> send to target server (proxy acts as client)
	resp = await client.request(
		method=request.method,
		url=url, 
		headers=headers,
		content=body,
		params=request.query_params
	)
	
	# clean response headers
	resp_headers = {
		k:v for k, v in resp.headers.items()
		if k.lower() not in ["content-length", "transfer-encoding", "content-encoding"]
	}
	
	# send back to client
	return Response(
		content=resp.content,
		status_code=resp.status_code,
		headers=resp_headers
	)
