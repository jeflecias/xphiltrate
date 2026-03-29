from fastapi import FastAPI, Response, Request, HTTPException
import httpx
from urllib.parse import urljoin

#setup fastapi, httpx
app = FastAPI()
client = httpx.AsyncClient()
TARGET_BASE = "https://example.com"

#decorator
@app.api_route("/{path:path}", methods=["GET","POST","PUT","DELETE"])
async def fetch(request: Request, path: str):
	# get clean url
	url = urljoin(TARGET_BASE.rstrip("/") + "/", path)
	
	if not url:
		raise HTTPException(status_code = 400, detail="?")
		
	# query param
	if request.query_params:
		url += "?" + str(request.query_params)
		
	# body
	body = await request.body()
		
	# forward headers
	headers = {
		k: v for k, v in request.headers.items()
		if k.lower() not in ["host", "content-length"]
	}
	
	# separate, debug
	headers["X-Debug"] = "true"
	headers["User-Agent"] = "Mozilla/5.0"
	# manually set host
	headers["Host"] = TARGET_BASE.split("//")[1].split("/")[0]
	
	# resp headers
	resp = await client.request(
		method=request.method,
		url=url, 
		headers=headers,
		content=body,
		params=request.query_params
	)
	
	resp_headers = {
		k:v for k, v in resp.headers.items()
		if k.lower() not in ["content-length", "transfer-encoding", "content-encoding"]
	}
	
	return Response(
		content=resp.content,
		status_code=resp.status_code,
		headers=resp_headers
	)
