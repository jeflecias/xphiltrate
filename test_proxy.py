from fastapi import FastAPI, Response, Request, HTTPException
import httpx

#setup fastapi, httpx
app = FastAPI()
client = httpx.AsyncClient()

@app.get("/fetch")
async def fetch(request: Request):
	# get url
	url = request.query_params.get("url")
	if not url:
		raise HTTPException(status_code = 400, detail="?")
		
	# proxy
	headers = {
		k: v for k, v in request.headers.items()
		if k.lower() not in ["host", "content-length"]
	}
	
	headers["X-Debug"] = "true"
	headers["User-Agent"] = "Mozilla/5.0"
	resp = await client.get(url, headers=headers)
	
	for k,v in headers.items():
		print(k,v)
	
	
	return Response(
		content=resp.content,
		status_code=resp.status_code,
		headers=headers
	)
