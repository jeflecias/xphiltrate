from fastapi import FastAPI
import uvicorn

app = FastAPI()

@app.get("/")
def root():
    return {"message": "proxy is alive"}

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8443,
        ssl_certfile="localhost+2.pem",
        ssl_keyfile="localhost+2-key.pem",
        log_level="info"
    )