import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Header, HTTPException
from fastapi.responses import HTMLResponse
from datetime import datetime
from pydantic import BaseModel
import asyncio
import os

app = FastAPI()

# =========================
# CONFIG
# =========================
API_KEY = os.getenv("MONITORING_API_KEY")
MAX_PAYLOAD_SIZE = 5000

active_connections = []
connections_lock = asyncio.Lock()

# =========================
# DATA MODEL (VALIDATION)
# =========================
class LogEntry(BaseModel):
    type: str
    source: str
    data: dict | str

# =========================
# HTML DASHBOARD (unchanged UI)
# =========================

# =========================
# AUTH CHECK
# =========================
def verify_api_key(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden")

# =========================
# ROUTES
# =========================
@app.get("/")
async def get_dashboard():
        HTML_CONTENT = """ 
    <!DOCTYPE html>
    <html>
    <head>
        <title>Intercept Dashboard</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 20px; }
            .container { max-width: 1000px; margin: auto; }
            .log-entry { background: #1e293b; border-left: 4px solid #38bdf8; padding: 15px; margin-bottom: 10px; border-radius: 4px; animation: fadeIn 0.3s; }
            .timestamp { color: #94a3b8; font-size: 0.85rem; font-family: monospace; }
            .tag { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: bold; margin-right: 10px; text-transform: uppercase; }
            .tag-cookie { background: #8b5cf6; color: white; }
            .tag-auth { background: #f43f5e; color: white; }
            .data { display: block; margin-top: 10px; color: #f1f5f9; background: #000; padding: 10px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔍 Traffic Observer</h1>
            <div id="logs"></div>
        </div>
        <script>
            const ws = new WebSocket(`ws://${window.location.host}/ws`);
            const logsContainer = document.getElementById('logs');

            ws.onmessage = (event) => {
                const item = JSON.parse(event.data);
                const div = document.createElement('div');
                div.className = 'log-entry';

                const tagClass = item.type.toLowerCase().includes('auth') ? 'tag-auth' : 'tag-cookie';

                div.innerHTML = `
                    <span class="timestamp">${item.time}</span><br>
                    <span class="tag ${tagClass}">${item.type}</span>
                    <strong>${item.source}</strong>
                    <code class="data">${JSON.stringify(item.data, null, 2)}</code>
                `;
                logsContainer.prepend(div);
            };
        </script>
    </body>
    </html>
    """

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    async with connections_lock:
        active_connections.append(websocket)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        async with connections_lock:
            if websocket in active_connections:
                active_connections.remove(websocket)

@app.post("/push")
async def push_log(entry: LogEntry, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)

    # Size protection
    if len(str(entry.data)) > MAX_PAYLOAD_SIZE:
        raise HTTPException(status_code=413, detail="Payload too large")

    payload = {
        "type": entry.type,
        "source": entry.source,
        "data": entry.data,
        "time": datetime.now().strftime("%H:%M:%S.%f")[:-3]
    }

    # Broadcast safely
    async with connections_lock:
        dead_connections = []
        for connection in active_connections:
            try:
                await connection.send_json(payload)
            except Exception:
                dead_connections.append(connection)

        for conn in dead_connections:
            active_connections.remove(conn)

    return {"status": "sent"}

@app.post("/ingest")
async def ingest(entry: LogEntry, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)

    payload = {
        "type": entry.type,
        "source": entry.source,
        "data": entry.data,
        "time": datetime.now().strftime("%H:%M:%S.%f")[:-3]
    }

    async with connections_lock:
        dead_connections = []
        for connection in active_connections:
            try:
                await connection.send_json(payload)
            except Exception:
                dead_connections.append(connection)

        for conn in dead_connections:
            active_connections.remove(conn)

    return {"status": "ingested"}

