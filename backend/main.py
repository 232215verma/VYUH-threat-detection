"""
NetGraph Sentinel — Backend (Phase 4/7/8: Full pipeline + demo controls + RAG explanations)
"""

import asyncio
from datetime import datetime, timezone

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from database import init_db, get_alerts, clear_alerts
from pipeline import run_simulation, run_single_attack_demo, run_full_demo_sequence

app = FastAPI(title="NetGraph Sentinel API", version="0.8.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


@app.on_event("startup")
def on_startup():
    init_db()


class SimulationRequest(BaseModel):
    csv_path: str = "../data/synthetic_traffic.csv"
    batch_size: int = 20
    delay_seconds: float = 0.5


class DemoAttackRequest(BaseModel):
    attack: str  # portscan | ddos | c2 | dga | dnstunnel | exfil


class ExplainRequest(BaseModel):
    type: str
    source: str | None = None
    target: str | None = None
    confidence: float = 0.0
    evidence: list[str] = []


VALID_ATTACKS = {"portscan", "ddos", "c2", "dga", "dnstunnel", "exfil"}


@app.get("/api/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@app.get("/api/hello")
def hello():
    return {"message": "NetGraph Sentinel backend is alive.", "phase": "8 - RAG explanations"}


@app.post("/api/start-simulation")
async def start_simulation(req: SimulationRequest):
    asyncio.create_task(
        run_simulation(req.csv_path, manager, req.batch_size, req.delay_seconds)
    )
    return {"status": "started", "csv_path": req.csv_path}


@app.post("/api/demo/attack")
async def demo_single_attack(req: DemoAttackRequest):
    if req.attack not in VALID_ATTACKS:
        return {"status": "error", "message": f"Unknown attack '{req.attack}'. Valid: {sorted(VALID_ATTACKS)}"}
    asyncio.create_task(run_single_attack_demo(req.attack, manager))
    return {"status": "started", "attack": req.attack}


@app.post("/api/demo/full")
async def demo_full_sequence():
    asyncio.create_task(run_full_demo_sequence(manager))
    return {"status": "started", "mode": "full_demo"}


@app.get("/api/alerts")
def list_alerts(limit: int = 100):
    return {"alerts": get_alerts(limit)}


@app.delete("/api/alerts")
def delete_alerts():
    clear_alerts()
    return {"status": "cleared"}


@app.post("/api/explain-alert")
def explain_alert_endpoint(req: ExplainRequest):
    from rag_engine import explain_alert
    return explain_alert(req.dict())


@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)