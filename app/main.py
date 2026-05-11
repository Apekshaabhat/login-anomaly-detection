from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from app.routers import auth, admin, simulation
from app.database.connection import engine
from app.database.models import Base
from app.ml.model import shared_anomaly_model
import json
from sqlalchemy import inspect, text

# Create database tables
Base.metadata.create_all(bind=engine)

def _add_column_if_missing(table_name: str, column_name: str, ddl: str) -> None:
    inspector = inspect(engine)
    columns = {column["name"] for column in inspector.get_columns(table_name)}
    if column_name in columns:
        return
    with engine.begin() as connection:
        connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {ddl}"))

if engine.url.get_backend_name() == "sqlite":
    _add_column_if_missing("users", "email", "email VARCHAR")
    _add_column_if_missing("users", "phone", "phone VARCHAR")
    _add_column_if_missing("users", "locked_at", "locked_at DATETIME")

app = FastAPI(
    title="Universal Login Security Middleware API",
    description="A production-grade API for login security, anomaly detection, and behavioral analysis",
    version="1.0.0"
)

connected_clients: list[WebSocket] = []

async def broadcast_event(event: dict) -> None:
    dead: list[WebSocket] = []
    for ws in connected_clients:
        try:
            await ws.send_text(json.dumps(event, default=str))
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in connected_clients:
            connected_clients.remove(ws)

app.state.broadcast_event = broadcast_event

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(admin.router, prefix="/api/admin", tags=["Administration"])
app.include_router(simulation.router, prefix="/api/simulation", tags=["Simulation"])

@app.on_event("startup")
def warm_models():
    shared_anomaly_model.load_model()

@app.get("/")
def read_root():
    return {"message": "Universal Login Security Middleware API"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in connected_clients:
            connected_clients.remove(websocket)
