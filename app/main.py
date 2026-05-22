from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from app.routers import auth, admin, simulation, model, devices, security, ai_security
from app.database.connection import engine
from app.database.connection import SessionLocal
from app.database.models import Base, User
from app.config import settings
from app.ml.model import shared_anomaly_model
from app.utils.helpers import hash_password
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

_add_column_if_missing("users", "email", "email VARCHAR")
_add_column_if_missing("users", "phone", "phone VARCHAR")
_add_column_if_missing("users", "locked_at", "locked_at DATETIME")
_add_column_if_missing("devices", "state", "state VARCHAR DEFAULT 'pending_verification'")
_add_column_if_missing("devices", "nickname", "nickname VARCHAR")
_add_column_if_missing("devices", "browser", "browser VARCHAR")
_add_column_if_missing("devices", "os", "os VARCHAR")
_add_column_if_missing("devices", "device_type", "device_type VARCHAR")
_add_column_if_missing("devices", "screen_resolution", "screen_resolution VARCHAR")
_add_column_if_missing("devices", "timezone", "timezone VARCHAR")
_add_column_if_missing("devices", "language", "language VARCHAR")
_add_column_if_missing("devices", "hardware_fingerprint", "hardware_fingerprint VARCHAR")
_add_column_if_missing("devices", "user_agent_hash", "user_agent_hash VARCHAR")
_add_column_if_missing("devices", "remember_device", "remember_device BOOLEAN DEFAULT FALSE")
_add_column_if_missing("devices", "first_ip_address", "first_ip_address VARCHAR")
_add_column_if_missing("devices", "last_ip_address", "last_ip_address VARCHAR")
_add_column_if_missing("devices", "approval_status", "approval_status VARCHAR DEFAULT 'approved'")
_add_column_if_missing("devices", "approved_at", "approved_at DATETIME")
_add_column_if_missing("devices", "last_mfa_method", "last_mfa_method VARCHAR")
_add_column_if_missing("devices", "suspicious_reason", "suspicious_reason TEXT")
_add_column_if_missing("devices", "blocked_at", "blocked_at DATETIME")
_add_column_if_missing("login_attempts", "mfa_required", "mfa_required BOOLEAN DEFAULT FALSE")
_add_column_if_missing("login_attempts", "mfa_method", "mfa_method VARCHAR")
_add_column_if_missing("login_attempts", "mfa_verified_at", "mfa_verified_at DATETIME")
_add_column_if_missing("login_attempts", "new_device", "new_device BOOLEAN DEFAULT FALSE")
_add_column_if_missing("login_attempts", "new_ip", "new_ip BOOLEAN DEFAULT FALSE")
_add_column_if_missing("login_attempts", "device_approval_status", "device_approval_status VARCHAR")
_add_column_if_missing("login_attempts", "asn", "asn VARCHAR")
_add_column_if_missing("login_attempts", "provider", "provider VARCHAR")
_add_column_if_missing("login_attempts", "country", "country VARCHAR")
_add_column_if_missing("login_attempts", "city", "city VARCHAR")
_add_column_if_missing("login_attempts", "is_vpn", "is_vpn BOOLEAN DEFAULT FALSE")
_add_column_if_missing("login_attempts", "is_proxy", "is_proxy BOOLEAN DEFAULT FALSE")
_add_column_if_missing("login_attempts", "is_tor", "is_tor BOOLEAN DEFAULT FALSE")
_add_column_if_missing("login_attempts", "ip_risk_score", "ip_risk_score FLOAT DEFAULT 0")
_add_column_if_missing("behavior_telemetry", "scroll_depth", "scroll_depth FLOAT")
_add_column_if_missing("behavior_telemetry", "scroll_velocity_mean", "scroll_velocity_mean FLOAT")
_add_column_if_missing("behavior_telemetry", "replay_event_count", "replay_event_count INTEGER DEFAULT 0")
_add_column_if_missing("behavior_telemetry", "replay_anomaly_score", "replay_anomaly_score FLOAT DEFAULT 0")


def _seed_demo_users() -> None:
    if not settings.seed_demo_users:
        return

    demo_users = [
        (settings.demo_user_username, settings.demo_user_password, settings.demo_user_email),
        (settings.demo_admin_username, settings.demo_admin_password, settings.demo_admin_email),
    ]
    db = SessionLocal()
    try:
        for username, password, email in demo_users:
            existing = db.query(User).filter(User.username == username).first()
            if existing:
                existing.email = email or existing.email
                existing.hashed_password = hash_password(password)
                existing.is_locked = False
                existing.locked_at = None
                continue
            db.add(
                User(
                    username=username,
                    email=email,
                    hashed_password=hash_password(password),
                    is_locked=False,
                )
            )
        db.commit()
    finally:
        db.close()


_seed_demo_users()

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

@app.middleware("http")
async def csrf_protection(request: Request, call_next):
    if settings.csrf_protection_enabled and request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        uses_cookie_auth = bool(request.cookies.get("access_token") or request.cookies.get("refresh_token"))
        if uses_cookie_auth:
            csrf_cookie = request.cookies.get("csrf_token")
            csrf_header = request.headers.get("x-csrf-token")
            if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
                from fastapi.responses import JSONResponse

                return JSONResponse({"detail": "CSRF token missing or invalid"}, status_code=403)
    return await call_next(request)

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(devices.router, prefix="/api/devices", tags=["Devices"])
app.include_router(security.router, prefix="/api/security", tags=["Security"])
app.include_router(ai_security.router, prefix="/api/ai", tags=["AI Security"])
app.include_router(admin.router, prefix="/api/admin", tags=["Administration"])
app.include_router(simulation.router, prefix="/api/simulation", tags=["Simulation"])
app.include_router(model.router, prefix="/api/model", tags=["Model Operations"])

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
