from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import User
from app.services.auth_context import get_current_user
from app.services.risk_engine import AdaptiveRiskEngine
from app.services.threat_intelligence import ThreatIntelligenceService

router = APIRouter()
risk_engine = AdaptiveRiskEngine()
threat_intel = ThreatIntelligenceService()


class BehaviorTelemetryRequest(BaseModel):
    session_id: str = Field(min_length=3, max_length=160)
    device_fingerprint: Optional[str] = Field(default=None, max_length=255)
    ip_address: Optional[str] = Field(default=None, max_length=80)
    page_path: Optional[str] = Field(default=None, max_length=255)
    typing_speed: Optional[float] = Field(default=None, ge=0, le=500)
    typing_variance: Optional[float] = Field(default=None, ge=0)
    key_hold_mean: Optional[float] = Field(default=None, ge=0)
    key_flight_mean: Optional[float] = Field(default=None, ge=0)
    correction_rate: Optional[float] = Field(default=None, ge=0, le=1)
    mouse_velocity_mean: Optional[float] = Field(default=None, ge=0)
    mouse_velocity_std: Optional[float] = Field(default=None, ge=0)
    mouse_idle_ratio: Optional[float] = Field(default=None, ge=0, le=1)
    scroll_depth: Optional[float] = Field(default=None, ge=0, le=1)
    scroll_velocity_mean: Optional[float] = Field(default=None, ge=0)
    replay_event_count: int = Field(default=0, ge=0, le=50000)
    replay_anomaly_score: Optional[float] = Field(default=None, ge=0, le=100)
    focus_change_count: int = Field(default=0, ge=0, le=500)
    active_seconds: float = Field(default=0.0, ge=0, le=86400)
    extra: Dict[str, Any] = Field(default_factory=dict)


class RiskScoreRequest(BaseModel):
    ip_address: str
    device_fingerprint: Optional[str] = None
    typing_speed: Optional[float] = None
    location_lat: Optional[float] = Field(default=None, ge=-90, le=90)
    location_lon: Optional[float] = Field(default=None, ge=-180, le=180)


class PasswordBreachRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


@router.post("/telemetry", response_model=dict)
def record_telemetry(
    payload: BehaviorTelemetryRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    data = payload.model_dump()
    if not data.get("ip_address"):
        data["ip_address"] = request.client.host if request.client else None
    return risk_engine.record_behavior_telemetry(current_user.id, payload.session_id, db, data)


@router.post("/risk-score", response_model=dict)
def score_risk(
    payload: RiskScoreRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return risk_engine.score_login_context(
        current_user.id,
        db,
        ip_address=payload.ip_address,
        device_fingerprint=payload.device_fingerprint,
        typing_speed=payload.typing_speed,
        latitude=payload.location_lat,
        longitude=payload.location_lon,
        user_agent=request.headers.get("user-agent"),
    )


@router.get("/dashboard", response_model=dict)
def ai_dashboard(db: Session = Depends(get_db)):
    return risk_engine.dashboard(db)


@router.get("/integrations", response_model=dict)
def integration_status():
    return risk_engine.integration_status()


@router.get("/threat-intel/ip/{ip_address}", response_model=dict)
def check_ip_threat_intel(ip_address: str, request: Request, db: Session = Depends(get_db)):
    return threat_intel.check_ip(ip_address, db=db, user_agent=request.headers.get("user-agent"))


@router.post("/threat-intel/password", response_model=dict)
def check_password_breach(payload: PasswordBreachRequest, db: Session = Depends(get_db)):
    return threat_intel.check_pwned_password(payload.password, db=db)
