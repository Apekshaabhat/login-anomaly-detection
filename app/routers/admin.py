from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Dict, Any
from collections import Counter, defaultdict
from statistics import mean
from datetime import datetime, timedelta
import json
from app.database.connection import get_db
from app.database.models import AuditLog, LoginAttempt, User, UserProfile, AlertRecord
from app.schemas.analytics import BehaviorResponse, BehaviorTrendPoint, BehaviorComparisonPoint, DashboardResponse
from app.services.logging_service import LoggingService
from app.services.anomaly_detection import AnomalyDetectionEngine
from app.services.account_lock import AccountLockService

router = APIRouter()
logging_service = LoggingService()
anomaly_engine = AnomalyDetectionEngine()
lock_service = AccountLockService()

class RetrainRequest(BaseModel):
    admin_token: str

class AddBlacklistRequest(BaseModel):
    password: str
    admin_token: str


class AdminActionRequest(BaseModel):
    admin_token: str


def _parse_reasons(raw_reasons: Any) -> List[str]:
    if not raw_reasons:
        return []
    if isinstance(raw_reasons, list):
        return raw_reasons
    try:
        return json.loads(raw_reasons)
    except Exception:
        return [str(raw_reasons)]


def _location_label(lat: float | None, lon: float | None) -> str:
    if lat is None or lon is None:
        return "Unknown"
    return f"{lat:.2f}, {lon:.2f}"


def _status_from_decision(decision: str, risk_score: float) -> str:
    if decision == "block":
        return "blocked"
    if risk_score >= 40 or decision == "require_verification":
        return "suspicious"
    return "safe"


def _alert_payload(alert: AlertRecord) -> Dict[str, Any]:
    username = alert.user.username if getattr(alert, "user", None) else f"user-{alert.user_id}"
    return {
        "id": alert.id,
        "user_id": alert.user_id,
        "username": username,
        "login_attempt_id": alert.login_attempt_id,
        "time": alert.created_at,
        "message": alert.message,
        "severity": alert.severity,
        "attack_type": alert.attack_type or "None",
        "resolved": alert.resolved,
        "requires_manual_action": alert.requires_manual_action,
        "auto_action": alert.auto_action,
    }

@router.get("/logs", response_model=List[Dict[str, Any]])
def get_audit_logs(limit: int = 100, db: Session = Depends(get_db)):
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "action": log.action,
            "details": log.details,
            "timestamp": log.timestamp,
            "ip_address": log.ip_address
        }
        for log in logs
    ]

@router.get("/login-attempts", response_model=List[Dict[str, Any]])
def get_login_attempts(user_id: int = None, limit: int = 100, db: Session = Depends(get_db)):
    query = db.query(LoginAttempt)
    if user_id:
        query = query.filter(LoginAttempt.user_id == user_id)
    attempts = query.order_by(LoginAttempt.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": attempt.id,
            "user_id": attempt.user_id,
            "timestamp": attempt.timestamp,
            "ip_address": attempt.ip_address,
            "success": attempt.success,
            "risk_score": attempt.risk_score,
            "decision": attempt.decision,
            "reasons": attempt.reasons
        }
        for attempt in attempts
    ]


@router.get("/alerts", response_model=List[Dict[str, Any]])
def get_alerts(limit: int = 100, db: Session = Depends(get_db)):
    alerts = db.query(AlertRecord).order_by(AlertRecord.created_at.desc()).limit(limit).all()
    return [_alert_payload(alert) for alert in alerts]


@router.post("/alerts/{alert_id}/resolve", response_model=dict)
def resolve_alert(alert_id: int, request: AdminActionRequest, db: Session = Depends(get_db)):
    if request.admin_token != "admin_secret":
        raise HTTPException(status_code=403, detail="Invalid admin token")

    alert = db.query(AlertRecord).filter(AlertRecord.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.resolved = True
    alert.resolved_at = datetime.utcnow()
    db.commit()
    return {"message": "Alert resolved"}


@router.post("/alerts/{alert_id}/block", response_model=dict)
def block_from_alert(alert_id: int, request: AdminActionRequest, db: Session = Depends(get_db)):
    if request.admin_token != "admin_secret":
        raise HTTPException(status_code=403, detail="Invalid admin token")

    alert = db.query(AlertRecord).filter(AlertRecord.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if not alert.user_id:
        raise HTTPException(status_code=400, detail="Alert has no linked user")

    lock_service.lock_account(alert.user_id, db, reason=f"Manual block from alert {alert.id}")
    attempt = db.query(LoginAttempt).filter(LoginAttempt.id == alert.login_attempt_id).first()
    if attempt:
        attempt.decision = "block"
        attempt.risk_score = max(70.0, attempt.risk_score or 0.0)
    alert.resolved = True
    alert.resolved_at = datetime.utcnow()
    alert.auto_action = "block"
    db.commit()
    return {"message": "User blocked from alert"}


@router.get("/dashboard", response_model=DashboardResponse)
def get_dashboard(limit: int = 100, db: Session = Depends(get_db)):
    attempts = db.query(LoginAttempt).order_by(LoginAttempt.timestamp.desc()).limit(limit).all()
    logs = []
    for attempt in attempts:
        username = attempt.user.username if attempt.user else f"user-{attempt.user_id}"
        logs.append({
            "id": attempt.id,
            "user": username,
            "time": attempt.timestamp,
            "location": _location_label(attempt.location_lat, attempt.location_lon),
            "device": attempt.device_fingerprint,
            "risk": round(attempt.risk_score or 0, 2),
            "status": _status_from_decision(attempt.decision, attempt.risk_score or 0),
            "ip_address": attempt.ip_address,
            "location_lat": attempt.location_lat,
            "location_lon": attempt.location_lon,
            "reasons": _parse_reasons(attempt.reasons),
        })

    grouped_scores = defaultdict(list)
    for attempt in reversed(attempts):
        grouped_scores[attempt.timestamp.strftime("%H:%M")].append(attempt.risk_score or 0)

    timeline = []
    all_scores = [attempt.risk_score or 0 for attempt in attempts]
    baseline = round(mean(all_scores), 2) if all_scores else 0.0
    for label, scores in grouped_scores.items():
        timeline.append({
            "time": label,
            "risk": round(mean(scores), 2),
            "baseline": baseline,
        })

    status_counts = Counter(item["status"] for item in logs)
    distribution = [
        {"name": "Normal", "value": status_counts.get("safe", 0)},
        {"name": "Suspicious", "value": status_counts.get("suspicious", 0)},
        {"name": "Blocked", "value": status_counts.get("blocked", 0)},
    ]

    return {
        "logs": logs,
        "timeline": timeline,
        "distribution": distribution,
    }


@router.get("/behavior/{username}", response_model=BehaviorResponse)
def get_behavior(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    profile = db.query(UserProfile).filter(UserProfile.user_id == user.id).first()
    attempts = db.query(LoginAttempt).filter(LoginAttempt.user_id == user.id).order_by(LoginAttempt.timestamp.asc()).all()
    recent_attempts = attempts[-30:]

    if not recent_attempts:
        return {
            "username": username,
            "is_new_user": True,
            "typical_login_time": "No data yet",
            "frequent_locations": [],
            "devices_used": [],
            "trust_score": 50.0,
            "trend_data": [],
            "comparison_data": [],
            "trust_history": [],
            "failed_attempts": 0,
        }

    location_counts = Counter(
        _location_label(item.location_lat, item.location_lon)
        for item in recent_attempts
        if item.location_lat is not None and item.location_lon is not None
    )
    device_counts = Counter(item.device_fingerprint for item in recent_attempts if item.device_fingerprint)

    trend_groups = defaultdict(list)
    for attempt in recent_attempts:
        trend_groups[attempt.timestamp.strftime("%m-%d")].append(attempt)

    trend_data = []
    for label, items in trend_groups.items():
        typing_values = [item.typing_speed for item in items if item.typing_speed is not None]
        trend_data.append(BehaviorTrendPoint(
            label=label,
            login_count=len(items),
            avg_typing_speed=round(mean(typing_values), 2) if typing_values else 0.0,
            failed_attempts=sum(1 for item in items if not item.success),
        ))

    last_attempt = recent_attempts[-1]
    typical_login_time = (
        f"{int(profile.login_time_mean):02d}:00 - {int(profile.login_time_mean + 1):02d}:00 UTC"
        if profile and profile.login_time_mean is not None
        else last_attempt.timestamp.strftime("%H:00 UTC")
    )

    avg_typing = mean([item.typing_speed for item in recent_attempts if item.typing_speed is not None]) if recent_attempts else 0.0
    current_typing = last_attempt.typing_speed or 0.0
    failed_attempts = sum(1 for item in recent_attempts if not item.success)
    normal_location_conf = 100.0
    if profile and profile.location_lat_mean is not None and last_attempt.location_lat is not None and last_attempt.location_lon is not None:
        location_delta = abs(last_attempt.location_lat - profile.location_lat_mean) + abs(last_attempt.location_lon - (profile.location_lon_mean or 0))
        normal_location_conf = max(0.0, 100.0 - (location_delta * 10))

    comparison_data = [
        BehaviorComparisonPoint(axis="Login Time", normal=85, current=70 if profile and profile.login_time_mean is not None else 50),
        BehaviorComparisonPoint(axis="Location", normal=90, current=round(normal_location_conf, 2)),
        BehaviorComparisonPoint(axis="Device", normal=95, current=100 if last_attempt.device_fingerprint in device_counts else 60),
        BehaviorComparisonPoint(axis="Typing Speed", normal=round(avg_typing or 60, 2), current=round(current_typing, 2)),
        BehaviorComparisonPoint(axis="Failed Attempts", normal=10, current=min(100, failed_attempts * 10)),
    ]

    trust_history = [
        {
            "date": attempt.timestamp.strftime("%Y-%m-%d"),
            "score": round(100 - min(100, attempt.risk_score or 0), 2),
        }
        for attempt in recent_attempts[-14:]
    ]

    trust_score = round(mean(item["score"] for item in trust_history), 2) if trust_history else 50.0

    return {
        "username": username,
        "is_new_user": profile.learning_mode if profile else True,
        "typical_login_time": typical_login_time,
        "frequent_locations": [item for item, _ in location_counts.most_common(3)],
        "devices_used": [item for item, _ in device_counts.most_common(5)],
        "trust_score": trust_score,
        "trend_data": trend_data,
        "comparison_data": comparison_data,
        "trust_history": trust_history,
        "failed_attempts": failed_attempts,
    }

@router.post("/retrain-model", response_model=dict)
def retrain_model(request: RetrainRequest, db: Session = Depends(get_db)):
    if request.admin_token != "admin_secret":
        raise HTTPException(status_code=403, detail="Invalid admin token")
    model_trained = anomaly_engine.retrain_from_login_attempts(db)
    if not model_trained:
        raise HTTPException(status_code=400, detail="Not enough successful login data to retrain model")

    sample_count = db.query(LoginAttempt).filter(LoginAttempt.success == True).count()
    logging_service.log_admin_action(0, "model_retrained", f"Retrained with {sample_count} successful samples", db)

    return {"message": "Model retrained successfully"}

@router.post("/add-blacklist", response_model=dict)
def add_to_blacklist(request: AddBlacklistRequest, db: Session = Depends(get_db)):
    if request.admin_token != "admin_secret":
        raise HTTPException(status_code=403, detail="Invalid admin token")

    from app.services.password_security import PasswordSecurityEngine
    engine = PasswordSecurityEngine()
    engine.add_to_blacklist(request.password)

    logging_service.log_admin_action(0, "blacklist_added", f"Added password to blacklist", db)

    return {"message": "Password added to blacklist"}
