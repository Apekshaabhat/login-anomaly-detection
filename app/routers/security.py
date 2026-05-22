import json
from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import AlertRecord, LoginAttempt, SecurityNotification, SessionToken, User
from app.services.auth_context import get_current_user

router = APIRouter()


def _parse_reasons(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else [str(parsed)]
    except ValueError:
        return [raw]


@router.get("/history", response_model=list[dict])
def login_history(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    attempts = db.query(LoginAttempt).filter(
        LoginAttempt.user_id == current_user.id,
    ).order_by(LoginAttempt.timestamp.desc()).limit(100).all()
    return [
        {
            "id": attempt.id,
            "timestamp": attempt.timestamp,
            "ip_address": attempt.ip_address,
            "location_lat": attempt.location_lat,
            "location_lon": attempt.location_lon,
            "country": attempt.country,
            "city": attempt.city,
            "device_fingerprint": attempt.device_fingerprint,
            "success": attempt.success,
            "risk_score": attempt.risk_score,
            "decision": attempt.decision,
            "reasons": _parse_reasons(attempt.reasons),
            "mfa_required": attempt.mfa_required,
            "mfa_method": attempt.mfa_method,
            "mfa_verified_at": attempt.mfa_verified_at,
            "new_device": attempt.new_device,
            "new_ip": attempt.new_ip,
            "device_approval_status": attempt.device_approval_status,
            "ip_risk_score": attempt.ip_risk_score,
            "asn": attempt.asn,
            "provider": attempt.provider,
            "is_vpn": attempt.is_vpn,
            "is_proxy": attempt.is_proxy,
            "is_tor": attempt.is_tor,
        }
        for attempt in attempts
    ]


@router.get("/alerts", response_model=list[dict])
def security_alerts(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    alerts = db.query(AlertRecord).filter(
        AlertRecord.user_id == current_user.id,
    ).order_by(AlertRecord.created_at.desc()).limit(100).all()
    notifications = db.query(SecurityNotification).filter(
        SecurityNotification.user_id == current_user.id,
    ).order_by(SecurityNotification.created_at.desc()).limit(100).all()

    alert_payload = [
        {
            "id": f"alert-{alert.id}",
            "source": "alert",
            "time": alert.created_at,
            "message": alert.message,
            "severity": alert.severity,
            "status": "resolved" if alert.resolved else "active",
            "type": alert.attack_type or "security",
        }
        for alert in alerts
    ]
    notification_payload = [
        {
            "id": f"notification-{notification.id}",
            "source": "notification",
            "time": notification.created_at,
            "message": notification.subject or notification.notification_type,
            "severity": "medium" if notification.notification_type == "security_alert" else "low",
            "status": notification.status,
            "type": notification.notification_type,
        }
        for notification in notifications
    ]
    return sorted(alert_payload + notification_payload, key=lambda item: item["time"], reverse=True)[:100]


@router.get("/sessions", response_model=list[dict])
def active_sessions(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sessions = db.query(SessionToken).filter(
        SessionToken.user_id == current_user.id,
    ).order_by(SessionToken.created_at.desc()).limit(100).all()
    now = datetime.utcnow()
    return [
        {
            "id": session.id,
            "ip_address": session.ip_address,
            "device_fingerprint": session.device_fingerprint,
            "user_agent_hash": session.user_agent_hash,
            "created_at": session.created_at,
            "last_used_at": session.last_used_at,
            "expires_at": session.expires_at,
            "revoked_at": session.revoked_at,
            "active": session.revoked_at is None and session.expires_at > now,
        }
        for session in sessions
    ]
