import logging
from sqlalchemy.orm import Session
from app.database.models import AlertRecord, AuditLog
from datetime import datetime
import json

class LoggingService:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO)

    def log_login_attempt(
        self,
        user_id: int,
        ip_address: str,
        success: bool,
        risk_score: float,
        decision: str,
        reasons: list,
        db: Session,
        login_attempt_id: int = None,
        mfa_method: str = None,
        new_device: bool = False,
        new_ip: bool = False,
        device_approval_status: str = None,
    ) -> None:
        details = {
            "user_id": user_id,
            "ip_address": ip_address,
            "success": success,
            "risk_score": risk_score,
            "decision": decision,
            "reasons": reasons,
            "mfa_method": mfa_method,
            "new_device": new_device,
            "new_ip": new_ip,
            "device_approval_status": device_approval_status,
        }

        audit_log = AuditLog(
            user_id=user_id,
            action="login_attempt",
            details=json.dumps(details, default=str),
            timestamp=datetime.utcnow(),
            ip_address=ip_address
        )
        db.add(audit_log)

        if risk_score >= 70 or decision == "block":
            severity = self._severity_from_risk(risk_score)
            alert = AlertRecord(
                user_id=user_id,
                login_attempt_id=login_attempt_id,
                severity=severity,
                message=f"High-risk login attempt from {ip_address}",
                attack_type=self._attack_type_from_reasons(reasons),
                requires_manual_action=severity in ("critical", "high"),
                auto_action="block" if decision == "block" else None,
            )
            db.add(alert)

        db.commit()

        self.logger.info(f"Login attempt for user {user_id}: {decision} (risk: {risk_score})")

    def log_admin_action(self, admin_user_id: int, action: str, details: str, db: Session) -> None:
        audit_log = AuditLog(
            user_id=admin_user_id,
            action=action,
            details=json.dumps({"details": details}, default=str),
            timestamp=datetime.utcnow()
        )
        db.add(audit_log)
        db.commit()

        self.logger.info(f"Admin action by {admin_user_id}: {action}")

    def log_security_event(self, user_id: int, event_type: str, details: str, db: Session, ip_address: str = None) -> None:
        audit_log = AuditLog(
            user_id=user_id,
            action=event_type,
            details=json.dumps({"details": details}, default=str),
            timestamp=datetime.utcnow(),
            ip_address=ip_address,
        )
        db.add(audit_log)
        db.commit()

        self.logger.info(f"Security event for user {user_id}: {event_type}")

    def _severity_from_risk(self, risk_score: float) -> str:
        if risk_score >= 90:
            return "critical"
        if risk_score >= 70:
            return "high"
        if risk_score >= 40:
            return "medium"
        return "low"

    def _attack_type_from_reasons(self, reasons: list) -> str:
        reason_text = " ".join(str(reason).lower() for reason in reasons)
        if "failed" in reason_text or "brute" in reason_text:
            return "brute_force"
        if "travel" in reason_text:
            return "account_takeover"
        if "device" in reason_text or "ip address" in reason_text:
            return "suspicious_device"
        return "None"
