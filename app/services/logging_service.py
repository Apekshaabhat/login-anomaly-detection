import logging
from sqlalchemy.orm import Session
from app.database.models import AuditLog
from datetime import datetime

class LoggingService:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO)

    def log_login_attempt(self, user_id: int, ip_address: str, success: bool, risk_score: float, decision: str, reasons: list, db: Session):
        details = {
            "ip_address": ip_address,
            "success": success,
            "risk_score": risk_score,
            "decision": decision,
            "reasons": reasons
        }

        audit_log = AuditLog(
            user_id=user_id,
            action="login_attempt",
            details=str(details),
            timestamp=datetime.utcnow(),
            ip_address=ip_address
        )
        db.add(audit_log)
        db.commit()

        self.logger.info(f"Login attempt for user {user_id}: {decision} (risk: {risk_score})")

    def log_admin_action(self, admin_user_id: int, action: str, details: str, db: Session):
        audit_log = AuditLog(
            user_id=admin_user_id,
            action=action,
            details=details,
            timestamp=datetime.utcnow()
        )
        db.add(audit_log)
        db.commit()

        self.logger.info(f"Admin action by {admin_user_id}: {action}")

    def log_security_event(self, user_id: int, action: str, details: str, db: Session, ip_address: str = None):
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            details=details,
            timestamp=datetime.utcnow(),
            ip_address=ip_address,
        )
        db.add(audit_log)
        db.commit()

        self.logger.info(f"Security event for user {user_id}: {action}")
