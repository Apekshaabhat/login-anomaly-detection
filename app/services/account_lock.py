from sqlalchemy.orm import Session
from app.database.models import User, AuditLog
from app.config import settings
from datetime import datetime, timedelta
from typing import Optional

class AccountLockService:
    def __init__(self):
        self.max_failed_attempts = settings.max_failed_attempts
        self.lockout_duration = timedelta(minutes=settings.lockout_duration_minutes)

    def should_lock_account(self, user_id: int, db: Session) -> bool:
        # Check recent failed attempts
        from app.database.models import LoginAttempt
        recent_failed = db.query(LoginAttempt).filter(
            LoginAttempt.user_id == user_id,
            LoginAttempt.success == False,
            LoginAttempt.timestamp >= datetime.utcnow() - timedelta(minutes=15)
        ).count()
        return recent_failed >= self.max_failed_attempts

    def lock_account(self, user_id: int, db: Session, reason: str = "Too many failed attempts"):
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            user.is_locked = True
            user.locked_at = datetime.utcnow()
            db.commit()

            # Log the action
            audit_log = AuditLog(
                user_id=user_id,
                action="account_locked",
                details=f"Account locked: {reason}",
                timestamp=datetime.utcnow()
            )
            db.add(audit_log)
            db.commit()

    def unlock_account(self, user_id: int, db: Session, admin_user_id: Optional[int] = None):
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            user.is_locked = False
            user.locked_at = None
            db.commit()

            # Log the action
            audit_log = AuditLog(
                user_id=user_id,
                action="account_unlocked",
                details=f"Account unlocked by admin {admin_user_id}" if admin_user_id else "Account unlocked",
                timestamp=datetime.utcnow()
            )
            db.add(audit_log)
            db.commit()

    def is_account_locked(self, user_id: int, db: Session) -> bool:
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_locked:
            return False
        if user.locked_at and datetime.utcnow() - user.locked_at >= self.lockout_duration:
            user.is_locked = False
            user.locked_at = None
            db.commit()
            return False
        return True
