import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt as jose_jwt
from sqlalchemy.orm import Session

from app.config import settings
from app.database.models import SessionToken


class TokenService:
    def hash_token(self, token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create_access_token(self, user_id: int) -> str:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
        return jose_jwt.encode(
            {
                "sub": str(user_id),
                "type": "access",
                "jti": secrets.token_urlsafe(16),
                "exp": expire,
            },
            settings.secret_key,
            algorithm=settings.algorithm,
        )

    def create_refresh_token(
        self,
        user_id: int,
        db: Session,
        ip_address: Optional[str] = None,
        user_agent_hash: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
        token_family: Optional[str] = None,
    ) -> str:
        refresh_token = secrets.token_urlsafe(48)
        token_family = token_family or secrets.token_urlsafe(16)
        session_token = SessionToken(
            user_id=user_id,
            token_hash=self.hash_token(refresh_token),
            token_family=token_family,
            ip_address=ip_address,
            user_agent_hash=user_agent_hash,
            device_fingerprint=device_fingerprint,
            expires_at=datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days),
        )
        db.add(session_token)
        db.commit()
        return refresh_token

    def rotate_refresh_token(
        self,
        refresh_token: str,
        db: Session,
        ip_address: Optional[str] = None,
        user_agent_hash: Optional[str] = None,
    ) -> tuple[int, str]:
        token_hash = self.hash_token(refresh_token)
        stored = db.query(SessionToken).filter(SessionToken.token_hash == token_hash).first()
        now = datetime.utcnow()
        if not stored or stored.revoked_at or stored.expires_at <= now:
            raise ValueError("Invalid refresh token")

        stored.revoked_at = now
        stored.last_used_at = now
        replacement = self.create_refresh_token(
            stored.user_id,
            db,
            ip_address=ip_address or stored.ip_address,
            user_agent_hash=user_agent_hash or stored.user_agent_hash,
            device_fingerprint=stored.device_fingerprint,
            token_family=stored.token_family,
        )
        stored.replaced_by_hash = self.hash_token(replacement)
        db.commit()
        return stored.user_id, replacement

    def revoke_refresh_token(self, refresh_token: str, db: Session) -> bool:
        token_hash = self.hash_token(refresh_token)
        stored = db.query(SessionToken).filter(SessionToken.token_hash == token_hash).first()
        if not stored:
            return False
        stored.revoked_at = datetime.utcnow()
        db.commit()
        return True

    def decode_access_token(self, token: str) -> int:
        try:
            payload = jose_jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        except JWTError as exc:
            raise ValueError("Invalid access token") from exc
        if payload.get("type") != "access":
            raise ValueError("Invalid access token")
        return int(payload["sub"])

    def create_approval_token(self, user_id: int, challenge_token: str, jti: str) -> str:
        expire = datetime.utcnow() + timedelta(seconds=settings.approval_token_ttl_seconds)
        return jose_jwt.encode(
            {
                "sub": str(user_id),
                "type": "device_approval",
                "challenge": challenge_token,
                "jti": jti,
                "exp": expire,
            },
            settings.secret_key,
            algorithm=settings.algorithm,
        )

    def decode_approval_token(self, token: str) -> dict:
        try:
            payload = jose_jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        except JWTError as exc:
            raise ValueError("Invalid approval token") from exc
        if payload.get("type") != "device_approval":
            raise ValueError("Invalid approval token")
        return payload
