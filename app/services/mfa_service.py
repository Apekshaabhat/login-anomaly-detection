import json
from typing import List

import pyotp
from sqlalchemy.orm import Session

from app.database.models import MFASecrets, User
from app.services.verification import VerificationService


class MFAService:
    def __init__(self) -> None:
        self.verification_service = VerificationService()

    def get_or_create(self, user: User, db: Session) -> MFASecrets:
        secrets = db.query(MFASecrets).filter(MFASecrets.user_id == user.id).first()
        if secrets:
            return secrets
        secrets = MFASecrets(user_id=user.id, email_verified=bool(user.email))
        db.add(secrets)
        db.commit()
        db.refresh(secrets)
        return secrets

    def begin_totp_setup(self, user: User, db: Session) -> dict:
        secrets = self.get_or_create(user, db)
        if not secrets.totp_secret:
            secrets.totp_secret = pyotp.random_base32()
            db.commit()
        issuer = "Login Anomaly Detection"
        provisioning_uri = pyotp.totp.TOTP(secrets.totp_secret).provisioning_uri(
            name=user.email or user.username,
            issuer_name=issuer,
        )
        return {"secret": secrets.totp_secret, "provisioning_uri": provisioning_uri}

    def enable_totp(self, user: User, otp: str, db: Session) -> bool:
        secrets = self.get_or_create(user, db)
        if not secrets.totp_secret:
            return False
        if not pyotp.TOTP(secrets.totp_secret).verify(otp, valid_window=1):
            return False
        secrets.totp_enabled = True
        db.commit()
        return True

    def verify_totp(self, user_id: int, otp: str, db: Session) -> bool:
        secrets = db.query(MFASecrets).filter(MFASecrets.user_id == user_id).first()
        if not secrets or not secrets.totp_enabled or not secrets.totp_secret:
            return False
        return pyotp.TOTP(secrets.totp_secret).verify(otp, valid_window=1)

    def generate_backup_codes(self, user: User, db: Session, count: int = 10) -> List[str]:
        secrets = self.get_or_create(user, db)
        codes = self.verification_service.generate_backup_codes(count)
        secrets.backup_codes_hash = json.dumps([self.verification_service.hash_otp(code) for code in codes])
        db.commit()
        return codes

    def consume_backup_code(self, user_id: int, code: str, db: Session) -> bool:
        secrets = db.query(MFASecrets).filter(MFASecrets.user_id == user_id).first()
        if not secrets or not secrets.backup_codes_hash:
            return False
        try:
            code_hashes = json.loads(secrets.backup_codes_hash)
        except ValueError:
            return False

        remaining = []
        matched = False
        for code_hash in code_hashes:
            if not matched and self.verification_service.verify_code_hash(code_hash, code):
                matched = True
                continue
            remaining.append(code_hash)

        if matched:
            secrets.backup_codes_hash = json.dumps(remaining)
            db.commit()
        return matched
