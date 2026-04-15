import pyotp
from datetime import datetime, timedelta
import secrets
from app.config import settings
from typing import List

class VerificationService:
    def __init__(self):
        self.otp_length = 6

    def generate_otp_secret(self) -> str:
        return pyotp.random_base32(length=settings.otp_secret_length)

    def generate_otp(self, secret: str) -> str:
        totp = pyotp.TOTP(secret)
        return totp.now()

    def verify_otp(self, secret: str, otp: str) -> bool:
        totp = pyotp.TOTP(secret)
        return totp.verify(otp)

    def generate_backup_codes(self, count: int = 10) -> List[str]:
        return [secrets.token_hex(4) for _ in range(count)]