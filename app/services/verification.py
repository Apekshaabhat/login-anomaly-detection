import secrets
from typing import List
import bcrypt
from app.config import settings
from app.services.email_service import EmailService
try:
    from passlib.context import CryptContext
except ModuleNotFoundError:
    CryptContext = None

otp_context = CryptContext(schemes=["bcrypt"], deprecated="auto") if CryptContext else None

class VerificationService:
    def __init__(self):
        self.otp_length = 6
        self.email_service = EmailService()

    def generate_otp(self) -> str:
        return f"{secrets.randbelow(1_000_000):06d}"

    def hash_otp(self, otp: str) -> str:
        if otp_context:
            return otp_context.hash(otp)
        return bcrypt.hashpw(otp.encode(), bcrypt.gensalt()).decode()

    def verify_otp(self, otp_hash: str, otp: str) -> bool:
        if len(otp) != self.otp_length or not otp.isdigit():
            return False
        return self.verify_code_hash(otp_hash, otp)

    def verify_code_hash(self, code_hash: str, code: str) -> bool:
        try:
            if not otp_context:
                return bcrypt.checkpw(code.encode(), code_hash.encode())
            return otp_context.verify(code, code_hash)
        except Exception:
            return False

    def send_otp(self, otp: str, destination: str, method: str = "email", username: str = "user") -> None:
        if method == "email":
            sent = self.email_service.send_otp_email(
                destination,
                username,
                otp,
                settings.verification_token_ttl_seconds,
            )
            if sent:
                return
        print(f"[OTP DELIVERY] Send '{otp}' to {destination} via {method}")

    def generate_backup_codes(self, count: int = 10) -> List[str]:
        return [secrets.token_hex(4) for _ in range(count)]
