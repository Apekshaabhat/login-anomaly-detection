import secrets
from typing import List
import bcrypt
try:
    from passlib.context import CryptContext
except ModuleNotFoundError:
    CryptContext = None

otp_context = CryptContext(schemes=["bcrypt"], deprecated="auto") if CryptContext else None

class VerificationService:
    def __init__(self):
        self.otp_length = 6

    def generate_otp(self) -> str:
        return f"{secrets.randbelow(1_000_000):06d}"

    def hash_otp(self, otp: str) -> str:
        if otp_context:
            return otp_context.hash(otp)
        return bcrypt.hashpw(otp.encode(), bcrypt.gensalt()).decode()

    def verify_otp(self, otp_hash: str, otp: str) -> bool:
        if len(otp) != self.otp_length or not otp.isdigit():
            return False
        try:
            if not otp_context:
                return bcrypt.checkpw(otp.encode(), otp_hash.encode())
            return otp_context.verify(otp, otp_hash)
        except Exception:
            return False

    def send_otp(self, otp: str, destination: str, method: str = "email") -> None:
        """
        Stub for OTP delivery.
        In production: integrate SendGrid for email or Twilio for SMS.
        For now, log to console.
        """
        print(f"[OTP DELIVERY] Send '{otp}' to {destination} via {method}")

    def generate_backup_codes(self, count: int = 10) -> List[str]:
        return [secrets.token_hex(4) for _ in range(count)]
