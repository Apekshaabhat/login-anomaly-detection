import secrets
import hashlib
from typing import List

class VerificationService:
    def __init__(self):
        self.otp_length = 6

    def generate_otp(self) -> str:
        digits = "0123456789"
        return "".join(secrets.choice(digits) for _ in range(self.otp_length))

    def hash_otp(self, otp: str) -> str:
        return hashlib.sha256(otp.encode()).hexdigest()

    def verify_otp(self, otp_hash: str, otp: str) -> bool:
        if len(otp) != self.otp_length or not otp.isdigit():
            return False
        return secrets.compare_digest(otp_hash, self.hash_otp(otp))

    def generate_backup_codes(self, count: int = 10) -> List[str]:
        return [secrets.token_hex(4) for _ in range(count)]
