import logging
from datetime import datetime
from typing import Optional

from app.services.email_service import EmailService

class NotificationService:
    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        self.email_service = EmailService()

    def send_new_device_ip_alert(
        self,
        user_id: int,
        username: str,
        user_email: Optional[str],
        ip_address: str,
        device_fingerprint: str,
        mfa_method: Optional[str],
        is_new_device: bool,
        is_new_ip: bool,
        approval_status: str,
        login_time: datetime,
        browser: Optional[str] = None,
        os: Optional[str] = None,
        location: Optional[str] = None,
        risk_score: float = 0.0,
        approve_url: Optional[str] = None,
        deny_url: Optional[str] = None,
    ) -> bool:
        if not user_email:
            self.logger.info("Skipping new device/IP alert for user %s because no email is set", user_id)
            return False

        signals = []
        if is_new_device:
            signals.append("new device")
        if is_new_ip:
            signals.append("new IP address")

        device_name = device_fingerprint[:24] if device_fingerprint else "Unknown device"
        details = {
            "device_name": device_name,
            "browser": browser,
            "os": os,
            "ip_address": ip_address,
            "location": location,
            "login_time": login_time.isoformat(),
            "risk_score": risk_score,
            "mfa_method": self._format_mfa_method(mfa_method),
            "approval_status": approval_status,
            "signals": signals,
        }
        return self.email_service.send_security_alert(
            user_email,
            username,
            details,
            approve_url=approve_url,
            deny_url=deny_url,
        )

    def send_email(self, to_email: str, subject: str, body: str) -> bool:
        return self.email_service.send_email(to_email, subject, body)

    def _format_mfa_method(self, mfa_method: Optional[str]) -> str:
        if mfa_method == "email_otp":
            return "Email OTP"
        if mfa_method == "sms_otp":
            return "SMS OTP"
        return "Not used"
