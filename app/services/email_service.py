import json
import logging
import smtplib
import urllib.error
import urllib.request
from datetime import datetime
from email.message import EmailMessage
from html import escape
from typing import Any, Dict, Optional

from app.config import settings


class EmailService:
    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)

    def send_email(
        self,
        to_email: str,
        subject: str,
        text_body: str,
        html_body: Optional[str] = None,
    ) -> bool:
        if not to_email:
            return False

        if settings.sendgrid_api_key:
            return self._send_sendgrid(to_email, subject, text_body, html_body)
        if settings.resend_api_key:
            return self._send_resend(to_email, subject, text_body, html_body)
        if settings.brevo_api_key:
            return self._send_brevo(to_email, subject, text_body, html_body)

        from_email = settings.smtp_from_email or settings.smtp_username
        if settings.smtp_host and from_email:
            return self._send_smtp(from_email, to_email, subject, text_body, html_body)

        self.logger.info("[EMAIL PREVIEW] To=%s Subject=%s Body=%s", to_email, subject, text_body)
        print(f"[EMAIL PREVIEW] To={to_email} Subject={subject}\n{text_body}")
        return False

    def send_otp_email(self, to_email: str, username: str, otp: str, expires_in_seconds: int) -> bool:
        minutes = max(1, round(expires_in_seconds / 60))
        subject = "Your login verification code"
        text_body = (
            f"Hello {username},\n\n"
            f"Your verification code is {otp}. It expires in {minutes} minutes.\n\n"
            "If you did not request this code, change your password immediately."
        )
        html_body = self._shell(
            "Login verification",
            [
                f"Hello {escape(username)},",
                f"Use this code to finish signing in. It expires in {minutes} minutes.",
                f"<div style=\"font-size:32px;letter-spacing:8px;font-weight:700;margin:24px 0;\">{escape(otp)}</div>",
                "If you did not request this code, change your password immediately.",
            ],
        )
        return self.send_email(to_email, subject, text_body, html_body)

    def send_security_alert(
        self,
        to_email: str,
        username: str,
        details: Dict[str, Any],
        approve_url: Optional[str] = None,
        deny_url: Optional[str] = None,
    ) -> bool:
        subject = "Security alert: new login detected"
        lines = [
            f"Hello {username},",
            "",
            "We detected a sign-in with details that need your attention.",
            f"Device: {details.get('device_name') or 'Unknown device'}",
            f"Browser: {details.get('browser') or 'Unknown'}",
            f"OS: {details.get('os') or 'Unknown'}",
            f"IP address: {details.get('ip_address') or 'Unknown'}",
            f"Location: {details.get('location') or 'Unknown'}",
            f"Login time (UTC): {details.get('login_time') or datetime.utcnow().isoformat()}",
            f"Risk score: {details.get('risk_score', 0)}",
        ]
        if approve_url and deny_url:
            lines.extend(["", f"Approve login: {approve_url}", f"Deny login: {deny_url}"])
        lines.extend(["", "If this was not you, deny the login and change your password."])

        html_rows = [
            ("Device", details.get("device_name")),
            ("Browser", details.get("browser")),
            ("OS", details.get("os")),
            ("IP address", details.get("ip_address")),
            ("Location", details.get("location")),
            ("Login time (UTC)", details.get("login_time")),
            ("Risk score", details.get("risk_score")),
        ]
        html_body = self._shell(
            "New login detected",
            [
                f"Hello {escape(username)},",
                "A login was detected from a device, IP, or location we do not fully trust yet.",
                self._details_table(html_rows),
                self._button_row(approve_url, deny_url) if approve_url and deny_url else "",
                "If this was not you, deny the login and change your password.",
            ],
        )
        return self.send_email(to_email, subject, "\n".join(lines), html_body)

    def send_password_reset_email(self, to_email: str, username: str, reset_url: str) -> bool:
        subject = "Reset your password"
        text_body = f"Hello {username},\n\nReset your password using this link:\n{reset_url}\n\nThis link expires soon."
        html_body = self._shell(
            "Password reset",
            [
                f"Hello {escape(username)},",
                "Use the secure link below to reset your password.",
                self._single_button("Reset password", reset_url),
                "This link expires soon.",
            ],
        )
        return self.send_email(to_email, subject, text_body, html_body)

    def _send_smtp(
        self,
        from_email: str,
        to_email: str,
        subject: str,
        text_body: str,
        html_body: Optional[str],
    ) -> bool:
        message = EmailMessage()
        message["From"] = from_email
        message["To"] = to_email
        message["Subject"] = subject
        message.set_content(text_body)
        if html_body:
            message.add_alternative(html_body, subtype="html")

        try:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
                if settings.smtp_use_tls:
                    server.starttls()
                if settings.smtp_username and settings.smtp_password:
                    server.login(settings.smtp_username, settings.smtp_password)
                server.send_message(message)
            return True
        except Exception as exc:
            self.logger.warning("Unable to send SMTP email to %s: %s", to_email, exc)
            return False

    def _send_sendgrid(
        self,
        to_email: str,
        subject: str,
        text_body: str,
        html_body: Optional[str],
    ) -> bool:
        from_email = settings.sendgrid_from_email or settings.smtp_from_email or settings.smtp_username
        if not from_email:
            self.logger.warning("SENDGRID_API_KEY is set but no sender email is configured")
            return False

        payload = {
            "personalizations": [{"to": [{"email": to_email}]}],
            "from": {"email": from_email},
            "subject": subject,
            "content": [
                {"type": "text/plain", "value": text_body},
            ],
        }
        if html_body:
            payload["content"].append({"type": "text/html", "value": html_body})

        request = urllib.request.Request(
            "https://api.sendgrid.com/v3/mail/send",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {settings.sendgrid_api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return 200 <= response.status < 300
        except urllib.error.URLError as exc:
            self.logger.warning("Unable to send SendGrid email to %s: %s", to_email, exc)
            return False

    def _send_resend(
        self,
        to_email: str,
        subject: str,
        text_body: str,
        html_body: Optional[str],
    ) -> bool:
        from_email = settings.resend_from_email or settings.smtp_from_email or settings.smtp_username
        if not from_email:
            self.logger.warning("RESEND_API_KEY is set but no sender email is configured")
            return False
        payload = {
            "from": from_email,
            "to": [to_email],
            "subject": subject,
            "text": text_body,
            **({"html": html_body} if html_body else {}),
        }
        request = urllib.request.Request(
            "https://api.resend.com/emails",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {settings.resend_api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return 200 <= response.status < 300
        except urllib.error.URLError as exc:
            self.logger.warning("Unable to send Resend email to %s: %s", to_email, exc)
            return False

    def _send_brevo(
        self,
        to_email: str,
        subject: str,
        text_body: str,
        html_body: Optional[str],
    ) -> bool:
        from_email = settings.brevo_from_email or settings.smtp_from_email or settings.smtp_username
        if not from_email:
            self.logger.warning("BREVO_API_KEY is set but no sender email is configured")
            return False
        payload = {
            "sender": {"email": from_email},
            "to": [{"email": to_email}],
            "subject": subject,
            "textContent": text_body,
            **({"htmlContent": html_body} if html_body else {}),
        }
        request = urllib.request.Request(
            "https://api.brevo.com/v3/smtp/email",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "api-key": settings.brevo_api_key or "",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return 200 <= response.status < 300
        except urllib.error.URLError as exc:
            self.logger.warning("Unable to send Brevo email to %s: %s", to_email, exc)
            return False

    def _shell(self, title: str, blocks: list[str]) -> str:
        content = "".join(f"<p>{block}</p>" for block in blocks if block)
        return f"""
        <!doctype html>
        <html>
          <body style="margin:0;background:#0f172a;color:#e2e8f0;font-family:Inter,Arial,sans-serif;">
            <div style="max-width:600px;margin:0 auto;padding:32px;">
              <div style="border:1px solid #334155;border-radius:12px;padding:28px;background:#111827;">
                <h1 style="font-size:22px;margin:0 0 16px;color:#67e8f9;">{escape(title)}</h1>
                <div style="font-size:14px;line-height:1.65;color:#cbd5e1;">{content}</div>
              </div>
              <p style="font-size:12px;color:#64748b;margin-top:16px;">Login Anomaly Detection security notice</p>
            </div>
          </body>
        </html>
        """

    def _details_table(self, rows: list[tuple[str, Any]]) -> str:
        cells = ""
        for label, value in rows:
            cells += (
                "<tr>"
                f"<td style=\"padding:8px 12px;color:#94a3b8;\">{escape(label)}</td>"
                f"<td style=\"padding:8px 12px;font-weight:600;\">{escape(str(value or 'Unknown'))}</td>"
                "</tr>"
            )
        return f"<table style=\"width:100%;border-collapse:collapse;margin:18px 0;\">{cells}</table>"

    def _button_row(self, approve_url: str, deny_url: str) -> str:
        return (
            "<div style=\"margin:24px 0;\">"
            f"{self._single_button('Approve login', approve_url)}"
            f"<a href=\"{escape(deny_url)}\" style=\"display:inline-block;margin-left:12px;color:#f87171;\">Deny login</a>"
            "</div>"
        )

    def _single_button(self, label: str, url: str) -> str:
        return (
            f"<a href=\"{escape(url)}\" "
            "style=\"display:inline-block;background:#06b6d4;color:#0f172a;"
            "font-weight:700;text-decoration:none;padding:10px 16px;border-radius:8px;\">"
            f"{escape(label)}</a>"
        )
