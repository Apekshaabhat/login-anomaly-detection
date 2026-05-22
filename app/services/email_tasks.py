from app.config import settings
from app.services.email_service import EmailService

try:
    from celery import Celery
except ModuleNotFoundError:
    Celery = None


celery_app = None
if Celery is not None:
    celery_app = Celery(
        "login_security_email",
        broker=settings.redis_url,
        backend=settings.redis_url,
    )


def send_email_task(to_email: str, subject: str, text_body: str, html_body: str | None = None) -> bool:
    return EmailService().send_email(to_email, subject, text_body, html_body)


if celery_app is not None:
    celery_app.task(name="email.send")(send_email_task)
