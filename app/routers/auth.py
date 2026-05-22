from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Request, Response
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field, IPvAnyAddress, ConfigDict, model_validator
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from app.database.connection import get_db, SessionLocal
from app.database.models import (
    AlertRecord,
    Device,
    DeviceApprovalRequest,
    LoginAttempt,
    LoginChallenge,
    SecurityNotification,
    User,
)
from app.schemas.analytics import AnalyzeRequest, AnalyzeResponse
from app.services.password_security import PasswordSecurityEngine
from app.services.anomaly_detection import AnomalyDetectionEngine
from app.services.behavioral_learning import BehavioralLearningSystem
from app.services.verification import VerificationService
from app.services.account_lock import AccountLockService
from app.services.logging_service import LoggingService
from app.services.notification import NotificationService
from app.services.email_service import EmailService
from app.services.ip_intelligence import IPIntelligenceService
from app.services.mfa_service import MFAService
from app.services.risk_engine import AdaptiveRiskEngine
from app.services.cache_store import CacheStore
from app.services.token_service import TokenService
from app.services.auth_context import get_current_user
from app.utils.helpers import hash_password, verify_password, serialize_keystroke_timing, calculate_typing_speed
from app.config import settings
import ipaddress
import json
import secrets
from urllib.parse import quote

router = APIRouter()
password_engine = PasswordSecurityEngine()
anomaly_engine = AnomalyDetectionEngine()
learning_system = BehavioralLearningSystem()
verification_service = VerificationService()
lock_service = AccountLockService()
logging_service = LoggingService()
notification_service = NotificationService()
email_service = EmailService()
ip_intelligence_service = IPIntelligenceService()
mfa_service = MFAService()
token_service = TokenService()
risk_engine = AdaptiveRiskEngine()

cache_store = CacheStore(settings.redis_url)

class PasswordValidationRequest(BaseModel):
    password: str

class UserRegistrationRequest(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    phone: Optional[str] = None

class LoginRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    username: str
    password: str
    ip_address: Optional[IPvAnyAddress] = None
    location_lat: Optional[float] = Field(default=None, ge=-90, le=90)
    location_lon: Optional[float] = Field(default=None, ge=-180, le=180)
    device_fingerprint: Optional[str] = Field(default=None, min_length=1, max_length=255)
    device_id: Optional[str] = Field(default=None, min_length=1, max_length=255)
    typing_speed: Optional[float] = Field(default=None, ge=0, le=500)
    keystroke_timing: Optional[List[float]] = None
    time_taken: Optional[float] = Field(default=None, gt=0, le=60)
    failed_attempts: Optional[int] = Field(default=0, ge=0, le=100)
    login_hour: Optional[float] = Field(default=None, ge=0, le=23.99)
    remember_device: bool = False
    browser: Optional[str] = Field(default=None, max_length=120)
    os: Optional[str] = Field(default=None, max_length=120)
    device_type: Optional[str] = Field(default=None, max_length=60)
    screen_resolution: Optional[str] = Field(default=None, max_length=60)
    timezone: Optional[str] = Field(default=None, max_length=120)
    language: Optional[str] = Field(default=None, max_length=60)
    hardware_fingerprint: Optional[str] = Field(default=None, max_length=255)
    user_agent_hash: Optional[str] = Field(default=None, max_length=255)
    device_nickname: Optional[str] = Field(default=None, max_length=120)

    @model_validator(mode="after")
    def sync_device_fields(self):
        chosen_device_id = self.device_id or self.device_fingerprint
        if not chosen_device_id:
            raise ValueError("device_id is required")
        self.device_id = chosen_device_id.strip()
        self.device_fingerprint = self.device_id
        return self

class LoginDecision(BaseModel):
    decision: str  # allow, require_verification, block
    risk_score: float
    level: Optional[str] = None
    reasons: List[str]
    explanation: str
    attack_types: List[str]
    attack_type: Optional[str] = None
    verification_token: Optional[str] = None
    debug_otp: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    login_attempt_id: Optional[int] = None
    ip_address: Optional[str] = None
    mfa_required: bool = False
    mfa_method: Optional[str] = None
    new_device: bool = False
    new_ip: bool = False
    device_approval_status: Optional[str] = None
    approval_required: bool = False
    challenge_state: Optional[str] = None
    captcha_required: bool = False
    fraud_probability: float = 0.0
    session_trust_score: float = 100.0
    recommended_action: Optional[str] = None

class VerificationRequest(BaseModel):
    username: str
    otp: str
    verification_token: str

class ResendOtpRequest(BaseModel):
    verification_token: str

class ApprovalRequest(BaseModel):
    approval_token: str

class RefreshRequest(BaseModel):
    refresh_token: Optional[str] = None

class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = None

class TOTPEnableRequest(BaseModel):
    otp: str = Field(min_length=6, max_length=6)

class AdminUnlockRequest(BaseModel):
    user_id: int
    admin_token: str

class FeedbackRequest(BaseModel):
    login_attempt_id: int
    is_false_positive: bool
    admin_token: str

def create_access_token(user_id: int) -> str:
    return token_service.create_access_token(user_id)

def _set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    cookie_kwargs = {
        "httponly": True,
        "secure": settings.secure_cookies,
        "samesite": "lax",
    }
    if settings.cookie_domain:
        cookie_kwargs["domain"] = settings.cookie_domain
    response.set_cookie(
        "access_token",
        access_token,
        max_age=settings.access_token_expire_minutes * 60,
        **cookie_kwargs,
    )
    response.set_cookie(
        "refresh_token",
        refresh_token,
        max_age=settings.refresh_token_expire_days * 24 * 60 * 60,
        **cookie_kwargs,
    )
    if settings.csrf_protection_enabled:
        response.set_cookie(
            "csrf_token",
            secrets.token_urlsafe(24),
            max_age=settings.refresh_token_expire_days * 24 * 60 * 60,
            httponly=False,
            secure=settings.secure_cookies,
            samesite="lax",
            domain=settings.cookie_domain,
        )

def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie("access_token", domain=settings.cookie_domain)
    response.delete_cookie("refresh_token", domain=settings.cookie_domain)
    response.delete_cookie("csrf_token", domain=settings.cookie_domain)

def _issue_token_pair(
    user_id: int,
    db: Session,
    ip_address: Optional[str] = None,
    user_agent_hash: Optional[str] = None,
    device_fingerprint: Optional[str] = None,
) -> tuple[str, str]:
    access_token = token_service.create_access_token(user_id)
    refresh_token = token_service.create_refresh_token(
        user_id,
        db,
        ip_address=ip_address,
        user_agent_hash=user_agent_hash,
        device_fingerprint=device_fingerprint,
    )
    return access_token, refresh_token

def _valid_ip(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    candidate = value.strip()
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        return None

def _is_local_ip(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        parsed = ipaddress.ip_address(value)
        return parsed.is_loopback or parsed.is_private or parsed.is_link_local
    except ValueError:
        return False

def _extract_client_ip(http_request: Optional[Request], fallback_ip: Optional[IPvAnyAddress]) -> str:
    parsed_fallback = _valid_ip(str(fallback_ip) if fallback_ip is not None else None)
    if http_request is not None:
        forwarded_for = http_request.headers.get("x-forwarded-for")
        if forwarded_for:
            for item in forwarded_for.split(","):
                parsed = _valid_ip(item)
                if parsed:
                    return parsed

        real_ip = _valid_ip(http_request.headers.get("x-real-ip"))
        if real_ip:
            return real_ip

        if http_request.client and http_request.client.host:
            parsed = _valid_ip(http_request.client.host)
            if parsed:
                if _is_local_ip(parsed) and parsed_fallback and not _is_local_ip(parsed_fallback):
                    return parsed_fallback
                return parsed

    return parsed_fallback or "0.0.0.0"

def _select_mfa_delivery(user: User, username: str) -> tuple[str, str, str]:
    if user.email:
        return "email_otp", user.email, "email"
    if user.phone:
        return "sms_otp", user.phone, "sms"
    return "email_otp", username, "email"

def _device_approval_status(needs_attention: bool) -> str:
    if settings.require_device_ip_approval and needs_attention:
        return "pending"
    return "approved"

def _mfa_label(mfa_method: Optional[str]) -> str:
    if mfa_method == "email_otp":
        return "Email OTP"
    if mfa_method == "sms_otp":
        return "SMS OTP"
    if mfa_method == "totp_or_email":
        return "Authenticator app or Email OTP"
    return "None"

def _risk_level_from_score(risk_score: float) -> str:
    if risk_score >= settings.critical_risk_threshold:
        return "CRITICAL"
    if risk_score >= settings.high_risk_threshold:
        return "HIGH"
    if risk_score >= settings.medium_risk_threshold:
        return "MEDIUM"
    return "LOW"

def _policy_for_risk(risk_score: float, forced_block: bool = False) -> Dict[str, Any]:
    level = _risk_level_from_score(risk_score)
    if forced_block or level == "CRITICAL":
        return {
            "decision": "block",
            "level": level,
            "mfa_required": False,
            "approval_required": False,
            "mfa_method": None,
        }
    if level == "HIGH":
        return {
            "decision": "require_verification",
            "level": level,
            "mfa_required": True,
            "approval_required": True,
            "mfa_method": "email_otp",
        }
    if level == "MEDIUM":
        return {
            "decision": "require_verification",
            "level": level,
            "mfa_required": True,
            "approval_required": False,
            "mfa_method": "email_otp",
        }
    return {
        "decision": "allow",
        "level": level,
        "mfa_required": False,
        "approval_required": False,
        "mfa_method": None,
    }

def _append_risk(anomaly_result: Dict[str, Any], risk_delta: float, reasons: List[str]) -> Dict[str, Any]:
    if risk_delta <= 0 and not reasons:
        return anomaly_result
    anomaly_result["risk_score"] = min(100.0, float(anomaly_result.get("risk_score") or 0.0) + max(0.0, risk_delta))
    anomaly_result["level"] = _risk_level_from_score(anomaly_result["risk_score"])
    current_reasons = anomaly_result.setdefault("reasons", [])
    for reason in reasons:
        if reason not in current_reasons:
            current_reasons.append(reason)
    anomaly_result["decision"] = _policy_for_risk(anomaly_result["risk_score"])["decision"]
    anomaly_result["explanation"] = (
        f"Risk score {anomaly_result['risk_score']:.1f}/100. "
        f"Triggered signals: {', '.join(current_reasons) or 'none'}."
    )
    return anomaly_result

def _device_location_label(city: Optional[str], country: Optional[str]) -> str:
    parts = [item for item in [city, country] if item]
    return ", ".join(parts) if parts else "Unknown"

def _approval_urls(approval_token: str) -> tuple[str, str]:
    base_api_url = (settings.api_public_url or "").rstrip("/")
    base_app_url = (settings.app_public_url or "").rstrip("/")
    encoded = quote(approval_token, safe="")
    if base_app_url:
        return (
            f"{base_app_url}/device-approval?token={encoded}&action=approve",
            f"{base_app_url}/device-approval?token={encoded}&action=deny",
        )
    if base_api_url:
        return (
            f"{base_api_url}/api/auth/approve-device?token={encoded}",
            f"{base_api_url}/api/auth/deny-device?token={encoded}",
        )
    return (
        f"/api/auth/approve-device?token={encoded}",
        f"/api/auth/deny-device?token={encoded}",
    )

def _cache_challenge(challenge: LoginChallenge, ttl_seconds: int, extra: Dict[str, Any]) -> None:
    payload = {
        "user_id": challenge.user_id,
        "attempts": challenge.otp_attempts or 0,
        "otp_hash": challenge.otp_hash,
        "issued_at": challenge.created_at.isoformat() if challenge.created_at else datetime.utcnow().isoformat(),
        "login_attempt_id": challenge.login_attempt_id,
        "mfa_method": (json.loads(challenge.required_methods or "[]") or [None])[0],
        "ip_address": challenge.ip_address,
        "device_fingerprint": challenge.device_fingerprint,
        "device_approval_status": "approved" if challenge.device_approved else "pending",
        "approval_required": challenge.approval_required,
        "device_approved": challenge.device_approved,
        "remember_device": challenge.remember_device,
        "resend_available_at": challenge.resend_available_at.isoformat() if challenge.resend_available_at else None,
        **extra,
    }
    cache_store.set_json(challenge.challenge_token, ttl_seconds, payload)

def _record_notification(
    db: Session,
    user_id: int,
    notification_type: str,
    destination: Optional[str],
    subject: str,
    payload: Dict[str, Any],
    sent: bool,
    error: Optional[str] = None,
) -> None:
    db.add(
        SecurityNotification(
            user_id=user_id,
            notification_type=notification_type,
            channel="email",
            destination=destination,
            subject=subject,
            status="sent" if sent else "preview",
            payload=json.dumps(payload, default=str),
            sent_at=datetime.utcnow() if sent else None,
            error=error,
        )
    )
    db.commit()

def _finalize_verified_challenge(
    challenge: LoginChallenge,
    verification_data: Dict[str, Any],
    response: Response,
    db: Session,
    user_agent_hash: Optional[str] = None,
) -> Dict[str, Any]:
    verified_at = datetime.utcnow()
    user_id = challenge.user_id
    login_attempt_id = challenge.login_attempt_id
    ip_address = challenge.ip_address
    device_fingerprint = challenge.device_fingerprint
    mfa_method = (json.loads(challenge.required_methods or "[]") or ["email_otp"])[0]

    if login_attempt_id:
        attempt = db.query(LoginAttempt).filter(LoginAttempt.id == login_attempt_id).first()
        if attempt:
            attempt.mfa_verified_at = verified_at

    if device_fingerprint:
        device = db.query(Device).filter(
            Device.user_id == user_id,
            Device.fingerprint == device_fingerprint,
        ).first()
        if device:
            device.approval_status = "approved"
            device.approved_at = device.approved_at or verified_at
            device.last_mfa_method = mfa_method
            device.last_ip_address = ip_address or device.last_ip_address
            device.last_seen = verified_at
            device.state = "trusted"
            device.is_trusted = challenge.remember_device or device.is_trusted

    login_data = verification_data.get("login_data") or {}
    if login_data:
        if isinstance(login_data.get("timestamp"), str):
            try:
                login_data["timestamp"] = datetime.fromisoformat(login_data["timestamp"])
            except ValueError:
                login_data["timestamp"] = verified_at
        learning_system.update_profile(user_id, login_data, db)
    else:
        db.commit()

    challenge.state = "approved"
    challenge.device_approved = True
    challenge.completed_at = verified_at
    db.commit()
    cache_store.delete(challenge.challenge_token)

    logging_service.log_security_event(
        user_id,
        "login_verified",
        f"Challenge {challenge.challenge_token} completed",
        db,
        ip_address=ip_address,
    )
    access_token, refresh_token = _issue_token_pair(
        user_id,
        db,
        ip_address=ip_address,
        user_agent_hash=user_agent_hash,
        device_fingerprint=device_fingerprint,
    )
    _set_auth_cookies(response, access_token, refresh_token)
    return {
        "message": "Login verified successfully",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "mfa_method": mfa_method,
        "login_attempt_id": login_attempt_id,
        "challenge_state": "approved",
    }

@router.post("/resend-otp", response_model=dict)
def resend_otp(request: ResendOtpRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    challenge = db.query(LoginChallenge).filter(LoginChallenge.challenge_token == request.verification_token).first()
    verification_data = cache_store.get_json(request.verification_token)
    if not challenge or not verification_data or challenge.expires_at <= datetime.utcnow():
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")
    if challenge.resend_available_at and challenge.resend_available_at > datetime.utcnow():
        raise HTTPException(status_code=429, detail="OTP resend is cooling down")

    user = db.query(User).filter(User.id == challenge.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    mfa_method, mfa_destination, mfa_delivery_method = _select_mfa_delivery(user, user.username)
    otp_code = verification_service.generate_otp()
    challenge.otp_hash = verification_service.hash_otp(otp_code)
    challenge.otp_sent_at = datetime.utcnow()
    challenge.resend_available_at = datetime.utcnow() + timedelta(seconds=settings.otp_resend_cooldown_seconds)
    challenge.otp_attempts = 0
    db.commit()
    verification_data["otp_hash"] = challenge.otp_hash
    verification_data["attempts"] = 0
    verification_data["resend_available_at"] = challenge.resend_available_at.isoformat()
    cache_store.set_json(request.verification_token, settings.verification_token_ttl_seconds, verification_data)
    background_tasks.add_task(verification_service.send_otp, otp_code, mfa_destination, mfa_delivery_method, user.username)
    return {"message": "OTP resent", "resend_available_at": challenge.resend_available_at}

def _handle_device_approval(approval_token: str, approved: bool, db: Session) -> Dict[str, Any]:
    try:
        payload = token_service.decode_approval_token(approval_token)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid approval token")

    approval = db.query(DeviceApprovalRequest).filter(DeviceApprovalRequest.token_jti == payload.get("jti")).first()
    if not approval or approval.status != "pending":
        raise HTTPException(status_code=400, detail="Approval token has already been used")
    if approval.expires_at <= datetime.utcnow():
        approval.status = "expired"
        db.commit()
        raise HTTPException(status_code=400, detail="Approval token expired")

    challenge = db.query(LoginChallenge).filter(LoginChallenge.challenge_token == payload.get("challenge")).first()
    approval.status = "approved" if approved else "denied"
    approval.consumed_at = datetime.utcnow()
    if challenge:
        challenge.device_approved = approved
        challenge.state = "pending_otp" if approved else "denied"
    if approval.device:
        approval.device.approval_status = "approved" if approved else "denied"
        approval.device.state = "pending_verification" if approved else "blocked"
        approval.device.blocked_at = None if approved else datetime.utcnow()
    db.commit()

    if challenge:
        cached = cache_store.get_json(challenge.challenge_token) or {}
        cached["device_approved"] = approved
        cached["device_approval_status"] = "approved" if approved else "denied"
        cached["approval_required"] = True
        cache_store.set_json(challenge.challenge_token, settings.verification_token_ttl_seconds, cached)

    logging_service.log_security_event(
        approval.user_id,
        "device_approval_approved" if approved else "device_approval_denied",
        f"Device approval request {approval.id} was {'approved' if approved else 'denied'}",
        db,
        ip_address=approval.requested_ip,
    )
    return {
        "message": "Login approved" if approved else "Login denied",
        "status": approval.status,
        "challenge_token": payload.get("challenge"),
    }

@router.post("/approve-device", response_model=dict)
def approve_device(request: ApprovalRequest, db: Session = Depends(get_db)):
    return _handle_device_approval(request.approval_token, True, db)

@router.get("/approve-device", response_model=dict)
def approve_device_link(token: str, db: Session = Depends(get_db)):
    return _handle_device_approval(token, True, db)

@router.post("/deny-device", response_model=dict)
def deny_device(request: ApprovalRequest, db: Session = Depends(get_db)):
    return _handle_device_approval(request.approval_token, False, db)

@router.get("/deny-device", response_model=dict)
def deny_device_link(token: str, db: Session = Depends(get_db)):
    return _handle_device_approval(token, False, db)

@router.get("/challenge/{challenge_token}", response_model=dict)
def get_challenge_status(
    challenge_token: str,
    http_request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    challenge = db.query(LoginChallenge).filter(LoginChallenge.challenge_token == challenge_token).first()
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    if challenge.expires_at <= datetime.utcnow():
        challenge.state = "expired"
        db.commit()
        cache_store.delete(challenge_token)
        return {"challenge_state": "expired", "approval_required": challenge.approval_required}

    cached = cache_store.get_json(challenge_token) or {}
    if cached.get("otp_verified") and challenge.device_approved:
        return _finalize_verified_challenge(
            challenge,
            cached,
            response,
            db,
            user_agent_hash=http_request.headers.get("user-agent") if http_request else None,
        )

    return {
        "challenge_state": challenge.state,
        "approval_required": challenge.approval_required,
        "device_approved": challenge.device_approved,
        "otp_verified": bool(cached.get("otp_verified")),
        "expires_at": challenge.expires_at,
    }

@router.post("/refresh", response_model=dict)
def refresh_session(
    request: RefreshRequest,
    http_request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    refresh_token = request.refresh_token or http_request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token required")
    try:
        user_id, rotated_refresh = token_service.rotate_refresh_token(
            refresh_token,
            db,
            ip_address=_extract_client_ip(http_request, None),
            user_agent_hash=http_request.headers.get("user-agent"),
        )
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    access_token = token_service.create_access_token(user_id)
    _set_auth_cookies(response, access_token, rotated_refresh)
    return {"access_token": access_token, "refresh_token": rotated_refresh, "token_type": "bearer"}

@router.post("/logout", response_model=dict)
def logout(
    request: LogoutRequest,
    http_request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    refresh_token = request.refresh_token or http_request.cookies.get("refresh_token")
    if refresh_token:
        token_service.revoke_refresh_token(refresh_token, db)
    _clear_auth_cookies(response)
    return {"message": "Logged out"}

@router.post("/mfa/totp/setup", response_model=dict)
def setup_totp(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return mfa_service.begin_totp_setup(current_user, db)

@router.post("/mfa/totp/enable", response_model=dict)
def enable_totp(
    request: TOTPEnableRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not mfa_service.enable_totp(current_user, request.otp, db):
        raise HTTPException(status_code=400, detail="Invalid authenticator code")
    codes = mfa_service.generate_backup_codes(current_user, db)
    return {"message": "Authenticator app enabled", "backup_codes": codes}

@router.post("/validate-password", response_model=dict)
def validate_password(request: PasswordValidationRequest, db: Session = Depends(get_db)):
    result = password_engine.validate_password(request.password)
    breach = risk_engine.threat_intel.check_pwned_password(request.password, db=db)
    result["breach_check"] = breach
    if breach.get("breached"):
        result["is_valid"] = False
        result.setdefault("errors", []).append(
            f"Password appears in breached password datasets {breach.get('breach_count', 0)} times"
        )
    return result

@router.post("/register", response_model=dict)
def register_user(request: UserRegistrationRequest, db: Session = Depends(get_db)):
    # Check if user exists
    existing_user = db.query(User).filter(User.username == request.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    # Validate password
    password_validation = password_engine.validate_password(request.password)
    breach = risk_engine.threat_intel.check_pwned_password(request.password, db=db)
    if breach.get("breached"):
        password_validation["is_valid"] = False
        password_validation.setdefault("errors", []).append("Password has appeared in public breach datasets")
    if not password_validation["is_valid"]:
        raise HTTPException(status_code=400, detail="Password does not meet requirements")

    # Create user
    hashed_password = hash_password(request.password)
    user = User(
        username=request.username,
        email=request.email,
        phone=request.phone,
        hashed_password=hashed_password,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return {"user_id": user.id, "message": "User registered successfully"}

def _auto_retrain_model():
    db = SessionLocal()
    try:
        anomaly_engine.retrain_from_login_attempts(db)
    finally:
        db.close()

def _should_trigger_daily_retraining() -> bool:
    retrain_key = "model:last_retrained_at"
    last_retrained_at = cache_store.get(retrain_key)
    current_day = datetime.utcnow().date().isoformat()
    if last_retrained_at == current_day:
        return False
    cache_store.setex(retrain_key, 60 * 60 * 24 * 2, current_day)
    return True

def _format_analysis_response(
    anomaly_result: Dict[str, Any],
    decision: Optional[str] = None,
    verification_token: Optional[str] = None,
    debug_otp: Optional[str] = None,
    access_token: Optional[str] = None,
    refresh_token: Optional[str] = None,
    login_attempt_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    mfa_required: bool = False,
    mfa_method: Optional[str] = None,
    new_device: bool = False,
    new_ip: bool = False,
    device_approval_status: Optional[str] = None,
    approval_required: bool = False,
    challenge_state: Optional[str] = None,
    captcha_required: bool = False,
    fraud_probability: float = 0.0,
    session_trust_score: float = 100.0,
    recommended_action: Optional[str] = None,
) -> Dict[str, Any]:
    attack_type = anomaly_result.get("attack_type") or "None"
    return {
        "risk_score": float(anomaly_result["risk_score"]),
        "level": anomaly_result.get("level") or "LOW",
        "reasons": anomaly_result.get("reasons", []),
        "attack_type": attack_type,
        "explanation": anomaly_result.get("explanation"),
        "decision": decision or anomaly_result.get("decision"),
        "verification_token": verification_token,
        "debug_otp": debug_otp,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "login_attempt_id": login_attempt_id,
        "ip_address": ip_address,
        "mfa_required": mfa_required,
        "mfa_method": mfa_method,
        "new_device": new_device,
        "new_ip": new_ip,
        "device_approval_status": device_approval_status,
        "approval_required": approval_required,
        "challenge_state": challenge_state,
        "captcha_required": captcha_required,
        "fraud_probability": fraud_probability,
        "session_trust_score": session_trust_score,
        "recommended_action": recommended_action,
        "attack_types": anomaly_result.get("attack_types", []),
    }

@router.post("/analyze", response_model=AnalyzeResponse)
def analyze_login(request: AnalyzeRequest, db: Session = Depends(get_db)):
    user = None
    if request.username:
        user = db.query(User).filter(User.username == request.username).first()

    timestamp = datetime.utcnow().replace(
        hour=int(request.login_hour),
        minute=int((request.login_hour % 1) * 60),
        second=0,
        microsecond=0,
    )
    login_data = {
        "timestamp": timestamp,
        "ip_address": str(request.ip_address),
        "location_lat": request.location_lat,
        "location_lon": request.location_lon,
        "device_fingerprint": request.device_id,
        "typing_speed": request.typing_speed,
        "failed_attempts_override": request.failed_attempts,
    }
    anomaly_result = anomaly_engine.detect_anomalies(user.id if user else -1, login_data, db)
    return _format_analysis_response(anomaly_result)

@router.post("/login", response_model=LoginDecision)
def login(
    request: LoginRequest,
    http_request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    request_ip = _extract_client_ip(http_request, request.ip_address)
    login_time = datetime.utcnow()

    # Rate limiting
    rate_limit_key = f"login:{request_ip}"
    attempts = cache_store.get(rate_limit_key)
    if attempts and int(attempts) >= settings.rate_limit_requests:
        raise HTTPException(status_code=429, detail="Too many login attempts")

    cache_store.incr(rate_limit_key)
    cache_store.expire(rate_limit_key, settings.rate_limit_window_seconds)

    user_rate_key = f"login_user:{request.username}"
    user_attempts = cache_store.get(user_rate_key)
    if user_attempts and int(user_attempts) >= settings.rate_limit_requests:
        raise HTTPException(status_code=429, detail="Too many login attempts for this account")

    cache_store.incr(user_rate_key)
    cache_store.expire(user_rate_key, settings.rate_limit_window_seconds)

    # Find user
    user = db.query(User).filter(User.username == request.username).first()
    if not user:
        verify_password(request.password, "$2b$12$placeholder_hash_to_waste_time")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Check if account is locked
    if lock_service.is_account_locked(user.id, db):
        raise HTTPException(status_code=403, detail="Account is locked")

    # Verify password
    password_correct = verify_password(request.password, user.hashed_password)
    success = password_correct
    existing_device = db.query(Device).filter(
        Device.user_id == user.id,
        Device.fingerprint == request.device_fingerprint,
    ).first()
    is_new_device = existing_device is None
    is_new_ip = db.query(LoginAttempt).filter(
        LoginAttempt.user_id == user.id,
        LoginAttempt.ip_address == request_ip,
        LoginAttempt.success == True,
    ).first() is None
    captcha_required = int(request.failed_attempts or 0) >= settings.captcha_after_failures

    # Calculate typing speed if not provided
    if request.time_taken and not request.typing_speed:
        request.typing_speed = calculate_typing_speed(len(request.password), request.time_taken)

    # Prepare login data
    login_data = {
        "timestamp": login_time,
        "ip_address": request_ip,
        "location_lat": request.location_lat,
        "location_lon": request.location_lon,
        "device_fingerprint": request.device_id,
        "typing_speed": request.typing_speed,
        "keystroke_timing": serialize_keystroke_timing(request.keystroke_timing) if request.keystroke_timing else None,
        "failed_attempts_override": request.failed_attempts,
    }

    # Detect anomalies
    anomaly_result = anomaly_engine.detect_anomalies(user.id, login_data, db)
    ip_intelligence = ip_intelligence_service.assess(
        user.id,
        request_ip,
        db,
        latitude=request.location_lat,
        longitude=request.location_lon,
        timestamp=login_time,
    )
    anomaly_result = _append_risk(
        anomaly_result,
        float(ip_intelligence.get("risk_score") or 0.0),
        ip_intelligence.get("reasons") or [],
    )
    adaptive_risk = risk_engine.score_login_context(
        user.id,
        db,
        ip_address=request_ip,
        device_fingerprint=request.device_fingerprint,
        typing_speed=request.typing_speed,
        latitude=request.location_lat,
        longitude=request.location_lon,
        user_agent=http_request.headers.get("user-agent") if http_request else None,
    )
    adaptive_delta = max(0.0, float(adaptive_risk.get("risk_score") or 0.0) - float(anomaly_result.get("risk_score") or 0.0))
    anomaly_result = _append_risk(
        anomaly_result,
        adaptive_delta * 0.45,
        adaptive_risk.get("reasons") or [],
    )

    forced_block = False
    device_blocked = bool(existing_device and existing_device.state == "blocked")
    if device_blocked:
        forced_block = True
        anomaly_result = _append_risk(anomaly_result, 50.0, ["Blocked device attempted login"])
    elif existing_device and existing_device.state == "suspicious":
        anomaly_result = _append_risk(anomaly_result, 20.0, ["Suspicious device state"])

    # If password wrong, increase risk
    if not password_correct:
        forced_block = True
        anomaly_result["risk_score"] = min(100.0, anomaly_result["risk_score"] + 50)
        anomaly_result["level"] = _risk_level_from_score(anomaly_result["risk_score"])
        anomaly_result["reasons"].append("Incorrect password")
        anomaly_result["explanation"] = f"{anomaly_result['explanation']} Incorrect password increased the final risk."

    # Make final decision
    verification_token = None
    otp_code = None
    mfa_method = None
    mfa_delivery_method = None
    mfa_destination = None
    challenge_state = None
    access_token = None
    refresh_token = None
    mfa_record = mfa_service.get_or_create(user, db) if password_correct else None
    policy = _policy_for_risk(anomaly_result["risk_score"], forced_block=forced_block)
    decision = policy["decision"]
    approval_required = bool(policy["approval_required"])
    if password_correct and settings.require_device_ip_approval and (is_new_device or is_new_ip):
        approval_required = True
        if decision == "allow":
            decision = "require_verification"
            policy["mfa_required"] = True
            policy["mfa_method"] = "email_otp"

    if password_correct and decision == "require_verification":
        mfa_method, mfa_destination, mfa_delivery_method = _select_mfa_delivery(user, request.username)
        if mfa_record and mfa_record.totp_enabled and mfa_method == "email_otp":
            mfa_method = "totp_or_email"
    else:
        approval_required = False

    device_approval_status = "pending" if approval_required else _device_approval_status(password_correct and (is_new_device or is_new_ip))

    # Create login attempt record
    login_attempt = LoginAttempt(
        user_id=user.id,
        timestamp=login_time,
        ip_address=request_ip,
        location_lat=request.location_lat,
        location_lon=request.location_lon,
        device_fingerprint=request.device_fingerprint,
        typing_speed=request.typing_speed,
        keystroke_timing=login_data["keystroke_timing"],
        success=success,
        risk_score=anomaly_result["risk_score"],
        decision=decision,
        reasons=json.dumps(anomaly_result["reasons"]),
        anomaly_score=anomaly_result.get("anomaly_score"),
        confidence_score=anomaly_result.get("confidence_score"),
        mfa_required=decision == "require_verification",
        mfa_method=mfa_method,
        new_device=is_new_device,
        new_ip=is_new_ip,
        device_approval_status=device_approval_status if password_correct else None,
        asn=ip_intelligence.get("asn"),
        provider=ip_intelligence.get("provider"),
        country=ip_intelligence.get("country"),
        city=ip_intelligence.get("city"),
        is_vpn=bool(ip_intelligence.get("is_vpn")),
        is_proxy=bool(ip_intelligence.get("is_proxy")),
        is_tor=bool(ip_intelligence.get("is_tor")),
        ip_risk_score=float(ip_intelligence.get("risk_score") or 0.0),
    )
    db.add(login_attempt)

    device = existing_device
    if password_correct:
        if not device:
            device = Device(
                user_id=user.id,
                fingerprint=request.device_fingerprint,
                first_ip_address=request_ip,
                approval_status=device_approval_status,
                state="pending_verification" if decision == "require_verification" else "trusted",
            )
            db.add(device)
        elif settings.require_device_ip_approval and (is_new_device or is_new_ip):
            device.approval_status = device_approval_status

        device.browser = request.browser or device.browser
        device.os = request.os or device.os
        device.device_type = request.device_type or device.device_type
        device.screen_resolution = request.screen_resolution or device.screen_resolution
        device.timezone = request.timezone or device.timezone
        device.language = request.language or device.language
        device.hardware_fingerprint = request.hardware_fingerprint or device.hardware_fingerprint
        device.user_agent_hash = request.user_agent_hash or device.user_agent_hash
        device.nickname = request.device_nickname or device.nickname
        device.remember_device = request.remember_device or device.remember_device
        if not device.first_ip_address:
            device.first_ip_address = request_ip
        device.last_ip_address = request_ip
        device.last_seen = login_time
        device.last_mfa_method = mfa_method
        if decision == "allow" and device_approval_status == "approved":
            device.state = "trusted" if request.remember_device else (device.state or "trusted")
            device.is_trusted = request.remember_device or device.is_trusted
            device.approval_status = "approved"
            device.approved_at = device.approved_at or login_time
        elif decision == "require_verification":
            device.state = "pending_verification"
        elif decision == "block" and not device_blocked:
            device.state = "suspicious"
            device.suspicious_reason = "; ".join(anomaly_result.get("reasons", []))

    db.flush()
    device_id = device.id if device else None
    db.commit()
    db.refresh(login_attempt)

    ip_intelligence_service.record_geo_history(
        user.id,
        login_attempt.id,
        request_ip,
        ip_intelligence,
        db,
        latitude=request.location_lat,
        longitude=request.location_lon,
    )

    if http_request is not None and hasattr(http_request.app.state, "broadcast_event"):
        event = {
            "type": "login_attempt",
            "user": request.username,
            "ip": request_ip,
            "risk_score": anomaly_result["risk_score"],
            "decision": decision,
            "timestamp": datetime.utcnow().isoformat(),
        }
        try:
            background_tasks.add_task(http_request.app.state.broadcast_event, event)
        except Exception:
            pass

    approval_token = None
    approve_url = None
    deny_url = None

    if decision == "require_verification" and mfa_method and mfa_destination and mfa_delivery_method:
        otp_code = verification_service.generate_otp()
        verification_token = f"verify_{secrets.token_urlsafe(32)}"
        expires_at = datetime.utcnow() + timedelta(seconds=settings.verification_token_ttl_seconds)
        resend_at = datetime.utcnow() + timedelta(seconds=settings.otp_resend_cooldown_seconds)
        required_methods = ["email_otp"]
        if mfa_method == "totp_or_email":
            required_methods = ["totp_or_email"]
        if approval_required:
            required_methods.append("device_approval")

        challenge = LoginChallenge(
            challenge_token=verification_token,
            user_id=user.id,
            login_attempt_id=login_attempt.id,
            state="pending_device_approval" if approval_required else "pending_otp",
            risk_level=policy["level"],
            risk_score=anomaly_result["risk_score"],
            required_methods=json.dumps(required_methods),
            verified_methods=json.dumps([]),
            otp_hash=verification_service.hash_otp(otp_code),
            otp_attempts=0,
            otp_sent_at=datetime.utcnow(),
            resend_available_at=resend_at,
            expires_at=expires_at,
            ip_address=request_ip,
            device_fingerprint=request.device_fingerprint,
            approval_required=approval_required,
            device_approved=not approval_required,
            remember_device=request.remember_device,
        )
        db.add(challenge)
        db.commit()
        db.refresh(challenge)
        challenge_state = challenge.state

        if approval_required:
            approval_jti = secrets.token_urlsafe(24)
            approval_token = token_service.create_approval_token(user.id, verification_token, approval_jti)
            approval_request = DeviceApprovalRequest(
                user_id=user.id,
                login_challenge_id=challenge.id,
                device_id=device_id,
                token_jti=approval_jti,
                status="pending",
                requested_ip=request_ip,
                requested_location=_device_location_label(ip_intelligence.get("city"), ip_intelligence.get("country")),
                risk_score=anomaly_result["risk_score"],
                expires_at=datetime.utcnow() + timedelta(seconds=settings.approval_token_ttl_seconds),
            )
            db.add(approval_request)
            db.commit()
            approve_url, deny_url = _approval_urls(approval_token)

        _cache_challenge(
            challenge,
            settings.verification_token_ttl_seconds,
            {
                "login_data": {
                    "timestamp": login_time.isoformat(),
                    "ip_address": request_ip,
                    "location_lat": request.location_lat,
                    "location_lon": request.location_lon,
                    "device_fingerprint": request.device_fingerprint,
                    "typing_speed": request.typing_speed,
                    "keystroke_timing": login_data["keystroke_timing"],
                    "failed_attempts_override": request.failed_attempts,
                },
            },
        )
        background_tasks.add_task(
            verification_service.send_otp,
            otp_code,
            mfa_destination,
            mfa_delivery_method,
            user.username,
        )
        db.add(
            SecurityNotification(
                user_id=user.id,
                notification_type="otp",
                channel="email",
                destination=mfa_destination,
                subject="Your login verification code",
                status="queued",
                payload=json.dumps({"login_attempt_id": login_attempt.id, "challenge_token": verification_token}),
            )
        )
        db.commit()

    needs_security_email = password_correct and (
        is_new_device
        or is_new_ip
        or bool(ip_intelligence.get("impossible_travel"))
        or decision == "block"
        or approval_required
    )
    if needs_security_email:
        signal_names = []
        if is_new_device:
            signal_names.append("new device")
        if is_new_ip:
            signal_names.append("new IP address")
        if ip_intelligence.get("impossible_travel"):
            signal_names.append("unusual location")
        alert = AlertRecord(
            user_id=user.id,
            login_attempt_id=login_attempt.id,
            severity="critical" if decision == "block" else ("high" if approval_required else ("medium" if decision == "require_verification" else "low")),
            message=f"Login from {' and '.join(signal_names)}: {request_ip}",
            attack_type="suspicious_device",
            requires_manual_action=device_approval_status == "pending",
            auto_action="block" if decision == "block" else None,
        )
        db.add(alert)
        db.add(
            SecurityNotification(
                user_id=user.id,
                notification_type="security_alert",
                channel="email",
                destination=user.email,
                subject="Security alert: new login detected",
                status="queued",
                payload=json.dumps(
                    {
                        "login_attempt_id": login_attempt.id,
                        "ip_address": request_ip,
                        "new_device": is_new_device,
                        "new_ip": is_new_ip,
                        "approval_required": approval_required,
                    },
                    default=str,
                ),
            )
        )
        db.commit()

        background_tasks.add_task(
            notification_service.send_new_device_ip_alert,
            user.id,
            user.username,
            user.email,
            request_ip,
            request.device_fingerprint,
            mfa_method,
            is_new_device,
            is_new_ip,
            device_approval_status,
            login_time,
            request.browser,
            request.os,
            _device_location_label(ip_intelligence.get("city"), ip_intelligence.get("country")),
            anomaly_result["risk_score"],
            approve_url,
            deny_url,
        )

    # Update behavioral profile after a fully allowed login.
    if success and decision == "allow":
        learning_system.update_profile(user.id, login_data, db)
        access_token, refresh_token = _issue_token_pair(
            user.id,
            db,
            ip_address=request_ip,
            user_agent_hash=request.user_agent_hash,
            device_fingerprint=request.device_fingerprint,
        )
        _set_auth_cookies(response, access_token, refresh_token)

    # Check for account lock
    if not success and lock_service.should_lock_account(user.id, db):
        lock_service.lock_account(user.id, db)

    # Log the attempt
    logging_service.log_login_attempt(
        user.id,
        request_ip,
        success,
        anomaly_result["risk_score"],
        decision,
        anomaly_result["reasons"],
        db,
        login_attempt_id=login_attempt.id,
        mfa_method=mfa_method,
        new_device=is_new_device,
        new_ip=is_new_ip,
        device_approval_status=device_approval_status if password_correct else None,
    )

    if success and decision == "allow":
        successful_logins = db.query(LoginAttempt).filter(LoginAttempt.success == True).count()
        if (
            successful_logins >= settings.min_training_samples
            and successful_logins % settings.auto_retrain_login_count == 0
        ):
            background_tasks.add_task(_auto_retrain_model)
        elif successful_logins >= settings.min_training_samples and _should_trigger_daily_retraining():
            background_tasks.add_task(_auto_retrain_model)

    response = LoginDecision(
        **_format_analysis_response(
            anomaly_result,
            decision=decision,
            access_token=access_token,
            refresh_token=refresh_token,
            login_attempt_id=login_attempt.id,
            ip_address=request_ip,
            mfa_required=decision == "require_verification",
            mfa_method=mfa_method,
            new_device=is_new_device,
            new_ip=is_new_ip,
            device_approval_status=device_approval_status if password_correct else None,
            approval_required=approval_required,
            challenge_state=challenge_state,
            captcha_required=captcha_required,
            fraud_probability=float(adaptive_risk.get("fraud_probability") or 0.0),
            session_trust_score=float(adaptive_risk.get("trust_score") or 100.0),
            recommended_action=adaptive_risk.get("recommended_action"),
        )
    )
    if decision == "require_verification":
        response.verification_token = verification_token
        if settings.expose_debug_otp:
            response.debug_otp = otp_code

    return response

@router.post("/verify", response_model=dict)
@router.post("/verify-otp", response_model=dict)
def verify_login(
    request: VerificationRequest,
    http_request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    # Get verification data
    verification_data = cache_store.get_json(request.verification_token)
    challenge = db.query(LoginChallenge).filter(LoginChallenge.challenge_token == request.verification_token).first()
    if not verification_data and not challenge:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")
    if challenge and challenge.expires_at <= datetime.utcnow():
        challenge.state = "expired"
        db.commit()
        cache_store.delete(request.verification_token)
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")
    if not verification_data and challenge:
        verification_data = {
            "user_id": challenge.user_id,
            "attempts": challenge.otp_attempts or 0,
            "otp_hash": challenge.otp_hash,
            "login_attempt_id": challenge.login_attempt_id,
            "mfa_method": (json.loads(challenge.required_methods or "[]") or ["email_otp"])[0],
            "ip_address": challenge.ip_address,
            "device_fingerprint": challenge.device_fingerprint,
            "approval_required": challenge.approval_required,
            "device_approved": challenge.device_approved,
            "remember_device": challenge.remember_device,
        }

    user_id = verification_data["user_id"]
    attempts = int(verification_data.get("attempts") or 0)

    if attempts >= settings.otp_rate_limit_attempts:
        raise HTTPException(status_code=400, detail="Too many verification attempts")

    email_otp_ok = verification_service.verify_otp(verification_data["otp_hash"], request.otp)
    totp_ok = mfa_service.verify_totp(user_id, request.otp, db)
    backup_ok = mfa_service.consume_backup_code(user_id, request.otp, db) if not email_otp_ok and not totp_ok else False
    if not (email_otp_ok or totp_ok or backup_ok):
        verification_data["attempts"] = attempts + 1
        if challenge:
            challenge.otp_attempts = verification_data["attempts"]
            db.commit()
        cache_store.set_json(request.verification_token, settings.verification_token_ttl_seconds, verification_data)
        raise HTTPException(status_code=400, detail="Invalid OTP")

    verified_at = datetime.utcnow()
    login_attempt_id = verification_data.get("login_attempt_id")
    mfa_method = verification_data.get("mfa_method")
    ip_address = verification_data.get("ip_address")
    device_fingerprint = verification_data.get("device_fingerprint")
    approval_required = bool(verification_data.get("approval_required"))
    device_approved = bool(verification_data.get("device_approved"))
    remember_device = bool(verification_data.get("remember_device"))
    device_approval_status = "approved" if device_approved else "pending"

    if challenge:
        verified_methods = json.loads(challenge.verified_methods or "[]")
        otp_method = "totp" if totp_ok else ("backup_code" if backup_ok else "email_otp")
        if otp_method not in verified_methods:
            verified_methods.append(otp_method)
        challenge.verified_methods = json.dumps(verified_methods)
        challenge.otp_attempts = attempts
        if approval_required and not device_approved:
            challenge.state = "pending_device_approval"
            verification_data["otp_verified"] = True
            verification_data["otp_verified_at"] = verified_at.isoformat()
            verification_data["device_approved"] = False
            cache_store.set_json(request.verification_token, settings.verification_token_ttl_seconds, verification_data)
            db.commit()
            return {
                "message": "OTP verified. Device approval is still pending.",
                "challenge_state": "pending_device_approval",
                "approval_required": True,
                "login_attempt_id": login_attempt_id,
            }

        challenge.state = "approved"
        challenge.device_approved = True
        challenge.completed_at = verified_at

    if login_attempt_id:
        attempt = db.query(LoginAttempt).filter(LoginAttempt.id == login_attempt_id).first()
        if attempt:
            attempt.mfa_verified_at = verified_at

    if device_fingerprint:
        device = db.query(Device).filter(
            Device.user_id == user_id,
            Device.fingerprint == device_fingerprint,
        ).first()
        if device:
            device.last_mfa_method = mfa_method
            device.last_ip_address = ip_address or device.last_ip_address
            device.last_seen = verified_at
            if not approval_required or device_approval_status == "approved":
                device.approval_status = "approved"
                device.approved_at = device.approved_at or verified_at
                device.state = "trusted"
                device.is_trusted = remember_device or device.is_trusted

    login_data = verification_data.get("login_data") or {}
    if login_data:
        if isinstance(login_data.get("timestamp"), str):
            try:
                login_data["timestamp"] = datetime.fromisoformat(login_data["timestamp"])
            except ValueError:
                login_data["timestamp"] = verified_at
        learning_system.update_profile(user_id, login_data, db)
    else:
        db.commit()

    logging_service.log_security_event(
        user_id,
        "login_verified",
        f"Verification token {request.verification_token} completed via {_mfa_label(mfa_method)}",
        db,
        ip_address=ip_address,
    )
    cache_store.delete(request.verification_token)

    user_agent_hash = None
    if http_request is not None:
        user_agent_hash = http_request.headers.get("user-agent")
    access_token, refresh_token = _issue_token_pair(
        user_id,
        db,
        ip_address=ip_address,
        user_agent_hash=user_agent_hash,
        device_fingerprint=device_fingerprint,
    )
    _set_auth_cookies(response, access_token, refresh_token)

    return {
        "message": "Login verified successfully",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "mfa_method": mfa_method,
        "login_attempt_id": login_attempt_id,
        "challenge_state": "approved",
    }

@router.post("/admin/unlock", response_model=dict)
def admin_unlock(request: AdminUnlockRequest, db: Session = Depends(get_db)):
    # Simplified admin check
    if request.admin_token != settings.admin_secret_token:
        raise HTTPException(status_code=403, detail="Invalid admin token")

    lock_service.unlock_account(request.user_id, db, admin_user_id=0)  # Assume admin id 0

    return {"message": "Account unlocked successfully"}

@router.post("/feedback", response_model=dict)
def submit_feedback(request: FeedbackRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    # Simplified admin check
    if request.admin_token != settings.admin_secret_token:
        raise HTTPException(status_code=403, detail="Invalid admin token")

    # Update the login attempt with feedback
    attempt = db.query(LoginAttempt).filter(LoginAttempt.id == request.login_attempt_id).first()
    if not attempt:
        raise HTTPException(status_code=404, detail="Login attempt not found")

    if request.is_false_positive:
        attempt.risk_score = max(0.0, (attempt.risk_score or 0.0) - 30)
        attempt.decision = "allow"
        db.commit()
        adjusted_attempts = db.query(LoginAttempt).filter(
            LoginAttempt.decision == "allow",
            LoginAttempt.risk_score <= 40,
        ).count()
        if adjusted_attempts >= 5:
            background_tasks.add_task(_auto_retrain_model)
    else:
        db.commit()

    return {"message": "Feedback submitted successfully"}
