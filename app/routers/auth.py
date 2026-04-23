from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field, IPvAnyAddress, ConfigDict, model_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from app.database.connection import get_db, SessionLocal
from app.database.models import User, LoginAttempt, Device
from app.schemas.analytics import AnalyzeRequest, AnalyzeResponse
from app.services.password_security import PasswordSecurityEngine
from app.services.anomaly_detection import AnomalyDetectionEngine
from app.services.behavioral_learning import BehavioralLearningSystem
from app.services.verification import VerificationService
from app.services.account_lock import AccountLockService
from app.services.logging_service import LoggingService
from app.services.cache_store import CacheStore
from app.utils.helpers import hash_password, verify_password, serialize_keystroke_timing, calculate_typing_speed
from app.config import settings
import json

router = APIRouter()
password_engine = PasswordSecurityEngine()
anomaly_engine = AnomalyDetectionEngine()
learning_system = BehavioralLearningSystem()
verification_service = VerificationService()
lock_service = AccountLockService()
logging_service = LoggingService()

cache_store = CacheStore(settings.redis_url)

class PasswordValidationRequest(BaseModel):
    password: str

class UserRegistrationRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    username: str
    password: str
    ip_address: IPvAnyAddress
    location_lat: Optional[float] = Field(default=None, ge=-90, le=90)
    location_lon: Optional[float] = Field(default=None, ge=-180, le=180)
    device_fingerprint: Optional[str] = Field(default=None, min_length=1, max_length=255)
    device_id: Optional[str] = Field(default=None, min_length=1, max_length=255)
    typing_speed: Optional[float] = Field(default=None, ge=0, le=500)
    keystroke_timing: Optional[List[float]] = None
    time_taken: Optional[float] = Field(default=None, gt=0, le=60)
    failed_attempts: Optional[int] = Field(default=0, ge=0, le=100)
    login_hour: Optional[float] = Field(default=None, ge=0, le=23.99)

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

class VerificationRequest(BaseModel):
    username: str
    otp: str
    verification_token: str

class AdminUnlockRequest(BaseModel):
    user_id: int
    admin_token: str

class FeedbackRequest(BaseModel):
    login_attempt_id: int
    is_false_positive: bool
    admin_token: str

@router.post("/validate-password", response_model=dict)
def validate_password(request: PasswordValidationRequest):
    result = password_engine.validate_password(request.password)
    return result

@router.post("/register", response_model=dict)
def register_user(request: UserRegistrationRequest, db: Session = Depends(get_db)):
    # Check if user exists
    existing_user = db.query(User).filter(User.username == request.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    # Validate password
    password_validation = password_engine.validate_password(request.password)
    if not password_validation["is_valid"]:
        raise HTTPException(status_code=400, detail="Password does not meet requirements")

    # Create user
    hashed_password = hash_password(request.password)
    user = User(username=request.username, hashed_password=hashed_password)
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
def login(request: LoginRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    request_ip = str(request.ip_address)

    # Rate limiting
    rate_limit_key = f"login:{request_ip}"
    attempts = cache_store.get(rate_limit_key)
    if attempts and int(attempts) >= settings.rate_limit_requests:
        raise HTTPException(status_code=429, detail="Too many login attempts")

    cache_store.incr(rate_limit_key)
    cache_store.expire(rate_limit_key, settings.rate_limit_window_seconds)

    # Find user
    user = db.query(User).filter(User.username == request.username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Check if account is locked
    if lock_service.is_account_locked(user.id, db):
        raise HTTPException(status_code=403, detail="Account is locked")

    # Verify password
    password_correct = verify_password(request.password, user.hashed_password)
    success = password_correct

    # Calculate typing speed if not provided
    if request.time_taken and not request.typing_speed:
        request.typing_speed = calculate_typing_speed(len(request.password), request.time_taken)

    # Prepare login data
    login_data = {
        "timestamp": datetime.utcnow(),
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

    # If password wrong, increase risk
    if not password_correct:
        anomaly_result["risk_score"] = min(100.0, anomaly_result["risk_score"] + 50)
        anomaly_result["level"] = "HIGH" if anomaly_result["risk_score"] >= 70 else anomaly_result.get("level")
        anomaly_result["reasons"].append("Incorrect password")
        anomaly_result["explanation"] = f"{anomaly_result['explanation']} Incorrect password increased the final risk."

    # Make final decision
    if not password_correct:
        decision = "block"
    elif anomaly_result["decision"] == "block":
        decision = "block"
    elif anomaly_result["decision"] == "require_verification":
        decision = "require_verification"
        otp_code = verification_service.generate_otp()
        verification_token = f"verify_{user.id}_{datetime.utcnow().timestamp()}"
        cache_store.set_json(
            verification_token,
            settings.verification_token_ttl_seconds,
            {
                "user_id": user.id,
                "attempts": 0,
                "otp_hash": verification_service.hash_otp(otp_code),
                "issued_at": datetime.utcnow().isoformat(),
            },
        )
    else:
        decision = "allow"

    # Create login attempt record
    login_attempt = LoginAttempt(
        user_id=user.id,
        timestamp=datetime.utcnow(),
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
        confidence_score=anomaly_result.get("confidence_score")
    )
    db.add(login_attempt)
    db.commit()

    # Update device trust
    device = db.query(Device).filter(Device.user_id == user.id, Device.fingerprint == request.device_fingerprint).first()
    if not device:
        device = Device(user_id=user.id, fingerprint=request.device_fingerprint)
        db.add(device)
    device.last_seen = datetime.utcnow()
    if success and decision == "allow":
        device.is_trusted = True
    db.commit()

    # Update behavioral profile if successful
    if success:
        learning_system.update_profile(user.id, login_data, db)

    # Check for account lock
    if not success and lock_service.should_lock_account(user.id, db):
        lock_service.lock_account(user.id, db)

    # Log the attempt
    logging_service.log_login_attempt(
        user.id, request_ip, success, anomaly_result["risk_score"], decision, anomaly_result["reasons"], db
    )

    if success:
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
        )
    )
    if decision == "require_verification":
        response.verification_token = verification_token
        if settings.expose_debug_otp:
            response.debug_otp = otp_code

    return response

@router.post("/verify", response_model=dict)
def verify_login(request: VerificationRequest, db: Session = Depends(get_db)):
    # Get verification data
    verification_data = cache_store.get_json(request.verification_token)
    if not verification_data:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")

    user_id = verification_data["user_id"]
    attempts = verification_data["attempts"]

    if attempts >= settings.verification_max_attempts:
        raise HTTPException(status_code=400, detail="Too many verification attempts")

    if not verification_service.verify_otp(verification_data["otp_hash"], request.otp):
        verification_data["attempts"] += 1
        cache_store.set_json(
            request.verification_token,
            settings.verification_token_ttl_seconds,
            verification_data,
        )
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # Mark as verified
    cache_store.delete(request.verification_token)

    # Update login attempt as successful
    # (In real implementation, link to the original attempt)

    logging_service.log_security_event(
        user_id,
        "login_verified",
        f"Verification token {request.verification_token} completed",
        db,
        ip_address=None,
    )

    return {"message": "Login verified successfully"}

@router.post("/admin/unlock", response_model=dict)
def admin_unlock(request: AdminUnlockRequest, db: Session = Depends(get_db)):
    # Simplified admin check
    if request.admin_token != "admin_secret":
        raise HTTPException(status_code=403, detail="Invalid admin token")

    lock_service.unlock_account(request.user_id, db, admin_user_id=0)  # Assume admin id 0

    return {"message": "Account unlocked successfully"}

@router.post("/feedback", response_model=dict)
def submit_feedback(request: FeedbackRequest, db: Session = Depends(get_db)):
    # Simplified admin check
    if request.admin_token != "admin_secret":
        raise HTTPException(status_code=403, detail="Invalid admin token")

    # Update the login attempt with feedback
    attempt = db.query(LoginAttempt).filter(LoginAttempt.id == request.login_attempt_id).first()
    if attempt:
        # In real implementation, use feedback to retrain model
        pass

    return {"message": "Feedback submitted successfully"}
