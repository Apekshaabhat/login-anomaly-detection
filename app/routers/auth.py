from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
from app.database.connection import get_db
from app.database.models import User, LoginAttempt, Device
from app.services.password_security import PasswordSecurityEngine
from app.services.anomaly_detection import AnomalyDetectionEngine
from app.services.behavioral_learning import BehavioralLearningSystem
from app.services.verification import VerificationService
from app.services.account_lock import AccountLockService
from app.services.logging_service import LoggingService
from app.utils.helpers import hash_password, verify_password, serialize_keystroke_timing, calculate_typing_speed
from app.config import settings
import redis
import json

router = APIRouter()
password_engine = PasswordSecurityEngine()
anomaly_engine = AnomalyDetectionEngine()
learning_system = BehavioralLearningSystem()
verification_service = VerificationService()
lock_service = AccountLockService()
logging_service = LoggingService()

redis_client = redis.Redis.from_url(settings.redis_url)

class PasswordValidationRequest(BaseModel):
    password: str

class UserRegistrationRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str
    ip_address: str
    location_lat: Optional[float] = None
    location_lon: Optional[float] = None
    device_fingerprint: str
    typing_speed: Optional[float] = None
    keystroke_timing: Optional[List[float]] = None
    time_taken: Optional[float] = None

class LoginDecision(BaseModel):
    decision: str  # allow, require_verification, block
    risk_score: float
    reasons: List[str]
    verification_token: Optional[str] = None

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

@router.post("/login", response_model=LoginDecision)
def login(request: LoginRequest, db: Session = Depends(get_db)):
    # Rate limiting
    rate_limit_key = f"login:{request.ip_address}"
    attempts = redis_client.get(rate_limit_key)
    if attempts and int(attempts) >= settings.rate_limit_requests:
        raise HTTPException(status_code=429, detail="Too many login attempts")

    redis_client.incr(rate_limit_key)
    redis_client.expire(rate_limit_key, settings.rate_limit_window_seconds)

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
        "ip_address": request.ip_address,
        "location_lat": request.location_lat,
        "location_lon": request.location_lon,
        "device_fingerprint": request.device_fingerprint,
        "typing_speed": request.typing_speed,
        "keystroke_timing": serialize_keystroke_timing(request.keystroke_timing) if request.keystroke_timing else None
    }

    # Detect anomalies
    anomaly_result = anomaly_engine.detect_anomalies(user.id, login_data, db)

    # If password wrong, increase risk
    if not password_correct:
        anomaly_result["risk_score"] += 50
        anomaly_result["reasons"].append("Incorrect password")

    # Make final decision
    if not password_correct:
        decision = "block"
    elif anomaly_result["decision"] == "block":
        decision = "block"
    elif anomaly_result["decision"] == "require_verification":
        decision = "require_verification"
        # Generate verification token (simplified)
        verification_token = f"verify_{user.id}_{datetime.utcnow().timestamp()}"
        redis_client.setex(verification_token, 300, json.dumps({"user_id": user.id, "attempts": 0}))
    else:
        decision = "allow"

    # Create login attempt record
    login_attempt = LoginAttempt(
        user_id=user.id,
        timestamp=datetime.utcnow(),
        ip_address=request.ip_address,
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
        user.id, request.ip_address, success, anomaly_result["risk_score"], decision, anomaly_result["reasons"], db
    )

    response = LoginDecision(
        decision=decision,
        risk_score=anomaly_result["risk_score"],
        reasons=anomaly_result["reasons"]
    )
    if decision == "require_verification":
        response.verification_token = verification_token

    return response

@router.post("/verify", response_model=dict)
def verify_login(request: VerificationRequest, db: Session = Depends(get_db)):
    # Get verification data
    verification_data = redis_client.get(request.verification_token)
    if not verification_data:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")

    data = json.loads(verification_data)
    user_id = data["user_id"]
    attempts = data["attempts"]

    if attempts >= 3:
        raise HTTPException(status_code=400, detail="Too many verification attempts")

    # Verify OTP (simplified, assume secret stored somewhere)
    # For demo, accept any 6-digit code
    if len(request.otp) != 6 or not request.otp.isdigit():
        data["attempts"] += 1
        redis_client.setex(request.verification_token, 300, json.dumps(data))
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # Mark as verified
    redis_client.delete(request.verification_token)

    # Update login attempt as successful
    # (In real implementation, link to the original attempt)

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