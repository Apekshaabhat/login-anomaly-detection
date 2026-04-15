from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Dict, Any
from app.database.connection import get_db
from app.database.models import AuditLog, LoginAttempt, User
from app.services.logging_service import LoggingService
from app.ml.model import AnomalyDetectionModel
from app.config import settings

router = APIRouter()
logging_service = LoggingService()
ml_model = AnomalyDetectionModel()

class RetrainRequest(BaseModel):
    admin_token: str

class AddBlacklistRequest(BaseModel):
    password: str
    admin_token: str

@router.get("/logs", response_model=List[Dict[str, Any]])
def get_audit_logs(limit: int = 100, db: Session = Depends(get_db)):
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "action": log.action,
            "details": log.details,
            "timestamp": log.timestamp,
            "ip_address": log.ip_address
        }
        for log in logs
    ]

@router.get("/login-attempts", response_model=List[Dict[str, Any]])
def get_login_attempts(user_id: int = None, limit: int = 100, db: Session = Depends(get_db)):
    query = db.query(LoginAttempt)
    if user_id:
        query = query.filter(LoginAttempt.user_id == user_id)
    attempts = query.order_by(LoginAttempt.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": attempt.id,
            "user_id": attempt.user_id,
            "timestamp": attempt.timestamp,
            "ip_address": attempt.ip_address,
            "success": attempt.success,
            "risk_score": attempt.risk_score,
            "decision": attempt.decision,
            "reasons": attempt.reasons
        }
        for attempt in attempts
    ]

@router.post("/retrain-model", response_model=dict)
def retrain_model(request: RetrainRequest, db: Session = Depends(get_db)):
    if request.admin_token != "admin_secret":
        raise HTTPException(status_code=403, detail="Invalid admin token")

    # Get training data from successful logins
    training_data = []
    attempts = db.query(LoginAttempt).filter(LoginAttempt.success == True).limit(1000).all()
    for attempt in attempts:
        training_data.append({
            'login_hour': attempt.timestamp.hour + attempt.timestamp.minute / 60,
            'location_lat': attempt.location_lat or 0,
            'location_lon': attempt.location_lon or 0,
            'typing_speed': attempt.typing_speed or 0,
            'failed_attempts': 0  # Simplified
        })

    ml_model.train(training_data)

    logging_service.log_admin_action(0, "model_retrained", f"Retrained with {len(training_data)} samples", db)

    return {"message": "Model retrained successfully"}

@router.post("/add-blacklist", response_model=dict)
def add_to_blacklist(request: AddBlacklistRequest, db: Session = Depends(get_db)):
    if request.admin_token != "admin_secret":
        raise HTTPException(status_code=403, detail="Invalid admin token")

    from app.services.password_security import PasswordSecurityEngine
    engine = PasswordSecurityEngine()
    engine.add_to_blacklist(request.password)

    logging_service.log_admin_action(0, "blacklist_added", f"Added password to blacklist", db)

    return {"message": "Password added to blacklist"}