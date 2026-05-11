from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Dict, Any
from app.database.connection import get_db
from app.routers.auth import login, LoginRequest
from app.services.live_simulation import LiveSimulationService
import random

router = APIRouter()
live_simulation_service = LiveSimulationService()

class BruteForceSimulationRequest(BaseModel):
    username: str
    passwords: List[str]
    ip_address: str = "192.168.1.100"

class AnomalySimulationRequest(BaseModel):
    username: str
    password: str
    anomaly_type: str  # new_device, new_location, fast_typing, slow_typing


class LiveSimulationRequest(BaseModel):
    count: int = 5

@router.post("/simulate-brute-force", response_model=List[Dict[str, Any]])
def simulate_brute_force(request: BruteForceSimulationRequest, db: Session = Depends(get_db)):
    results = []
    background_tasks = BackgroundTasks()
    for password in request.passwords:
        login_req = LoginRequest(
            username=request.username,
            password=password,
            ip_address=request.ip_address,
            device_id="simulated_device",
            typing_speed=random.uniform(1, 3),
            keystroke_timing=[random.uniform(0.1, 0.5) for _ in range(len(password))]
        )
        try:
            result = login(login_req, None, background_tasks, db=db)
            results.append({
                "password": password,
                "decision": result.decision,
                "risk_score": result.risk_score,
                "reasons": result.reasons
            })
        except Exception as e:
            results.append({
                "password": password,
                "error": str(e)
            })
    return results

@router.post("/simulate-anomaly", response_model=Dict[str, Any])
def simulate_anomaly(request: AnomalySimulationRequest, db: Session = Depends(get_db)):
    background_tasks = BackgroundTasks()
    login_req = LoginRequest(
        username=request.username,
        password=request.password,
        ip_address="192.168.1.100",
        device_id="normal_device",
        location_lat=40.7128,
        location_lon=-74.0060,
        typing_speed=2.0,
        keystroke_timing=[0.2] * len(request.password)
    )

    if request.anomaly_type == "new_device":
        login_req.device_id = "unknown_device_123"
        login_req.device_fingerprint = "unknown_device_123"
    elif request.anomaly_type == "new_location":
        login_req.location_lat = -33.8688
        login_req.location_lon = 151.2093
    elif request.anomaly_type == "fast_typing":
        login_req.typing_speed = 10.0
        login_req.keystroke_timing = [0.01] * len(request.password)
    elif request.anomaly_type == "slow_typing":
        login_req.typing_speed = 0.1
        login_req.keystroke_timing = [1.0] * len(request.password)

    try:
        result = login(login_req, None, background_tasks, db=db)
        return {
            "anomaly_type": request.anomaly_type,
            "decision": result.decision,
            "risk_score": result.risk_score,
            "reasons": result.reasons
        }
    except Exception as e:
        return {
            "anomaly_type": request.anomaly_type,
            "error": str(e)
        }


@router.post("/live/generate", response_model=Dict[str, Any])
def generate_live_activity(request: LiveSimulationRequest, db: Session = Depends(get_db)):
    generated = live_simulation_service.generate_live_attempts(db, count=max(1, min(request.count, 25)))
    return {
        "generated": len(generated),
        "attempts": generated,
    }
