from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.ml.registry import model_registry
from app.services.model_monitoring import model_monitoring_service

router = APIRouter()


class ModelExplainRequest(BaseModel):
    login_features: Dict[str, Any] = Field(default_factory=dict)


@router.get("/status", response_model=dict)
def get_model_status(db: Session = Depends(get_db)) -> Dict[str, Any]:
    return model_monitoring_service.get_status(db)


@router.get("/drift", response_model=dict)
def get_model_drift(db: Session = Depends(get_db)) -> Dict[str, Any]:
    return model_monitoring_service.get_drift(db)


@router.post("/retrain", response_model=dict)
def retrain_model(db: Session = Depends(get_db)) -> Dict[str, Any]:
    result = model_monitoring_service.retrain(db)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Model retraining failed"))
    return result


@router.get("/history", response_model=list)
def get_model_history() -> list:
    return model_monitoring_service.get_history()


@router.post("/explain", response_model=dict)
def explain_model_prediction(request: ModelExplainRequest, db: Session = Depends(get_db)) -> Dict[str, Any]:
    return model_monitoring_service.explain(request.login_features, db)


@router.get("/monitoring", response_model=dict)
def get_model_monitoring(db: Session = Depends(get_db)) -> Dict[str, Any]:
    return model_monitoring_service.get_monitoring(db)


@router.get("/confusion-matrix", response_model=dict)
def get_model_confusion_matrix(db: Session = Depends(get_db)) -> Dict[str, Any]:
    return model_monitoring_service.get_confusion_matrix(db)


@router.get("/registry", response_model=dict)
def get_model_registry() -> Dict[str, Any]:
    return {
        "default_model": model_registry.default_model_key,
        "models": model_registry.list_models(),
    }
