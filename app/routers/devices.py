from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import Device, TrustedIP, User
from app.services.auth_context import get_current_user
from app.services.logging_service import LoggingService

router = APIRouter()
logging_service = LoggingService()


class TrustDeviceRequest(BaseModel):
    device_id: int
    nickname: Optional[str] = Field(default=None, max_length=120)
    remember_device: bool = True


class TrustIPRequest(BaseModel):
    ip_address: str
    label: Optional[str] = Field(default=None, max_length=120)


def _device_payload(device: Device) -> dict:
    return {
        "id": device.id,
        "fingerprint": device.fingerprint,
        "nickname": device.nickname,
        "browser": device.browser,
        "os": device.os,
        "device_type": device.device_type,
        "screen_resolution": device.screen_resolution,
        "timezone": device.timezone,
        "language": device.language,
        "hardware_fingerprint": device.hardware_fingerprint,
        "user_agent_hash": device.user_agent_hash,
        "state": device.state or ("trusted" if device.is_trusted else "pending_verification"),
        "is_trusted": device.is_trusted,
        "remember_device": device.remember_device,
        "first_ip_address": device.first_ip_address,
        "last_ip_address": device.last_ip_address,
        "approval_status": device.approval_status,
        "approved_at": device.approved_at,
        "last_mfa_method": device.last_mfa_method,
        "first_seen": device.first_seen,
        "last_seen": device.last_seen,
    }


@router.get("", response_model=list[dict])
@router.get("/", response_model=list[dict])
def list_devices(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    devices = db.query(Device).filter(Device.user_id == current_user.id).order_by(Device.last_seen.desc()).all()
    return [_device_payload(device) for device in devices]


@router.post("/trust", response_model=dict)
def trust_device(
    request: TrustDeviceRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    device = db.query(Device).filter(Device.id == request.device_id, Device.user_id == current_user.id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.state == "blocked":
        raise HTTPException(status_code=400, detail="Blocked devices cannot be trusted")

    device.is_trusted = True
    device.remember_device = request.remember_device
    device.nickname = request.nickname or device.nickname
    device.state = "trusted"
    device.approval_status = "approved"
    device.approved_at = device.approved_at or datetime.utcnow()
    db.commit()
    logging_service.log_security_event(current_user.id, "device_trusted", f"Trusted device {device.id}", db)
    return {"message": "Device trusted", "device": _device_payload(device)}


@router.delete("/{device_id}", response_model=dict)
def revoke_device(
    device_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    device = db.query(Device).filter(Device.id == device_id, Device.user_id == current_user.id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    device.is_trusted = False
    device.remember_device = False
    device.state = "blocked"
    device.blocked_at = datetime.utcnow()
    db.commit()
    logging_service.log_security_event(current_user.id, "device_revoked", f"Revoked device {device.id}", db)
    return {"message": "Device revoked"}


@router.post("/trusted-ips", response_model=dict)
def trust_ip(
    request: TrustIPRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    trusted = db.query(TrustedIP).filter(
        TrustedIP.user_id == current_user.id,
        TrustedIP.ip_address == request.ip_address,
    ).first()
    if not trusted:
        trusted = TrustedIP(user_id=current_user.id, ip_address=request.ip_address, created_at=datetime.utcnow())
        db.add(trusted)
    trusted.label = request.label or trusted.label
    trusted.last_seen_at = datetime.utcnow()
    db.commit()
    return {"message": "IP trusted", "ip_address": trusted.ip_address}
