from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, IPvAnyAddress, field_validator


class AnalyzeRequest(BaseModel):
    login_hour: float = Field(ge=0, le=23.99)
    location_lat: float = Field(ge=-90, le=90)
    location_lon: float = Field(ge=-180, le=180)
    typing_speed: float = Field(ge=0, le=500)
    failed_attempts: int = Field(ge=0, le=100)
    device_id: str = Field(min_length=1, max_length=255)
    ip_address: IPvAnyAddress
    username: Optional[str] = Field(default=None, max_length=255)

    @field_validator("device_id", "username", mode="before")
    @classmethod
    def strip_strings(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        cleaned = value.strip()
        return cleaned or None


class AnalyzeResponse(BaseModel):
    risk_score: float
    level: str
    reasons: List[str]
    attack_type: str
    explanation: Optional[str] = None
    decision: Optional[str] = None
    verification_token: Optional[str] = None
    debug_otp: Optional[str] = None


class DashboardLogItem(BaseModel):
    id: int
    user: str
    time: datetime
    location: str
    device: str
    risk: float
    status: str
    ip_address: str
    location_lat: Optional[float] = None
    location_lon: Optional[float] = None
    reasons: List[str] = []


class DashboardTimelinePoint(BaseModel):
    time: str
    risk: float
    baseline: float


class DashboardResponse(BaseModel):
    logs: List[DashboardLogItem]
    timeline: List[DashboardTimelinePoint]
    distribution: List[Dict[str, Any]]


class BehaviorTrendPoint(BaseModel):
    label: str
    login_count: int
    avg_typing_speed: float
    failed_attempts: int


class BehaviorComparisonPoint(BaseModel):
    axis: str
    normal: float
    current: float


class BehaviorResponse(BaseModel):
    username: str
    is_new_user: bool
    typical_login_time: str
    frequent_locations: List[str]
    devices_used: List[str]
    trust_score: float
    trend_data: List[BehaviorTrendPoint]
    comparison_data: List[BehaviorComparisonPoint]
    trust_history: List[Dict[str, Any]]
    failed_attempts: int
