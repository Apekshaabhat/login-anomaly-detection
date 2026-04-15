import bcrypt
import jwt
from datetime import datetime, timedelta
from app.config import settings
import hashlib
import json
from geopy.distance import geodesic
from typing import List, Dict, Any

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt

def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    return geodesic((lat1, lon1), (lat2, lon2)).km

def calculate_travel_velocity(distance: float, time_diff_hours: float) -> float:
    if time_diff_hours == 0:
        return float('inf')
    return distance / time_diff_hours

def hash_string(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def serialize_keystroke_timing(timing: List[float]) -> str:
    return json.dumps(timing)

def deserialize_keystroke_timing(timing_str: str) -> List[float]:
    return json.loads(timing_str)

def calculate_typing_speed(password_length: int, time_taken: float) -> float:
    if time_taken == 0:
        return 0
    return password_length / time_taken

def normalize_location(lat: float, lon: float) -> tuple:
    # Normalize to reduce precision for privacy
    return round(lat, 2), round(lon, 2)