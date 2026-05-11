from datetime import datetime, timedelta
from app.config import settings
import hashlib
import json
import math
import bcrypt
try:
    from passlib.context import CryptContext
except ModuleNotFoundError:
    CryptContext = None
from jose import jwt as jose_jwt
from typing import List

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto") if CryptContext else None

def hash_password(password: str) -> str:
    if password_context:
        return password_context.hash(password)
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    try:
        if not password_context:
            return bcrypt.checkpw(plain.encode(), hashed.encode())
        return password_context.verify(plain, hashed)
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    to_encode.update({"exp": expire})
    encoded_jwt = jose_jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt

def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    earth_radius_km = 6371.0
    lat1_rad, lon1_rad = math.radians(lat1), math.radians(lon1)
    lat2_rad, lon2_rad = math.radians(lat2), math.radians(lon2)
    delta_lat = lat2_rad - lat1_rad
    delta_lon = lon2_rad - lon1_rad
    a = (
        math.sin(delta_lat / 2) ** 2
        + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return earth_radius_km * c

def calculate_travel_velocity(distance: float, time_diff_hours: float) -> float:
    if time_diff_hours <= 0:
        return float('inf')
    return distance / time_diff_hours

def hash_string(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def serialize_keystroke_timing(timing: List[float]) -> str:
    return json.dumps(timing)

def deserialize_keystroke_timing(timing_str: str) -> List[float]:
    return json.loads(timing_str)

def calculate_typing_speed(char_count: int, time_taken: float) -> float:
    if time_taken <= 0:
        return 0.0
    return char_count / time_taken

def normalize_location(lat: float, lon: float) -> tuple:
    # Normalize to reduce precision for privacy
    return round(lat, 2), round(lon, 2)
