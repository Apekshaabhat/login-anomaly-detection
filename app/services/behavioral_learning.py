from sqlalchemy.orm import Session
from app.database.models import UserProfile, LoginAttempt, Device
from app.config import settings
from datetime import datetime, timedelta
from statistics import mean, stdev
import json
from typing import Dict, Any, List

class BehavioralLearningSystem:
    def __init__(self):
        self.learning_period_days = settings.learning_mode_days

    def is_in_learning_mode(self, user_id: int, db: Session) -> bool:
        profile = db.query(UserProfile).filter(UserProfile.user_id == user_id).first()
        if not profile:
            return True
        return profile.learning_mode

    def update_profile(self, user_id: int, login_data: Dict[str, Any], db: Session):
        profile = db.query(UserProfile).filter(UserProfile.user_id == user_id).first()
        if not profile:
            profile = UserProfile(user_id=user_id)
            db.add(profile)

        successful_count = db.query(LoginAttempt).filter(
            LoginAttempt.user_id == user_id,
            LoginAttempt.success == True,
        ).count()
        sample_count = max(1, successful_count)

        timestamp = login_data.get("timestamp", datetime.utcnow())
        login_hour = timestamp.hour + timestamp.minute / 60
        profile.login_time_mean, profile.login_time_std = self._welford_update(
            profile.login_time_mean,
            profile.login_time_std,
            sample_count,
            login_hour,
        )

        if login_data.get("location_lat") is not None and login_data.get("location_lon") is not None:
            profile.location_lat_mean, profile.location_std = self._welford_update(
                profile.location_lat_mean,
                profile.location_std,
                sample_count,
                float(login_data["location_lat"]),
            )
            profile.location_lon_mean, _ = self._welford_update(
                profile.location_lon_mean,
                profile.location_std,
                sample_count,
                float(login_data["location_lon"]),
            )

        if login_data.get("typing_speed") is not None:
            profile.typing_speed_mean, profile.typing_speed_std = self._welford_update(
                profile.typing_speed_mean,
                profile.typing_speed_std,
                sample_count,
                float(login_data["typing_speed"]),
            )

        if login_data.get("keystroke_timing"):
            profile.keystroke_rhythm = login_data["keystroke_timing"]

        if successful_count >= 10:
            profile.learning_mode = False

        db.commit()

    def _welford_update(
        self,
        current_mean: float | None,
        current_std: float | None,
        sample_count: int,
        value: float,
    ) -> tuple[float, float]:
        if sample_count <= 1 or current_mean is None:
            return value, 0.0

        previous_count = sample_count - 1
        previous_m2 = (current_std or 0.0) ** 2 * max(previous_count - 1, 0)
        delta = value - current_mean
        new_mean = current_mean + delta / sample_count
        delta2 = value - new_mean
        new_m2 = previous_m2 + delta * delta2
        new_variance = new_m2 / max(sample_count - 1, 1)
        return new_mean, new_variance ** 0.5

    def calculate_confidence_score(self, user_id: int, login_data: Dict[str, Any], db: Session) -> float:
        profile = db.query(UserProfile).filter(UserProfile.user_id == user_id).first()
        if not profile or profile.learning_mode:
            return 0.5  # Neutral during learning

        confidence = 1.0

        # Login time confidence
        if profile.login_time_mean is not None:
            login_hour = login_data.get('timestamp', datetime.utcnow()).hour + login_data.get('timestamp', datetime.utcnow()).minute / 60
            time_diff = abs(login_hour - profile.login_time_mean)
            time_confidence = max(0, 1 - time_diff / (profile.login_time_std or 1))
            confidence *= time_confidence

        # Location confidence
        if profile.location_lat_mean and login_data.get('location_lat'):
            lat_diff = abs(login_data['location_lat'] - profile.location_lat_mean)
            lon_diff = abs(login_data['location_lon'] - profile.location_lon_mean)
            location_diff = (lat_diff + lon_diff) / 2
            location_confidence = max(0, 1 - location_diff / (profile.location_std or 1))
            confidence *= location_confidence

        # Typing speed confidence
        if profile.typing_speed_mean and login_data.get('typing_speed'):
            speed_diff = abs(login_data['typing_speed'] - profile.typing_speed_mean)
            speed_confidence = max(0, 1 - speed_diff / (profile.typing_speed_std or 1))
            confidence *= speed_confidence

        return confidence
