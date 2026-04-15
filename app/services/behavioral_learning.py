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

        # Get recent successful logins
        recent_logins = db.query(LoginAttempt).filter(
            LoginAttempt.user_id == user_id,
            LoginAttempt.success == True,
            LoginAttempt.timestamp >= datetime.utcnow() - timedelta(days=30)
        ).all()

        if len(recent_logins) >= 5:
            # Update login times
            login_hours = [la.timestamp.hour + la.timestamp.minute / 60 for la in recent_logins]
            profile.login_time_mean = mean(login_hours)
            profile.login_time_std = stdev(login_hours) if len(login_hours) > 1 else 0

            # Update locations
            locations = [(la.location_lat, la.location_lon) for la in recent_logins if la.location_lat and la.location_lon]
            if locations:
                lats, lons = zip(*locations)
                profile.location_lat_mean = mean(lats)
                profile.location_lon_mean = mean(lons)
                profile.location_std = stdev(lats + lons) / 2 if len(lats) > 1 else 0

            # Update typing speed
            typing_speeds = [la.typing_speed for la in recent_logins if la.typing_speed]
            if typing_speeds:
                profile.typing_speed_mean = mean(typing_speeds)
                profile.typing_speed_std = stdev(typing_speeds) if len(typing_speeds) > 1 else 0

            # Update keystroke rhythm (simplified)
            keystrokes = [json.loads(la.keystroke_timing) for la in recent_logins if la.keystroke_timing]
            if keystrokes:
                avg_keystroke = [mean(k) for k in zip(*keystrokes)]
                profile.keystroke_rhythm = json.dumps(avg_keystroke)

            # Check if learning mode should end
            first_login = min(la.timestamp for la in recent_logins)
            if datetime.utcnow() - first_login > timedelta(days=self.learning_period_days):
                profile.learning_mode = False

        db.commit()

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