from sqlalchemy.orm import Session
from app.database.models import LoginAttempt, Device
from app.services.behavioral_learning import BehavioralLearningSystem
from app.ml.model import AnomalyDetectionModel
from app.utils.helpers import calculate_distance, calculate_travel_velocity
from app.config import settings
from datetime import datetime, timedelta
from typing import Dict, Any, List

class AnomalyDetectionEngine:
    def __init__(self):
        self.learning_system = BehavioralLearningSystem()
        self.ml_model = AnomalyDetectionModel()

    def detect_anomalies(self, user_id: int, login_data: Dict[str, Any], db: Session) -> Dict[str, Any]:
        reasons = []
        risk_score = 0

        # Rule-based checks
        risk_score, rule_reasons = self._rule_based_checks(user_id, login_data, db)
        reasons.extend(rule_reasons)

        # ML-based anomaly score
        ml_features = self._extract_features(user_id, login_data, db)
        anomaly_score = self.ml_model.predict_anomaly_score(ml_features)
        if anomaly_score > settings.anomaly_threshold:
            risk_score += 30
            reasons.append("ML anomaly detected")

        # Behavioral confidence
        confidence_score = self.learning_system.calculate_confidence_score(user_id, login_data, db)
        risk_score = max(0, risk_score - (confidence_score * 20))  # Reduce risk if high confidence

        # Device trust
        device_trust = self._check_device_trust(user_id, login_data.get('device_fingerprint'), db)
        if not device_trust:
            risk_score += 20
            reasons.append("Untrusted device")

        # Travel velocity
        travel_risk, travel_reason = self._check_travel_velocity(user_id, login_data, db)
        if travel_risk:
            risk_score += 25
            reasons.append(travel_reason)

        risk_score = min(100, max(0, risk_score))

        decision = self._make_decision(risk_score)

        return {
            "risk_score": risk_score,
            "anomaly_score": anomaly_score,
            "confidence_score": confidence_score,
            "decision": decision,
            "reasons": reasons
        }

    def _rule_based_checks(self, user_id: int, login_data: Dict[str, Any], db: Session) -> tuple:
        risk_score = 0
        reasons = []

        # Check recent failed attempts
        recent_attempts = db.query(LoginAttempt).filter(
            LoginAttempt.user_id == user_id,
            LoginAttempt.timestamp >= datetime.utcnow() - timedelta(hours=1)
        ).all()

        failed_count = sum(1 for attempt in recent_attempts if not attempt.success)
        if failed_count >= 3:
            risk_score += 30
            reasons.append(f"Multiple failed attempts ({failed_count})")

        # Check for unusual login time (simplified)
        current_hour = login_data.get('timestamp', datetime.utcnow()).hour
        if current_hour < 6 or current_hour > 22:  # Unusual hours
            risk_score += 10
            reasons.append("Unusual login time")

        return risk_score, reasons

    def _extract_features(self, user_id: int, login_data: Dict[str, Any], db: Session) -> Dict[str, Any]:
        timestamp = login_data.get('timestamp', datetime.utcnow())
        login_hour = timestamp.hour + timestamp.minute / 60

        # Count recent failed attempts
        recent_failed = db.query(LoginAttempt).filter(
            LoginAttempt.user_id == user_id,
            LoginAttempt.success == False,
            LoginAttempt.timestamp >= datetime.utcnow() - timedelta(hours=1)
        ).count()

        return {
            'login_hour': login_hour,
            'location_lat': login_data.get('location_lat', 0),
            'location_lon': login_data.get('location_lon', 0),
            'typing_speed': login_data.get('typing_speed', 0),
            'failed_attempts': recent_failed
        }

    def _check_device_trust(self, user_id: int, device_fingerprint: str, db: Session) -> bool:
        if not device_fingerprint:
            return False
        device = db.query(Device).filter(
            Device.user_id == user_id,
            Device.fingerprint == device_fingerprint
        ).first()
        return device.is_trusted if device else False

    def _check_travel_velocity(self, user_id: int, login_data: Dict[str, Any], db: Session) -> tuple:
        if not (login_data.get('location_lat') and login_data.get('location_lon')):
            return False, ""

        current_lat, current_lon = login_data['location_lat'], login_data['location_lon']
        current_time = login_data.get('timestamp', datetime.utcnow())

        # Get last successful login
        last_login = db.query(LoginAttempt).filter(
            LoginAttempt.user_id == user_id,
            LoginAttempt.success == True,
            LoginAttempt.location_lat.isnot(None)
        ).order_by(LoginAttempt.timestamp.desc()).first()

        if last_login:
            distance = calculate_distance(current_lat, current_lon, last_login.location_lat, last_login.location_lon)
            time_diff = (current_time - last_login.timestamp).total_seconds() / 3600
            velocity = calculate_travel_velocity(distance, time_diff)
            if velocity > settings.travel_velocity_threshold:
                return True, f"Impossible travel detected ({velocity:.1f} km/h)"

        return False, ""

    def _make_decision(self, risk_score: float) -> str:
        if risk_score < 30:
            return "allow"
        elif risk_score < 70:
            return "require_verification"
        else:
            return "block"