from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from app.config import settings
from app.database.models import Device, LoginAttempt
from app.ml.model import FEATURE_COLUMNS, shared_anomaly_model
from app.utils.helpers import calculate_distance


class AnomalyDetectionEngine:
    def __init__(self) -> None:
        self.ml_model = shared_anomaly_model

    def detect_anomalies(self, user_id: int, login_data: Dict[str, Any], db: Session) -> Dict[str, Any]:
        risk_score = 0.0
        reasons: List[str] = []
        attack_types: List[str] = []
        timestamp = login_data.get("timestamp") or datetime.utcnow()

        failed_attempts = int(login_data.get("failed_attempts_override") or 0)
        if failed_attempts >= 3:
            risk_score += 20
            reasons.append("Multiple failed attempts")
            attack_types.append("brute_force")

        device_fingerprint = login_data.get("device_fingerprint")
        known_device = None
        if device_fingerprint:
            known_device = db.query(Device).filter(
                Device.user_id == user_id,
                Device.fingerprint == device_fingerprint,
            ).first()
        if not known_device:
            risk_score += 15
            reasons.append("Unrecognized device")

        if timestamp.hour < 6 or timestamp.hour > 23:
            risk_score += 10
            reasons.append("Unusual login time")

        geo_distance = self._geo_distance_from_last_success(user_id, login_data, timestamp, db)
        if geo_distance["velocity"] > settings.travel_velocity_threshold:
            risk_score += 30
            reasons.append("Impossible travel speed detected")
            attack_types.append("account_takeover")

        features = {
            "login_hour": timestamp.hour + timestamp.minute / 60,
            "location_lat": login_data.get("location_lat") or 0,
            "location_lon": login_data.get("location_lon") or 0,
            "typing_speed": login_data.get("typing_speed") or 0,
            "failed_attempts": failed_attempts,
            "ip_risk_score": 0,
            "device_usage_frequency": 0,
            "login_interval_hours": 0,
            "geo_distance_from_last_login": geo_distance["distance"],
        }
        ml_result = self.ml_model.predict_anomaly_score(features)
        if ml_result.get("is_anomalous"):
            risk_score += 25
            reasons.append("ML model flagged as anomalous")

        risk_score = min(100.0, risk_score)
        level = self._risk_level(risk_score)
        decision = self._decision(risk_score)
        unique_attack_types = list(dict.fromkeys(attack_types))

        return {
            "risk_score": risk_score,
            "level": level,
            "decision": decision,
            "reasons": reasons,
            "explanation": (
                f"Risk score {risk_score:.1f}/100. "
                f"Triggered signals: {', '.join(reasons) or 'none'}."
            ),
            "attack_type": unique_attack_types[0] if unique_attack_types else "None",
            "attack_types": unique_attack_types,
            "anomaly_score": float(ml_result.get("normalized_score", 0.0)),
            "confidence_score": max(0.0, min(1.0, 1.0 - (risk_score / 100.0))),
        }

    def retrain_from_login_attempts(self, db: Session) -> bool:
        attempts = db.query(LoginAttempt).filter(LoginAttempt.success == True).order_by(
            LoginAttempt.timestamp.asc()
        ).all()
        data: List[Dict[str, Any]] = []
        last_success_by_user: Dict[int, LoginAttempt] = {}

        for attempt in attempts:
            previous = last_success_by_user.get(attempt.user_id)
            interval_hours = 0.0
            distance = 0.0
            if previous:
                interval_hours = max(0.0, (attempt.timestamp - previous.timestamp).total_seconds() / 3600)
                if (
                    attempt.location_lat is not None
                    and attempt.location_lon is not None
                    and previous.location_lat is not None
                    and previous.location_lon is not None
                ):
                    distance = calculate_distance(
                        attempt.location_lat,
                        attempt.location_lon,
                        previous.location_lat,
                        previous.location_lon,
                    )

            row = {
                "login_hour": attempt.timestamp.hour + attempt.timestamp.minute / 60,
                "location_lat": attempt.location_lat or 0,
                "location_lon": attempt.location_lon or 0,
                "typing_speed": attempt.typing_speed or 0,
                "failed_attempts": 0,
                "ip_risk_score": 0,
                "device_usage_frequency": 0,
                "login_interval_hours": interval_hours,
                "geo_distance_from_last_login": distance,
            }
            data.append({column: row.get(column, 0) for column in FEATURE_COLUMNS})
            last_success_by_user[attempt.user_id] = attempt

        return bool(self.ml_model.train(data))

    def _geo_distance_from_last_success(
        self,
        user_id: int,
        login_data: Dict[str, Any],
        timestamp: datetime,
        db: Session,
    ) -> Dict[str, float]:
        current_lat = login_data.get("location_lat")
        current_lon = login_data.get("location_lon")
        if current_lat is None or current_lon is None:
            return {"distance": 0.0, "velocity": 0.0}

        last_login = db.query(LoginAttempt).filter(
            LoginAttempt.user_id == user_id,
            LoginAttempt.success == True,
            LoginAttempt.location_lat.isnot(None),
            LoginAttempt.location_lon.isnot(None),
        ).order_by(LoginAttempt.timestamp.desc()).first()

        if not last_login:
            return {"distance": 0.0, "velocity": 0.0}

        distance = calculate_distance(current_lat, current_lon, last_login.location_lat, last_login.location_lon)
        time_diff_hours = max((timestamp - last_login.timestamp).total_seconds() / 3600, 0.0)
        velocity = distance / time_diff_hours if time_diff_hours > 0 else float("inf")
        return {"distance": distance, "velocity": velocity}

    def _risk_level(self, risk_score: float) -> str:
        if risk_score >= 70:
            return "HIGH"
        if risk_score >= 40:
            return "MEDIUM"
        return "LOW"

    def _decision(self, risk_score: float) -> str:
        if risk_score >= 70:
            return "block"
        if risk_score >= 40:
            return "require_verification"
        return "allow"
