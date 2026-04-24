from sqlalchemy.orm import Session
from app.database.models import LoginAttempt, Device
from app.services.behavioral_learning import BehavioralLearningSystem
from app.ml.model import shared_anomaly_model
from app.utils.helpers import calculate_distance, calculate_travel_velocity
from app.config import settings
from datetime import datetime, timedelta
from typing import Dict, Any, List

class AnomalyDetectionEngine:
    def __init__(self):
        self.learning_system = BehavioralLearningSystem()
        self.ml_model = shared_anomaly_model

    def detect_anomalies(self, user_id: int, login_data: Dict[str, Any], db: Session) -> Dict[str, Any]:
        reasons = []
        attack_types = []

        # Rule engine: deterministic security checks get first say.
        rule_risk, rule_reasons, failed_count = self._rule_based_checks(user_id, login_data, db)
        reasons.extend(rule_reasons)

        # Device trust
        device_trust = self._check_device_trust(user_id, login_data.get('device_fingerprint'), db)
        device_risk = 0.0 if device_trust else 85.0
        if not device_trust:
            reasons.append("New device detected")
            attack_types.append("Suspicious Device")

        # Travel velocity
        travel_risk, travel_reason, travel_speed = self._check_travel_velocity(user_id, login_data, db)
        if travel_risk > 0:
            reasons.append(travel_reason)
            if travel_speed > 1000:
                attack_types.append("Impossible Travel")

        if failed_count >= settings.max_failed_attempts:
            attack_types.append("Brute Force")

        rule_risk = self._combine_rule_risk(rule_risk, device_risk, travel_risk)
        rule_based_high_risk = self._is_rule_based_high_risk(
            rule_risk=rule_risk,
            failed_count=failed_count,
            travel_speed=travel_speed,
        )

        if rule_based_high_risk:
            risk_score = 100.0
            decision = "block"
            level = "HIGH"
            confidence_score = 0.0
            explanation = self._build_explanation(reasons, attack_types, risk_score, confidence_score)
            return {
                "risk_score": risk_score,
                "level": level,
                "anomaly_score": 0.0,
                "ml_raw_score": 0.0,
                "confidence_score": confidence_score,
                "decision": decision,
                "reasons": reasons,
                "attack_types": sorted(set(attack_types)),
                "attack_type": self._primary_attack_type(attack_types),
                "explanation": explanation,
                "risk_components": {
                    "rule_risk": round(rule_risk, 2),
                    "ml_risk": 0.0,
                    "device_risk": round(device_risk, 2),
                    "travel_risk": round(travel_risk, 2),
                    "behavior_risk": 0.0,
                },
            }

        # ML-based anomaly score
        ml_features = self._extract_features(user_id, login_data, db)
        ml_result = self.ml_model.predict_anomaly_score(ml_features)
        ml_risk = ml_result["normalized_score"] * 100
        if ml_result["is_anomalous"]:
            contributor_labels = ", ".join(item["feature"] for item in ml_result["top_contributors"])
            reasons.append(f"ML anomaly detected from {contributor_labels}")
            attack_types.append("Behavioral Anomaly")

        # Behavioral confidence
        confidence_score = self.learning_system.calculate_confidence_score(user_id, login_data, db)
        behavior_risk = (1 - confidence_score) * 100

        risk_score = self._combine_final_risk(rule_risk, ml_risk, behavior_risk)

        decision = self._make_decision(risk_score)
        level = self._risk_level(risk_score)
        explanation = self._build_explanation(reasons, attack_types, risk_score, confidence_score)

        return {
            "risk_score": round(risk_score, 2),
            "level": level,
            "anomaly_score": ml_result["normalized_score"],
            "ml_raw_score": ml_result["raw_score"],
            "confidence_score": confidence_score,
            "decision": decision,
            "reasons": reasons,
            "attack_types": sorted(set(attack_types)),
            "attack_type": self._primary_attack_type(attack_types),
            "explanation": explanation,
            "risk_components": {
                "rule_risk": round(rule_risk, 2),
                "ml_risk": round(ml_risk, 2),
                "device_risk": round(device_risk, 2),
                "travel_risk": round(travel_risk, 2),
                "behavior_risk": round(behavior_risk, 2),
            },
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
            risk_score += min(100, failed_count * 12)
            reasons.append(f"Multiple failed attempts ({failed_count})")

        # Check for unusual login time (simplified)
        current_hour = login_data.get('timestamp', datetime.utcnow()).hour
        if current_hour < 6 or current_hour > 22:  # Unusual hours
            risk_score += 25
            reasons.append("Unusual login time")

        return min(100, risk_score), reasons, failed_count

    def _combine_rule_risk(self, behavior_rule_risk: float, device_risk: float, travel_risk: float) -> float:
        return min(
            100.0,
            max(
                behavior_rule_risk,
                device_risk * 0.6,
                travel_risk,
                behavior_rule_risk + (device_risk * 0.2) + (travel_risk * 0.3),
            ),
        )

    def _is_rule_based_high_risk(self, rule_risk: float, failed_count: int, travel_speed: float) -> bool:
        if failed_count >= settings.max_failed_attempts:
            return True
        if travel_speed >= settings.travel_velocity_threshold * 2:
            return True
        return rule_risk >= 95

    def _combine_final_risk(self, rule_risk: float, ml_risk: float, behavior_risk: float) -> float:
        final_score = (
            0.45 * rule_risk +
            0.35 * ml_risk +
            0.20 * behavior_risk
        )
        return min(100.0, max(0.0, final_score))

    def _extract_features(self, user_id: int, login_data: Dict[str, Any], db: Session) -> Dict[str, Any]:
        timestamp = login_data.get('timestamp', datetime.utcnow())
        login_hour = timestamp.hour + timestamp.minute / 60

        # Count recent failed attempts
        if login_data.get("failed_attempts_override") is not None:
            recent_failed = int(login_data["failed_attempts_override"])
        else:
            recent_failed = db.query(LoginAttempt).filter(
                LoginAttempt.user_id == user_id,
                LoginAttempt.success == False,
                LoginAttempt.timestamp >= datetime.utcnow() - timedelta(hours=1)
            ).count()

        total_attempts = db.query(LoginAttempt).filter(LoginAttempt.user_id == user_id).count()
        device_usage_count = 0
        if login_data.get("device_fingerprint"):
            device_usage_count = db.query(LoginAttempt).filter(
                LoginAttempt.user_id == user_id,
                LoginAttempt.device_fingerprint == login_data["device_fingerprint"]
            ).count()

        device_usage_frequency = device_usage_count / max(total_attempts, 1)

        recent_ip_failures = 0
        if login_data.get("ip_address"):
            recent_ip_failures = db.query(LoginAttempt).filter(
                LoginAttempt.ip_address == login_data["ip_address"],
                LoginAttempt.success == False,
                LoginAttempt.timestamp >= datetime.utcnow() - timedelta(hours=1)
            ).count()

        ip_risk_score = min(1.0, recent_ip_failures / max(settings.max_failed_attempts, 1))

        last_login = db.query(LoginAttempt).filter(
            LoginAttempt.user_id == user_id,
            LoginAttempt.success == True
        ).order_by(LoginAttempt.timestamp.desc()).first()

        login_interval_hours = 24.0
        geo_distance_from_last_login = 0.0
        if last_login:
            login_interval_hours = max(
                0.0,
                (timestamp - last_login.timestamp).total_seconds() / 3600,
            )
            if (
                login_data.get("location_lat") is not None
                and login_data.get("location_lon") is not None
                and last_login.location_lat is not None
                and last_login.location_lon is not None
            ):
                geo_distance_from_last_login = calculate_distance(
                    login_data["location_lat"],
                    login_data["location_lon"],
                    last_login.location_lat,
                    last_login.location_lon,
                )

        return {
            'login_hour': login_hour,
            'location_lat': login_data.get('location_lat', 0),
            'location_lon': login_data.get('location_lon', 0),
            'typing_speed': login_data.get('typing_speed', 0),
            'failed_attempts': recent_failed,
            'ip_risk_score': ip_risk_score,
            'device_usage_frequency': device_usage_frequency,
            'login_interval_hours': login_interval_hours,
            'geo_distance_from_last_login': geo_distance_from_last_login,
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
        if login_data.get('location_lat') is None or login_data.get('location_lon') is None:
            return 0.0, "", 0.0

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
                normalized_velocity = min(100.0, (velocity / settings.travel_velocity_threshold) * 100)
                return normalized_velocity, f"High travel speed detected ({velocity:.1f} km/h)", velocity

        return 0.0, "", 0.0

    def _make_decision(self, risk_score: float) -> str:
        if risk_score < 30:
            return "allow"
        elif risk_score < 70:
            return "require_verification"
        else:
            return "block"

    def _build_explanation(
        self,
        reasons: List[str],
        attack_types: List[str],
        risk_score: float,
        confidence_score: float,
    ) -> str:
        if not reasons:
            return (
                f"Low-risk login with confidence score {confidence_score:.2f}; "
                f"final risk score {risk_score:.1f}."
            )

        summary = ", ".join(reasons[:3])
        attack_label = f" Attack types: {', '.join(sorted(set(attack_types)))}." if attack_types else ""
        return (
            f"Risk score {risk_score:.1f} driven by {summary}. "
            f"Behavioral confidence {confidence_score:.2f}.{attack_label}"
        )

    def _risk_level(self, risk_score: float) -> str:
        if risk_score < 40:
            return "LOW"
        if risk_score < 70:
            return "MEDIUM"
        return "HIGH"

    def _primary_attack_type(self, attack_types: List[str]) -> str:
        if not attack_types:
            return "None"

        priority = ["Brute Force", "Impossible Travel", "Suspicious Device", "Behavioral Anomaly"]
        for item in priority:
            if item in attack_types:
                return item
        return attack_types[0]

    def retrain_from_login_attempts(self, db: Session, limit: int = 2000) -> bool:
        attempts = db.query(LoginAttempt).filter(
            LoginAttempt.success == True
        ).order_by(LoginAttempt.timestamp.asc()).limit(limit).all()

        training_data = []
        last_success_by_user: Dict[int, LoginAttempt] = {}
        device_counts: Dict[tuple, int] = {}

        for attempt in attempts:
            user_key = (attempt.user_id, attempt.device_fingerprint)
            device_counts[user_key] = device_counts.get(user_key, 0) + 1

            last_login = last_success_by_user.get(attempt.user_id)
            login_interval_hours = 24.0
            geo_distance_from_last_login = 0.0

            if last_login:
                login_interval_hours = max(
                    0.0,
                    (attempt.timestamp - last_login.timestamp).total_seconds() / 3600,
                )
                if (
                    attempt.location_lat is not None and attempt.location_lon is not None
                    and last_login.location_lat is not None and last_login.location_lon is not None
                ):
                    geo_distance_from_last_login = calculate_distance(
                        attempt.location_lat,
                        attempt.location_lon,
                        last_login.location_lat,
                        last_login.location_lon,
                    )

            user_attempt_count = sum(1 for item in attempts if item.user_id == attempt.user_id)
            training_data.append({
                "login_hour": attempt.timestamp.hour + attempt.timestamp.minute / 60,
                "location_lat": attempt.location_lat or 0,
                "location_lon": attempt.location_lon or 0,
                "typing_speed": attempt.typing_speed or 0,
                "failed_attempts": 0,
                "ip_risk_score": 0,
                "device_usage_frequency": device_counts[user_key] / max(user_attempt_count, 1),
                "login_interval_hours": login_interval_hours,
                "geo_distance_from_last_login": geo_distance_from_last_login,
            })
            last_success_by_user[attempt.user_id] = attempt

        return self.ml_model.train(training_data)
