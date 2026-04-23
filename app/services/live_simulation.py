import json
import random
from datetime import datetime, timedelta
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from app.database.models import AlertRecord, Device, LoginAttempt, User
from app.utils.helpers import hash_password


SIM_USERS = [
    {"username": "alex.chen", "home": (40.7128, -74.0060)},
    {"username": "sarah.jones", "home": (51.5074, -0.1278)},
    {"username": "raj.patel", "home": (19.0760, 72.8777)},
    {"username": "emma.wilson", "home": (43.6532, -79.3832)},
]

DEVICE_MAP = {
    "known_windows": "Chrome / Windows 11",
    "known_mac": "Safari / macOS 14",
    "known_mobile": "Safari / iOS 17",
    "unknown_device": "Unknown / Untrusted Device",
}


class LiveSimulationService:
    def ensure_demo_users(self, db: Session) -> List[User]:
        users: List[User] = []
        for seed in SIM_USERS:
            user = db.query(User).filter(User.username == seed["username"]).first()
            if not user:
                user = User(
                    username=seed["username"],
                    hashed_password=hash_password("StrongPass123!"),
                )
                db.add(user)
                db.flush()
            users.append(user)
        db.commit()
        return users

    def generate_live_attempts(self, db: Session, count: int = 5) -> List[Dict[str, Any]]:
        users = self.ensure_demo_users(db)
        generated_attempts: List[Dict[str, Any]] = []

        for _ in range(count):
            user = random.choice(users)
            severity = random.choices(
                population=["low", "medium", "high", "critical"],
                weights=[0.4, 0.3, 0.2, 0.1],
                k=1,
            )[0]
            generated_attempts.append(self._create_attempt_for_severity(user, severity, db))

        db.commit()
        return generated_attempts

    def _create_attempt_for_severity(self, user: User, severity: str, db: Session) -> Dict[str, Any]:
        seed = next(item for item in SIM_USERS if item["username"] == user.username)
        base_lat, base_lon = seed["home"]
        timestamp = datetime.utcnow() - timedelta(seconds=random.randint(0, 45))

        config = self._severity_config(severity, base_lat, base_lon)
        attack_type = config["attack_type"]
        risk_score = config["risk_score"]
        decision = config["decision"]
        success = config["success"]
        device_fingerprint = f"{user.username}:{config['device_fingerprint']}"

        attempt = LoginAttempt(
            user_id=user.id,
            timestamp=timestamp,
            ip_address=config["ip_address"],
            location_lat=config["location_lat"],
            location_lon=config["location_lon"],
            device_fingerprint=device_fingerprint,
            typing_speed=config["typing_speed"],
            keystroke_timing=json.dumps(config["keystroke_timing"]),
            success=success,
            risk_score=risk_score,
            decision=decision,
            reasons=json.dumps(config["reasons"]),
            anomaly_score=round(risk_score / 100, 3),
            confidence_score=round(max(0.05, 1 - (risk_score / 120)), 3),
        )
        db.add(attempt)
        db.flush()

        device = db.query(Device).filter(
            Device.user_id == user.id,
            Device.fingerprint == device_fingerprint,
        ).first()
        if not device:
            device = Device(user_id=user.id, fingerprint=device_fingerprint)
            db.add(device)

        device.last_seen = timestamp
        device.is_trusted = severity == "low"

        if severity == "critical":
            user.is_locked = True

        if severity in {"medium", "high", "critical"}:
            alert = AlertRecord(
                user_id=user.id,
                login_attempt_id=attempt.id,
                severity=severity,
                message=config["alert_message"],
                attack_type=attack_type,
                resolved=severity == "critical",
                requires_manual_action=severity in {"medium", "high"},
                auto_action="block" if severity == "critical" else None,
                resolved_at=timestamp if severity == "critical" else None,
            )
            db.add(alert)

        return {
            "id": attempt.id,
            "username": user.username,
            "severity": severity,
            "risk_score": risk_score,
            "decision": decision,
        }

    def _severity_config(self, severity: str, base_lat: float, base_lon: float) -> Dict[str, Any]:
        if severity == "low":
            return {
                "risk_score": random.randint(8, 35),
                "decision": "allow",
                "success": True,
                "attack_type": "None",
                "reasons": ["Known device", "Expected login pattern"],
                "location_lat": round(base_lat + random.uniform(-0.05, 0.05), 4),
                "location_lon": round(base_lon + random.uniform(-0.05, 0.05), 4),
                "device_fingerprint": random.choice(["known_windows", "known_mac", "known_mobile"]),
                "typing_speed": round(random.uniform(32, 55), 2),
                "keystroke_timing": [round(random.uniform(0.12, 0.28), 2) for _ in range(6)],
                "ip_address": f"10.0.0.{random.randint(2, 250)}",
                "alert_message": "",
            }
        if severity == "medium":
            return {
                "risk_score": random.randint(45, 65),
                "decision": "require_verification",
                "success": True,
                "attack_type": "Suspicious Device",
                "reasons": ["New device detected", "Unusual login time"],
                "location_lat": round(base_lat + random.uniform(-0.2, 0.2), 4),
                "location_lon": round(base_lon + random.uniform(-0.2, 0.2), 4),
                "device_fingerprint": "unknown_device",
                "typing_speed": round(random.uniform(20, 32), 2),
                "keystroke_timing": [round(random.uniform(0.2, 0.45), 2) for _ in range(6)],
                "ip_address": f"172.16.0.{random.randint(2, 250)}",
                "alert_message": "Medium risk login detected. Manual review available.",
            }
        if severity == "high":
            return {
                "risk_score": random.randint(72, 88),
                "decision": "require_verification",
                "success": False,
                "attack_type": "Impossible Travel",
                "reasons": ["High travel speed detected", "Multiple failed attempts", "New device detected"],
                "location_lat": round(base_lat + random.uniform(15, 30), 4),
                "location_lon": round(base_lon + random.uniform(15, 30), 4),
                "device_fingerprint": "unknown_device",
                "typing_speed": round(random.uniform(12, 24), 2),
                "keystroke_timing": [round(random.uniform(0.05, 0.14), 2) for _ in range(6)],
                "ip_address": f"203.0.113.{random.randint(2, 250)}",
                "alert_message": "High risk login detected. Manual block is recommended.",
            }
        return {
            "risk_score": random.randint(91, 99),
            "decision": "block",
            "success": False,
            "attack_type": "Brute Force",
            "reasons": ["Multiple failed attempts", "High travel speed detected", "New device detected"],
            "location_lat": round(base_lat + random.uniform(25, 45), 4),
            "location_lon": round(base_lon + random.uniform(25, 45), 4),
            "device_fingerprint": "unknown_device",
            "typing_speed": round(random.uniform(6, 18), 2),
            "keystroke_timing": [round(random.uniform(0.03, 0.1), 2) for _ in range(6)],
            "ip_address": f"198.51.100.{random.randint(2, 250)}",
            "alert_message": "Critical attack detected. User auto-blocked.",
        }
