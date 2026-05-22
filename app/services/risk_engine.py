import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from statistics import mean, pstdev
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.config import settings
from app.database.models import (
    AlertRecord,
    BehaviorTelemetry,
    Device,
    GeoLoginHistory,
    LoginAttempt,
    SessionRiskSnapshot,
    UserProfile,
)
from app.services.threat_intelligence import ThreatIntelligenceService


class AdaptiveRiskEngine:
    def __init__(self) -> None:
        self.threat_intel = ThreatIntelligenceService()

    def record_behavior_telemetry(
        self,
        user_id: int,
        session_id: str,
        db: Session,
        telemetry: Dict[str, Any],
    ) -> Dict[str, Any]:
        anomaly_score = self._behavior_anomaly_score(user_id, telemetry, db)
        trust_score = max(0.0, 100.0 - anomaly_score)
        record = BehaviorTelemetry(
            user_id=user_id,
            session_id=session_id,
            device_fingerprint=telemetry.get("device_fingerprint"),
            ip_address=telemetry.get("ip_address"),
            page_path=telemetry.get("page_path"),
            typing_speed=telemetry.get("typing_speed"),
            typing_variance=telemetry.get("typing_variance"),
            key_hold_mean=telemetry.get("key_hold_mean"),
            key_flight_mean=telemetry.get("key_flight_mean"),
            correction_rate=telemetry.get("correction_rate"),
            mouse_velocity_mean=telemetry.get("mouse_velocity_mean"),
            mouse_velocity_std=telemetry.get("mouse_velocity_std"),
            mouse_idle_ratio=telemetry.get("mouse_idle_ratio"),
            scroll_depth=telemetry.get("scroll_depth"),
            scroll_velocity_mean=telemetry.get("scroll_velocity_mean"),
            replay_event_count=int(telemetry.get("replay_event_count") or 0),
            replay_anomaly_score=float(telemetry.get("replay_anomaly_score") or 0.0),
            focus_change_count=int(telemetry.get("focus_change_count") or 0),
            active_seconds=float(telemetry.get("active_seconds") or 0.0),
            raw_features=json.dumps(telemetry, default=str),
            anomaly_score=anomaly_score,
            trust_score=trust_score,
        )
        db.add(record)
        db.commit()

        snapshot = self.score_session(user_id, session_id, db, telemetry=telemetry)
        return {
            "telemetry_id": record.id,
            "behavior_anomaly_score": anomaly_score,
            "trust_score": trust_score,
            **snapshot,
        }

    def score_login_context(
        self,
        user_id: int,
        db: Session,
        ip_address: str,
        device_fingerprint: Optional[str] = None,
        typing_speed: Optional[float] = None,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        risk = 0.0
        reasons: list[str] = []
        confidence_parts: list[float] = []

        device = None
        if device_fingerprint:
            device = db.query(Device).filter(
                Device.user_id == user_id,
                Device.fingerprint == device_fingerprint,
            ).first()
        if not device:
            risk += 18
            reasons.append("Unknown device")
        elif device.state == "blocked":
            risk += 80
            reasons.append("Blocked device")
        elif device.state == "suspicious":
            risk += 35
            reasons.append("Suspicious device state")
        elif device.is_trusted:
            risk -= 12
            confidence_parts.append(0.9)

        profile = db.query(UserProfile).filter(UserProfile.user_id == user_id).first()
        if typing_speed is not None and profile and profile.typing_speed_mean is not None:
            typing_std = max(profile.typing_speed_std or 1.0, 1.0)
            z_score = abs(typing_speed - profile.typing_speed_mean) / typing_std
            if z_score > 2.5:
                risk += min(25.0, z_score * 5)
                reasons.append("Typing biometrics drift")
            confidence_parts.append(min(1.0, max(0.0, 1.0 - (z_score / 6.0))))

        threat = self.threat_intel.check_ip(ip_address, db=db, user_agent=user_agent)
        threat_score = float(threat.get("risk_score") or 0.0)
        if threat_score >= 40:
            risk += threat_score * 0.45
            reasons.append(f"Threat intelligence verdict: {threat.get('verdict')}")

        geo = self._geo_risk(user_id, latitude, longitude, db)
        if geo["impossible_travel"]:
            risk += 35
            reasons.append("Impossible travel")
        elif geo["distance_km"] > 1200:
            risk += 12
            reasons.append("Large location change")

        historical = self._historical_risk(user_id, ip_address, db)
        risk += historical["risk_delta"]
        reasons.extend(historical["reasons"])
        confidence_parts.append(historical["confidence"])

        risk_score = max(0.0, min(100.0, risk))
        fraud_probability = round(risk_score / 100.0, 4)
        confidence = round(mean(confidence_parts), 4) if confidence_parts else 0.55
        decision = self._decision(risk_score)
        return {
            "risk_score": round(risk_score, 2),
            "trust_score": round(max(0.0, 100.0 - risk_score), 2),
            "fraud_probability": fraud_probability,
            "confidence": confidence,
            "decision": decision,
            "recommended_action": self._recommended_action(risk_score),
            "reasons": list(dict.fromkeys(reasons)),
            "threat_intelligence": threat,
            "geo": geo,
        }

    def score_session(
        self,
        user_id: int,
        session_id: str,
        db: Session,
        telemetry: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        since = datetime.utcnow() - timedelta(minutes=30)
        recent = db.query(BehaviorTelemetry).filter(
            BehaviorTelemetry.user_id == user_id,
            BehaviorTelemetry.session_id == session_id,
            BehaviorTelemetry.created_at >= since,
        ).order_by(BehaviorTelemetry.created_at.desc()).limit(20).all()

        anomaly_values = [item.anomaly_score or 0.0 for item in recent]
        latest = recent[0] if recent else None
        behavior_risk = mean(anomaly_values) if anomaly_values else self._behavior_anomaly_score(user_id, telemetry or {}, db)
        focus_risk = min(12.0, float((telemetry or {}).get("focus_change_count") or (latest.focus_change_count if latest else 0)) * 1.5)
        idle_ratio = float((telemetry or {}).get("mouse_idle_ratio") or (latest.mouse_idle_ratio if latest else 0) or 0)
        idle_risk = 10.0 if idle_ratio > 0.85 else 0.0

        risk_score = max(0.0, min(100.0, behavior_risk + focus_risk + idle_risk))
        trust_score = max(0.0, 100.0 - risk_score)
        reasons = []
        if behavior_risk >= 30:
            reasons.append("Behavioral biometrics drift")
        if focus_risk:
            reasons.append("Frequent focus changes")
        if idle_risk:
            reasons.append("High idle ratio")

        snapshot = SessionRiskSnapshot(
            user_id=user_id,
            session_id=session_id,
            device_fingerprint=(telemetry or {}).get("device_fingerprint") or (latest.device_fingerprint if latest else None),
            ip_address=(telemetry or {}).get("ip_address") or (latest.ip_address if latest else None),
            risk_score=risk_score,
            trust_score=trust_score,
            fraud_probability=risk_score / 100.0,
            confidence=0.7 if recent else 0.45,
            decision=self._decision(risk_score),
            reasons=json.dumps(reasons),
            recommended_action=self._recommended_action(risk_score),
        )
        db.add(snapshot)
        db.commit()
        return {
            "session_risk_score": round(risk_score, 2),
            "session_trust_score": round(trust_score, 2),
            "fraud_probability": round(risk_score / 100.0, 4),
            "decision": snapshot.decision,
            "recommended_action": snapshot.recommended_action,
            "reasons": reasons,
        }

    def dashboard(self, db: Session) -> Dict[str, Any]:
        since = datetime.utcnow() - timedelta(hours=24)
        attempts = db.query(LoginAttempt).filter(LoginAttempt.timestamp >= since).order_by(LoginAttempt.timestamp.asc()).all()
        snapshots = db.query(SessionRiskSnapshot).filter(SessionRiskSnapshot.created_at >= since).order_by(SessionRiskSnapshot.created_at.asc()).all()
        telemetry = db.query(BehaviorTelemetry).filter(BehaviorTelemetry.created_at >= since).order_by(BehaviorTelemetry.created_at.asc()).all()
        alerts = db.query(AlertRecord).filter(AlertRecord.created_at >= since).order_by(AlertRecord.created_at.desc()).limit(25).all()

        country_counts = Counter(attempt.country or "Unknown" for attempt in attempts if (attempt.risk_score or 0) >= 40)
        timeline_groups: dict[str, list[float]] = defaultdict(list)
        for attempt in attempts:
            timeline_groups[attempt.timestamp.strftime("%H:00")].append(attempt.risk_score or 0.0)
        trust_groups: dict[str, list[float]] = defaultdict(list)
        for snapshot in snapshots:
            trust_groups[snapshot.created_at.strftime("%H:00")].append(snapshot.trust_score or 0.0)

        return {
            "attack_monitoring": {
                "total_attempts": len(attempts),
                "blocked": sum(1 for item in attempts if item.decision == "block"),
                "mfa_triggered": sum(1 for item in attempts if item.mfa_required),
                "high_risk": sum(1 for item in attempts if (item.risk_score or 0) >= 70),
            },
            "suspicious_sessions": [
                {
                    "session_id": item.session_id,
                    "user_id": item.user_id,
                    "risk_score": round(item.risk_score or 0, 2),
                    "trust_score": round(item.trust_score or 0, 2),
                    "decision": item.decision,
                    "reasons": json.loads(item.reasons or "[]"),
                    "time": item.created_at,
                }
                for item in sorted(snapshots, key=lambda row: row.risk_score or 0, reverse=True)[:12]
            ],
            "risk_analytics": {
                "average_risk": round(mean([item.risk_score or 0 for item in attempts]), 2) if attempts else 0.0,
                "average_session_trust": round(mean([item.trust_score or 100 for item in snapshots]), 2) if snapshots else 100.0,
                "fraud_probability": round(mean([item.fraud_probability or 0 for item in snapshots]), 4) if snapshots else 0.0,
            },
            "login_heatmap": [
                {"country": country, "attempts": count}
                for country, count in country_counts.most_common(10)
            ],
            "anomaly_timeline": [
                {"time": label, "risk": round(mean(scores), 2)}
                for label, scores in timeline_groups.items()
            ],
            "trust_score_trends": [
                {"time": label, "trust": round(mean(scores), 2)}
                for label, scores in trust_groups.items()
            ],
            "behavioral_biometrics": {
                "events": len(telemetry),
                "average_anomaly": round(mean([item.anomaly_score or 0 for item in telemetry]), 2) if telemetry else 0.0,
                "average_trust": round(mean([item.trust_score or 100 for item in telemetry]), 2) if telemetry else 100.0,
            },
            "alerts": [
                {
                    "id": alert.id,
                    "severity": alert.severity,
                    "message": alert.message,
                    "attack_type": alert.attack_type,
                    "time": alert.created_at,
                }
                for alert in alerts
            ],
            "enterprise_capabilities": self.integration_status(),
            "ml_strategy": {
                "active": "Isolation Forest + rules-based adaptive risk",
                "upgrade_ready": ["autoencoder", "xgboost", "sequence_login_model"],
                "signals": [
                    "typing_rhythm",
                    "mouse_movement",
                    "scroll_behavior",
                    "session_replay_anomaly",
                    "device_trust",
                    "threat_intelligence",
                    "geo_velocity",
                ],
            },
        }

    def integration_status(self) -> Dict[str, Any]:
        return {
            "threat_intelligence": [
                {"name": "IPQualityScore", "configured": bool(settings.ipqualityscore_api_key), "capability": "VPN/proxy/TOR/bot and fraud score"},
                {"name": "AbuseIPDB", "configured": bool(settings.abuseipdb_api_key), "capability": "reported malicious IP checks"},
                {"name": "MaxMind GeoIP2", "configured": bool(settings.maxmind_license_key or settings.maxmind_geoip_db_path), "capability": "accurate geolocation and ASN"},
                {"name": "VirusTotal", "configured": bool(settings.virustotal_api_key), "capability": "advanced IP/domain enrichment"},
                {"name": "Have I Been Pwned", "configured": True, "capability": "k-anonymous breached password checks"},
            ],
            "authentication_mfa": [
                {"name": "Authy", "configured": bool(settings.authy_api_key), "capability": "production push/SMS MFA"},
                {"name": "Firebase Authentication", "configured": bool(settings.firebase_project_id), "capability": "OTP and social login provider"},
                {"name": "Clerk", "configured": bool(settings.clerk_publishable_key), "capability": "modern auth, devices, sessions"},
                {"name": "Auth0", "configured": bool(settings.auth0_domain), "capability": "enterprise adaptive authentication reference"},
            ],
            "notifications": [
                {"name": "SendGrid", "configured": bool(settings.sendgrid_api_key), "capability": "security email and OTP delivery"},
                {"name": "Resend", "configured": bool(settings.resend_api_key), "capability": "transactional email"},
                {"name": "Brevo", "configured": bool(settings.brevo_api_key), "capability": "transactional email"},
                {"name": "SMTP", "configured": bool(settings.smtp_host), "capability": "provider-neutral mail fallback"},
            ],
            "device_behavior": [
                {"name": "FingerprintJS", "configured": bool(settings.fingerprintjs_public_key), "capability": "professional browser/device fingerprinting"},
                {"name": "rrweb", "configured": settings.rrweb_enabled, "capability": "session replay anomaly metadata"},
                {"name": "Leaflet", "configured": True, "capability": "free login location maps"},
                {"name": "Mapbox", "configured": bool(settings.mapbox_access_token), "capability": "premium live attack map option"},
            ],
        }

    def _behavior_anomaly_score(self, user_id: int, telemetry: Dict[str, Any], db: Session) -> float:
        recent = db.query(BehaviorTelemetry).filter(
            BehaviorTelemetry.user_id == user_id,
        ).order_by(BehaviorTelemetry.created_at.desc()).limit(50).all()
        score = 0.0

        for field, weight in [
            ("typing_speed", 12.0),
            ("typing_variance", 10.0),
            ("key_hold_mean", 8.0),
            ("key_flight_mean", 8.0),
            ("mouse_velocity_mean", 10.0),
            ("mouse_idle_ratio", 8.0),
            ("scroll_depth", 6.0),
            ("scroll_velocity_mean", 8.0),
        ]:
            value = telemetry.get(field)
            baseline_values = [getattr(item, field) for item in recent if getattr(item, field) is not None]
            if value is None or len(baseline_values) < 5:
                continue
            spread = max(pstdev(baseline_values), 1.0)
            delta = abs(float(value) - mean(baseline_values)) / spread
            if delta > 2:
                score += min(weight, delta * (weight / 3.0))

        correction_rate = float(telemetry.get("correction_rate") or 0.0)
        if correction_rate > 0.35:
            score += 10
        if float(telemetry.get("mouse_idle_ratio") or 0.0) > 0.9:
            score += 8
        if float(telemetry.get("replay_anomaly_score") or 0.0) > 40:
            score += min(18.0, float(telemetry.get("replay_anomaly_score") or 0.0) * 0.25)
        if int(telemetry.get("replay_event_count") or 0) > 3000:
            score += 6
        return round(max(0.0, min(100.0, score)), 2)

    def _geo_risk(self, user_id: int, latitude: Optional[float], longitude: Optional[float], db: Session) -> Dict[str, Any]:
        if latitude is None or longitude is None:
            return {"distance_km": 0.0, "velocity_kmh": 0.0, "impossible_travel": False}
        previous = db.query(GeoLoginHistory).filter(
            GeoLoginHistory.user_id == user_id,
            GeoLoginHistory.latitude.isnot(None),
            GeoLoginHistory.longitude.isnot(None),
        ).order_by(GeoLoginHistory.created_at.desc()).first()
        if not previous:
            return {"distance_km": 0.0, "velocity_kmh": 0.0, "impossible_travel": False}
        from app.utils.helpers import calculate_distance

        distance = calculate_distance(latitude, longitude, previous.latitude, previous.longitude)
        hours = max((datetime.utcnow() - previous.created_at).total_seconds() / 3600, 0.01)
        velocity = distance / hours
        return {
            "distance_km": round(distance, 2),
            "velocity_kmh": round(velocity, 2),
            "impossible_travel": velocity > settings.travel_velocity_threshold,
        }

    def _historical_risk(self, user_id: int, ip_address: str, db: Session) -> Dict[str, Any]:
        recent = db.query(LoginAttempt).filter(
            LoginAttempt.user_id == user_id,
        ).order_by(LoginAttempt.timestamp.desc()).limit(50).all()
        risk_delta = 0.0
        reasons = []
        if recent and ip_address not in {item.ip_address for item in recent if item.success}:
            risk_delta += 12
            reasons.append("IP not present in user history")
        failed_recent = sum(1 for item in recent[:10] if not item.success)
        if failed_recent >= 3:
            risk_delta += 18
            reasons.append("Recent failed login burst")
        confidence = min(0.95, 0.35 + (len(recent) / 100))
        return {"risk_delta": risk_delta, "reasons": reasons, "confidence": confidence}

    def _decision(self, risk_score: float) -> str:
        if risk_score >= settings.session_critical_risk_threshold:
            return "block"
        if risk_score >= settings.session_high_risk_threshold:
            return "require_verification"
        if risk_score >= settings.medium_risk_threshold:
            return "monitor"
        return "allow"

    def _recommended_action(self, risk_score: float) -> str:
        if risk_score >= settings.session_critical_risk_threshold:
            return "terminate_session"
        if risk_score >= settings.session_high_risk_threshold:
            return "step_up_mfa"
        if risk_score >= settings.medium_risk_threshold:
            return "increase_monitoring"
        return "allow"
