import ipaddress
from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.config import settings
from app.database.models import GeoLoginHistory, IPReputation, LoginAttempt, SuspiciousIP, TrustedIP
from app.utils.helpers import calculate_distance


class IPIntelligenceService:
    def assess(
        self,
        user_id: int,
        ip_address: str,
        db: Session,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        timestamp: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        timestamp = timestamp or datetime.utcnow()
        risk_score = 0.0
        reasons: list[str] = []

        profile = self._get_or_create_reputation(ip_address, db)
        trusted_ip = db.query(TrustedIP).filter(
            TrustedIP.user_id == user_id,
            TrustedIP.ip_address == ip_address,
        ).first()
        if trusted_ip:
            trusted_ip.last_seen_at = timestamp
            risk_score -= 10

        suspicious_ip = db.query(SuspiciousIP).filter(SuspiciousIP.ip_address == ip_address).first()
        if suspicious_ip and (not suspicious_ip.blocked_until or suspicious_ip.blocked_until > timestamp):
            risk_score += 35
            reasons.append(suspicious_ip.reason or "IP appears on the suspicious IP list")

        if profile.is_vpn:
            risk_score += 15
            reasons.append("VPN endpoint detected")
        if profile.is_proxy:
            risk_score += 15
            reasons.append("Proxy endpoint detected")
        if profile.is_tor:
            risk_score += 30
            reasons.append("TOR exit node detected")

        window_start = timestamp - timedelta(minutes=10)
        recent_ip_attempts = db.query(LoginAttempt).filter(
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.timestamp >= window_start,
        ).all()
        failed_from_ip = sum(1 for item in recent_ip_attempts if not item.success)
        if failed_from_ip >= 5:
            risk_score += 25
            reasons.append("Brute-force pattern from this IP")

        unique_users = {item.user_id for item in recent_ip_attempts if item.user_id}
        if len(unique_users) >= 4:
            risk_score += 20
            reasons.append("Multiple users targeted from the same IP")

        recent_user_ips = db.query(LoginAttempt).filter(
            LoginAttempt.user_id == user_id,
            LoginAttempt.timestamp >= timestamp - timedelta(minutes=15),
        ).all()
        unique_recent_ips = {item.ip_address for item in recent_user_ips if item.ip_address}
        if len(unique_recent_ips) >= 4 and ip_address not in unique_recent_ips:
            risk_score += 20
            reasons.append("Rapid IP switching detected")

        geo = self._geo_velocity(user_id, db, latitude, longitude, timestamp)
        if geo["impossible_travel"]:
            risk_score += 30
            reasons.append("Impossible travel detected")

        profile.risk_score = max(profile.risk_score or 0.0, min(100.0, risk_score))
        profile.last_checked_at = timestamp
        db.commit()

        return {
            "ip_address": ip_address,
            "asn": profile.asn,
            "provider": profile.provider,
            "country": profile.country,
            "city": profile.city,
            "is_vpn": profile.is_vpn,
            "is_proxy": profile.is_proxy,
            "is_tor": profile.is_tor,
            "risk_score": max(0.0, min(100.0, risk_score)),
            "reasons": reasons,
            "distance_from_previous_km": geo["distance"],
            "velocity_kmh": geo["velocity"],
            "impossible_travel": geo["impossible_travel"],
            "failed_from_ip": failed_from_ip,
            "unique_users_from_ip": len(unique_users),
        }

    def record_geo_history(
        self,
        user_id: int,
        login_attempt_id: int,
        ip_address: str,
        intelligence: Dict[str, Any],
        db: Session,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
    ) -> None:
        history = GeoLoginHistory(
            user_id=user_id,
            login_attempt_id=login_attempt_id,
            ip_address=ip_address,
            country=intelligence.get("country"),
            city=intelligence.get("city"),
            latitude=latitude,
            longitude=longitude,
            asn=intelligence.get("asn"),
            provider=intelligence.get("provider"),
            distance_from_previous_km=intelligence.get("distance_from_previous_km") or 0.0,
            velocity_kmh=intelligence.get("velocity_kmh") or 0.0,
            impossible_travel=bool(intelligence.get("impossible_travel")),
        )
        db.add(history)
        db.commit()

    def failed_login_heatmap(self, db: Session, hours: int = 24) -> list[dict[str, Any]]:
        since = datetime.utcnow() - timedelta(hours=hours)
        attempts = db.query(LoginAttempt).filter(
            LoginAttempt.timestamp >= since,
            LoginAttempt.success == False,
        ).all()
        counts = Counter((item.country or "Unknown", item.city or "Unknown") for item in attempts)
        return [
            {"country": country, "city": city, "failed_attempts": count}
            for (country, city), count in counts.most_common(25)
        ]

    def _get_or_create_reputation(self, ip_address: str, db: Session) -> IPReputation:
        profile = db.query(IPReputation).filter(IPReputation.ip_address == ip_address).first()
        if profile:
            return profile

        parsed = self._parse_ip(ip_address)
        is_private = bool(parsed and (parsed.is_private or parsed.is_loopback))
        profile = IPReputation(
            ip_address=ip_address,
            asn="local" if is_private else None,
            provider="Local network" if is_private else None,
            country="Local" if is_private else None,
            city="Local" if is_private else None,
            risk_score=0.0,
            source="local_heuristic",
        )
        db.add(profile)
        db.commit()
        db.refresh(profile)
        return profile

    def _geo_velocity(
        self,
        user_id: int,
        db: Session,
        latitude: Optional[float],
        longitude: Optional[float],
        timestamp: datetime,
    ) -> Dict[str, float | bool]:
        if latitude is None or longitude is None:
            return {"distance": 0.0, "velocity": 0.0, "impossible_travel": False}

        previous = db.query(GeoLoginHistory).filter(
            GeoLoginHistory.user_id == user_id,
            GeoLoginHistory.latitude.isnot(None),
            GeoLoginHistory.longitude.isnot(None),
        ).order_by(GeoLoginHistory.created_at.desc()).first()
        if not previous:
            return {"distance": 0.0, "velocity": 0.0, "impossible_travel": False}

        distance = calculate_distance(latitude, longitude, previous.latitude, previous.longitude)
        hours = max((timestamp - previous.created_at).total_seconds() / 3600, 0.0)
        velocity = distance / hours if hours > 0 else float("inf")
        return {
            "distance": round(distance, 2),
            "velocity": round(velocity, 2) if velocity != float("inf") else velocity,
            "impossible_travel": velocity > settings.travel_velocity_threshold,
        }

    def _parse_ip(self, ip_address: str):
        try:
            return ipaddress.ip_address(ip_address)
        except ValueError:
            return None
