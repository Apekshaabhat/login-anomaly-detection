import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.config import settings
from app.database.models import ThreatIntelRecord


class ThreatIntelligenceService:
    def check_ip(self, ip_address: str, db: Optional[Session] = None, user_agent: Optional[str] = None) -> Dict[str, Any]:
        cached = self._cached("ip", ip_address, db)
        if cached:
            return cached

        providers = []
        if settings.abuseipdb_api_key:
            providers.append(self._check_abuseipdb(ip_address))
        if settings.ipqualityscore_api_key:
            providers.append(self._check_ipqualityscore(ip_address, user_agent=user_agent))
        if settings.virustotal_api_key:
            providers.append(self._check_virustotal_ip(ip_address))
        geo = self._maxmind_context(ip_address)
        if geo:
            providers.append(geo)
        if not providers:
            providers.append({
                "provider": "local",
                "risk_score": 0.0,
                "verdict": "not_configured",
                "summary": "Threat intelligence API keys are not configured; using local heuristics only.",
                "raw": {},
            })

        risk_score = max(item["risk_score"] for item in providers)
        verdict = self._verdict(risk_score)
        summary = "; ".join(item["summary"] for item in providers if item.get("summary"))
        result = {
            "indicator": ip_address,
            "indicator_type": "ip",
            "risk_score": risk_score,
            "verdict": verdict,
            "providers": providers,
            "summary": summary,
            "checked_at": datetime.utcnow().isoformat(),
        }
        self._store("ip", ip_address, "aggregate", result, db)
        return result

    def check_pwned_password(self, password: str, db: Optional[Session] = None) -> Dict[str, Any]:
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        cached = self._cached("password_hash_prefix", prefix, db)

        found_count = 0
        provider_status = "live"
        if cached and cached.get("raw_suffixes"):
            suffixes = cached["raw_suffixes"]
            found_count = int(suffixes.get(suffix, 0))
            provider_status = "cache"
        else:
            suffixes = self._fetch_pwned_password_range(prefix)
            if not suffixes:
                return {
                    "breached": False,
                    "breach_count": 0,
                    "risk_score": 0.0,
                    "verdict": "unknown",
                    "provider": "haveibeenpwned",
                    "provider_status": "unavailable",
                    "attribution": "Have I Been Pwned Pwned Passwords",
                }
            found_count = int(suffixes.get(suffix, 0))
            self._store(
                "password_hash_prefix",
                prefix,
                "haveibeenpwned",
                {
                    "indicator": prefix,
                    "indicator_type": "password_hash_prefix",
                    "risk_score": 100.0 if found_count else 0.0,
                    "verdict": "compromised" if found_count else "clear",
                    "summary": "Pwned Passwords k-anonymity range response cached by SHA-1 prefix.",
                    "raw_suffixes": suffixes,
                },
                db,
            )

        return {
            "breached": found_count > 0,
            "breach_count": found_count,
            "risk_score": 100.0 if found_count else 0.0,
            "verdict": "compromised" if found_count else "clear",
            "provider": "haveibeenpwned",
            "provider_status": provider_status,
            "attribution": "Have I Been Pwned Pwned Passwords",
        }

    def _check_abuseipdb(self, ip_address: str) -> Dict[str, Any]:
        params = urllib.parse.urlencode({"ipAddress": ip_address, "maxAgeInDays": "90", "verbose": ""})
        request = urllib.request.Request(
            f"https://api.abuseipdb.com/api/v2/check?{params}",
            headers={"Key": settings.abuseipdb_api_key or "", "Accept": "application/json"},
            method="GET",
        )
        data = self._json_request(request)
        payload = data.get("data", {})
        score = float(payload.get("abuseConfidenceScore") or 0.0)
        return {
            "provider": "abuseipdb",
            "risk_score": score,
            "verdict": self._verdict(score),
            "summary": f"Abuse confidence {score:.0f}; reports {payload.get('totalReports', 0)}.",
            "raw": payload,
        }

    def _check_ipqualityscore(self, ip_address: str, user_agent: Optional[str] = None) -> Dict[str, Any]:
        encoded_ip = urllib.parse.quote(ip_address, safe="")
        query = {"strictness": "1", "allow_public_access_points": "true"}
        if user_agent:
            query["user_agent"] = user_agent
        url = f"https://ipqualityscore.com/api/json/ip/{settings.ipqualityscore_api_key}/{encoded_ip}?{urllib.parse.urlencode(query)}"
        data = self._json_request(urllib.request.Request(url, method="GET"))
        score = float(data.get("fraud_score") or 0.0)
        flags = [
            name
            for name in ["proxy", "vpn", "tor", "bot_status", "recent_abuse"]
            if data.get(name)
        ]
        return {
            "provider": "ipqualityscore",
            "risk_score": score,
            "verdict": self._verdict(score),
            "summary": f"Fraud score {score:.0f}; flags: {', '.join(flags) or 'none'}.",
            "raw": data,
        }

    def _check_virustotal_ip(self, ip_address: str) -> Dict[str, Any]:
        request = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(ip_address, safe='')}",
            headers={"x-apikey": settings.virustotal_api_key or ""},
            method="GET",
        )
        data = self._json_request(request)
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        risk_score = min(100.0, malicious * 20.0 + suspicious * 10.0)
        return {
            "provider": "virustotal",
            "risk_score": risk_score,
            "verdict": self._verdict(risk_score),
            "summary": f"VirusTotal malicious engines {malicious}; suspicious engines {suspicious}.",
            "raw": attributes or data,
        }

    def _maxmind_context(self, ip_address: str) -> Optional[Dict[str, Any]]:
        if not (settings.maxmind_license_key or settings.maxmind_geoip_db_path):
            return None
        return {
            "provider": "maxmind_geoip2",
            "risk_score": 0.0,
            "verdict": "context",
            "summary": "MaxMind GeoIP2 is configured for accurate geolocation/ASN enrichment.",
            "raw": {
                "ip_address": ip_address,
                "db_path_configured": bool(settings.maxmind_geoip_db_path),
                "web_service_configured": bool(settings.maxmind_account_id and settings.maxmind_license_key),
            },
        }

    def _fetch_pwned_password_range(self, prefix: str) -> Dict[str, int]:
        request = urllib.request.Request(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true", "User-Agent": "login-anomaly-detection"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=settings.threat_intel_timeout_seconds) as response:
                body = response.read().decode("utf-8", errors="replace")
        except urllib.error.URLError:
            return {}

        suffixes: Dict[str, int] = {}
        for line in body.splitlines():
            if ":" not in line:
                continue
            suffix, count = line.split(":", 1)
            try:
                suffixes[suffix.strip().upper()] = int(count.strip())
            except ValueError:
                continue
        return suffixes

    def _json_request(self, request: urllib.request.Request) -> Dict[str, Any]:
        try:
            with urllib.request.urlopen(request, timeout=settings.threat_intel_timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as exc:
            return {"error": str(exc)}

    def _cached(self, indicator_type: str, indicator: str, db: Optional[Session]) -> Optional[Dict[str, Any]]:
        if db is None:
            return None
        record = db.query(ThreatIntelRecord).filter(
            ThreatIntelRecord.indicator_type == indicator_type,
            ThreatIntelRecord.indicator == indicator,
            ThreatIntelRecord.expires_at > datetime.utcnow(),
        ).order_by(ThreatIntelRecord.checked_at.desc()).first()
        if not record or not record.raw_data:
            return None
        try:
            return json.loads(record.raw_data)
        except ValueError:
            return None

    def _store(
        self,
        indicator_type: str,
        indicator: str,
        provider: str,
        result: Dict[str, Any],
        db: Optional[Session],
    ) -> None:
        if db is None:
            return
        record = ThreatIntelRecord(
            indicator=indicator,
            indicator_type=indicator_type,
            provider=provider,
            risk_score=float(result.get("risk_score") or 0.0),
            verdict=result.get("verdict") or "unknown",
            summary=result.get("summary"),
            raw_data=json.dumps(result, default=str),
            checked_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(seconds=settings.threat_intel_cache_ttl_seconds),
        )
        db.add(record)
        db.commit()

    def _verdict(self, risk_score: float) -> str:
        if risk_score >= 90:
            return "critical"
        if risk_score >= 75:
            return "high"
        if risk_score >= 40:
            return "medium"
        return "low"
