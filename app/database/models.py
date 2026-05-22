from sqlalchemy import Column, Integer, String, DateTime, Float, Boolean, Text, ForeignKey, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, nullable=True, unique=True)
    phone = Column(String, nullable=True)
    hashed_password = Column(String)
    is_locked = Column(Boolean, default=False)
    locked_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    profiles = relationship("UserProfile", back_populates="user")
    devices = relationship("Device", back_populates="user")
    login_attempts = relationship("LoginAttempt", back_populates="user")
    mfa_secrets = relationship("MFASecrets", back_populates="user", uselist=False)
    session_tokens = relationship("SessionToken", back_populates="user")

class UserProfile(Base):
    __tablename__ = "user_profiles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    login_time_mean = Column(Float, nullable=True)
    login_time_std = Column(Float, nullable=True)
    location_lat_mean = Column(Float, nullable=True)
    location_lon_mean = Column(Float, nullable=True)
    location_std = Column(Float, nullable=True)
    device_fingerprint = Column(String, nullable=True)
    typing_speed_mean = Column(Float, nullable=True)
    typing_speed_std = Column(Float, nullable=True)
    keystroke_rhythm = Column(Text, nullable=True)  # JSON string
    confidence_score = Column(Float, default=0.0)
    learning_mode = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", back_populates="profiles")

class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("user_id", "fingerprint", name="uq_device_user_fingerprint"),)

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    fingerprint = Column(String, index=True)
    is_trusted = Column(Boolean, default=False)
    state = Column(String, default="pending_verification", index=True)  # trusted, pending_verification, blocked, suspicious
    nickname = Column(String, nullable=True)
    browser = Column(String, nullable=True)
    os = Column(String, nullable=True)
    device_type = Column(String, nullable=True)
    screen_resolution = Column(String, nullable=True)
    timezone = Column(String, nullable=True)
    language = Column(String, nullable=True)
    hardware_fingerprint = Column(String, nullable=True)
    user_agent_hash = Column(String, nullable=True)
    remember_device = Column(Boolean, default=False)
    first_ip_address = Column(String, nullable=True)
    last_ip_address = Column(String, nullable=True)
    approval_status = Column(String, default="approved")  # pending, approved, denied
    approved_at = Column(DateTime, nullable=True)
    last_mfa_method = Column(String, nullable=True)
    suspicious_reason = Column(Text, nullable=True)
    blocked_at = Column(DateTime, nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="devices")

class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String)
    location_lat = Column(Float, nullable=True)
    location_lon = Column(Float, nullable=True)
    device_fingerprint = Column(String)
    typing_speed = Column(Float, nullable=True)
    keystroke_timing = Column(Text, nullable=True)  # JSON string
    success = Column(Boolean)
    risk_score = Column(Float)
    decision = Column(String)  # allow, require_verification, block
    reasons = Column(Text)  # JSON string
    anomaly_score = Column(Float, nullable=True)
    confidence_score = Column(Float, nullable=True)
    mfa_required = Column(Boolean, default=False)
    mfa_method = Column(String, nullable=True)
    mfa_verified_at = Column(DateTime, nullable=True)
    new_device = Column(Boolean, default=False)
    new_ip = Column(Boolean, default=False)
    device_approval_status = Column(String, nullable=True)
    asn = Column(String, nullable=True)
    provider = Column(String, nullable=True)
    country = Column(String, nullable=True)
    city = Column(String, nullable=True)
    is_vpn = Column(Boolean, default=False)
    is_proxy = Column(Boolean, default=False)
    is_tor = Column(Boolean, default=False)
    ip_risk_score = Column(Float, default=0.0)

    user = relationship("User", back_populates="login_attempts")


class MFASecrets(Base):
    __tablename__ = "mfa_secrets"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, index=True)
    email_verified = Column(Boolean, default=False)
    totp_secret = Column(String, nullable=True)
    totp_enabled = Column(Boolean, default=False)
    backup_codes_hash = Column(Text, nullable=True)  # JSON array of bcrypt hashes
    recovery_codes_generated_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", back_populates="mfa_secrets")


class LoginChallenge(Base):
    __tablename__ = "login_challenges"

    id = Column(Integer, primary_key=True, index=True)
    challenge_token = Column(String, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    login_attempt_id = Column(Integer, ForeignKey("login_attempts.id"), nullable=True)
    state = Column(String, default="pending_otp", index=True)
    risk_level = Column(String, nullable=True)
    risk_score = Column(Float, default=0.0)
    required_methods = Column(Text, nullable=True)  # JSON array
    verified_methods = Column(Text, nullable=True)  # JSON array
    otp_hash = Column(String, nullable=True)
    otp_attempts = Column(Integer, default=0)
    otp_sent_at = Column(DateTime, nullable=True)
    resend_available_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, index=True)
    ip_address = Column(String, nullable=True)
    device_fingerprint = Column(String, nullable=True)
    approval_required = Column(Boolean, default=False)
    device_approved = Column(Boolean, default=False)
    remember_device = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    user = relationship("User")
    login_attempt = relationship("LoginAttempt")


class SessionToken(Base):
    __tablename__ = "session_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    token_hash = Column(String, unique=True, index=True)
    token_family = Column(String, index=True)
    user_agent_hash = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    device_fingerprint = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, index=True)
    revoked_at = Column(DateTime, nullable=True)
    replaced_by_hash = Column(String, nullable=True)

    user = relationship("User", back_populates="session_tokens")


class DeviceApprovalRequest(Base):
    __tablename__ = "device_approval_requests"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    login_challenge_id = Column(Integer, ForeignKey("login_challenges.id"), nullable=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    token_jti = Column(String, unique=True, index=True)
    status = Column(String, default="pending", index=True)  # pending, approved, denied, expired
    requested_ip = Column(String, nullable=True)
    requested_location = Column(String, nullable=True)
    risk_score = Column(Float, default=0.0)
    expires_at = Column(DateTime, index=True)
    consumed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")
    login_challenge = relationship("LoginChallenge")
    device = relationship("Device")


class SecurityNotification(Base):
    __tablename__ = "security_notifications"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    notification_type = Column(String, index=True)
    channel = Column(String, default="email")
    destination = Column(String, nullable=True)
    subject = Column(String, nullable=True)
    status = Column(String, default="queued", index=True)
    payload = Column(Text, nullable=True)
    sent_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")


class IPReputation(Base):
    __tablename__ = "ip_reputation"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True)
    asn = Column(String, nullable=True)
    provider = Column(String, nullable=True)
    country = Column(String, nullable=True)
    city = Column(String, nullable=True)
    is_vpn = Column(Boolean, default=False)
    is_proxy = Column(Boolean, default=False)
    is_tor = Column(Boolean, default=False)
    risk_score = Column(Float, default=0.0)
    source = Column(String, default="local")
    raw_data = Column(Text, nullable=True)
    last_checked_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)


class TrustedIP(Base):
    __tablename__ = "trusted_ips"
    __table_args__ = (UniqueConstraint("user_id", "ip_address", name="uq_trusted_ip_user_ip"),)

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    ip_address = Column(String, index=True)
    label = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_seen_at = Column(DateTime, nullable=True)

    user = relationship("User")


class SuspiciousIP(Base):
    __tablename__ = "suspicious_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True)
    reason = Column(Text, nullable=True)
    severity = Column(String, default="medium", index=True)
    source = Column(String, default="local")
    first_seen_at = Column(DateTime, default=datetime.utcnow)
    last_seen_at = Column(DateTime, default=datetime.utcnow)
    blocked_until = Column(DateTime, nullable=True)


class GeoLoginHistory(Base):
    __tablename__ = "geo_login_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    login_attempt_id = Column(Integer, ForeignKey("login_attempts.id"), nullable=True)
    ip_address = Column(String, index=True)
    country = Column(String, nullable=True)
    city = Column(String, nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    asn = Column(String, nullable=True)
    provider = Column(String, nullable=True)
    distance_from_previous_km = Column(Float, default=0.0)
    velocity_kmh = Column(Float, default=0.0)
    impossible_travel = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")
    login_attempt = relationship("LoginAttempt")


# The requested TrustedDevice model is represented by the existing devices table
# to preserve compatibility with the current login pipeline and dashboards.
TrustedDevice = Device


class BehaviorTelemetry(Base):
    __tablename__ = "behavior_telemetry"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    session_id = Column(String, index=True)
    device_fingerprint = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    page_path = Column(String, nullable=True)
    typing_speed = Column(Float, nullable=True)
    typing_variance = Column(Float, nullable=True)
    key_hold_mean = Column(Float, nullable=True)
    key_flight_mean = Column(Float, nullable=True)
    correction_rate = Column(Float, nullable=True)
    mouse_velocity_mean = Column(Float, nullable=True)
    mouse_velocity_std = Column(Float, nullable=True)
    mouse_idle_ratio = Column(Float, nullable=True)
    scroll_depth = Column(Float, nullable=True)
    scroll_velocity_mean = Column(Float, nullable=True)
    replay_event_count = Column(Integer, default=0)
    replay_anomaly_score = Column(Float, default=0.0)
    focus_change_count = Column(Integer, default=0)
    active_seconds = Column(Float, default=0.0)
    raw_features = Column(Text, nullable=True)
    anomaly_score = Column(Float, default=0.0)
    trust_score = Column(Float, default=100.0)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    user = relationship("User")


class SessionRiskSnapshot(Base):
    __tablename__ = "session_risk_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    session_id = Column(String, index=True)
    device_fingerprint = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    risk_score = Column(Float, default=0.0)
    trust_score = Column(Float, default=100.0)
    fraud_probability = Column(Float, default=0.0)
    confidence = Column(Float, default=0.0)
    decision = Column(String, default="allow")
    reasons = Column(Text, nullable=True)
    recommended_action = Column(String, default="allow")
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    user = relationship("User")


class ThreatIntelRecord(Base):
    __tablename__ = "threat_intel_records"

    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String, index=True)
    indicator_type = Column(String, index=True)  # ip, password_hash_prefix, email
    provider = Column(String, index=True)
    risk_score = Column(Float, default=0.0)
    verdict = Column(String, default="unknown")
    summary = Column(Text, nullable=True)
    raw_data = Column(Text, nullable=True)
    checked_at = Column(DateTime, default=datetime.utcnow, index=True)
    expires_at = Column(DateTime, nullable=True, index=True)

class PasswordBlacklist(Base):
    __tablename__ = "password_blacklist"

    id = Column(Integer, primary_key=True, index=True)
    password_hash = Column(String, unique=True, index=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String)
    details = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String, nullable=True)


class AlertRecord(Base):
    __tablename__ = "alert_records"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    login_attempt_id = Column(Integer, ForeignKey("login_attempts.id"), nullable=True)
    severity = Column(String, index=True)  # low, medium, high, critical
    message = Column(Text)
    attack_type = Column(String, nullable=True)
    resolved = Column(Boolean, default=False)
    requires_manual_action = Column(Boolean, default=False)
    auto_action = Column(String, nullable=True)  # allow, block
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)

    user = relationship("User")
    login_attempt = relationship("LoginAttempt")
