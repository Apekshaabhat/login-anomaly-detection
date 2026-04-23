from sqlalchemy import Column, Integer, String, DateTime, Float, Boolean, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_locked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    profiles = relationship("UserProfile", back_populates="user")
    devices = relationship("Device", back_populates="user")
    login_attempts = relationship("LoginAttempt", back_populates="user")

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

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    fingerprint = Column(String, unique=True, index=True)
    is_trusted = Column(Boolean, default=False)
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

    user = relationship("User", back_populates="login_attempts")

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
