from pydantic import field_validator
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    database_url: str = "sqlite:///./login_security.db"
    redis_url: str = "redis://localhost:6379"
    secret_key: str = "your-secret-key-here"
    algorithm: str = "HS256"
    admin_secret_token: str = "admin-secret-token"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 14
    approval_token_ttl_seconds: int = 900
    otp_resend_cooldown_seconds: int = 60
    learning_mode_days: int = 7
    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 15
    rate_limit_requests: int = 5
    rate_limit_window_seconds: int = 60
    otp_rate_limit_attempts: int = 3
    otp_secret_length: int = 32
    anomaly_threshold: float = 0.5
    medium_risk_threshold: float = 40.0
    high_risk_threshold: float = 70.0
    critical_risk_threshold: float = 90.0
    travel_velocity_threshold: float = 500  # km/h
    model_threshold_percentile: float = 95.0
    min_training_samples: int = 20
    auto_retrain_login_count: int = 50
    drift_threshold: float = 0.7
    model_metadata_path: str = "app/ml/model_metadata.json"
    model_monitoring_log_path: str = "app/ml/model_predictions.jsonl"
    verification_token_ttl_seconds: int = 300
    verification_max_attempts: int = 3
    expose_debug_otp: bool = False
    require_device_ip_approval: bool = False
    app_public_url: Optional[str] = None
    api_public_url: Optional[str] = None
    csrf_protection_enabled: bool = False
    secure_cookies: bool = False
    cookie_domain: Optional[str] = None
    captcha_after_failures: int = 5
    bot_detection_enabled: bool = True
    abuseipdb_api_key: Optional[str] = None
    ipqualityscore_api_key: Optional[str] = None
    hibp_api_key: Optional[str] = None
    threat_intel_timeout_seconds: int = 4
    threat_intel_cache_ttl_seconds: int = 3600
    continuous_auth_interval_seconds: int = 30
    session_high_risk_threshold: float = 70.0
    session_critical_risk_threshold: float = 90.0
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from_email: Optional[str] = None
    smtp_use_tls: bool = True
    sendgrid_api_key: Optional[str] = None
    sendgrid_from_email: Optional[str] = None
    resend_api_key: Optional[str] = None
    resend_from_email: Optional[str] = None
    brevo_api_key: Optional[str] = None
    brevo_from_email: Optional[str] = None
    maxmind_account_id: Optional[str] = None
    maxmind_license_key: Optional[str] = None
    maxmind_geoip_db_path: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    authy_api_key: Optional[str] = None
    firebase_project_id: Optional[str] = None
    clerk_publishable_key: Optional[str] = None
    auth0_domain: Optional[str] = None
    fingerprintjs_public_key: Optional[str] = None
    rrweb_enabled: bool = False
    mapbox_access_token: Optional[str] = None
    seed_demo_users: bool = True
    demo_user_username: str = "demo_user"
    demo_user_password: str = "DemoUser@12345"
    demo_user_email: Optional[str] = "demo@example.com"
    demo_admin_username: str = "admin_user"
    demo_admin_password: str = "AdminUser@12345"
    demo_admin_email: Optional[str] = "admin@example.com"
    postgres_pool_size: int = 10
    postgres_max_overflow: int = 20

    @field_validator("database_url", mode="before")
    @classmethod
    def default_blank_database_url(cls, value: str) -> str:
        if value is None or not str(value).strip():
            return "sqlite:///./login_security.db"
        return str(value)

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
