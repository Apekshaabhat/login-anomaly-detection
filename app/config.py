from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    database_url: str = "sqlite:///./login_security.db"
    redis_url: str = "redis://localhost:6379"
    secret_key: str = "your-secret-key-here"
    algorithm: str = "HS256"
    admin_secret_token: str = "change-this-admin-token"
    access_token_expire_minutes: int = 30
    learning_mode_days: int = 7
    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 15
    rate_limit_requests: int = 5
    rate_limit_window_seconds: int = 60
    otp_secret_length: int = 32
    anomaly_threshold: float = 0.5
    travel_velocity_threshold: float = 500  # km/h
    model_threshold_percentile: float = 95.0
    min_training_samples: int = 20
    auto_retrain_login_count: int = 50
    verification_token_ttl_seconds: int = 300
    verification_max_attempts: int = 3
    expose_debug_otp: bool = False
    postgres_pool_size: int = 10
    postgres_max_overflow: int = 20

    class Config:
        env_file = ".env"

settings = Settings()
