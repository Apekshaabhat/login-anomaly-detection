"""adaptive mfa security schema

Revision ID: 20260522_mfa
Revises:
Create Date: 2026-05-22
"""

from alembic import op
import sqlalchemy as sa


revision = "20260522_mfa"
down_revision = None
branch_labels = None
depends_on = None


def _add_column(table_name: str, column: sa.Column) -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {item["name"] for item in inspector.get_columns(table_name)}
    if column.name not in columns:
        op.add_column(table_name, column)


def upgrade() -> None:
    for column in [
        sa.Column("state", sa.String(), server_default="pending_verification"),
        sa.Column("nickname", sa.String(), nullable=True),
        sa.Column("browser", sa.String(), nullable=True),
        sa.Column("os", sa.String(), nullable=True),
        sa.Column("device_type", sa.String(), nullable=True),
        sa.Column("screen_resolution", sa.String(), nullable=True),
        sa.Column("timezone", sa.String(), nullable=True),
        sa.Column("language", sa.String(), nullable=True),
        sa.Column("hardware_fingerprint", sa.String(), nullable=True),
        sa.Column("user_agent_hash", sa.String(), nullable=True),
        sa.Column("remember_device", sa.Boolean(), server_default=sa.false()),
        sa.Column("suspicious_reason", sa.Text(), nullable=True),
        sa.Column("blocked_at", sa.DateTime(), nullable=True),
    ]:
        _add_column("devices", column)

    for column in [
        sa.Column("asn", sa.String(), nullable=True),
        sa.Column("provider", sa.String(), nullable=True),
        sa.Column("country", sa.String(), nullable=True),
        sa.Column("city", sa.String(), nullable=True),
        sa.Column("is_vpn", sa.Boolean(), server_default=sa.false()),
        sa.Column("is_proxy", sa.Boolean(), server_default=sa.false()),
        sa.Column("is_tor", sa.Boolean(), server_default=sa.false()),
        sa.Column("ip_risk_score", sa.Float(), server_default="0"),
    ]:
        _add_column("login_attempts", column)

    op.create_table(
        "mfa_secrets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("email_verified", sa.Boolean(), default=False),
        sa.Column("totp_secret", sa.String(), nullable=True),
        sa.Column("totp_enabled", sa.Boolean(), default=False),
        sa.Column("backup_codes_hash", sa.Text(), nullable=True),
        sa.Column("recovery_codes_generated_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("user_id"),
    )
    op.create_index("ix_mfa_secrets_user_id", "mfa_secrets", ["user_id"])

    op.create_table(
        "login_challenges",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("challenge_token", sa.String(), nullable=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("login_attempt_id", sa.Integer(), sa.ForeignKey("login_attempts.id"), nullable=True),
        sa.Column("state", sa.String(), nullable=True),
        sa.Column("risk_level", sa.String(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("required_methods", sa.Text(), nullable=True),
        sa.Column("verified_methods", sa.Text(), nullable=True),
        sa.Column("otp_hash", sa.String(), nullable=True),
        sa.Column("otp_attempts", sa.Integer(), nullable=True),
        sa.Column("otp_sent_at", sa.DateTime(), nullable=True),
        sa.Column("resend_available_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("device_fingerprint", sa.String(), nullable=True),
        sa.Column("approval_required", sa.Boolean(), nullable=True),
        sa.Column("device_approved", sa.Boolean(), nullable=True),
        sa.Column("remember_device", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("challenge_token"),
    )
    op.create_index("ix_login_challenges_challenge_token", "login_challenges", ["challenge_token"])
    op.create_index("ix_login_challenges_user_id", "login_challenges", ["user_id"])
    op.create_index("ix_login_challenges_state", "login_challenges", ["state"])

    op.create_table(
        "session_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("token_hash", sa.String(), nullable=True),
        sa.Column("token_family", sa.String(), nullable=True),
        sa.Column("user_agent_hash", sa.String(), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("device_fingerprint", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("replaced_by_hash", sa.String(), nullable=True),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_session_tokens_user_id", "session_tokens", ["user_id"])
    op.create_index("ix_session_tokens_token_hash", "session_tokens", ["token_hash"])
    op.create_index("ix_session_tokens_token_family", "session_tokens", ["token_family"])

    op.create_table(
        "device_approval_requests",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("login_challenge_id", sa.Integer(), sa.ForeignKey("login_challenges.id"), nullable=True),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("devices.id"), nullable=True),
        sa.Column("token_jti", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("requested_ip", sa.String(), nullable=True),
        sa.Column("requested_location", sa.String(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("consumed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("token_jti"),
    )
    op.create_index("ix_device_approval_requests_user_id", "device_approval_requests", ["user_id"])
    op.create_index("ix_device_approval_requests_token_jti", "device_approval_requests", ["token_jti"])

    op.create_table(
        "security_notifications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("notification_type", sa.String(), nullable=True),
        sa.Column("channel", sa.String(), nullable=True),
        sa.Column("destination", sa.String(), nullable=True),
        sa.Column("subject", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("payload", sa.Text(), nullable=True),
        sa.Column("sent_at", sa.DateTime(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_security_notifications_user_id", "security_notifications", ["user_id"])
    op.create_index("ix_security_notifications_notification_type", "security_notifications", ["notification_type"])

    op.create_table(
        "ip_reputation",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("asn", sa.String(), nullable=True),
        sa.Column("provider", sa.String(), nullable=True),
        sa.Column("country", sa.String(), nullable=True),
        sa.Column("city", sa.String(), nullable=True),
        sa.Column("is_vpn", sa.Boolean(), nullable=True),
        sa.Column("is_proxy", sa.Boolean(), nullable=True),
        sa.Column("is_tor", sa.Boolean(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("source", sa.String(), nullable=True),
        sa.Column("raw_data", sa.Text(), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("ip_address"),
    )
    op.create_index("ix_ip_reputation_ip_address", "ip_reputation", ["ip_address"])

    op.create_table(
        "trusted_ips",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("label", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("user_id", "ip_address", name="uq_trusted_ip_user_ip"),
    )
    op.create_index("ix_trusted_ips_user_id", "trusted_ips", ["user_id"])
    op.create_index("ix_trusted_ips_ip_address", "trusted_ips", ["ip_address"])

    op.create_table(
        "suspicious_ips",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("source", sa.String(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.Column("blocked_until", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("ip_address"),
    )
    op.create_index("ix_suspicious_ips_ip_address", "suspicious_ips", ["ip_address"])
    op.create_index("ix_suspicious_ips_severity", "suspicious_ips", ["severity"])

    op.create_table(
        "geo_login_history",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("login_attempt_id", sa.Integer(), sa.ForeignKey("login_attempts.id"), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("country", sa.String(), nullable=True),
        sa.Column("city", sa.String(), nullable=True),
        sa.Column("latitude", sa.Float(), nullable=True),
        sa.Column("longitude", sa.Float(), nullable=True),
        sa.Column("asn", sa.String(), nullable=True),
        sa.Column("provider", sa.String(), nullable=True),
        sa.Column("distance_from_previous_km", sa.Float(), nullable=True),
        sa.Column("velocity_kmh", sa.Float(), nullable=True),
        sa.Column("impossible_travel", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_geo_login_history_user_id", "geo_login_history", ["user_id"])
    op.create_index("ix_geo_login_history_ip_address", "geo_login_history", ["ip_address"])


def downgrade() -> None:
    for table_name in [
        "geo_login_history",
        "suspicious_ips",
        "trusted_ips",
        "ip_reputation",
        "security_notifications",
        "device_approval_requests",
        "session_tokens",
        "login_challenges",
        "mfa_secrets",
    ]:
        op.drop_table(table_name)
