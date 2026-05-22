"""ai security enhancements

Revision ID: 20260522_ai
Revises: 20260522_mfa
Create Date: 2026-05-22
"""

from alembic import op
import sqlalchemy as sa


revision = "20260522_ai"
down_revision = "20260522_mfa"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "behavior_telemetry",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("device_fingerprint", sa.String(), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("page_path", sa.String(), nullable=True),
        sa.Column("typing_speed", sa.Float(), nullable=True),
        sa.Column("typing_variance", sa.Float(), nullable=True),
        sa.Column("key_hold_mean", sa.Float(), nullable=True),
        sa.Column("key_flight_mean", sa.Float(), nullable=True),
        sa.Column("correction_rate", sa.Float(), nullable=True),
        sa.Column("mouse_velocity_mean", sa.Float(), nullable=True),
        sa.Column("mouse_velocity_std", sa.Float(), nullable=True),
        sa.Column("mouse_idle_ratio", sa.Float(), nullable=True),
        sa.Column("focus_change_count", sa.Integer(), nullable=True),
        sa.Column("active_seconds", sa.Float(), nullable=True),
        sa.Column("raw_features", sa.Text(), nullable=True),
        sa.Column("anomaly_score", sa.Float(), nullable=True),
        sa.Column("trust_score", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_behavior_telemetry_user_id", "behavior_telemetry", ["user_id"])
    op.create_index("ix_behavior_telemetry_session_id", "behavior_telemetry", ["session_id"])
    op.create_index("ix_behavior_telemetry_created_at", "behavior_telemetry", ["created_at"])

    op.create_table(
        "session_risk_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("device_fingerprint", sa.String(), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("trust_score", sa.Float(), nullable=True),
        sa.Column("fraud_probability", sa.Float(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("decision", sa.String(), nullable=True),
        sa.Column("reasons", sa.Text(), nullable=True),
        sa.Column("recommended_action", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_session_risk_snapshots_user_id", "session_risk_snapshots", ["user_id"])
    op.create_index("ix_session_risk_snapshots_session_id", "session_risk_snapshots", ["session_id"])
    op.create_index("ix_session_risk_snapshots_created_at", "session_risk_snapshots", ["created_at"])

    op.create_table(
        "threat_intel_records",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("indicator", sa.String(), nullable=True),
        sa.Column("indicator_type", sa.String(), nullable=True),
        sa.Column("provider", sa.String(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("verdict", sa.String(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("raw_data", sa.Text(), nullable=True),
        sa.Column("checked_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_threat_intel_records_indicator", "threat_intel_records", ["indicator"])
    op.create_index("ix_threat_intel_records_indicator_type", "threat_intel_records", ["indicator_type"])
    op.create_index("ix_threat_intel_records_provider", "threat_intel_records", ["provider"])
    op.create_index("ix_threat_intel_records_checked_at", "threat_intel_records", ["checked_at"])
    op.create_index("ix_threat_intel_records_expires_at", "threat_intel_records", ["expires_at"])


def downgrade() -> None:
    op.drop_table("threat_intel_records")
    op.drop_table("session_risk_snapshots")
    op.drop_table("behavior_telemetry")
