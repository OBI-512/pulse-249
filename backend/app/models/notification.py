from __future__ import annotations

from datetime import datetime
from typing import Any
import uuid

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .core import Common


NOTIFICATION_CHANNEL_TYPES = ("EMAIL", "WEBHOOK")
NOTIFICATION_DELIVERY_STATES = ("PENDING", "SUPPRESSED", "CLAIMED", "SENT", "FAILED", "CANCELLED")


class NotificationPolicy(Common):
    __tablename__ = "notification_policies"
    __table_args__ = (
        CheckConstraint(
            "minimum_severity IN ('INFO','WARNING','MINOR','MAJOR','CRITICAL')",
            name="ck_notification_policies_minimum_severity",
        ),
        Index("ix_notification_policies_enabled_alarm", "enabled", "alarm_type"),
    )

    name: Mapped[str] = mapped_column(String(160), unique=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"), nullable=False)
    alarm_type: Mapped[str | None] = mapped_column(String(80))
    minimum_severity: Mapped[str] = mapped_column(String(20), default="MAJOR", server_default="MAJOR", nullable=False)
    description: Mapped[str | None] = mapped_column(Text)


class NotificationPolicyStep(Common):
    __tablename__ = "notification_policy_steps"
    __table_args__ = (
        UniqueConstraint("policy_id", "step_order", name="uq_notification_policy_steps_order"),
        CheckConstraint("step_order >= 1", name="ck_notification_policy_steps_order"),
        CheckConstraint("delay_seconds >= 0", name="ck_notification_policy_steps_delay"),
        CheckConstraint(
            "channel_type IN ('EMAIL','WEBHOOK')",
            name="ck_notification_policy_steps_channel_type",
        ),
        CheckConstraint("max_attempts BETWEEN 1 AND 10", name="ck_notification_policy_steps_max_attempts"),
        CheckConstraint("retry_base_seconds BETWEEN 5 AND 3600", name="ck_notification_policy_steps_retry_base"),
        CheckConstraint("retry_max_seconds BETWEEN 5 AND 86400", name="ck_notification_policy_steps_retry_max"),
        CheckConstraint("retry_max_seconds >= retry_base_seconds", name="ck_notification_policy_steps_retry_order"),
        Index("ix_notification_policy_steps_policy_order", "policy_id", "step_order"),
    )

    policy_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("notification_policies.id", ondelete="CASCADE"), nullable=False
    )
    step_order: Mapped[int] = mapped_column(Integer, nullable=False)
    delay_seconds: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    channel_type: Mapped[str] = mapped_column(String(20), nullable=False)
    destination: Mapped[str] = mapped_column(String(500), nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3, server_default="3", nullable=False)
    retry_base_seconds: Mapped[int] = mapped_column(Integer, default=30, server_default="30", nullable=False)
    retry_max_seconds: Mapped[int] = mapped_column(Integer, default=900, server_default="900", nullable=False)


class NotificationDelivery(Common):
    __tablename__ = "notification_deliveries"
    __table_args__ = (
        CheckConstraint(
            "channel_type IN ('EMAIL','WEBHOOK')",
            name="ck_notification_deliveries_channel_type",
        ),
        CheckConstraint(
            "status IN ('PENDING','SUPPRESSED','CLAIMED','SENT','FAILED','CANCELLED')",
            name="ck_notification_deliveries_status",
        ),
        CheckConstraint("occurrence_number >= 1", name="ck_notification_deliveries_occurrence"),
        CheckConstraint("attempt_count >= 0", name="ck_notification_deliveries_attempt_count"),
        Index("uq_notification_deliveries_idempotency", "idempotency_key", unique=True),
        Index("ix_notification_deliveries_due", "status", "next_attempt_at"),
        Index("ix_notification_deliveries_alarm_status", "alarm_id", "status"),
        Index("ix_notification_deliveries_claim_expires", "claim_expires_at"),
    )

    alarm_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alarms.id", ondelete="CASCADE"), nullable=False)
    event_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("operational_events.id", ondelete="SET NULL"))
    policy_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("notification_policies.id", ondelete="RESTRICT"), nullable=False)
    policy_step_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("notification_policy_steps.id", ondelete="RESTRICT"), nullable=False)
    occurrence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    channel_type: Mapped[str] = mapped_column(String(20), nullable=False)
    destination: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="PENDING", server_default="PENDING", nullable=False)
    scheduled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(120))
    response_status: Mapped[int | None] = mapped_column(Integer)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    claim_token: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    claim_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    maintenance_window_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("maintenance_windows.id", ondelete="SET NULL")
    )
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, server_default="{}", nullable=False
    )
