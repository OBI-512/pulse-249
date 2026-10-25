from __future__ import annotations

from datetime import datetime
from typing import Any
import uuid

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .core import Common


ALARM_SEVERITIES = ("INFO", "WARNING", "MINOR", "MAJOR", "CRITICAL")
ALARM_STATES = ("ACTIVE", "CLEARED")
ALARM_HISTORY_ACTIONS = (
    "OPENED",
    "REOPENED",
    "ACKNOWLEDGED",
    "ASSIGNED",
    "UNASSIGNED",
    "MANUALLY_CLEARED",
    "AUTO_CLEARED",
    "NOTIFICATION_SUPPRESSED",
)


class OperationalEvent(Common):
    """Immutable operational fact emitted by the monitoring domain.

    Events describe what happened. They are not acknowledgable or assignable;
    those mutable NOC workflow concerns belong to :class:`Alarm`.
    """

    __tablename__ = "operational_events"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('INFO','WARNING','MINOR','MAJOR','CRITICAL')",
            name="ck_operational_events_severity",
        ),
        Index("ix_operational_events_occurred_at", "occurred_at"),
        Index("ix_operational_events_device_occurred_at", "device_id", "occurred_at"),
        Index("ix_operational_events_type_occurred_at", "event_type", "occurred_at"),
        Index("ix_operational_events_correlation_occurred_at", "correlation_key", "occurred_at"),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    correlation_key: Mapped[str] = mapped_column(String(255), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, server_default="{}", nullable=False
    )


class Alarm(Common):
    """Current NOC workflow state for one correlated operational condition."""

    __tablename__ = "alarms"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('INFO','WARNING','MINOR','MAJOR','CRITICAL')",
            name="ck_alarms_severity",
        ),
        CheckConstraint(
            "state IN ('ACTIVE','CLEARED')",
            name="ck_alarms_state",
        ),
        CheckConstraint("occurrence_count >= 1", name="ck_alarms_occurrence_count"),
        Index("uq_alarms_correlation_key", "correlation_key", unique=True),
        Index("ix_alarms_state_severity", "state", "severity"),
        Index("ix_alarms_device_state", "device_id", "state"),
        Index("ix_alarms_owner_state", "owner_user_id", "state"),
        Index("ix_alarms_last_raised_at", "last_raised_at"),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    alarm_type: Mapped[str] = mapped_column(String(80), nullable=False)
    correlation_key: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    state: Mapped[str] = mapped_column(
        String(20), default="ACTIVE", server_default="ACTIVE", nullable=False
    )
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    first_raised_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_raised_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_cleared_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    occurrence_count: Mapped[int] = mapped_column(
        Integer, default=1, server_default="1", nullable=False
    )
    last_event_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("operational_events.id", ondelete="SET NULL")
    )


class AlarmHistory(Common):
    """Append-only lifecycle trail for one alarm."""

    __tablename__ = "alarm_history"
    __table_args__ = (
        CheckConstraint(
            "action IN ('OPENED','REOPENED','ACKNOWLEDGED','ASSIGNED','UNASSIGNED','MANUALLY_CLEARED','AUTO_CLEARED','NOTIFICATION_SUPPRESSED')",
            name="ck_alarm_history_action",
        ),
        Index("ix_alarm_history_alarm_occurred_at", "alarm_id", "occurred_at"),
        Index("ix_alarm_history_action_occurred_at", "action", "occurred_at"),
    )

    alarm_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("alarms.id", ondelete="CASCADE"), nullable=False
    )
    event_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("operational_events.id", ondelete="SET NULL")
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )
    action: Mapped[str] = mapped_column(String(40), nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    note: Mapped[str | None] = mapped_column(Text)
    before_summary: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    after_summary: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, server_default="{}", nullable=False
    )
