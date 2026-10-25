from __future__ import annotations

from datetime import datetime
import uuid

from sqlalchemy import Boolean, CheckConstraint, DateTime, Float, ForeignKey, Index, Integer, String, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from .core import Common


AVAILABILITY_STATES = ("ONLINE", "SUSPECT", "OFFLINE", "UNKNOWN", "MAINTENANCE")
AVAILABILITY_PROFILES = ("ICMP", "TCP", "SNMP")


class DeviceAvailability(Common):
    """Server-authoritative availability state for one registered device."""

    __tablename__ = "device_availability"
    __table_args__ = (
        CheckConstraint(
            "status IN ('ONLINE','SUSPECT','OFFLINE','UNKNOWN','MAINTENANCE')",
            name="ck_device_availability_status",
        ),
        CheckConstraint(
            "profile IN ('ICMP','TCP','SNMP')",
            name="ck_device_availability_profile",
        ),
        CheckConstraint(
            "consecutive_failures >= 0",
            name="ck_device_availability_consecutive_failures",
        ),
        Index("uq_device_availability_device", "device_id", unique=True),
        Index("ix_device_availability_status", "status"),
        Index(
            "ix_device_availability_due",
            "next_check_at",
            postgresql_where=text("enabled"),
        ),
        Index("ix_device_availability_lease_expires", "lease_expires_at"),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(20), default="UNKNOWN", server_default="UNKNOWN", nullable=False
    )
    profile: Mapped[str] = mapped_column(
        String(20), default="ICMP", server_default="ICMP", nullable=False
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default=text("true"), nullable=False
    )

    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_failure_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )
    consecutive_failures: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    latency_ms: Mapped[float | None] = mapped_column(Float)
    last_result_code: Mapped[str | None] = mapped_column(String(80))

    next_check_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )
    last_dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_token: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
