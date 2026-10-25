from __future__ import annotations

from datetime import datetime
import uuid

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from .core import Common


MAINTENANCE_TARGET_TYPES = ("DEVICE", "LOCATION", "CITY", "GROUP", "NETWORK")


class MaintenanceWindow(Common):
    """Scheduled operational maintenance without mutating device lifecycle.

    Target references are intentionally polymorphic so historical maintenance
    records survive entity deletion/purge. API creation always validates the
    referenced resource and the caller's resource scope.
    """

    __tablename__ = "maintenance_windows"
    __table_args__ = (
        CheckConstraint(
            "target_type IN ('DEVICE','LOCATION','CITY','GROUP','NETWORK')",
            name="ck_maintenance_windows_target_type",
        ),
        CheckConstraint("ends_at > starts_at", name="ck_maintenance_windows_time_range"),
        Index("ix_maintenance_windows_target_time", "target_type", "target_id", "starts_at", "ends_at"),
        Index(
            "ix_maintenance_windows_active_time",
            "starts_at",
            "ends_at",
            postgresql_where=text("enabled AND cancelled_at IS NULL"),
        ),
    )

    name: Mapped[str] = mapped_column(String(160), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    target_type: Mapped[str] = mapped_column(String(20), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"), nullable=False)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    cancelled_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
