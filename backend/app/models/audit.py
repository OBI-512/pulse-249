from __future__ import annotations

from datetime import datetime
from typing import Any
import uuid

from sqlalchemy import CheckConstraint, DateTime, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .core import Common


class AuditLog(Common):
    """Immutable evidence describing one security or business-domain event.

    PostgreSQL enforces append-only behavior through the trigger installed by
    migration 0006.  The ORM deliberately exposes no relationship that could
    cascade or rewrite historical actor/entity identity.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        CheckConstraint(
            "result IN ('SUCCESS','FAILURE','ATTEMPT')",
            name="ck_audit_logs_result",
        ),
        Index("ix_audit_logs_occurred_at", "occurred_at"),
        Index("ix_audit_logs_actor_occurred_at", "actor_user_id", "occurred_at"),
        Index("ix_audit_logs_actor_display_snapshot", "actor_display_name_snapshot"),
        Index("ix_audit_logs_entity_occurred_at", "entity_type", "entity_id", "occurred_at"),
        Index("ix_audit_logs_action_occurred_at", "action", "occurred_at"),
        Index("ix_audit_logs_result_occurred_at", "result", "occurred_at"),
        Index("ix_audit_logs_request_id", "request_id"),
    )

    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    actor_username_snapshot: Mapped[str | None] = mapped_column(String(150))
    actor_display_name_snapshot: Mapped[str | None] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(80))
    entity_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    entity_display_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    result: Mapped[str] = mapped_column(
        String(30),
        default="SUCCESS",
        server_default="SUCCESS",
        nullable=False,
    )
    request_id: Mapped[str | None] = mapped_column(String(128))
    source_ip: Mapped[str | None] = mapped_column(String(64))
    description: Mapped[str | None] = mapped_column(Text)
    before_summary: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    after_summary: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        default=dict,
        server_default="{}",
        nullable=False,
    )
