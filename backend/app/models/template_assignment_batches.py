from __future__ import annotations

from datetime import datetime
from typing import Any
import uuid

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .core import Common


class TemplateAssignmentBatch(Common):
    """Metadata-only TP4 preview/apply envelope.

    This model intentionally contains no configuration-operation linkage or
    execution/dispatch state. It records immutable request/scope evidence and
    aggregate assignment outcomes only.
    """

    __tablename__ = "template_assignment_batches"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PREVIEWED','APPLYING','SUCCEEDED','PARTIAL','FAILED','EXPIRED')",
            name="ck_template_assignment_batches_status",
        ),
        CheckConstraint(
            "char_length(request_fingerprint) = 64",
            name="ck_template_assignment_batches_request_fingerprint",
        ),
        CheckConstraint(
            "authorization_scope_fingerprint IS NULL OR char_length(authorization_scope_fingerprint) = 64",
            name="ck_template_assignment_batches_scope_fingerprint",
        ),
        CheckConstraint(
            "target_count >= 0 AND ready_count >= 0 AND noop_count >= 0 AND blocked_count >= 0 "
            "AND succeeded_count >= 0 AND failed_count >= 0",
            name="ck_template_assignment_batches_nonnegative_counters",
        ),
        CheckConstraint(
            "ready_count <= target_count AND noop_count <= target_count AND blocked_count <= target_count "
            "AND succeeded_count <= target_count AND failed_count <= target_count",
            name="ck_template_assignment_batches_counter_bounds",
        ),
        Index(
            "uq_template_assignment_batches_actor_idempotency",
            "actor_user_id",
            "idempotency_key",
            unique=True,
            postgresql_where=text("idempotency_key IS NOT NULL"),
        ),
        Index(
            "ix_template_assignment_batches_actor_created",
            "actor_user_id",
            "created_at",
        ),
        Index(
            "ix_template_assignment_batches_status_expiry",
            "status",
            "preview_expires_at",
        ),
    )

    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    status: Mapped[str] = mapped_column(
        String(20), default="PREVIEWED", server_default="PREVIEWED", nullable=False
    )
    idempotency_key: Mapped[str | None] = mapped_column(String(128))
    request_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    authorization_scope: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb"), nullable=False
    )
    authorization_scope_fingerprint: Mapped[str | None] = mapped_column(String(64))
    request_summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb"), nullable=False
    )
    target_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    ready_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    noop_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    blocked_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    succeeded_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    failed_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    preview_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TemplateAssignmentBatchTarget(Common):
    """Immutable TP4 device membership with sanitized preview/apply evidence."""

    __tablename__ = "template_assignment_batch_targets"
    __table_args__ = (
        UniqueConstraint(
            "batch_id", "device_id", name="uq_template_assignment_batch_targets_batch_device"
        ),
        UniqueConstraint(
            "batch_id", "target_ordinal", name="uq_template_assignment_batch_targets_batch_ordinal"
        ),
        CheckConstraint(
            "target_ordinal >= 0",
            name="ck_template_assignment_batch_targets_ordinal",
        ),
        CheckConstraint(
            "preview_status IN ('READY','NOOP','BLOCKED')",
            name="ck_template_assignment_batch_targets_preview_status",
        ),
        CheckConstraint(
            "apply_status IN ('NOT_APPLIED','SUCCEEDED','FAILED','SKIPPED')",
            name="ck_template_assignment_batch_targets_apply_status",
        ),
        Index(
            "ix_template_assignment_batch_targets_batch_preview",
            "batch_id",
            "preview_status",
        ),
        Index(
            "ix_template_assignment_batch_targets_batch_apply",
            "batch_id",
            "apply_status",
        ),
        Index(
            "ix_template_assignment_batch_targets_device_created",
            "device_id",
            "created_at",
        ),
    )

    batch_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("template_assignment_batches.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False
    )
    target_ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    preview_status: Mapped[str] = mapped_column(
        String(20), default="READY", server_default="READY", nullable=False
    )
    apply_status: Mapped[str] = mapped_column(
        String(20), default="NOT_APPLIED", server_default="NOT_APPLIED", nullable=False
    )
    warnings: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb"), nullable=False
    )
    blockers: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb"), nullable=False
    )
    planned_changes: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb"), nullable=False
    )
    family_outcomes: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb"), nullable=False
    )
    failure_code: Mapped[str | None] = mapped_column(String(120))
    failure_message: Mapped[str | None] = mapped_column(Text)
    terminal_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
