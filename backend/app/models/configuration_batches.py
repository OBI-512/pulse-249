from __future__ import annotations

from datetime import datetime
from typing import Any
import uuid

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .core import Common


class ConfigurationBatch(Common):
    """Durable F3 orchestration envelope over F1 single-device operations."""

    __tablename__ = "configuration_batches"
    __table_args__ = (
        CheckConstraint(
            "operation_type IN ('CAPTURE','APPLY','VERIFY','RESTORE')",
            name="ck_configuration_batches_operation_type",
        ),
        CheckConstraint(
            "status IN ('QUEUED','SCHEDULED','RUNNING','PAUSED','ABORTING','ABORTED','SUCCEEDED','PARTIAL','FAILED','CANCELLED')",
            name="ck_configuration_batches_status",
        ),
        CheckConstraint(
            "rollout_mode IN ('ALL_AT_ONCE','CANARY_PERCENTAGE','WAVES')",
            name="ck_configuration_batches_rollout_mode",
        ),
        CheckConstraint(
            "maintenance_policy IN ('NONE','REQUIRE_ACTIVE_WINDOW')",
            name="ck_configuration_batches_maintenance_policy",
        ),
        CheckConstraint(
            "char_length(request_fingerprint) = 64",
            name="ck_configuration_batches_request_fingerprint",
        ),
        CheckConstraint(
            "authorization_scope_fingerprint IS NULL OR char_length(authorization_scope_fingerprint) = 64",
            name="ck_configuration_batches_scope_fingerprint",
        ),
        CheckConstraint(
            "target_count >= 0 AND dispatched_count >= 0 AND succeeded_count >= 0 "
            "AND failed_count >= 0 AND aborted_count >= 0",
            name="ck_configuration_batches_nonnegative_counters",
        ),
        CheckConstraint(
            "dispatched_count <= target_count AND succeeded_count <= target_count "
            "AND failed_count <= target_count AND aborted_count <= target_count",
            name="ck_configuration_batches_counter_bounds",
        ),
        Index(
            "uq_configuration_batches_actor_idempotency",
            "actor_user_id",
            "idempotency_key",
            unique=True,
            postgresql_where=text("idempotency_key IS NOT NULL"),
        ),
        Index("ix_configuration_batches_status_not_before", "status", "not_before"),
        Index("ix_configuration_batches_actor_created", "actor_user_id", "created_at"),
    )

    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    operation_type: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default="QUEUED", server_default="QUEUED", nullable=False
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
    rollout_mode: Mapped[str] = mapped_column(
        String(24), default="ALL_AT_ONCE", server_default="ALL_AT_ONCE", nullable=False
    )
    rollout_parameters: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb"), nullable=False
    )
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    maintenance_policy: Mapped[str] = mapped_column(
        String(32), default="NONE", server_default="NONE", nullable=False
    )
    target_count: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    dispatched_count: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    succeeded_count: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    failed_count: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    aborted_count: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    queued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    paused_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    aborted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ConfigurationBatchTarget(Common):
    """Immutable F3 target membership with permanent F1 operation linkage."""

    __tablename__ = "configuration_batch_targets"
    __table_args__ = (
        UniqueConstraint(
            "batch_id", "device_id", name="uq_configuration_batch_targets_batch_device"
        ),
        UniqueConstraint(
            "batch_id",
            "target_ordinal",
            name="uq_configuration_batch_targets_batch_ordinal",
        ),
        UniqueConstraint(
            "configuration_operation_id",
            name="uq_configuration_batch_targets_operation",
        ),
        CheckConstraint(
            "target_ordinal >= 0",
            name="ck_configuration_batch_targets_ordinal",
        ),
        CheckConstraint(
            "wave_number >= 0",
            name="ck_configuration_batch_targets_wave",
        ),
        CheckConstraint(
            "status IN ('WAITING','READY','DISPATCHED','SUCCEEDED','FAILED','SKIPPED','ABORTED')",
            name="ck_configuration_batch_targets_status",
        ),
        CheckConstraint(
            "(configuration_operation_id IS NULL AND status IN ('WAITING','READY','SKIPPED','ABORTED')) "
            "OR (configuration_operation_id IS NOT NULL AND status IN ('DISPATCHED','SUCCEEDED','FAILED','ABORTED'))",
            name="ck_configuration_batch_targets_operation_status",
        ),
        Index(
            "ix_configuration_batch_targets_batch_wave_status",
            "batch_id",
            "wave_number",
            "status",
        ),
        Index(
            "ix_configuration_batch_targets_device_created",
            "device_id",
            "created_at",
        ),
    )

    batch_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("configuration_batches.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False
    )
    target_ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    wave_number: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(20), default="WAITING", server_default="WAITING", nullable=False
    )
    configuration_operation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("configuration_operations.id", ondelete="RESTRICT")
    )
    failure_code: Mapped[str | None] = mapped_column(String(120))
    failure_message: Mapped[str | None] = mapped_column(Text)
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    terminal_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
