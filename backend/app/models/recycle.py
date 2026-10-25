"""Persistent recycle-bin action ledger."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .core import Common


RECYCLE_ROOT_ENTITY_TYPES = (
    "NETWORK",
    "CITY",
    "LOCATION",
    "SECTOR",
    "DEVICE",
    "CUSTOMER",
    "CUSTOMER_SERVICE",
    "DEVICE_GROUP",
    "DEVICE_RELATIONSHIP",
    "DEVICE_IP",
    "DEVICE_INTERFACE",
)

RECYCLE_ITEM_ENTITY_TYPES = RECYCLE_ROOT_ENTITY_TYPES + (
    "DEVICE_PLACEMENT",
    "DEVICE_HIERARCHY_LINK",
    "DEVICE_GROUP_MEMBERSHIP", "DEVICE_GROUP_NESTING",
)


class RecycleBinBatch(Common):
    __tablename__ = "recycle_bin_batches"
    __table_args__ = (
        CheckConstraint(
            "status IN ('RECYCLED','RESTORED','PURGE_FAILED')",
            name="ck_recycle_bin_batches_status",
        ),
        CheckConstraint(
            "root_entity_type IN ("
            + ",".join(f"'{value}'" for value in RECYCLE_ROOT_ENTITY_TYPES)
            + ")",
            name="ck_recycle_bin_batches_root_type",
        ),
        Index("ix_recycle_bin_batches_status", "status"),
        Index(
            "ix_recycle_bin_batches_due_purge",
            "purge_after",
            postgresql_where=text("status IN ('RECYCLED','PURGE_FAILED')"),
        ),
        Index(
            "uq_recycle_bin_batches_open_root",
            "root_entity_type",
            "root_entity_id",
            unique=True,
            postgresql_where=text("status IN ('RECYCLED','PURGE_FAILED')"),
        ),
    )

    root_entity_type: Mapped[str] = mapped_column(String(80), nullable=False)
    root_entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    root_display_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        server_default=text("'{}'::jsonb"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(30), default="RECYCLED", server_default="RECYCLED", nullable=False)
    deleted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    deleted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
    )
    deletion_reason: Mapped[str | None] = mapped_column(Text)
    purge_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    restored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    restored_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT")
    )
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(120))
    last_error_message: Mapped[str | None] = mapped_column(Text)


class RecycleBinItem(Common):
    __tablename__ = "recycle_bin_items"
    __table_args__ = (
        UniqueConstraint(
            "batch_id",
            "entity_type",
            "entity_id",
            name="uq_recycle_bin_item_entity",
        ),
        CheckConstraint(
            "item_role IN ('ROOT','BUNDLE')",
            name="ck_recycle_bin_items_role",
        ),
        CheckConstraint(
            "entity_type IN ("
            + ",".join(f"'{value}'" for value in RECYCLE_ITEM_ENTITY_TYPES)
            + ")",
            name="ck_recycle_bin_items_entity_type",
        ),
        Index("ix_recycle_bin_items_batch_id", "batch_id"),
        Index("ix_recycle_bin_items_entity", "entity_type", "entity_id"),
    )

    batch_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("recycle_bin_batches.id", ondelete="CASCADE"),
        nullable=False,
    )
    entity_type: Mapped[str] = mapped_column(String(80), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    item_role: Mapped[str] = mapped_column(String(20), nullable=False)
    display_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        server_default=text("'{}'::jsonb"),
        nullable=False,
    )
    restore_order: Mapped[int] = mapped_column(Integer, nullable=False)
    purge_order: Mapped[int] = mapped_column(Integer, nullable=False)
