"""Public API schemas for recoverable deletion and restoration."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import Field

from .common import APIModel, Timestamped


class RecycleBinItemRead(Timestamped):
    batch_id: UUID
    entity_type: str
    entity_id: UUID
    item_role: str
    display_snapshot: dict[str, Any] = Field(default_factory=dict)
    restore_order: int
    purge_order: int


class RecycleBinBatchSummary(Timestamped):
    root_entity_type: str
    root_entity_id: UUID
    root_display_snapshot: dict[str, Any] = Field(default_factory=dict)
    status: str
    deleted_at: datetime
    deleted_by_user_id: UUID | None = None
    deletion_reason: str | None = None
    purge_after: datetime
    restored_at: datetime | None = None
    restored_by_user_id: UUID | None = None
    last_attempt_at: datetime | None = None
    last_error_code: str | None = None
    last_error_message: str | None = None
    item_count: int = 0


class RecycleBinBatchDetail(RecycleBinBatchSummary):
    items: list[RecycleBinItemRead] = Field(default_factory=list)


class RecycleBinPage(APIModel):
    items: list[RecycleBinBatchSummary]
    total: int
    page: int
    page_size: int


class RecycleBinItemPage(APIModel):
    items: list[RecycleBinItemRead]
    total: int
    page: int
    page_size: int


class RecyclePreviewResponse(APIModel):
    root: dict[str, Any]
    bundled_items: list[dict[str, Any]] = Field(default_factory=list)
    blockers: list[dict[str, Any]] = Field(default_factory=list)
    requires_confirmation: bool = False
