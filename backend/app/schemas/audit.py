"""Public schemas for immutable audit evidence."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import Field

from .common import APIModel


class AuditLogRead(APIModel):
    id: UUID
    occurred_at: datetime
    actor_user_id: UUID | None = None
    actor_username_snapshot: str | None = None
    actor_display_name_snapshot: str | None = None
    action: str
    entity_type: str | None = None
    entity_id: UUID | None = None
    entity_display_snapshot: dict[str, Any] | None = None
    result: str
    request_id: str | None = None
    source_ip: str | None = None
    description: str | None = None
    before_summary: dict[str, Any] | None = None
    after_summary: dict[str, Any] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditLogPage(APIModel):
    items: list[AuditLogRead]
    total: int
    page: int
    page_size: int
