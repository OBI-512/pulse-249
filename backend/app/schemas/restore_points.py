from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class RestorePointCreate(BaseModel):
    description: str | None = Field(default=None, max_length=1000)


class RestorePointRestore(BaseModel):
    confirmation: str = Field(min_length=36, max_length=36)


class RestorePointRead(BaseModel):
    id: UUID
    source: str
    status: str
    description: str | None
    artifact_size: int | None
    sha256: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    retention_until: datetime | None
    pinned: bool
    failure_code: str | None
    failure_message: str | None

    model_config = {"from_attributes": True}


class RestorePointPage(BaseModel):
    items: list[RestorePointRead]
    total: int
    page: int
    page_size: int




class RestorePointRestoreAccepted(BaseModel):
    restore_point_id: UUID
    emergency_restore_point_id: UUID
    status: str
    request_id: str | None = None
    message: str


class RestorePointPin(BaseModel):
    pinned: bool
