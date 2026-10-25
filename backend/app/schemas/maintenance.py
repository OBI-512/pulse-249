from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class MaintenanceWindowCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    reason: str | None = Field(default=None, max_length=4000)
    target_type: str
    target_id: UUID
    starts_at: datetime
    ends_at: datetime

    @field_validator("target_type")
    @classmethod
    def normalize_target_type(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in {"DEVICE", "LOCATION", "CITY", "GROUP", "NETWORK"}:
            raise ValueError("target_type must be DEVICE, LOCATION, CITY, GROUP, or NETWORK")
        return normalized

    @field_validator("starts_at", "ends_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("maintenance timestamps must include a timezone")
        return value


class MaintenanceWindowUpdate(MaintenanceWindowCreate):
    """Full replacement payload for editing an upcoming maintenance window."""



class MaintenanceWindowCancel(BaseModel):
    reason: str | None = Field(default=None, max_length=1000)


class MaintenanceWindowRead(BaseModel):
    id: UUID
    name: str
    reason: str | None = None
    target_type: str
    target_id: UUID
    target_display_name: str
    starts_at: datetime
    ends_at: datetime
    enabled: bool
    cancelled_at: datetime | None = None
    created_by_user_id: UUID | None = None
    cancelled_by_user_id: UUID | None = None
    state: str
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class MaintenanceTargetOption(BaseModel):
    id: UUID
    target_type: str
    label: str
    context: str | None = None
