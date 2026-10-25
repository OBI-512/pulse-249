from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class AlarmAcknowledgeRequest(BaseModel):
    note: str | None = Field(default=None, max_length=1000)


class AlarmOwnerUpdate(BaseModel):
    owner_user_id: UUID | None = None
    note: str | None = Field(default=None, max_length=1000)


class AlarmClearRequest(BaseModel):
    note: str | None = Field(default=None, max_length=1000)


class AlarmRead(BaseModel):
    id: UUID
    device_id: UUID
    alarm_type: str
    correlation_key: str
    severity: str
    state: str
    summary: str
    first_raised_at: datetime
    last_raised_at: datetime
    last_cleared_at: datetime | None = None
    acknowledged_at: datetime | None = None
    acknowledged_by_user_id: UUID | None = None
    owner_user_id: UUID | None = None
    occurrence_count: int
    last_event_id: UUID | None = None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class AlarmPageItem(AlarmRead):
    device_display_name: str
    availability_status: str | None = None
    management_ip: str | None = None
    owner_display_name: str | None = None
    acknowledged_by_display_name: str | None = None


class AlarmSummary(BaseModel):
    active_total: int = 0
    unacknowledged: int = 0
    info: int = 0
    warning: int = 0
    minor: int = 0
    major: int = 0
    critical: int = 0


class AlarmHistoryRead(BaseModel):
    id: UUID
    alarm_id: UUID
    event_id: UUID | None = None
    occurred_at: datetime
    action: str
    actor_user_id: UUID | None = None
    actor_display_name: str | None = None
    note: str | None = None
    before_summary: dict | None = None
    after_summary: dict | None = None
    metadata: dict = Field(default_factory=dict)


class OperationalEventRead(BaseModel):
    id: UUID
    device_id: UUID
    event_type: str
    severity: str
    correlation_key: str
    occurred_at: datetime
    summary: str
    metadata: dict = Field(default_factory=dict)
    model_config = ConfigDict(from_attributes=True)
