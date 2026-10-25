from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


AVAILABILITY_PROFILES = {"ICMP", "TCP", "SNMP"}
AVAILABILITY_STATES = {"ONLINE", "SUSPECT", "OFFLINE", "UNKNOWN", "MAINTENANCE"}


class DeviceAvailabilityUpdate(BaseModel):
    profile: str | None = Field(default=None, max_length=20)
    enabled: bool | None = None

    @field_validator("profile")
    @classmethod
    def validate_profile(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().upper()
        if normalized not in AVAILABILITY_PROFILES:
            raise ValueError("profile must be ICMP, TCP, or SNMP")
        return normalized


class DeviceAvailabilityRead(BaseModel):
    id: UUID
    device_id: UUID
    status: str
    profile: str
    enabled: bool
    last_check_at: datetime | None = None
    last_success_at: datetime | None = None
    last_failure_at: datetime | None = None
    status_changed_at: datetime
    consecutive_failures: int
    latency_ms: float | None = None
    last_result_code: str | None = None
    next_check_at: datetime
    last_dispatched_at: datetime | None = None
    lease_expires_at: datetime | None = None
    model_config = ConfigDict(from_attributes=True)


class DeviceAvailabilityPageItem(DeviceAvailabilityRead):
    display_name: str
    management_ip: str | None = None
    lifecycle_state: str


class DeviceAvailabilitySummary(BaseModel):
    online: int = 0
    suspect: int = 0
    offline: int = 0
    unknown: int = 0
    maintenance: int = 0
    total: int = 0
