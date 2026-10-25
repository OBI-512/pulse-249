from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class DashboardAvailabilityCounts(BaseModel):
    total: int = 0
    online: int = 0
    suspect: int = 0
    offline: int = 0
    unknown: int = 0
    maintenance: int = 0


class DashboardAlarmCounts(BaseModel):
    active_total: int = 0
    unacknowledged: int = 0
    info: int = 0
    warning: int = 0
    minor: int = 0
    major: int = 0
    critical: int = 0


class DashboardBreakdown(BaseModel):
    key: str
    label: str
    context: str | None = None
    total: int = 0
    online: int = 0
    suspect: int = 0
    offline: int = 0
    unknown: int = 0
    maintenance: int = 0


class DashboardOutage(BaseModel):
    event_id: str
    device_id: str
    device_display_name: str
    occurred_at: datetime
    summary: str
    current_status: str | None = None
    network_name: str | None = None
    location_name: str | None = None


class DashboardPollingHealth(BaseModel):
    enabled: bool
    status: str
    interval_seconds: int
    worker_concurrency: int
    dispatch_limit_per_tick: int
    task_batch_size: int
    max_outstanding_devices: int
    monitored_devices: int
    due_now: int
    overdue: int
    active_leases: int
    checked_last_interval: int
    latest_check_at: datetime | None = None
    latest_dispatch_at: datetime | None = None
    worker_heartbeat_at: datetime | None = None
    worker_heartbeat_age_seconds: float | None = None
    redis_status: str


class OperationsDashboardRead(BaseModel):
    generated_at: datetime
    availability: DashboardAvailabilityCounts
    alarms: DashboardAlarmCounts | None = None
    authorized_device_categories: list[str] = Field(default_factory=list)
    by_device_type: list[DashboardBreakdown]
    by_network: list[DashboardBreakdown]
    top_locations: list[DashboardBreakdown]
    recent_outages: list[DashboardOutage]
    polling: DashboardPollingHealth
