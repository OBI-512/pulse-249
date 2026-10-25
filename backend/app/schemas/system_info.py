from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class SystemInformationRead(BaseModel):
    application_version: str
    database_status: str
    postgresql_version: str | None = None
    alembic_revision: str | None = None
    redis_status: str
    worker_status: str | None = None
    maintenance_mode: bool
    last_automatic_restore_point_at: datetime | None = None
    restore_point_schedule: dict[str, object]
    last_recycle_purge_at: datetime | None = None
    log_storage: dict[str, object]
