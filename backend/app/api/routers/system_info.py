"""Bounded read-only system status for the eventual settings UI."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, Depends
from redis.asyncio import Redis
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...models import AuditLog, RestorePoint
from ...schemas.system_info import SystemInformationRead
from ...security.authorization import authorize_request
from ...services.maintenance import maintenance_mode_active
from ...services.settings_registry import get_typed_setting
from ...settings import settings


router = APIRouter(
    prefix="/system-information",
    tags=["System Information"],
    dependencies=[Depends(authorize_request)],
)


async def _redis_status() -> str:
    client = Redis.from_url(settings.redis_url, decode_responses=True)
    try:
        return "ONLINE" if await client.ping() else "OFFLINE"
    except Exception:
        return "OFFLINE"
    finally:
        await client.aclose()


@router.get("", response_model=SystemInformationRead)
async def read_system_information(db: AsyncSession = Depends(get_db)):
    try:
        postgresql_version = str(await db.scalar(text("SHOW server_version")))
        database_status = "ONLINE"
        revision = await db.scalar(text("SELECT version_num FROM alembic_version LIMIT 1"))
    except Exception:
        postgresql_version = None
        database_status = "OFFLINE"
        revision = None

    last_automatic = await db.scalar(
        select(RestorePoint.completed_at)
        .where(RestorePoint.source == "AUTOMATIC", RestorePoint.status.in_(("READY", "RESTORED")))
        .order_by(RestorePoint.completed_at.desc())
        .limit(1)
    ) if database_status == "ONLINE" else None
    last_purge = await db.scalar(
        select(AuditLog.occurred_at)
        .where(AuditLog.action == "RECYCLE_PURGE_COMPLETED", AuditLog.result == "SUCCESS")
        .order_by(AuditLog.occurred_at.desc())
        .limit(1)
    ) if database_status == "ONLINE" else None
    log_root = Path(settings.data_root).resolve() / "logs"
    schedule = {
        "enabled": (await get_typed_setting(db, "restore_points.enabled"))["value"],
        "time": (await get_typed_setting(db, "restore_points.schedule_time"))["value"],
        "timezone": (await get_typed_setting(db, "restore_points.timezone"))["value"],
    }
    return SystemInformationRead(
        application_version=os.getenv("FTTW_APPLICATION_VERSION", "1.4.0"),
        database_status=database_status,
        postgresql_version=postgresql_version,
        alembic_revision=str(revision) if revision else None,
        redis_status=await _redis_status(),
        # No worker ping is fabricated; a later monitoring agent can expose a
        # verified liveness signal without changing this contract.
        worker_status=None,
        maintenance_mode=await maintenance_mode_active(),
        last_automatic_restore_point_at=last_automatic,
        restore_point_schedule=schedule,
        last_recycle_purge_at=last_purge,
        log_storage={"available": log_root.is_dir(), "path_kind": "managed_data_root"},
    )
