"""Retention cleanup for rotated operational-log files."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.celery_app.config import celery_app
from app.observability.logging import log_directory
from app.services.maintenance import maintenance_mode_active
from app.services.settings_registry import get_typed_setting
from app.settings import settings


async def _cleanup() -> dict[str, object]:
    if await maintenance_mode_active():
        return {"deleted": 0, "reason": "MAINTENANCE_MODE"}
    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with factory() as db:
            days = int((await get_typed_setting(db, "logs.retention_days"))["value"])
    finally:
        await engine.dispose()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    deleted = 0
    for path in Path(log_directory()).glob("*.jsonl.*"):
        try:
            modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            if modified < cutoff:
                path.unlink(missing_ok=True)
                deleted += 1
        except OSError:
            continue
    return {"deleted": deleted, "retention_days": days}


@celery_app.task(name="fttw.operational_logs.cleanup")
def cleanup_operational_logs() -> dict[str, object]:
    return asyncio.run(_cleanup())
