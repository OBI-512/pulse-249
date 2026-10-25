from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.celery_app.config import celery_app
from app.models import IntegrationConnector
from app.settings import settings
from app.integrations.sync import run_connector_sync


def _factory():
    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    return engine, async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def _sync_one(connector_id: UUID, mode: str) -> dict[str, object]:
    if not settings.integrations_enabled:
        return {"status": "DISABLED", "core_dependency": False}
    engine, SessionLocal = _factory()
    try:
        async with SessionLocal() as db:
            connector = await db.scalar(select(IntegrationConnector).where(IntegrationConnector.id == connector_id).with_for_update())
            if connector is None or not connector.enabled:
                return {"status": "SKIPPED", "reason": "CONNECTOR_DISABLED"}
            run = await run_connector_sync(db, connector, mode=mode)
            await db.commit()
            return {"status": run.status, "run_id": str(run.id), "received": run.records_received, "changed": run.records_changed}
    finally:
        await engine.dispose()


async def _reconcile_due() -> dict[str, object]:
    if not settings.integrations_enabled:
        return {"status": "DISABLED", "core_dependency": False, "queued": 0}
    engine, SessionLocal = _factory()
    try:
        now = datetime.now(timezone.utc)
        async with SessionLocal() as db:
            rows = list((await db.scalars(select(IntegrationConnector).where(IntegrationConnector.enabled.is_(True)))).all())
            due = []
            for row in rows:
                config = row.config or {}
                cooldown = max(0, min(int(config.get("circuit_breaker_seconds") or 60), 3600))
                if row.last_error_at is not None and cooldown and row.last_error_at + timedelta(seconds=cooldown) > now:
                    continue
                if row.last_reconciled_at is None or row.last_reconciled_at + timedelta(seconds=row.reconciliation_interval_seconds) <= now:
                    due.append(row)
        for row in due:
            celery_app.send_task("fttw.integrations.sync_connector", args=[str(row.id), "INCREMENTAL"], expires=300)
        return {"status": "QUEUED", "queued": len(due)}
    finally:
        await engine.dispose()


@celery_app.task(name="fttw.integrations.reconcile_due", time_limit=60, soft_time_limit=50)
def reconcile_due():
    return asyncio.run(_reconcile_due())


@celery_app.task(name="fttw.integrations.sync_connector", time_limit=300, soft_time_limit=270)
def sync_connector(connector_id: str, mode: str = "INCREMENTAL"):
    normalized = mode.upper()
    if normalized not in {"FULL", "INCREMENTAL"}:
        raise ValueError("Unsupported integration sync mode")
    return asyncio.run(_sync_one(UUID(connector_id), normalized))
