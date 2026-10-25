"""Scheduled recycle-bin retention work.

The task owns its database transaction. Domain services only stage changes, so
one failed batch cannot leave partially purged business data behind.
"""

from __future__ import annotations

import asyncio

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.celery_app.config import celery_app
from app.services.recycle_bin import purge_due_batches
from app.services.audit import record_audit, record_failure_audit
from app.settings import settings
from app.services.maintenance import maintenance_mode_active


async def _purge_expired() -> dict[str, object]:
    if await maintenance_mode_active():
        return {"considered": 0, "purged": 0, "failed": 0, "batch_ids": [], "reason": "MAINTENANCE_MODE"}
    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    try:
        async with session_factory() as db:
            try:
                await record_audit(
                    db,
                    action="RECYCLE_PURGE_STARTED",
                    entity_type="RecycleBinScheduler",
                    description="Scheduled recycle-bin purge started.",
                    metadata={"execution": "celery"},
                )
                await db.commit()
                result = await purge_due_batches(db)
                await record_audit(
                    db,
                    action="RECYCLE_PURGE_COMPLETED",
                    entity_type="RecycleBinScheduler",
                    description="Scheduled recycle-bin purge completed.",
                    after_summary={
                        "considered": result.considered,
                        "purged": result.purged,
                        "failed": result.failed,
                    },
                    metadata={"execution": "celery"},
                )
                await db.commit()
            except Exception as exc:
                await db.rollback()
                await record_failure_audit(
                    action="RECYCLE_PURGE_FAILED",
                    entity_type="RecycleBinScheduler",
                    description="Scheduled recycle-bin purge failed.",
                    metadata={
                        "execution": "celery",
                        "error_type": type(exc).__name__,
                    },
                )
                raise

        if isinstance(result, dict):
            return result
        if isinstance(result, int):
            return {"considered": result, "purged": result, "failed": 0, "batch_ids": []}
        return {
            "considered": result.considered,
            "purged": result.purged,
            "failed": result.failed,
            "batch_ids": [str(batch_id) for batch_id in result.batch_ids],
        }
    finally:
        await engine.dispose()


@celery_app.task(name="fttw.recycle_bin.purge_expired")
def purge_expired_recycle_bin() -> dict[str, object]:
    return asyncio.run(_purge_expired())
