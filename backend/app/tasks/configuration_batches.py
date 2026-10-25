from __future__ import annotations

import asyncio
import logging
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.celery_app.config import celery_app
from app.services.configuration_batches import (
    dispatch_batch,
    due_batch_ids,
    reconcile_batch,
)
from app.settings import settings


logger = logging.getLogger(__name__)


def _factory():
    engine = create_async_engine(
        settings.database_url,
        pool_pre_ping=True,
        poolclass=NullPool,
    )
    return engine, async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )


async def _dispatch(batch_id: UUID) -> dict[str, str]:
    engine, SessionLocal = _factory()
    try:
        async with SessionLocal() as db:
            batch = await dispatch_batch(db, batch_id)
            if batch is None:
                return {"batch_id": str(batch_id), "status": "MISSING"}
            return {"batch_id": str(batch.id), "status": batch.status}
    finally:
        await engine.dispose()


async def _reconcile(batch_id: UUID) -> dict[str, str]:
    engine, SessionLocal = _factory()
    try:
        async with SessionLocal() as db:
            batch = await reconcile_batch(db, batch_id)
            await db.commit()
            if batch is None:
                return {"batch_id": str(batch_id), "status": "MISSING"}
            return {"batch_id": str(batch.id), "status": batch.status}
    finally:
        await engine.dispose()


async def _sweep() -> dict[str, int]:
    engine, SessionLocal = _factory()
    processed = 0
    try:
        async with SessionLocal() as db:
            batch_ids = await due_batch_ids(db, limit=100)
        for batch_id in batch_ids:
            try:
                async with SessionLocal() as db:
                    await dispatch_batch(db, batch_id)
                processed += 1
            except Exception:
                # Never log request payload, configuration text, device output,
                # credentials, or exception text from an orchestration failure.
                logger.error(
                    "configuration_batch_sweep_failed",
                    extra={
                        "event": "CONFIGURATION_BATCH_SWEEP_FAILED",
                        "batch_id": str(batch_id),
                    },
                )
        return {"candidates": len(batch_ids), "processed": processed}
    finally:
        await engine.dispose()


@celery_app.task(
    name="fttw.configuration.batch.dispatch",
    time_limit=300,
    soft_time_limit=270,
)
def dispatch_configuration_batch(batch_id: str):
    return asyncio.run(_dispatch(UUID(batch_id)))


@celery_app.task(
    name="fttw.configuration.batch.reconcile",
    time_limit=120,
    soft_time_limit=100,
)
def reconcile_configuration_batch(batch_id: str):
    return asyncio.run(_reconcile(UUID(batch_id)))


@celery_app.task(
    name="fttw.configuration.batch.sweep",
    time_limit=300,
    soft_time_limit=270,
)
def sweep_configuration_batches():
    return asyncio.run(_sweep())
