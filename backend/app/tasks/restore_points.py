"""Scheduled restore-point creation using the dedicated Celery worker."""

from __future__ import annotations

import asyncio
import secrets

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.celery_app.config import celery_app
from app.services.restore_points import (
    automatic_restore_point_due,
    cleanup_expired_restore_points,
    create_restore_point,
    delete_restore_point_artifacts,
)
from app.services.maintenance import acquire_restore_lock, maintenance_mode_active, release_restore_lock
from app.settings import settings


async def _run_automatic_restore_point() -> dict[str, object]:
    if await maintenance_mode_active():
        return {"created": False, "reason": "MAINTENANCE_MODE"}
    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    lock_token = secrets.token_urlsafe(32)
    try:
        if not await acquire_restore_lock(token=lock_token, ttl_seconds=900):
            return {"created": False, "reason": "LOCKED"}
        async with factory() as db:
            if not await automatic_restore_point_due(db):
                return {"created": False, "reason": "NOT_DUE"}
            point = await create_restore_point(
                db, source="AUTOMATIC", created_by_user_id=None,
                description="Scheduled automatic restore point.",
            )
            await db.commit()
            return {"created": True, "restore_point_id": str(point.id)}
    finally:
        try:
            await release_restore_lock(token=lock_token)
        except Exception:
            pass
        await engine.dispose()


@celery_app.task(name="fttw.restore_points.create_automatic")
def create_automatic_restore_point() -> dict[str, object]:
    return asyncio.run(_run_automatic_restore_point())


async def _cleanup_restore_point_retention() -> dict[str, object]:
    if await maintenance_mode_active():
        return {"deleted": 0, "reason": "MAINTENANCE_MODE"}
    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with factory() as db:
            result = await cleanup_expired_restore_points(db)
            await db.commit()
        for artifact_name in result.pop("artifact_names", []):
            delete_restore_point_artifacts(artifact_name)
        return result
    finally:
        await engine.dispose()


@celery_app.task(name="fttw.restore_points.cleanup_expired")
def cleanup_restore_point_retention() -> dict[str, object]:
    return asyncio.run(_cleanup_restore_point_retention())
