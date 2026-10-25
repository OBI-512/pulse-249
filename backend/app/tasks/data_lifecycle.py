from __future__ import annotations

import asyncio

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.celery_app.config import celery_app
from app.services.data_lifecycle import run_all_lifecycle_once
from app.services.maintenance import maintenance_mode_active
from app.settings import settings as app_settings


async def _run_lifecycle() -> dict[str, object]:
    if await maintenance_mode_active():
        return {"status": "SKIPPED", "reason": "SYSTEM_MAINTENANCE_MODE"}
    engine = create_async_engine(app_settings.database_url, pool_pre_ping=True)
    SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with SessionLocal() as db:
            runs = await run_all_lifecycle_once(db)
            await db.commit()
            return {
                "status": "COMPLETED",
                "runs": [{"data_class": row.data_class, "status": row.status, "purged": row.purged_rows, "rolled_up": row.rolled_up_rows} for row in runs],
            }
    finally:
        await engine.dispose()


@celery_app.task(name="fttw.data_lifecycle.run", time_limit=900, soft_time_limit=840)
def run_data_lifecycle():
    return asyncio.run(_run_lifecycle())
