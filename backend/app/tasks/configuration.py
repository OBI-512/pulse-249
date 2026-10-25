from __future__ import annotations

import asyncio
import logging
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.celery_app.config import celery_app
from app.models import ConfigurationOperation
from app.services.configuration import execute_operation, mark_interrupted_operation
from app.settings import settings


logger = logging.getLogger(__name__)


def _factory():
    # Celery invokes asyncio.run() per task. NullPool prevents asyncpg
    # connections from surviving into a different event loop between tasks.
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


async def _run(operation_id: UUID, *, redelivered: bool) -> dict[str, str]:
    engine, SessionLocal = _factory()
    try:
        async with SessionLocal() as db:
            current = await db.scalar(
                select(ConfigurationOperation).where(
                    ConfigurationOperation.id == operation_id
                )
            )
            if current is None:
                return {"operation_id": str(operation_id), "status": "MISSING"}
            if redelivered and current.status in {"RUNNING", "ROLLING_BACK"}:
                status = await mark_interrupted_operation(db, operation_id)
                return {"operation_id": str(operation_id), "status": status}

        async with SessionLocal() as db:
            status = await execute_operation(db, operation_id)
            return {"operation_id": str(operation_id), "status": status}
    except Exception:
        # If an exception escapes the service boundary (including a task time
        # limit), fail any active state closed. Never leave a RUNNING operation
        # indefinitely locked after the broker has already accepted the task.
        try:
            async with SessionLocal() as recovery_db:
                current = await recovery_db.scalar(
                    select(ConfigurationOperation).where(
                        ConfigurationOperation.id == operation_id
                    )
                )
                if current is not None and current.status in {"RUNNING", "ROLLING_BACK"}:
                    await mark_interrupted_operation(recovery_db, operation_id)
        except Exception:
            pass
        # Do not emit exception text/tracebacks here: adapter/transport failures
        # can carry device-originated text. The durable operation record stores a
        # controlled failure code; logs contain only the operation identifier.
        logger.error(
            "configuration_operation_task_failed",
            extra={
                "event": "CONFIGURATION_OPERATION_TASK_FAILED",
                "operation_id": str(operation_id),
            },
        )
        raise
    finally:
        await engine.dispose()


@celery_app.task(
    bind=True,
    name="fttw.configuration.execute",
    time_limit=1800,
    soft_time_limit=1740,
)
def execute_configuration_operation(self, operation_id: str):
    delivery = getattr(self.request, "delivery_info", None) or {}
    return asyncio.run(
        _run(
            UUID(operation_id),
            redelivered=bool(delivery.get("redelivered")),
        )
    )
