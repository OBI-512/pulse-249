from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.celery_app.config import celery_app
from app.models import User
from app.schemas.configuration_batches import (
    ConfigurationBatchCreate,
    ConfigurationBatchDetail,
    ConfigurationBatchQueued,
    ConfigurationBatchRead,
    ConfigurationBatchTargetRead,
)
from app.security.authorization import authorize_request, get_current_user
from app.services.configuration_batches import (
    abort_batch,
    create_batch,
    get_batch_for_actor,
    list_batches_for_actor,
    pause_batch,
    resume_batch,
)


router = APIRouter(
    prefix="/configuration-batches",
    tags=["Configuration Management"],
    dependencies=[Depends(authorize_request)],
)


def _detail(batch, targets) -> ConfigurationBatchDetail:
    return ConfigurationBatchDetail(
        batch=ConfigurationBatchRead.model_validate(batch),
        targets=[ConfigurationBatchTargetRead.model_validate(row) for row in targets],
    )


def _request_dispatch(batch_id: UUID) -> None:
    # Batch dispatch is idempotent at the target-link boundary. Broker failure
    # here is non-destructive: Beat will discover the durable batch later and
    # no per-device operation has been emitted by this API helper.
    try:
        celery_app.send_task(
            "fttw.configuration.batch.dispatch",
            args=[str(batch_id)],
            queue="configuration",
        )
    except Exception:
        pass


@router.post("", response_model=ConfigurationBatchQueued, status_code=202)
async def create_configuration_batch(
    payload: ConfigurationBatchCreate,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    batch, created = await create_batch(db, payload=payload, actor=actor)
    await db.commit()
    if created:
        _request_dispatch(batch.id)
    return ConfigurationBatchQueued(
        batch_id=batch.id,
        status=batch.status,
        created=created,
    )


@router.get("", response_model=list[ConfigurationBatchRead])
async def list_configuration_batches(
    limit: int = Query(default=100, ge=1, le=500),
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    rows = await list_batches_for_actor(db, actor=actor, limit=limit)
    return [ConfigurationBatchRead.model_validate(row) for row in rows]


@router.get("/{batch_id}", response_model=ConfigurationBatchDetail)
async def get_configuration_batch(
    batch_id: UUID,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    batch, targets = await get_batch_for_actor(
        db, batch_id=batch_id, actor=actor
    )
    return _detail(batch, targets)


@router.post("/{batch_id}/pause", response_model=ConfigurationBatchDetail)
async def pause_configuration_batch(
    batch_id: UUID,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    batch = await pause_batch(db, batch_id=batch_id, actor=actor)
    await db.commit()
    batch, targets = await get_batch_for_actor(db, batch_id=batch.id, actor=actor)
    return _detail(batch, targets)


@router.post("/{batch_id}/resume", response_model=ConfigurationBatchDetail)
async def resume_configuration_batch(
    batch_id: UUID,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    batch = await resume_batch(db, batch_id=batch_id, actor=actor)
    await db.commit()
    _request_dispatch(batch.id)
    batch, targets = await get_batch_for_actor(db, batch_id=batch.id, actor=actor)
    return _detail(batch, targets)


@router.post("/{batch_id}/abort", response_model=ConfigurationBatchDetail)
async def abort_configuration_batch(
    batch_id: UUID,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    batch = await abort_batch(db, batch_id=batch_id, actor=actor)
    await db.commit()
    try:
        celery_app.send_task(
            "fttw.configuration.batch.reconcile",
            args=[str(batch.id)],
            queue="configuration",
        )
    except Exception:
        pass
    batch, targets = await get_batch_for_actor(db, batch_id=batch.id, actor=actor)
    return _detail(batch, targets)
