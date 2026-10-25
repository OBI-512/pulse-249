"""Administrator-facing API for recoverable deletion lifecycle actions."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import Text, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...models import RecycleBinBatch, RecycleBinItem, User
from ...models.recycle import RECYCLE_ITEM_ENTITY_TYPES, RECYCLE_ROOT_ENTITY_TYPES
from ...schemas.recycle_bin import (
    RecycleBinBatchDetail,
    RecycleBinBatchSummary,
    RecycleBinItemPage,
    RecycleBinItemRead,
    RecycleBinPage,
    RecyclePreviewResponse,
)
from ...security.authorization import authorize_request
from ...security.resource_scope import not_found_scope_error, scope_for_actor
from ...security.recycle_scope import batch_is_in_scope, preview_scope_conflicts, recycle_batch_scope_clause
from ...services.audit import record_audit, record_failure_audit
from ...services.recycle_bin import (
    RecycleBinError,
    get_recycle_batch,
    preview_recycle,
    purge_recycle_batch,
    restore_recycle_batch,
)


router = APIRouter(
    prefix="/recycle-bin",
    tags=["Recycle Bin"],
    dependencies=[Depends(authorize_request)],
)

_VISIBLE_STATUSES = frozenset({"RECYCLED", "RESTORED", "PURGE_FAILED"})


def _raise_service_error(exc: RecycleBinError) -> None:
    detail: dict[str, Any] = {"code": exc.code, "message": exc.message}
    if exc.conflicts:
        detail["conflicts"] = exc.conflicts
    raise HTTPException(status_code=exc.status_code, detail=detail) from exc


def _as_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if is_dataclass(value):
        return asdict(value)
    if hasattr(value, "model_dump"):
        return value.model_dump()
    return {
        key: item
        for key, item in vars(value).items()
        if not key.startswith("_")
    }


def _batch_summary(batch: RecycleBinBatch, item_count: int) -> RecycleBinBatchSummary:
    return RecycleBinBatchSummary.model_validate(
        {**batch.__dict__, "item_count": item_count}
    )


def _batch_detail(
    batch: RecycleBinBatch,
    items: list[RecycleBinItem],
) -> RecycleBinBatchDetail:
    return RecycleBinBatchDetail.model_validate(
        {
            **batch.__dict__,
            "item_count": len(items),
            "items": items,
        }
    )


def _validate_entity_type(value: str, *, include_internal: bool = False) -> str:
    normalized = value.strip().upper()
    allowed = RECYCLE_ITEM_ENTITY_TYPES if include_internal else RECYCLE_ROOT_ENTITY_TYPES
    if normalized not in allowed:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "code": "UNSUPPORTED_RECYCLE_ENTITY_TYPE",
                "message": f"Entity type '{normalized}' is not recoverable.",
            },
        )
    return normalized


@router.get("", response_model=RecycleBinPage)
async def list_recycle_batches(
    status_filter: str | None = Query(None, alias="status"),
    entity_type: str | None = None,
    search: str | None = Query(None, min_length=1, max_length=200),
    deleted_after: datetime | None = None,
    deleted_before: datetime | None = None,
    purge_before: datetime | None = None,
    sort_by: str = Query("deleted_at", min_length=1, max_length=40),
    sort_direction: str = Query("desc", min_length=3, max_length=4),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    filters = [await recycle_batch_scope_clause(db, scope)]
    if status_filter and status_filter.strip().upper() not in {"ALL", "HISTORY"}:
        normalized_status = status_filter.strip().upper()
        if normalized_status not in _VISIBLE_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "code": "INVALID_RECYCLE_STATUS",
                    "message": f"Unsupported recycle status '{normalized_status}'.",
                },
            )
        filters.append(RecycleBinBatch.status == normalized_status)
    elif not status_filter:
        filters.append(
            RecycleBinBatch.status.in_(("RECYCLED", "PURGE_FAILED"))
        )
    if entity_type:
        filters.append(
            RecycleBinBatch.root_entity_type
            == _validate_entity_type(entity_type)
        )
    if search:
        pattern = f"%{search.strip()}%"
        filters.append(
            or_(
                RecycleBinBatch.root_entity_type.ilike(pattern),
                cast(RecycleBinBatch.root_display_snapshot, Text).ilike(pattern),
                RecycleBinBatch.deletion_reason.ilike(pattern),
            )
        )
    if deleted_after:
        filters.append(RecycleBinBatch.deleted_at >= deleted_after)
    if deleted_before:
        filters.append(RecycleBinBatch.deleted_at <= deleted_before)
    if purge_before:
        filters.append(RecycleBinBatch.purge_after <= purge_before)

    total = await db.scalar(
        select(func.count(RecycleBinBatch.id)).where(*filters)
    )

    item_count = func.count(RecycleBinItem.id)
    display_name = func.coalesce(
        RecycleBinBatch.root_display_snapshot["label"].as_string(),
        RecycleBinBatch.root_display_snapshot["display_name"].as_string(),
        RecycleBinBatch.root_display_snapshot["name"].as_string(),
        RecycleBinBatch.root_display_snapshot["code"].as_string(),
        cast(RecycleBinBatch.root_entity_id, Text),
    )
    sort_fields = {
        "root_entity_type": RecycleBinBatch.root_entity_type,
        "display": display_name,
        "deleted_at": RecycleBinBatch.deleted_at,
        "purge_after": RecycleBinBatch.purge_after,
        "item_count": item_count,
        "status": RecycleBinBatch.status,
    }
    normalized_sort = sort_by.strip().lower()
    normalized_direction = sort_direction.strip().lower()
    if normalized_sort not in sort_fields:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "code": "INVALID_RECYCLE_SORT",
                "message": f"Unsupported recycle sort field '{normalized_sort}'.",
            },
        )
    if normalized_direction not in {"asc", "desc"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "code": "INVALID_RECYCLE_SORT_DIRECTION",
                "message": f"Unsupported recycle sort direction '{normalized_direction}'.",
            },
        )
    sort_expression = sort_fields[normalized_sort]
    primary_order = sort_expression.asc() if normalized_direction == "asc" else sort_expression.desc()

    statement = (
        select(RecycleBinBatch, item_count)
        .outerjoin(
            RecycleBinItem,
            RecycleBinItem.batch_id == RecycleBinBatch.id,
        )
        .where(*filters)
        .group_by(RecycleBinBatch.id)
        .order_by(primary_order, RecycleBinBatch.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = (await db.execute(statement)).all()
    return RecycleBinPage(
        items=[_batch_summary(batch, item_count) for batch, item_count in rows],
        total=total or 0,
        page=page,
        page_size=page_size,
    )


@router.get("/items", response_model=RecycleBinItemPage)
async def list_recycle_items(
    batch_id: UUID | None = None,
    entity_type: str | None = None,
    batch_status: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    filters = []
    batch_filters = [await recycle_batch_scope_clause(db, scope)]
    if batch_id:
        filters.append(RecycleBinItem.batch_id == batch_id)
    if entity_type:
        filters.append(
            RecycleBinItem.entity_type
            == _validate_entity_type(entity_type, include_internal=True)
        )

    if batch_status and batch_status.strip().upper() not in {"ALL", "HISTORY"}:
        normalized_status = batch_status.strip().upper()
        if normalized_status not in _VISIBLE_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "code": "INVALID_RECYCLE_STATUS",
                    "message": f"Unsupported recycle status '{normalized_status}'.",
                },
            )
        batch_filters.append(RecycleBinBatch.status == normalized_status)
    elif not batch_status:
        batch_filters.append(
            RecycleBinBatch.status.in_(("RECYCLED", "PURGE_FAILED"))
        )

    total = await db.scalar(
        select(func.count(RecycleBinItem.id))
        .join(RecycleBinBatch, RecycleBinBatch.id == RecycleBinItem.batch_id)
        .where(*filters, *batch_filters)
    )
    items = (
        await db.scalars(
            select(RecycleBinItem)
            .join(RecycleBinBatch, RecycleBinBatch.id == RecycleBinItem.batch_id)
            .where(*filters, *batch_filters)
            .order_by(
                RecycleBinItem.created_at.desc(),
                RecycleBinItem.restore_order,
                RecycleBinItem.id,
            )
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()
    return RecycleBinItemPage(
        items=[RecycleBinItemRead.model_validate(item) for item in items],
        total=total or 0,
        page=page,
        page_size=page_size,
    )


@router.get("/preview", response_model=RecyclePreviewResponse)
async def preview_recycle_dependencies(
    entity_type: str,
    entity_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    try:
        preview = await preview_recycle(
            db,
            entity_type=_validate_entity_type(entity_type),
            entity_id=entity_id,
        )
    except RecycleBinError as exc:
        _raise_service_error(exc)

    conflicts = await preview_scope_conflicts(
        db, actor_user_id=getattr(actor, "id", None), entity_type=preview.entity_type,
        entity_id=preview.entity_id, bundled_items=list(preview.bundled_items),
    )
    if conflicts:
        raise HTTPException(status_code=404, detail={"code": "RESOURCE_NOT_FOUND", "message": "Resource not found."})

    return RecyclePreviewResponse(
        root={
            "entity_type": preview.entity_type,
            "entity_id": preview.entity_id,
            "display_snapshot": preview.display_snapshot,
        },
        bundled_items=[_as_mapping(item) for item in preview.bundled_items],
        blockers=[_as_mapping(blocker) for blocker in preview.blockers],
        requires_confirmation=preview.requires_confirmation,
    )


@router.get("/{batch_id}", response_model=RecycleBinBatchDetail)
async def retrieve_recycle_batch(
    batch_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    if not scope.global_access and await batch_is_in_scope(db, scope, batch_id) is None:
        raise not_found_scope_error("Recycle batch")
    try:
        batch, items = await get_recycle_batch(db, batch_id=batch_id)
    except RecycleBinError as exc:
        _raise_service_error(exc)
    return _batch_detail(batch, items)


@router.post("/{batch_id}/restore", response_model=RecycleBinBatchDetail)
async def restore_batch(
    batch_id: UUID,
    actor: User | None = Depends(authorize_request),
    db: AsyncSession = Depends(get_db),
):
    actor_id = getattr(actor, "id", None)
    scope = await scope_for_actor(db, actor)
    if not scope.global_access and await batch_is_in_scope(db, scope, batch_id) is None:
        raise not_found_scope_error("Recycle batch")
    try:
        batch, _ = await get_recycle_batch(db, batch_id=batch_id)
    except RecycleBinError as exc:
        _raise_service_error(exc)
    root_snapshot = batch.root_display_snapshot
    await record_audit(
        db,
        action="RECYCLE_RESTORE_STARTED",
        entity_type="RecycleBinBatch",
        entity_id=batch_id,
        entity_display_snapshot=root_snapshot,
        description="Recycle-bin restore workflow started.",
        actor_user_id=actor_id,
        metadata={
            "root_entity_type": batch.root_entity_type,
            "root_entity_id": str(batch.root_entity_id),
        },
    )
    await db.commit()
    try:
        batch = await restore_recycle_batch(
            db,
            batch_id=batch_id,
            actor_user_id=actor_id,
        )
        _, items = await get_recycle_batch(db, batch_id=batch.id)
        await record_audit(
            db,
            action="RECYCLE_RESTORE_COMPLETED",
            entity_type="RecycleBinBatch",
            entity_id=batch_id,
            entity_display_snapshot=root_snapshot,
            description="Recycle-bin restore workflow completed.",
            actor_user_id=actor_id,
            before_summary={"status": "RECYCLED"},
            after_summary={"status": "RESTORED"},
            metadata={
                "root_entity_type": batch.root_entity_type,
                "root_entity_id": str(batch.root_entity_id),
                "item_count": len(items),
            },
        )
        await db.commit()
    except RecycleBinError as exc:
        await db.rollback()
        await record_failure_audit(
            action="RECYCLE_RESTORE_FAILED",
            entity_type="RecycleBinBatch",
            entity_id=batch_id,
            entity_display_snapshot=root_snapshot,
            description="Recycle-bin restore workflow failed.",
            actor_user_id=actor_id,
            metadata={"error_code": exc.code},
        )
        _raise_service_error(exc)
    except Exception as exc:
        await db.rollback()
        await record_failure_audit(
            action="RECYCLE_RESTORE_FAILED",
            entity_type="RecycleBinBatch",
            entity_id=batch_id,
            entity_display_snapshot=root_snapshot,
            description="Recycle-bin restore workflow failed.",
            actor_user_id=actor_id,
            metadata={"error_type": type(exc).__name__},
        )
        raise
    return _batch_detail(batch, items)


@router.delete("/{batch_id}", status_code=status.HTTP_204_NO_CONTENT)
async def permanently_purge_batch(
    batch_id: UUID,
    force: bool = False,
    confirmation: str | None = None,
    actor: User | None = Depends(authorize_request),
    db: AsyncSession = Depends(get_db),
):
    actor_id = getattr(actor, "id", None)
    scope = await scope_for_actor(db, actor)
    if not scope.global_access and await batch_is_in_scope(db, scope, batch_id) is None:
        raise not_found_scope_error("Recycle batch")
    if force and confirmation != str(batch_id):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "code": "RECYCLE_PURGE_CONFIRMATION_INVALID",
                "message": (
                    "Early permanent purge requires confirmation equal to "
                    "the recycle batch UUID."
                ),
            },
        )
    try:
        batch, items = await get_recycle_batch(db, batch_id=batch_id)
    except RecycleBinError as exc:
        _raise_service_error(exc)
    root_snapshot = batch.root_display_snapshot
    root_entity_type = batch.root_entity_type
    root_entity_id = batch.root_entity_id
    await record_audit(
        db,
        action="RECYCLE_PURGE_STARTED",
        entity_type="RecycleBinBatch",
        entity_id=batch_id,
        entity_display_snapshot=root_snapshot,
        description="Recycle-bin purge workflow started.",
        actor_user_id=actor_id,
        metadata={
            "root_entity_type": root_entity_type,
            "root_entity_id": str(root_entity_id),
            "item_count": len(items),
            "force": force,
        },
    )
    await db.commit()
    try:
        await purge_recycle_batch(
            db,
            batch_id=batch_id,
            actor_user_id=actor_id,
            enforce_retention=not force,
        )
        await record_audit(
            db,
            action="RECYCLE_PURGE_COMPLETED",
            entity_type="RecycleBinBatch",
            entity_id=batch_id,
            entity_display_snapshot=root_snapshot,
            description="Recycle-bin purge workflow completed.",
            actor_user_id=actor_id,
            before_summary={"status": batch.status},
            after_summary={"status": "PURGED"},
            metadata={
                "root_entity_type": root_entity_type,
                "root_entity_id": str(root_entity_id),
                "item_count": len(items),
                "force": force,
            },
        )
        await db.commit()
    except RecycleBinError as exc:
        await db.rollback()
        await record_failure_audit(
            action="RECYCLE_PURGE_FAILED",
            entity_type="RecycleBinBatch",
            entity_id=batch_id,
            entity_display_snapshot=root_snapshot,
            description="Recycle-bin purge workflow failed.",
            actor_user_id=actor_id,
            metadata={"error_code": exc.code, "force": force},
        )
        _raise_service_error(exc)
    except Exception as exc:
        await db.rollback()
        await record_failure_audit(
            action="RECYCLE_PURGE_FAILED",
            entity_type="RecycleBinBatch",
            entity_id=batch_id,
            entity_display_snapshot=root_snapshot,
            description="Recycle-bin purge workflow failed.",
            actor_user_id=actor_id,
            metadata={"error_type": type(exc).__name__, "force": force},
        )
        raise
    return None
