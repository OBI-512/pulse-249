from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...models import RestorePoint, User
from ...schemas.restore_points import RestorePointCreate, RestorePointPage, RestorePointPin, RestorePointRead, RestorePointRestore, RestorePointRestoreAccepted
from ...security.authorization import authorize_request
from ...services.restore_points import (
    create_restore_point,
    delete_restore_point,
    delete_restore_point_artifacts,
    get_restore_point,
    request_database_restore,
    set_restore_point_pin,
    verify_restore_point,
)
from ...services.maintenance import clear_maintenance_mode, release_restore_lock
from ...services.audit import record_failure_audit



router = APIRouter(
    prefix="/restore-points",
    tags=["Restore Points"],
    dependencies=[Depends(authorize_request)],
)


def _restore_point_base(status: str | None = None):
    statement = select(RestorePoint).where(RestorePoint.status != "DELETED")
    if status:
        statement = statement.where(RestorePoint.status == status.upper())
    return statement


@router.get("", response_model=list[RestorePointRead])
async def list_restore_points(
    limit: int = Query(100, ge=1, le=500),
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Compatibility endpoint retained for existing clients and tests."""
    statement = _restore_point_base(status).order_by(RestorePoint.created_at.desc(), RestorePoint.id).limit(limit)
    return list((await db.scalars(statement)).all())


@router.get("/page", response_model=RestorePointPage)
async def page_restore_points(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    status: str | None = None,
    source: str | None = None,
    pinned: bool | None = None,
    search: str | None = Query(None, max_length=200),
    sort_by: str = Query("created_at", max_length=40),
    sort_direction: str = Query("desc", pattern="^(?i:asc|desc)$"),
    db: AsyncSession = Depends(get_db),
):
    statement = _restore_point_base(status)
    if source:
        statement = statement.where(RestorePoint.source == source.upper())
    if pinned is not None:
        statement = statement.where(RestorePoint.pinned.is_(pinned))
    if search and search.strip():
        pattern = f"%{search.strip()}%"
        statement = statement.where(or_(
            RestorePoint.description.ilike(pattern),
            RestorePoint.artifact_name.ilike(pattern),
            RestorePoint.failure_code.ilike(pattern),
            RestorePoint.request_id.ilike(pattern),
        ))
    sort_map = {
        "created_at": RestorePoint.created_at, "source": RestorePoint.source, "status": RestorePoint.status,
        "description": RestorePoint.description, "artifact_size": RestorePoint.artifact_size,
        "retention_until": RestorePoint.retention_until, "pinned": RestorePoint.pinned,
    }
    sort_expr = sort_map.get(sort_by)
    if sort_expr is None:
        from fastapi import HTTPException
        raise HTTPException(422, detail={"code":"INVALID_RESTORE_POINT_SORT","message":"Unsupported restore-point sort column."})
    total_stmt = select(func.count()).select_from(statement.order_by(None).subquery())
    total = int((await db.scalar(total_stmt)) or 0)
    order = sort_expr.desc() if sort_direction.lower() == "desc" else sort_expr.asc()
    statement = statement.order_by(order.nullslast(), RestorePoint.id.asc()).offset((page - 1) * page_size).limit(page_size)
    items = list((await db.scalars(statement)).all())
    return RestorePointPage(items=items, total=total, page=page, page_size=page_size)


@router.get("/{restore_point_id}", response_model=RestorePointRead)
async def read_restore_point(restore_point_id: UUID, db: AsyncSession = Depends(get_db)):
    return await get_restore_point(db, restore_point_id)


@router.post("", response_model=RestorePointRead, status_code=201)
async def create_manual_restore_point(
    payload: RestorePointCreate,
    actor: User = Depends(authorize_request),
    db: AsyncSession = Depends(get_db),
):
    point = await create_restore_point(
        db, source="MANUAL", created_by_user_id=actor.id, description=payload.description
    )
    await db.commit()
    await db.refresh(point)
    return point


@router.post("/{restore_point_id}/verify", response_model=RestorePointRead)
async def verify_point(restore_point_id: UUID, db: AsyncSession = Depends(get_db)):
    point = await verify_restore_point(db, restore_point_id=restore_point_id)
    await db.commit()
    await db.refresh(point)
    return point


@router.post(
    "/{restore_point_id}/restore",
    response_model=RestorePointRestoreAccepted,
    status_code=202,
)
async def restore_point(
    restore_point_id: UUID,
    payload: RestorePointRestore,
    actor: User = Depends(authorize_request),
    db: AsyncSession = Depends(get_db),
):
    task_args = await request_database_restore(
        db, restore_point_id=restore_point_id, confirmation=payload.confirmation,
        actor_user_id=actor.id, actor_username_snapshot=actor.username,
        actor_display_name_snapshot=actor.display_name,
    )
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        await clear_maintenance_mode()
        try:
            await release_restore_lock(token=str(task_args["lock_token"]))
        except Exception:
            pass
        raise

    try:
        # Import lazily so the API process only dispatches the privileged task;
        # it never imports or calls pg_restore execution code directly.
        from ...tasks.restore_control import execute_database_restore
        execute_database_restore.apply_async(
            kwargs=task_args, queue="restore_control",
        )
    except Exception as exc:
        # The database preparation committed but the control task was not
        # queued. Restore a safe READY state and release external maintenance.
        point = await get_restore_point(db, restore_point_id, lock=True)
        point.status = "READY"
        emergency_id = task_args.get("emergency_point_id")
        if emergency_id:
            try:
                emergency = await get_restore_point(db, UUID(str(emergency_id)), lock=True)
                emergency.pinned = False
            except Exception:
                pass
        await db.commit()
        await record_failure_audit(
            action="SYSTEM_RESTORE_FAILED", entity_type="RestorePoint", entity_id=restore_point_id,
            actor_user_id=actor.id, actor_username_snapshot=actor.username,
            actor_display_name_snapshot=actor.display_name,
            description="Restore-control task could not be dispatched.",
            metadata={"error_type": type(exc).__name__},
        )
        await clear_maintenance_mode()
        try:
            await release_restore_lock(token=str(task_args["lock_token"]))
        except Exception:
            pass
        raise
    return RestorePointRestoreAccepted(
        restore_point_id=restore_point_id,
        emergency_restore_point_id=UUID(str(task_args["emergency_point_id"])),
        status="RESTORING",
        request_id=str(task_args.get("request_id") or "") or None,
        message=(
            "Restore safety checks passed and the restore job was queued. "
            "This is not a success confirmation; completion is determined by "
            "the restore-control worker."
        ),
    )


@router.patch("/{restore_point_id}/pin", response_model=RestorePointRead)
async def pin_restore_point(
    restore_point_id: UUID,
    payload: RestorePointPin,
    db: AsyncSession = Depends(get_db),
):
    point = await set_restore_point_pin(db, restore_point_id=restore_point_id, pinned=payload.pinned)
    await db.commit()
    await db.refresh(point)
    return point


@router.delete("/{restore_point_id}", status_code=204)
async def remove_restore_point(
    restore_point_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    point = await delete_restore_point(db, restore_point_id=restore_point_id)
    artifact_name = point.artifact_name
    await db.commit()
    delete_restore_point_artifacts(artifact_name)
    return Response(status_code=204)
