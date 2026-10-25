from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...core.exceptions import APIError
from ...models import City, Device, DeviceGroup, DevicePlacement, Location, MaintenanceWindow, Network
from ...schemas.maintenance import MaintenanceTargetOption, MaintenanceWindowCancel, MaintenanceWindowCreate, MaintenanceWindowRead, MaintenanceWindowUpdate
from ...schemas.pagination import PageResult
from ...security.authorization import authorize_request
from ...security.resource_scope import scope_for_actor
from ...security.scope_queries import city_scope_clause, device_scope_clause, group_scope_clause, location_scope_clause, network_scope_clause
from ...services.maintenance_windows import (
    cancel_maintenance_window,
    create_maintenance_window,
    maintenance_window_scope_clause,
    target_display_name,
    update_maintenance_window,
)


router = APIRouter(
    prefix="/maintenance-windows",
    tags=["Maintenance"],
    dependencies=[Depends(authorize_request)],
)


def _state(row: MaintenanceWindow, now: datetime) -> str:
    if row.cancelled_at is not None or not row.enabled:
        return "CANCELLED"
    if row.ends_at <= now:
        return "PAST"
    if row.starts_at > now:
        return "UPCOMING"
    return "ACTIVE"


async def _read(db: AsyncSession, row: MaintenanceWindow, now: datetime | None = None) -> MaintenanceWindowRead:
    moment = now or datetime.now(timezone.utc)
    return MaintenanceWindowRead(
        id=row.id,
        name=row.name,
        reason=row.reason,
        target_type=row.target_type,
        target_id=row.target_id,
        target_display_name=await target_display_name(db, row),
        starts_at=row.starts_at,
        ends_at=row.ends_at,
        enabled=row.enabled,
        cancelled_at=row.cancelled_at,
        created_by_user_id=row.created_by_user_id,
        cancelled_by_user_id=row.cancelled_by_user_id,
        state=_state(row, moment),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.get("/targets", response_model=PageResult[MaintenanceTargetOption])
async def list_maintenance_targets(
    target_type: str = Query(..., max_length=20),
    search: str | None = Query(default=None, max_length=200),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=250),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    normalized = target_type.strip().upper()
    pattern = f"%{search.strip()}%" if search and search.strip() else None
    if normalized == "DEVICE":
        clause = await device_scope_clause(db, scope, device_col=Device.id)
        filters = [Device.deleted_at.is_(None), clause]
        if pattern:
            filters.append(or_(Device.display_name.ilike(pattern), Device.hostname.ilike(pattern)))
        total = int((await db.scalar(select(func.count(Device.id)).where(*filters))) or 0)
        rows = list((await db.scalars(select(Device).where(*filters).order_by(Device.display_name, Device.id).offset((page-1)*page_size).limit(page_size))).all())
        items = [MaintenanceTargetOption(id=row.id, target_type=normalized, label=row.display_name, context=row.hostname) for row in rows]
    elif normalized == "LOCATION":
        clause = location_scope_clause(scope, location_col=Location.id, city_col=Location.city_id)
        filters = [Location.deleted_at.is_(None), clause]
        if pattern:
            filters.append(or_(Location.name.ilike(pattern), Location.code.ilike(pattern)))
        total = int((await db.scalar(select(func.count(Location.id)).where(*filters))) or 0)
        rows = (await db.execute(select(Location, City.name).join(City, City.id == Location.city_id).where(*filters).order_by(Location.name, Location.id).offset((page-1)*page_size).limit(page_size))).all()
        items = [MaintenanceTargetOption(id=row.id, target_type=normalized, label=row.name, context=city_name) for row, city_name in rows]
    elif normalized == "CITY":
        clause = city_scope_clause(scope, city_col=City.id, network_col=City.network_id)
        filters = [City.deleted_at.is_(None), clause]
        if pattern:
            filters.append(or_(City.name.ilike(pattern), City.code.ilike(pattern)))
        total = int((await db.scalar(select(func.count(City.id)).where(*filters))) or 0)
        rows = (await db.execute(
            select(City, Network.name)
            .join(Network, Network.id == City.network_id)
            .where(*filters)
            .order_by(City.name, City.id)
            .offset((page-1)*page_size).limit(page_size)
        )).all()
        items = [MaintenanceTargetOption(id=row.id, target_type=normalized, label=row.name, context=network_name) for row, network_name in rows]
    elif normalized == "GROUP":
        clause = group_scope_clause(scope, group=DeviceGroup)
        filters = [DeviceGroup.deleted_at.is_(None), clause]
        if pattern:
            filters.append(or_(DeviceGroup.name.ilike(pattern), DeviceGroup.code.ilike(pattern)))
        total = int((await db.scalar(select(func.count(DeviceGroup.id)).where(*filters))) or 0)
        rows = list((await db.scalars(
            select(DeviceGroup).where(*filters)
            .order_by(DeviceGroup.name, DeviceGroup.id)
            .offset((page-1)*page_size).limit(page_size)
        )).all())
        items = [MaintenanceTargetOption(
            id=row.id, target_type=normalized, label=row.name,
            context=f"{row.membership_mode.title()} · {row.device_scope.replace('_',' ').title()}"
        ) for row in rows]
    elif normalized == "NETWORK":
        clause = network_scope_clause(scope, network_col=Network.id)
        filters = [Network.deleted_at.is_(None), clause]
        if pattern:
            filters.append(or_(Network.name.ilike(pattern), Network.code.ilike(pattern)))
        total = int((await db.scalar(select(func.count(Network.id)).where(*filters))) or 0)
        rows = list((await db.scalars(select(Network).where(*filters).order_by(Network.name, Network.id).offset((page-1)*page_size).limit(page_size))).all())
        items = [MaintenanceTargetOption(id=row.id, target_type=normalized, label=row.name, context=row.code) for row in rows]
    else:
        raise APIError(422, "INVALID_MAINTENANCE_TARGET", "target_type must be DEVICE, LOCATION, CITY, GROUP, or NETWORK.")
    return PageResult(items=items, total=total, page=page, page_size=page_size)


@router.get("", response_model=PageResult[MaintenanceWindowRead])
async def list_maintenance_windows(
    state: str = Query("ALL", max_length=20),
    target_type: str | None = Query(default=None, max_length=20),
    search: str | None = Query(default=None, max_length=200),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=250),
    sort_by: str = Query("starts_at", max_length=40),
    sort_direction: str = Query("desc", pattern="^(?i:asc|desc)$"),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    scope_clause = await maintenance_window_scope_clause(db, scope)
    now = datetime.now(timezone.utc)
    filters = [scope_clause]
    normalized_state = state.strip().upper()
    if normalized_state == "ACTIVE":
        filters.extend([
            MaintenanceWindow.enabled.is_(True), MaintenanceWindow.cancelled_at.is_(None),
            MaintenanceWindow.starts_at <= now, MaintenanceWindow.ends_at > now,
        ])
    elif normalized_state == "UPCOMING":
        filters.extend([
            MaintenanceWindow.enabled.is_(True), MaintenanceWindow.cancelled_at.is_(None),
            MaintenanceWindow.starts_at > now,
        ])
    elif normalized_state == "PAST":
        filters.extend([MaintenanceWindow.cancelled_at.is_(None), MaintenanceWindow.ends_at <= now])
    elif normalized_state == "CANCELLED":
        filters.append(or_(MaintenanceWindow.cancelled_at.is_not(None), MaintenanceWindow.enabled.is_(False)))
    elif normalized_state != "ALL":
        raise APIError(422, "INVALID_MAINTENANCE_STATE", "state must be ACTIVE, UPCOMING, PAST, CANCELLED, or ALL.")

    if target_type:
        normalized_target = target_type.strip().upper()
        if normalized_target not in {"DEVICE", "LOCATION", "CITY", "GROUP", "NETWORK"}:
            raise APIError(422, "INVALID_MAINTENANCE_TARGET", "target_type must be DEVICE, LOCATION, CITY, GROUP, or NETWORK.")
        filters.append(MaintenanceWindow.target_type == normalized_target)
    if search and search.strip():
        pattern = f"%{search.strip()}%"
        filters.append(or_(MaintenanceWindow.name.ilike(pattern), MaintenanceWindow.reason.ilike(pattern)))

    total = int((await db.scalar(select(func.count(MaintenanceWindow.id)).where(*filters))) or 0)
    state_order = case(
        (or_(MaintenanceWindow.cancelled_at.is_not(None), MaintenanceWindow.enabled.is_(False)), 3),
        (MaintenanceWindow.ends_at <= now, 2),
        (MaintenanceWindow.starts_at > now, 1),
        else_=0,
    )
    target_name = case(
        (
            MaintenanceWindow.target_type == "DEVICE",
            select(Device.display_name)
            .where(Device.id == MaintenanceWindow.target_id)
            .correlate(MaintenanceWindow)
            .scalar_subquery(),
        ),
        (
            MaintenanceWindow.target_type == "LOCATION",
            select(Location.name)
            .where(Location.id == MaintenanceWindow.target_id)
            .correlate(MaintenanceWindow)
            .scalar_subquery(),
        ),
        (
            MaintenanceWindow.target_type == "CITY",
            select(City.name)
            .where(City.id == MaintenanceWindow.target_id)
            .correlate(MaintenanceWindow)
            .scalar_subquery(),
        ),
        (
            MaintenanceWindow.target_type == "GROUP",
            select(DeviceGroup.name)
            .where(DeviceGroup.id == MaintenanceWindow.target_id)
            .correlate(MaintenanceWindow)
            .scalar_subquery(),
        ),
        (
            MaintenanceWindow.target_type == "NETWORK",
            select(Network.name)
            .where(Network.id == MaintenanceWindow.target_id)
            .correlate(MaintenanceWindow)
            .scalar_subquery(),
        ),
        else_=MaintenanceWindow.target_type,
    )
    sort_map = {
        "state": state_order,
        "name": func.lower(MaintenanceWindow.name),
        "target": func.lower(func.coalesce(target_name, "")),
        "starts_at": MaintenanceWindow.starts_at,
        "ends_at": MaintenanceWindow.ends_at,
        "reason": func.lower(func.coalesce(MaintenanceWindow.reason, "")),
    }
    normalized_sort = sort_by.strip().lower() if isinstance(sort_by, str) else "starts_at"
    sort_expr = sort_map.get(normalized_sort)
    if sort_expr is None:
        raise APIError(422, "INVALID_MAINTENANCE_SORT", "Unsupported maintenance-window sort field.")
    order = sort_expr.desc() if (sort_direction.lower() if isinstance(sort_direction, str) else "desc") == "desc" else sort_expr.asc()
    rows = list((await db.scalars(
        select(MaintenanceWindow)
        .where(*filters)
        .order_by(order, MaintenanceWindow.starts_at.desc(), MaintenanceWindow.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )).all())
    return PageResult(
        items=[await _read(db, row, now) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("", response_model=MaintenanceWindowRead)
async def create_maintenance_window_api(
    payload: MaintenanceWindowCreate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    row = await create_maintenance_window(
        db,
        scope=scope,
        target_type=payload.target_type,
        target_id=payload.target_id,
        name=payload.name,
        reason=payload.reason,
        starts_at=payload.starts_at,
        ends_at=payload.ends_at,
        actor_user_id=getattr(actor, "id", None),
    )
    await db.commit()
    await db.refresh(row)
    return await _read(db, row)


@router.put("/{window_id}", response_model=MaintenanceWindowRead)
async def update_maintenance_window_api(
    window_id: UUID,
    payload: MaintenanceWindowUpdate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    scope_clause = await maintenance_window_scope_clause(db, scope)
    row = await db.scalar(
        select(MaintenanceWindow)
        .where(MaintenanceWindow.id == window_id, scope_clause)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if row is None:
        raise APIError(404, "RESOURCE_NOT_FOUND", "Maintenance window not found.")
    await update_maintenance_window(
        db,
        scope=scope,
        window=row,
        target_type=payload.target_type,
        target_id=payload.target_id,
        name=payload.name,
        reason=payload.reason,
        starts_at=payload.starts_at,
        ends_at=payload.ends_at,
        actor_user_id=getattr(actor, "id", None),
    )
    await db.commit()
    await db.refresh(row)
    return await _read(db, row)


@router.post("/{window_id}/cancel", response_model=MaintenanceWindowRead)
async def cancel_maintenance_window_api(
    window_id: UUID,
    payload: MaintenanceWindowCancel,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    scope_clause = await maintenance_window_scope_clause(db, scope)
    row = await db.scalar(
        select(MaintenanceWindow)
        .where(MaintenanceWindow.id == window_id, scope_clause)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if row is None:
        raise APIError(404, "RESOURCE_NOT_FOUND", "Maintenance window not found.")
    await cancel_maintenance_window(
        db,
        window=row,
        actor_user_id=getattr(actor, "id", None),
        reason=payload.reason,
    )
    await db.commit()
    await db.refresh(row)
    return await _read(db, row)
