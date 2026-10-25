from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from ..deps import get_db
from ...core.exceptions import APIError
from ...models import Alarm, AlarmHistory, Device, DeviceAvailability, DeviceIP, OperationalEvent, User
from ...schemas.alarm import (
    AlarmAcknowledgeRequest,
    AlarmClearRequest,
    AlarmHistoryRead,
    AlarmOwnerUpdate,
    AlarmPageItem,
    AlarmRead,
    AlarmSummary,
    OperationalEventRead,
)
from ...schemas.pagination import PageResult
from ...security.authorization import authorize_request
from ...security.resource_scope import scope_for_actor
from ...security.scope_queries import device_scope_clause
from ...services.alarms import acknowledge_alarm, assign_alarm, clear_alarm


router = APIRouter(
    prefix="/alarms",
    tags=["Alarms"],
    dependencies=[Depends(authorize_request)],
)


def _management_ip_subquery():
    return (
        select(DeviceIP.ip_address)
        .where(DeviceIP.device_id == Device.id, DeviceIP.deleted_at.is_(None))
        .order_by(DeviceIP.is_management.desc(), DeviceIP.is_primary.desc(), DeviceIP.id)
        .limit(1)
        .scalar_subquery()
    )


async def _scoped_alarm(
    db: AsyncSession,
    actor,
    alarm_id: UUID,
    *,
    for_update: bool = False,
) -> Alarm:
    scope = await scope_for_actor(db, actor)
    scope_clause = await device_scope_clause(db, scope, device_col=Device.id)
    stmt = (
        select(Alarm)
        .join(Device, Device.id == Alarm.device_id)
        .where(
            Alarm.id == alarm_id,
            Device.deleted_at.is_(None),
            scope_clause,
        )
    )
    if for_update:
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    row = await db.scalar(stmt)
    if row is None:
        raise APIError(404, "RESOURCE_NOT_FOUND", "Alarm not found.")
    return row


def _actor_id(actor) -> UUID | None:
    return getattr(actor, "id", None)


async def _alarm_page_item(db: AsyncSession, alarm: Alarm) -> AlarmPageItem:
    owner = aliased(User)
    acknowledger = aliased(User)
    management_ip = _management_ip_subquery()
    row = (await db.execute(
        select(
            Device.display_name,
            DeviceAvailability.status,
            management_ip.label("management_ip"),
            func.coalesce(owner.display_name, owner.username).label("owner_display_name"),
            func.coalesce(acknowledger.display_name, acknowledger.username).label("acknowledged_by_display_name"),
        )
        .select_from(Device)
        .outerjoin(DeviceAvailability, DeviceAvailability.device_id == Device.id)
        .outerjoin(owner, owner.id == alarm.owner_user_id)
        .outerjoin(acknowledger, acknowledger.id == alarm.acknowledged_by_user_id)
        .where(Device.id == alarm.device_id)
    )).one()
    payload = AlarmRead.model_validate(alarm).model_dump()
    payload.update({
        "device_display_name": row.display_name,
        "availability_status": row.status,
        "management_ip": row.management_ip,
        "owner_display_name": row.owner_display_name,
        "acknowledged_by_display_name": row.acknowledged_by_display_name,
    })
    return AlarmPageItem.model_validate(payload)


@router.get("/summary", response_model=AlarmSummary)
async def alarm_summary(
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    scope_clause = await device_scope_clause(db, scope, device_col=Device.id)
    rows = (await db.execute(
        select(
            Alarm.severity,
            func.count(Alarm.id).label("total"),
            func.sum(case((Alarm.acknowledged_at.is_(None), 1), else_=0)).label("unacknowledged"),
        )
        .join(Device, Device.id == Alarm.device_id)
        .where(
            Alarm.state == "ACTIVE",
            Device.deleted_at.is_(None),
            scope_clause,
        )
        .group_by(Alarm.severity)
    )).all()
    severity_counts = {severity.lower(): int(total) for severity, total, _ in rows}
    return AlarmSummary(
        active_total=sum(int(total) for _, total, _ in rows),
        unacknowledged=sum(int(unacknowledged or 0) for _, _, unacknowledged in rows),
        info=severity_counts.get("info", 0),
        warning=severity_counts.get("warning", 0),
        minor=severity_counts.get("minor", 0),
        major=severity_counts.get("major", 0),
        critical=severity_counts.get("critical", 0),
    )


@router.get("/page", response_model=PageResult[AlarmPageItem])
async def list_alarms_page(
    state: str | None = Query(default="ALL", max_length=20),
    severity: str | None = Query(default=None, max_length=20),
    acknowledged: bool | None = Query(default=None),
    owner: str | None = Query(default=None, max_length=20),
    search: str | None = Query(default=None, max_length=200),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    sort_by: str = Query("last_raised_at", max_length=40),
    sort_direction: str = Query("desc", pattern="^(?i:asc|desc)$"),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    scope_clause = await device_scope_clause(db, scope, device_col=Device.id)
    filters = [Device.deleted_at.is_(None), scope_clause]
    if state:
        normalized = state.strip().upper()
        if normalized not in {"ACTIVE", "CLEARED", "ALL"}:
            raise APIError(422, "INVALID_ALARM_STATE", "state must be ACTIVE, CLEARED, or ALL.")
        if normalized != "ALL":
            filters.append(Alarm.state == normalized)
    if severity:
        normalized = severity.strip().upper()
        if normalized not in {"INFO", "WARNING", "MINOR", "MAJOR", "CRITICAL"}:
            raise APIError(422, "INVALID_ALARM_SEVERITY", "Unsupported alarm severity.")
        filters.append(Alarm.severity == normalized)
    if acknowledged is True:
        filters.append(Alarm.acknowledged_at.is_not(None))
    elif acknowledged is False:
        filters.append(Alarm.acknowledged_at.is_(None))
    if owner:
        normalized = owner.strip().upper()
        if normalized == "OWNED":
            filters.append(Alarm.owner_user_id.is_not(None))
        elif normalized == "UNOWNED":
            filters.append(Alarm.owner_user_id.is_(None))
        elif normalized != "ALL":
            raise APIError(422, "INVALID_ALARM_OWNER_FILTER", "owner must be OWNED, UNOWNED, or ALL.")
    if search and search.strip():
        pattern = f"%{search.strip()}%"
        filters.append(or_(
            Device.display_name.ilike(pattern),
            Alarm.summary.ilike(pattern),
            Alarm.correlation_key.ilike(pattern),
            Alarm.alarm_type.ilike(pattern),
        ))

    total = int((await db.scalar(
        select(func.count(Alarm.id))
        .join(Device, Device.id == Alarm.device_id)
        .where(*filters)
    )) or 0)

    management_ip = _management_ip_subquery()
    owner_user = aliased(User)
    ack_user = aliased(User)
    severity_order = case(
        (Alarm.severity == "INFO", 0),
        (Alarm.severity == "WARNING", 1),
        (Alarm.severity == "MINOR", 2),
        (Alarm.severity == "MAJOR", 3),
        (Alarm.severity == "CRITICAL", 4),
        else_=-1,
    )
    state_order = case(
        (Alarm.state == "ACTIVE", 0),
        (Alarm.state == "CLEARED", 1),
        else_=2,
    )
    acknowledged_order = case((Alarm.acknowledged_at.is_not(None), 1), else_=0)
    owner_presence = case((Alarm.owner_user_id.is_not(None), 1), else_=0)
    owner_name = func.lower(func.coalesce(owner_user.display_name, owner_user.username, ""))

    normalized_sort = sort_by.strip().lower() if isinstance(sort_by, str) else "last_raised_at"
    normalized_direction = sort_direction.strip().lower() if isinstance(sort_direction, str) else "desc"
    direction_desc = normalized_direction == "desc"

    simple_sort_map = {
        "severity": severity_order,
        "device": func.lower(Device.display_name),
        "state": state_order,
        "acknowledged": acknowledged_order,
        "occurrence_count": Alarm.occurrence_count,
        "last_raised_at": Alarm.last_raised_at,
    }
    if normalized_sort == "owner":
        order_clauses = [
            owner_presence.desc() if direction_desc else owner_presence.asc(),
            owner_name.desc() if direction_desc else owner_name.asc(),
        ]
    else:
        sort_expr = simple_sort_map.get(normalized_sort)
        if sort_expr is None:
            raise APIError(422, "INVALID_ALARM_SORT", "Unsupported alarm sort field.")
        order_clauses = [sort_expr.desc() if direction_desc else sort_expr.asc()]

    rows = (await db.execute(
        select(
            Alarm,
            Device.display_name.label("device_display_name"),
            DeviceAvailability.status.label("availability_status"),
            management_ip.label("management_ip"),
            func.coalesce(owner_user.display_name, owner_user.username).label("owner_display_name"),
            func.coalesce(ack_user.display_name, ack_user.username).label("acknowledged_by_display_name"),
        )
        .join(Device, Device.id == Alarm.device_id)
        .outerjoin(DeviceAvailability, DeviceAvailability.device_id == Device.id)
        .outerjoin(owner_user, owner_user.id == Alarm.owner_user_id)
        .outerjoin(ack_user, ack_user.id == Alarm.acknowledged_by_user_id)
        .where(*filters)
        .order_by(*order_clauses, Alarm.last_raised_at.desc(), Alarm.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )).all()

    items: list[AlarmPageItem] = []
    for alarm, display_name, availability_status, ip_address, owner_display, ack_display in rows:
        payload = AlarmRead.model_validate(alarm).model_dump()
        payload.update({
            "device_display_name": display_name,
            "availability_status": availability_status,
            "management_ip": ip_address,
            "owner_display_name": owner_display,
            "acknowledged_by_display_name": ack_display,
        })
        items.append(AlarmPageItem.model_validate(payload))
    return PageResult(items=items, total=total, page=page, page_size=page_size)


@router.get("/{alarm_id}", response_model=AlarmPageItem)
async def get_alarm(
    alarm_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    alarm = await _scoped_alarm(db, actor, alarm_id)
    return await _alarm_page_item(db, alarm)


@router.get("/{alarm_id}/events", response_model=list[OperationalEventRead])
async def get_alarm_events(
    alarm_id: UUID,
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    alarm = await _scoped_alarm(db, actor, alarm_id)
    rows = list((await db.scalars(
        select(OperationalEvent)
        .where(OperationalEvent.correlation_key == alarm.correlation_key)
        .order_by(OperationalEvent.occurred_at.desc(), OperationalEvent.id.desc())
        .limit(limit)
    )).all())
    return [
        OperationalEventRead(
            id=row.id,
            device_id=row.device_id,
            event_type=row.event_type,
            severity=row.severity,
            correlation_key=row.correlation_key,
            occurred_at=row.occurred_at,
            summary=row.summary,
            metadata=row.metadata_,
        )
        for row in rows
    ]


@router.get("/{alarm_id}/history", response_model=list[AlarmHistoryRead])
async def get_alarm_history(
    alarm_id: UUID,
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    alarm = await _scoped_alarm(db, actor, alarm_id)
    actor_user = aliased(User)
    rows = (await db.execute(
        select(
            AlarmHistory,
            func.coalesce(actor_user.display_name, actor_user.username).label("actor_display_name"),
        )
        .outerjoin(actor_user, actor_user.id == AlarmHistory.actor_user_id)
        .where(AlarmHistory.alarm_id == alarm.id)
        .order_by(AlarmHistory.occurred_at.desc(), AlarmHistory.id.desc())
        .limit(limit)
    )).all()
    return [
        AlarmHistoryRead(
            id=history.id,
            alarm_id=history.alarm_id,
            event_id=history.event_id,
            occurred_at=history.occurred_at,
            action=history.action,
            actor_user_id=history.actor_user_id,
            actor_display_name=actor_display,
            note=history.note,
            before_summary=history.before_summary,
            after_summary=history.after_summary,
            metadata=history.metadata_,
        )
        for history, actor_display in rows
    ]


@router.post("/{alarm_id}/acknowledge", response_model=AlarmPageItem)
async def acknowledge_alarm_api(
    alarm_id: UUID,
    payload: AlarmAcknowledgeRequest,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    alarm = await _scoped_alarm(db, actor, alarm_id, for_update=True)
    try:
        await acknowledge_alarm(db, alarm=alarm, actor_user_id=_actor_id(actor), note=payload.note)
    except ValueError as exc:
        if str(exc) == "CLEARED_ALARM_CANNOT_BE_ACKNOWLEDGED":
            raise APIError(409, "ALARM_CLEARED", "A cleared alarm cannot be acknowledged.") from exc
        raise
    await db.commit()
    await db.refresh(alarm)
    return await _alarm_page_item(db, alarm)


@router.patch("/{alarm_id}/owner", response_model=AlarmPageItem)
async def update_alarm_owner(
    alarm_id: UUID,
    payload: AlarmOwnerUpdate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    alarm = await _scoped_alarm(db, actor, alarm_id, for_update=True)
    try:
        await assign_alarm(
            db,
            alarm=alarm,
            owner_user_id=payload.owner_user_id,
            actor_user_id=_actor_id(actor),
            note=payload.note,
        )
    except ValueError as exc:
        code = str(exc)
        if code == "CLEARED_ALARM_CANNOT_BE_ASSIGNED":
            raise APIError(409, "ALARM_CLEARED", "A cleared alarm cannot be assigned.") from exc
        if code == "ALARM_OWNER_NOT_ACTIVE":
            raise APIError(422, "ALARM_OWNER_NOT_ACTIVE", "The requested alarm owner is not an active user.") from exc
        raise
    await db.commit()
    await db.refresh(alarm)
    return await _alarm_page_item(db, alarm)


@router.post("/{alarm_id}/clear", response_model=AlarmPageItem)
async def clear_alarm_api(
    alarm_id: UUID,
    payload: AlarmClearRequest,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    alarm = await _scoped_alarm(db, actor, alarm_id, for_update=True)
    await clear_alarm(db, alarm=alarm, actor_user_id=_actor_id(actor), note=payload.note)
    await db.commit()
    await db.refresh(alarm)
    return await _alarm_page_item(db, alarm)

