from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.models import Device, DeviceIP, DeviceType, TelemetryDeviceState, TelemetryMetric, TelemetryMetricRollup, TelemetryProfile
from app.schemas.pagination import PageResult
from app.schemas.phase_d import (
    CollectNowRequest, TelemetryProfileRead, TelemetryProfileUpdate, TelemetrySeriesPoint,
    TelemetrySeriesRead, TelemetryStateRead, TelemetrySummaryRead,
)
from app.security.authorization import authorize_request
from app.security.resource_scope import require_global_scope, scope_for_actor
from app.security.scope_queries import device_scope_clause, require_device
from app.services.audit import record_audit
from app.telemetry.collectors import validate_metric_definitions


router = APIRouter(prefix="/telemetry", tags=["Telemetry"], dependencies=[Depends(authorize_request)])
PAGE_SIZES = {50, 100, 200, 300, 400, 500}


def _page_size(value: int) -> int:
    if value not in PAGE_SIZES:
        raise HTTPException(422, detail={"code": "INVALID_PAGE_SIZE", "message": "Page size must be one of 50, 100, 200, 300, 400, 500."})
    return value


@router.get("/profiles", response_model=list[TelemetryProfileRead])
async def list_profiles(
    search: str | None = Query(None, max_length=100),
    enabled: bool | None = Query(None),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    stmt = (
        select(TelemetryProfile, DeviceType.code, DeviceType.name)
        .join(DeviceType, DeviceType.id == TelemetryProfile.device_type_id)
    )
    if search and search.strip():
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(or_(
            TelemetryProfile.name.ilike(pattern),
            TelemetryProfile.description.ilike(pattern),
            TelemetryProfile.protocol.ilike(pattern),
            DeviceType.code.ilike(pattern),
            DeviceType.name.ilike(pattern),
        ))
    if enabled is not None:
        stmt = stmt.where(TelemetryProfile.enabled.is_(enabled))
    rows = (await db.execute(stmt.order_by(DeviceType.name, TelemetryProfile.id))).all()
    return [
        {**TelemetryProfileRead.model_validate(profile).model_dump(), "device_type_code": code, "device_type_name": type_name}
        for profile, code, type_name in rows
    ]


@router.patch("/profiles/{profile_id}", response_model=TelemetryProfileRead)
async def update_profile(profile_id: UUID, payload: TelemetryProfileUpdate, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    await require_global_scope(db, actor, message="Global resource scope is required to manage telemetry profiles.")
    profile = await db.scalar(select(TelemetryProfile).where(TelemetryProfile.id == profile_id).with_for_update().execution_options(populate_existing=True))
    if profile is None:
        raise HTTPException(404, detail={"code": "RESOURCE_NOT_FOUND", "message": "Telemetry profile not found."})
    data = payload.model_dump()
    definitions = [item.model_dump() for item in payload.metric_definitions]
    try:
        validate_metric_definitions(definitions, max_metrics=payload.max_metrics)
    except ValueError as exc:
        raise HTTPException(422, detail={"code": "TELEMETRY_PROFILE_INVALID", "message": str(exc)}) from exc
    data["metric_definitions"] = definitions
    for key, value in data.items():
        setattr(profile, key, value)
    await record_audit(db, action="TELEMETRY_PROFILE_UPDATED", entity_type="TelemetryProfile", entity_id=profile.id, description="Telemetry collection profile updated.", metadata={"device_type_id": str(profile.device_type_id), "interval_seconds": profile.interval_seconds})
    await db.commit()
    await db.refresh(profile)
    device_type = await db.get(DeviceType, profile.device_type_id)
    return {
        **TelemetryProfileRead.model_validate(profile).model_dump(),
        "device_type_code": device_type.code if device_type else None,
        "device_type_name": device_type.name if device_type else None,
    }


@router.get("/states", response_model=PageResult[TelemetryStateRead])
async def list_states(
    page: int = Query(1, ge=1),
    page_size: int = Query(50),
    search: str | None = Query(None, max_length=100),
    status: str | None = Query(None, max_length=20),
    enabled: bool | None = Query(None),
    device_type: str | None = Query(None, max_length=64),
    sort_by: str = Query("next_collect_at", max_length=40),
    sort_direction: str = Query("asc", pattern="^(?i:asc|desc)$"),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    page_size = _page_size(page_size)
    scope = await scope_for_actor(db, actor)
    clause = await device_scope_clause(db, scope)

    filters = [Device.deleted_at.is_(None), clause]
    if status:
        filters.append(TelemetryDeviceState.status == status.upper())
    if enabled is not None:
        filters.append(TelemetryDeviceState.enabled.is_(enabled))
    if device_type:
        filters.append(DeviceType.code == device_type.strip().upper())
    if search and search.strip():
        pattern = f"%{search.strip()}%"
        ip_match = select(DeviceIP.id).where(
            DeviceIP.device_id == Device.id,
            DeviceIP.deleted_at.is_(None),
            DeviceIP.ip_address.ilike(pattern),
        ).exists()
        filters.append(or_(
            Device.display_name.ilike(pattern),
            Device.hostname.ilike(pattern),
            DeviceType.code.ilike(pattern),
            DeviceType.name.ilike(pattern),
            ip_match,
        ))

    base = (
        select(TelemetryDeviceState)
        .join(Device, Device.id == TelemetryDeviceState.device_id)
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .where(*filters)
    )
    total = int((await db.scalar(select(func.count()).select_from(base.order_by(None).subquery()))) or 0)

    page_stmt = (
        select(TelemetryDeviceState, Device.display_name)
        .join(Device, Device.id == TelemetryDeviceState.device_id)
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .where(*filters)
    )
    sort_map = {
        "device_name": Device.display_name,
        "status": TelemetryDeviceState.status,
        "last_collect_at": TelemetryDeviceState.last_collect_at,
        "next_collect_at": TelemetryDeviceState.next_collect_at,
        "consecutive_failures": TelemetryDeviceState.consecutive_failures,
        "last_duration_ms": TelemetryDeviceState.last_duration_ms,
        "last_error_code": TelemetryDeviceState.last_error_code,
    }
    sort_expr = sort_map.get(sort_by)
    if sort_expr is None:
        raise HTTPException(422, detail={"code": "INVALID_SORT", "message": "Unsupported telemetry sort field."})
    order = sort_expr.desc() if sort_direction.lower() == "desc" else sort_expr.asc()
    rows = (await db.execute(
        page_stmt.order_by(order.nullslast(), TelemetryDeviceState.device_id.asc())
        .offset((page - 1) * page_size).limit(page_size)
    )).all()
    items = [
        {**TelemetryStateRead.model_validate(state).model_dump(), "device_display_name": display_name}
        for state, display_name in rows
    ]
    return PageResult(items=items, total=total, page=page, page_size=page_size)


@router.get("/summary", response_model=TelemetrySummaryRead)
async def telemetry_summary(db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    scope = await scope_for_actor(db, actor)
    clause = await device_scope_clause(db, scope)
    now = datetime.now(timezone.utc)
    sub = select(TelemetryDeviceState).join(Device, Device.id == TelemetryDeviceState.device_id).where(Device.deleted_at.is_(None), clause).subquery()
    row = (await db.execute(select(
        func.count(sub.c.id),
        func.count().filter(sub.c.enabled.is_(True)),
        func.count().filter(sub.c.enabled.is_(True), sub.c.next_collect_at <= now),
        func.count().filter(sub.c.status == "OK"),
        func.count().filter(sub.c.status == "ERROR"),
        func.count().filter(sub.c.status == "PENDING"),
        func.count().filter(sub.c.status == "DISABLED"),
        func.min(sub.c.next_collect_at).filter(sub.c.enabled.is_(True), sub.c.next_collect_at <= now),
    ))).one()
    return TelemetrySummaryRead(total=int(row[0] or 0), enabled=int(row[1] or 0), due=int(row[2] or 0), ok=int(row[3] or 0), error=int(row[4] or 0), pending=int(row[5] or 0), disabled=int(row[6] or 0), oldest_due_at=row[7])


@router.post("/collect-now")
async def collect_now(payload: CollectNowRequest, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    scope = await scope_for_actor(db, actor)
    ids = list(dict.fromkeys(payload.device_ids))
    if not ids:
        return {"queued": 0}
    for device_id in ids:
        await require_device(db, scope, device_id)
    states = list((await db.scalars(select(TelemetryDeviceState).where(TelemetryDeviceState.device_id.in_(ids)).with_for_update())).all())
    now = datetime.now(timezone.utc)
    queued = 0
    for state in states:
        if state.enabled:
            state.next_collect_at = now
            state.lease_token = None
            state.lease_expires_at = None
            queued += 1
    await record_audit(db, action="TELEMETRY_COLLECTION_REQUESTED", entity_type="TelemetryDeviceState", description="Immediate telemetry collection requested.", metadata={"device_count": queued})
    await db.commit()
    return {"queued": queued}


@router.get("/devices/{device_id}/metrics/{metric_key}", response_model=TelemetrySeriesRead)
async def metric_series(
    device_id: UUID, metric_key: str, start: datetime | None = None, end: datetime | None = None,
    resolution: str = Query("raw", pattern="^(raw|hour)$"), limit: int = Query(2000, ge=1, le=10000),
    db: AsyncSession = Depends(get_db), actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    await require_device(db, scope, device_id)
    end_at = end or datetime.now(timezone.utc)
    start_at = start or (end_at - timedelta(hours=24))
    if start_at >= end_at:
        raise HTTPException(422, detail={"code": "INVALID_TIME_RANGE", "message": "start must be before end."})
    if resolution == "raw":
        rows = list((await db.scalars(select(TelemetryMetric).where(
            TelemetryMetric.device_id == device_id, TelemetryMetric.metric_key == metric_key,
            TelemetryMetric.collected_at >= start_at, TelemetryMetric.collected_at <= end_at,
        ).order_by(TelemetryMetric.collected_at).limit(limit))).all())
        points = [TelemetrySeriesPoint(at=row.collected_at, value=row.numeric_value if row.numeric_value is not None else row.text_value, sample_count=1, unit=row.unit, source=row.source) for row in rows]
    else:
        bucket = 3600
        rows = list((await db.scalars(select(TelemetryMetricRollup).where(
            TelemetryMetricRollup.device_id == device_id, TelemetryMetricRollup.metric_key == metric_key,
            TelemetryMetricRollup.bucket_seconds == bucket, TelemetryMetricRollup.bucket_start >= start_at,
            TelemetryMetricRollup.bucket_start <= end_at,
        ).order_by(TelemetryMetricRollup.bucket_start).limit(limit))).all())
        points = [TelemetrySeriesPoint(at=row.bucket_start, value=row.avg_value, sample_count=row.sample_count, unit=row.unit, source=f"ROLLUP_{resolution.upper()}") for row in rows]
    return TelemetrySeriesRead(device_id=device_id, metric_key=metric_key, start=start_at, end=end_at, resolution=resolution, points=points)
