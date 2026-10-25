from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...models import Device, DeviceAvailability, DeviceIP
from ...schemas.availability import (
    DeviceAvailabilityPageItem,
    DeviceAvailabilityRead,
    DeviceAvailabilitySummary,
    DeviceAvailabilityUpdate,
)
from ...schemas.pagination import PageResult
from ...security.authorization import authorize_request
from ...security.resource_scope import scope_for_actor
from ...security.scope_queries import device_scope_clause, require_device
from ...services.audit import record_audit
from ...core.exceptions import APIError
from ...availability.service import ensure_device_availability, synchronize_operational_state


router = APIRouter()


def _management_ip_subquery():
    return (
        select(DeviceIP.ip_address)
        .where(DeviceIP.device_id == Device.id)
        .order_by(DeviceIP.is_management.desc(), DeviceIP.is_primary.desc(), DeviceIP.id)
        .limit(1)
        .scalar_subquery()
    )


@router.get("/availability/summary", response_model=DeviceAvailabilitySummary)
async def availability_summary(
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    scope_clause = await device_scope_clause(db, scope, device_col=Device.id)
    rows = (await db.execute(
        select(DeviceAvailability.status, func.count(DeviceAvailability.id))
        .join(Device, Device.id == DeviceAvailability.device_id)
        .where(
            Device.deleted_at.is_(None),
            Device.lifecycle_state != "DECOMMISSIONED",
            scope_clause,
        )
        .group_by(DeviceAvailability.status)
    )).all()
    counts = {status: int(count) for status, count in rows}
    return DeviceAvailabilitySummary(
        online=counts.get("ONLINE", 0),
        suspect=counts.get("SUSPECT", 0),
        offline=counts.get("OFFLINE", 0),
        unknown=counts.get("UNKNOWN", 0),
        maintenance=counts.get("MAINTENANCE", 0),
        total=sum(counts.values()),
    )


@router.get("/availability/page", response_model=PageResult[DeviceAvailabilityPageItem])
async def list_availability_page(
    status: str | None = Query(default=None, max_length=20),
    profile: str | None = Query(default=None, max_length=20),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    scope_clause = await device_scope_clause(db, scope, device_col=Device.id)
    filters = [Device.deleted_at.is_(None), scope_clause]
    if status:
        filters.append(DeviceAvailability.status == status.strip().upper())
    if profile:
        filters.append(DeviceAvailability.profile == profile.strip().upper())
    total = int((await db.scalar(
        select(func.count(DeviceAvailability.id))
        .join(Device, Device.id == DeviceAvailability.device_id)
        .where(*filters)
    )) or 0)
    management_ip = _management_ip_subquery()
    rows = (await db.execute(
        select(DeviceAvailability, Device.display_name, Device.lifecycle_state, management_ip.label("management_ip"))
        .join(Device, Device.id == DeviceAvailability.device_id)
        .where(*filters)
        .order_by(Device.display_name, Device.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )).all()
    items = []
    for availability, display_name, lifecycle_state, management_ip_value in rows:
        payload = DeviceAvailabilityRead.model_validate(availability).model_dump()
        payload.update({
            "display_name": display_name,
            "lifecycle_state": lifecycle_state,
            "management_ip": management_ip_value,
        })
        items.append(DeviceAvailabilityPageItem.model_validate(payload))
    return PageResult(items=items, total=total, page=page, page_size=page_size)


@router.get("/{device_id}/availability", response_model=DeviceAvailabilityRead)
async def get_device_availability(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await require_device(db, await scope_for_actor(db, actor), device_id)
    row = await db.scalar(select(DeviceAvailability).where(DeviceAvailability.device_id == device_id))
    if row is None:
        raise APIError(503, "AVAILABILITY_STATE_INITIALIZING", "Device availability state is being initialized.")
    return row


@router.patch("/{device_id}/availability", response_model=DeviceAvailabilityRead)
async def update_device_availability(
    device_id: UUID,
    payload: DeviceAvailabilityUpdate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    device = await require_device(db, await scope_for_actor(db, actor), device_id, for_update=True)
    row = await ensure_device_availability(db, device, for_update=True)
    before = {"profile": row.profile, "enabled": row.enabled, "status": row.status}
    data = payload.model_dump(exclude_unset=True)
    for key, value in data.items():
        if value is not None:
            setattr(row, key, value)
    if data:
        now = datetime.now(timezone.utc)
        row.status = "MAINTENANCE" if device.lifecycle_state == "MAINTENANCE" else "UNKNOWN"
        row.status_changed_at = now
        row.consecutive_failures = 0
        row.latency_ms = None
        row.last_result_code = "CONFIGURATION_CHANGED"
        row.next_check_at = min(row.next_check_at, now)
        row.lease_token = None
        row.lease_expires_at = None
    if data:
        await synchronize_operational_state(
            db, device=device, availability=row, source="AVAILABILITY_CONFIGURATION"
        )
    after = {"profile": row.profile, "enabled": row.enabled, "status": row.status}
    if before != after:
        await record_audit(
            db,
            action="DEVICE_AVAILABILITY_CONFIGURATION_CHANGED",
            entity_type="Device",
            entity_id=device.id,
            entity_display_snapshot={"display_name": device.display_name},
            description="Device availability polling configuration changed.",
            before_summary=before,
            after_summary=after,
        )
        if before["status"] != after["status"]:
            await record_audit(
                db,
                action="DEVICE_AVAILABILITY_CHANGED",
                entity_type="Device",
                entity_id=device.id,
                entity_display_snapshot={"display_name": device.display_name},
                description="Device availability state reset because polling configuration changed.",
                before_summary={"availability_status": before["status"]},
                after_summary={"availability_status": after["status"]},
                metadata={"source": "CONFIGURATION"},
            )
    await db.commit()
    await db.refresh(row)
    return row
