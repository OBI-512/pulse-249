from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import and_, case, exists, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import APIError
from app.models import City, Device, DeviceGroup, DevicePlacement, Location, MaintenanceWindow, Network, NotificationDelivery
from app.security.resource_scope import EffectiveResourceScope
from app.security.scope_queries import (
    device_scope_clause,
    city_scope_clause,
    group_scope_clause,
    location_scope_clause,
    network_scope_clause,
    require_city,
    require_group,
    require_location,
    require_network,
)
from app.services.groups import effective_group_device_ids
from app.services.audit import record_audit


@dataclass(frozen=True)
class ActiveMaintenance:
    windows: tuple[MaintenanceWindow, ...]
    suppressed_until: datetime

    @property
    def primary(self) -> MaintenanceWindow:
        return self.windows[0]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def _require_scoped_device(
    db: AsyncSession,
    scope: EffectiveResourceScope,
    device_id: UUID,
) -> Device:
    clause = await device_scope_clause(db, scope, device_col=Device.id)
    row = await db.scalar(select(Device).where(Device.id == device_id, Device.deleted_at.is_(None), clause))
    if row is None:
        raise APIError(404, "RESOURCE_NOT_FOUND", "Device not found.")
    return row


async def validate_target(
    db: AsyncSession,
    scope: EffectiveResourceScope,
    *,
    target_type: str,
    target_id: UUID,
):
    normalized = target_type.strip().upper()
    if normalized == "DEVICE":
        return await _require_scoped_device(db, scope, target_id)
    if normalized == "LOCATION":
        row = await require_location(db, scope, target_id)
        if row.deleted_at is not None:
            raise APIError(404, "RESOURCE_NOT_FOUND", "Location not found.")
        return row
    if normalized == "CITY":
        row = await require_city(db, scope, target_id)
        if row.deleted_at is not None:
            raise APIError(404, "RESOURCE_NOT_FOUND", "City not found.")
        return row
    if normalized == "GROUP":
        row = await require_group(db, scope, target_id)
        if row.deleted_at is not None:
            raise APIError(404, "RESOURCE_NOT_FOUND", "Group not found.")
        return row
    if normalized == "NETWORK":
        row = await require_network(db, scope, target_id)
        if row.deleted_at is not None:
            raise APIError(404, "RESOURCE_NOT_FOUND", "Network not found.")
        return row
    raise APIError(422, "INVALID_MAINTENANCE_TARGET", "target_type must be DEVICE, LOCATION, CITY, GROUP, or NETWORK.")


async def maintenance_window_scope_clause(
    db: AsyncSession,
    scope: EffectiveResourceScope,
    *,
    window=MaintenanceWindow,
):
    if scope.global_access:
        return True

    device_ok = await device_scope_clause(db, scope, device_col=Device.id)
    device_match = and_(
        window.target_type == "DEVICE",
        exists(select(1).select_from(Device).where(
            Device.id == window.target_id,
            Device.deleted_at.is_(None),
            device_ok,
        )),
    )
    location_match = and_(
        window.target_type == "LOCATION",
        exists(select(1).select_from(Location).where(
            Location.id == window.target_id,
            Location.deleted_at.is_(None),
            location_scope_clause(scope, location_col=Location.id, city_col=Location.city_id),
        )),
    )
    city_match = and_(
        window.target_type == "CITY",
        exists(select(1).select_from(City).where(
            City.id == window.target_id,
            City.deleted_at.is_(None),
            city_scope_clause(scope, city_col=City.id, network_col=City.network_id),
        )),
    )
    group_match = and_(
        window.target_type == "GROUP",
        exists(select(1).select_from(DeviceGroup).where(
            DeviceGroup.id == window.target_id,
            DeviceGroup.deleted_at.is_(None),
            group_scope_clause(scope, group=DeviceGroup),
        )),
    )
    network_match = and_(
        window.target_type == "NETWORK",
        exists(select(1).select_from(Network).where(
            Network.id == window.target_id,
            Network.deleted_at.is_(None),
            network_scope_clause(scope, network_col=Network.id),
        )),
    )
    return or_(device_match, location_match, city_match, group_match, network_match)


async def active_maintenance_for_device(
    db: AsyncSession,
    device_id: UUID,
    *,
    at: datetime | None = None,
) -> ActiveMaintenance | None:
    """Resolve active maintenance for a device across physical and organizational scope.

    Availability polling remains independent. CITY follows the device's current
    placement; GROUP uses the current effective group population, including
    nested and dynamic groups.
    """

    moment = at or utcnow()
    placement = await db.scalar(select(DevicePlacement).where(
        DevicePlacement.device_id == device_id,
        DevicePlacement.deleted_at.is_(None),
    ))
    target_pairs: list[tuple[str, UUID]] = [("DEVICE", device_id)]
    if placement is not None:
        target_pairs.extend([
            ("LOCATION", placement.location_id),
            ("CITY", placement.city_id),
            ("NETWORK", placement.network_id),
        ])

    fixed_target_clause = or_(*[
        and_(MaintenanceWindow.target_type == kind, MaintenanceWindow.target_id == target_id)
        for kind, target_id in target_pairs
    ])
    base_filters = (
        MaintenanceWindow.enabled.is_(True),
        MaintenanceWindow.cancelled_at.is_(None),
        MaintenanceWindow.starts_at <= moment,
        MaintenanceWindow.ends_at > moment,
    )

    fixed_rows = list((await db.scalars(
        select(MaintenanceWindow).where(*base_filters, fixed_target_clause)
    )).all())

    group_rows = list((await db.scalars(
        select(MaintenanceWindow).where(*base_filters, MaintenanceWindow.target_type == "GROUP")
    )).all())
    matching_group_rows: list[MaintenanceWindow] = []
    for window in group_rows:
        if device_id in await effective_group_device_ids(db, window.target_id):
            matching_group_rows.append(window)

    rows = fixed_rows + matching_group_rows
    if not rows:
        return None

    priority = {"DEVICE": 0, "GROUP": 1, "LOCATION": 2, "CITY": 3, "NETWORK": 4}
    rows.sort(key=lambda row: (priority.get(row.target_type, 99), -row.ends_at.timestamp(), str(row.id)))
    return ActiveMaintenance(tuple(rows), max(row.ends_at for row in rows))


async def create_maintenance_window(
    db: AsyncSession,
    *,
    scope: EffectiveResourceScope,
    target_type: str,
    target_id: UUID,
    name: str,
    reason: str | None,
    starts_at: datetime,
    ends_at: datetime,
    actor_user_id: UUID | None,
) -> MaintenanceWindow:
    normalized_type = target_type.strip().upper()
    target = await validate_target(db, scope, target_type=normalized_type, target_id=target_id)
    now = utcnow()
    if ends_at <= starts_at:
        raise APIError(422, "INVALID_MAINTENANCE_WINDOW", "ends_at must be later than starts_at.")
    if ends_at <= now:
        raise APIError(422, "INVALID_MAINTENANCE_WINDOW", "A maintenance window must end in the future.")
    clean_name = name.strip()
    if not clean_name:
        raise APIError(422, "INVALID_MAINTENANCE_WINDOW", "name is required.")

    row = MaintenanceWindow(
        name=clean_name[:160],
        reason=(reason.strip()[:4000] if reason and reason.strip() else None),
        target_type=normalized_type,
        target_id=target_id,
        starts_at=starts_at,
        ends_at=ends_at,
        enabled=True,
        created_by_user_id=actor_user_id,
    )
    db.add(row)
    await db.flush()
    await record_audit(
        db,
        action="MAINTENANCE_WINDOW_CREATED",
        entity_type="MaintenanceWindow",
        entity_id=row.id,
        entity_display_snapshot={"name": row.name, "target": getattr(target, "display_name", getattr(target, "name", str(target_id)))},
        description="Scheduled maintenance window created.",
        after_summary={
            "target_type": normalized_type,
            "target_id": str(target_id),
            "starts_at": starts_at.isoformat(),
            "ends_at": ends_at.isoformat(),
        },
    )
    return row


async def update_maintenance_window(
    db: AsyncSession,
    *,
    scope: EffectiveResourceScope,
    window: MaintenanceWindow,
    target_type: str,
    target_id: UUID,
    name: str,
    reason: str | None,
    starts_at: datetime,
    ends_at: datetime,
    actor_user_id: UUID | None,
    now: datetime | None = None,
) -> MaintenanceWindow:
    """Edit a maintenance window only while it is still upcoming.

    The editable window must remain upcoming after the change. Historical,
    active and cancelled maintenance records are immutable so operational
    evidence is never rewritten after maintenance has begun.
    """

    occurred_at = now or utcnow()
    if window.cancelled_at is not None or not window.enabled or window.starts_at <= occurred_at:
        raise APIError(
            409,
            "MAINTENANCE_WINDOW_NOT_EDITABLE",
            "Only upcoming maintenance windows can be edited.",
        )

    normalized_type = target_type.strip().upper()
    target = await validate_target(db, scope, target_type=normalized_type, target_id=target_id)
    clean_name = name.strip()
    if not clean_name:
        raise APIError(422, "INVALID_MAINTENANCE_WINDOW", "name is required.")
    if starts_at <= occurred_at:
        raise APIError(
            422,
            "INVALID_MAINTENANCE_WINDOW",
            "An edited maintenance window must start in the future.",
        )
    if ends_at <= starts_at:
        raise APIError(422, "INVALID_MAINTENANCE_WINDOW", "ends_at must be later than starts_at.")

    before = {
        "name": window.name,
        "reason": window.reason,
        "target_type": window.target_type,
        "target_id": str(window.target_id),
        "starts_at": window.starts_at.isoformat(),
        "ends_at": window.ends_at.isoformat(),
    }
    window.name = clean_name[:160]
    window.reason = reason.strip()[:4000] if reason and reason.strip() else None
    window.target_type = normalized_type
    window.target_id = target_id
    window.starts_at = starts_at
    window.ends_at = ends_at
    await db.flush()

    await record_audit(
        db,
        action="MAINTENANCE_WINDOW_UPDATED",
        entity_type="MaintenanceWindow",
        entity_id=window.id,
        actor_user_id=actor_user_id,
        entity_display_snapshot={
            "name": window.name,
            "target": getattr(target, "display_name", getattr(target, "name", str(target_id))),
        },
        description="Upcoming maintenance window updated.",
        before_summary=before,
        after_summary={
            "name": window.name,
            "reason": window.reason,
            "target_type": window.target_type,
            "target_id": str(window.target_id),
            "starts_at": window.starts_at.isoformat(),
            "ends_at": window.ends_at.isoformat(),
        },
    )
    return window


async def cancel_maintenance_window(
    db: AsyncSession,
    *,
    window: MaintenanceWindow,
    actor_user_id: UUID | None,
    reason: str | None = None,
    now: datetime | None = None,
) -> bool:
    if window.cancelled_at is not None:
        return False
    occurred_at = now or utcnow()
    window.cancelled_at = occurred_at
    window.cancelled_by_user_id = actor_user_id

    # A cancelled maintenance window must not keep notifications sleeping until
    # its former end time. Make its suppressed work immediately eligible; the
    # delivery worker re-evaluates overlapping maintenance before any send.
    suppressed = list((await db.scalars(
        select(NotificationDelivery)
        .where(
            NotificationDelivery.status == "SUPPRESSED",
            NotificationDelivery.maintenance_window_id == window.id,
        )
        .with_for_update(skip_locked=True)
    )).all())
    for delivery in suppressed:
        delivery.status = "PENDING"
        delivery.next_attempt_at = occurred_at
        delivery.maintenance_window_id = None

    await record_audit(
        db,
        action="MAINTENANCE_WINDOW_CANCELLED",
        entity_type="MaintenanceWindow",
        entity_id=window.id,
        entity_display_snapshot={"name": window.name},
        description="Scheduled maintenance window cancelled.",
        before_summary={"cancelled_at": None},
        after_summary={"cancelled_at": occurred_at.isoformat()},
        metadata={
            "reason": reason.strip()[:1000] if reason and reason.strip() else None,
            "suppressed_deliveries_rescheduled": len(suppressed),
        },
    )
    return True


async def target_display_name(db: AsyncSession, window: MaintenanceWindow) -> str:
    if window.target_type == "DEVICE":
        row = await db.get(Device, window.target_id)
        return row.display_name if row else str(window.target_id)
    if window.target_type == "LOCATION":
        row = await db.get(Location, window.target_id)
        return row.name if row else str(window.target_id)
    if window.target_type == "CITY":
        row = await db.get(City, window.target_id)
        return row.name if row else str(window.target_id)
    if window.target_type == "GROUP":
        row = await db.get(DeviceGroup, window.target_id)
        return row.name if row else str(window.target_id)
    if window.target_type == "NETWORK":
        row = await db.get(Network, window.target_id)
        return row.name if row else str(window.target_id)
    return str(window.target_id)
