from __future__ import annotations

from datetime import datetime, timedelta, timezone

from redis.asyncio import Redis
from sqlalchemy import case, func, literal, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.availability.settings import load_availability_settings
from app.models import (
    Alarm,
    City,
    Device,
    DeviceAvailability,
    DeviceGroup,
    DevicePlacement,
    DeviceType,
    Location,
    Network,
    OperationalEvent,
)
from app.schemas.dashboard import (
    DashboardAlarmCounts,
    DashboardAvailabilityCounts,
    DashboardBreakdown,
    DashboardOutage,
    DashboardPollingHealth,
    OperationsDashboardRead,
)
from app.security.resource_scope import EffectiveResourceScope
from app.security.scope_queries import device_scope_clause
from app.settings import settings


_AVAILABILITY_STATES = ("ONLINE", "SUSPECT", "OFFLINE", "UNKNOWN", "MAINTENANCE")
_WORKER_HEARTBEAT_KEY = "fttw:availability:worker_heartbeat"
_OVERVIEW_DEVICE_CATEGORIES = ("ACCESS_POINT", "CPE", "SECTOR")


async def authorized_overview_device_categories(
    db: AsyncSession,
    scope: EffectiveResourceScope,
) -> list[str]:
    """Return dashboard device categories permitted by the effective WHERE scope.

    Geographic/global grants authorize every dashboard category even when the
    authorized population currently contains zero devices. GROUP-only grants
    derive category capability from the active group's declared device_scope,
    not from observed counts, so zero never means "not authorized".
    """
    if (
        scope.global_access
        or scope.network_ids
        or scope.city_ids
        or scope.location_ids
        or scope.sector_ids
    ):
        return list(_OVERVIEW_DEVICE_CATEGORIES)

    if not scope.group_ids:
        return []

    scopes = list((await db.scalars(
        select(DeviceGroup.device_scope).where(
            DeviceGroup.id.in_(tuple(scope.group_ids)),
            DeviceGroup.deleted_at.is_(None),
        )
    )).all())
    if "ANY" in scopes:
        return list(_OVERVIEW_DEVICE_CATEGORIES)

    permitted = set(scopes).intersection(_OVERVIEW_DEVICE_CATEGORIES)
    return [code for code in _OVERVIEW_DEVICE_CATEGORIES if code in permitted]


def _state_columns(status_expr):
    return [
        func.sum(case((status_expr == state, 1), else_=0)).label(state.lower())
        for state in _AVAILABILITY_STATES
    ]


def _breakdown(*, key: object, label: object, context: object, total: object, values: dict[str, object]) -> DashboardBreakdown:
    return DashboardBreakdown(
        key=str(key),
        label=str(label),
        context=str(context) if context is not None else None,
        total=int(total or 0),
        online=int(values.get("online") or 0),
        suspect=int(values.get("suspect") or 0),
        offline=int(values.get("offline") or 0),
        unknown=int(values.get("unknown") or 0),
        maintenance=int(values.get("maintenance") or 0),
    )


async def _worker_heartbeat() -> tuple[str, datetime | None, float | None]:
    client = Redis.from_url(settings.redis_url, decode_responses=True)
    try:
        raw = await client.get(_WORKER_HEARTBEAT_KEY)
        if not raw:
            return "ONLINE", None, None
        heartbeat = datetime.fromisoformat(raw)
        if heartbeat.tzinfo is None:
            heartbeat = heartbeat.replace(tzinfo=timezone.utc)
        age = max(0.0, (datetime.now(timezone.utc) - heartbeat).total_seconds())
        return "ONLINE", heartbeat, age
    except Exception:
        return "OFFLINE", None, None
    finally:
        await client.aclose()


async def build_operations_dashboard(
    db: AsyncSession,
    *,
    scope: EffectiveResourceScope,
    include_alarms: bool,
    recent_outage_limit: int = 10,
    top_location_limit: int = 12,
) -> OperationsDashboardRead:
    now = datetime.now(timezone.utc)
    authorized_device_categories = await authorized_overview_device_categories(db, scope)
    scope_clause = await device_scope_clause(db, scope, device_col=Device.id)
    active_device_filters = (
        Device.deleted_at.is_(None),
        Device.lifecycle_state != "DECOMMISSIONED",
        scope_clause,
    )
    status_expr = func.coalesce(DeviceAvailability.status, literal("UNKNOWN"))

    availability_row = (await db.execute(
        select(
            func.count(Device.id).label("total"),
            *_state_columns(status_expr),
        )
        .select_from(Device)
        .outerjoin(DeviceAvailability, DeviceAvailability.device_id == Device.id)
        .where(*active_device_filters)
    )).one()
    availability = DashboardAvailabilityCounts(
        total=int(availability_row.total or 0),
        online=int(availability_row.online or 0),
        suspect=int(availability_row.suspect or 0),
        offline=int(availability_row.offline or 0),
        unknown=int(availability_row.unknown or 0),
        maintenance=int(availability_row.maintenance or 0),
    )

    type_rows = (await db.execute(
        select(
            DeviceType.code.label("key"),
            DeviceType.name.label("label"),
            func.count(Device.id).label("total"),
            *_state_columns(status_expr),
        )
        .select_from(Device)
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .outerjoin(DeviceAvailability, DeviceAvailability.device_id == Device.id)
        .where(*active_device_filters)
        .group_by(DeviceType.code, DeviceType.name)
        .order_by(func.count(Device.id).desc(), DeviceType.name)
    )).all()
    by_device_type = [
        _breakdown(
            key=row.key,
            label=row.label,
            context=None,
            total=row.total,
            values=row._mapping,
        )
        for row in type_rows
    ]

    network_rows = (await db.execute(
        select(
            Network.id.label("key"),
            Network.name.label("label"),
            func.count(Device.id).label("total"),
            *_state_columns(status_expr),
        )
        .select_from(Device)
        .join(DevicePlacement, DevicePlacement.device_id == Device.id)
        .join(Network, Network.id == DevicePlacement.network_id)
        .outerjoin(DeviceAvailability, DeviceAvailability.device_id == Device.id)
        .where(*active_device_filters, DevicePlacement.deleted_at.is_(None), Network.deleted_at.is_(None))
        .group_by(Network.id, Network.name)
        .order_by(func.count(Device.id).desc(), Network.name)
    )).all()
    by_network = [
        _breakdown(
            key=row.key,
            label=row.label,
            context=None,
            total=row.total,
            values=row._mapping,
        )
        for row in network_rows
    ]

    top_location_ids = (
        select(
            DevicePlacement.location_id.label("location_id"),
            func.count(Device.id).label("device_count"),
        )
        .select_from(Device)
        .join(DevicePlacement, DevicePlacement.device_id == Device.id)
        .where(*active_device_filters, DevicePlacement.deleted_at.is_(None))
        .group_by(DevicePlacement.location_id)
        .order_by(func.count(Device.id).desc(), DevicePlacement.location_id)
        .limit(top_location_limit)
        .subquery()
    )
    location_rows = (await db.execute(
        select(
            Location.id.label("key"),
            Location.name.label("label"),
            Network.name.label("network_name"),
            func.count(Device.id).label("total"),
            *_state_columns(status_expr),
        )
        .select_from(top_location_ids)
        .join(Location, Location.id == top_location_ids.c.location_id)
        .join(City, City.id == Location.city_id)
        .join(Network, Network.id == City.network_id)
        .join(DevicePlacement, DevicePlacement.location_id == Location.id)
        .join(Device, Device.id == DevicePlacement.device_id)
        .outerjoin(DeviceAvailability, DeviceAvailability.device_id == Device.id)
        .where(*active_device_filters, DevicePlacement.deleted_at.is_(None), Location.deleted_at.is_(None))
        .group_by(Location.id, Location.name, Network.name, top_location_ids.c.device_count)
        .order_by(top_location_ids.c.device_count.desc(), Location.name)
    )).all()
    top_locations = [
        _breakdown(
            key=row.key,
            label=row.label,
            context=row.network_name,
            total=row.total,
            values=row._mapping,
        )
        for row in location_rows
    ]

    alarms: DashboardAlarmCounts | None = None
    recent_outages: list[DashboardOutage] = []
    if include_alarms:
        alarm_rows = (await db.execute(
            select(
                Alarm.severity,
                func.count(Alarm.id).label("total"),
                func.sum(case((Alarm.acknowledged_at.is_(None), 1), else_=0)).label("unacknowledged"),
            )
            .join(Device, Device.id == Alarm.device_id)
            .where(Alarm.state == "ACTIVE", *active_device_filters)
            .group_by(Alarm.severity)
        )).all()
        severity_counts = {str(severity).lower(): int(total or 0) for severity, total, _ in alarm_rows}
        alarms = DashboardAlarmCounts(
            active_total=sum(int(total or 0) for _, total, _ in alarm_rows),
            unacknowledged=sum(int(unacknowledged or 0) for _, _, unacknowledged in alarm_rows),
            info=severity_counts.get("info", 0),
            warning=severity_counts.get("warning", 0),
            minor=severity_counts.get("minor", 0),
            major=severity_counts.get("major", 0),
            critical=severity_counts.get("critical", 0),
        )

        outage_rows = (await db.execute(
            select(
                OperationalEvent.id,
                OperationalEvent.device_id,
                OperationalEvent.occurred_at,
                OperationalEvent.summary,
                Device.display_name,
                DeviceAvailability.status,
                Network.name.label("network_name"),
                Location.name.label("location_name"),
            )
            .join(Device, Device.id == OperationalEvent.device_id)
            .outerjoin(DeviceAvailability, DeviceAvailability.device_id == Device.id)
            .outerjoin(DevicePlacement, (DevicePlacement.device_id == Device.id) & DevicePlacement.deleted_at.is_(None))
            .outerjoin(Location, Location.id == DevicePlacement.location_id)
            .outerjoin(Network, Network.id == DevicePlacement.network_id)
            .where(
                OperationalEvent.event_type == "DEVICE_AVAILABILITY_OFFLINE",
                *active_device_filters,
            )
            .order_by(OperationalEvent.occurred_at.desc(), OperationalEvent.id.desc())
            .limit(recent_outage_limit)
        )).all()
        recent_outages = [
            DashboardOutage(
                event_id=str(row.id),
                device_id=str(row.device_id),
                device_display_name=row.display_name,
                occurred_at=row.occurred_at,
                summary=row.summary,
                current_status=row.status,
                network_name=row.network_name,
                location_name=row.location_name,
            )
            for row in outage_rows
        ]

    runtime = await load_availability_settings(db)
    monitored_filters = (
        DeviceAvailability.enabled.is_(True),
        Device.deleted_at.is_(None),
        Device.lifecycle_state != "DECOMMISSIONED",
        scope_clause,
    )
    overdue_before = now - timedelta(seconds=max(5, min(runtime.interval_seconds, 60)))
    recent_after = now - timedelta(seconds=runtime.interval_seconds)
    polling_row = (await db.execute(
        select(
            func.count(DeviceAvailability.id).label("monitored_devices"),
            func.sum(case((DeviceAvailability.next_check_at <= now, 1), else_=0)).label("due_now"),
            func.sum(case((DeviceAvailability.next_check_at <= overdue_before, 1), else_=0)).label("overdue"),
            func.sum(case((DeviceAvailability.lease_expires_at > now, 1), else_=0)).label("active_leases"),
            func.sum(case((DeviceAvailability.last_check_at >= recent_after, 1), else_=0)).label("checked_last_interval"),
            func.max(DeviceAvailability.last_check_at).label("latest_check_at"),
            func.max(DeviceAvailability.last_dispatched_at).label("latest_dispatch_at"),
        )
        .select_from(DeviceAvailability)
        .join(Device, Device.id == DeviceAvailability.device_id)
        .where(*monitored_filters)
    )).one()

    redis_status, worker_heartbeat_at, heartbeat_age = await _worker_heartbeat()
    monitored_devices = int(polling_row.monitored_devices or 0)
    due_now = int(polling_row.due_now or 0)
    overdue = int(polling_row.overdue or 0)
    active_leases = int(polling_row.active_leases or 0)
    if not runtime.enabled:
        polling_status = "DISABLED"
    elif redis_status != "ONLINE":
        polling_status = "DEGRADED"
    elif worker_heartbeat_at is None:
        polling_status = "STARTING" if monitored_devices else "IDLE"
    elif heartbeat_age is not None and heartbeat_age > 45:
        polling_status = "DEGRADED"
    elif overdue > max(5, runtime.dispatch_limit_per_tick * 2):
        polling_status = "BACKLOG"
    else:
        polling_status = "HEALTHY"

    polling = DashboardPollingHealth(
        enabled=runtime.enabled,
        status=polling_status,
        interval_seconds=runtime.interval_seconds,
        worker_concurrency=runtime.worker_concurrency,
        dispatch_limit_per_tick=runtime.dispatch_limit_per_tick,
        task_batch_size=runtime.task_batch_size,
        max_outstanding_devices=runtime.max_outstanding_devices,
        monitored_devices=monitored_devices,
        due_now=due_now,
        overdue=overdue,
        active_leases=active_leases,
        checked_last_interval=int(polling_row.checked_last_interval or 0),
        latest_check_at=polling_row.latest_check_at,
        latest_dispatch_at=polling_row.latest_dispatch_at,
        worker_heartbeat_at=worker_heartbeat_at,
        worker_heartbeat_age_seconds=round(heartbeat_age, 3) if heartbeat_age is not None else None,
        redis_status=redis_status,
    )

    return OperationsDashboardRead(
        generated_at=now,
        availability=availability,
        alarms=alarms,
        authorized_device_categories=authorized_device_categories,
        by_device_type=by_device_type,
        by_network=by_network,
        top_locations=top_locations,
        recent_outages=recent_outages,
        polling=polling,
    )
