from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
import re
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.models import (
    Alarm, AuditLog, City, Customer, CustomerService, Device, DeviceAvailability, DeviceIP,
    DeviceGroup, DeviceType, Location, Network, OperationalEvent, Permission, ReportDefinition,
    ReportDelivery, ReportJob, ReportSchedule, RolePermission, Sector, User, UserPermission, UserRole,
)
from app.security.permissions import Permission as P
from app.security.resource_scope import EffectiveResourceScope, load_effective_resource_scope
from app.security.scope_queries import customer_service_scope_clause, device_scope_clause
from app.services.authorization_snapshot import scope_fingerprint, scope_snapshot
from app.services.group_effective import effective_group_context_subquery, effective_group_population_subquery
from app.services.audit import record_audit
from app.services.tabular_formats import write_tabular_bytes
from app.settings import settings


REPORT_CATALOG: dict[str, dict[str, Any]] = {
    "inventory": {
        "name": "Inventory",
        "description": "Managed device inventory and current placement/state.",
        "sensitive_fields": ["management_ip", "serial_number"],
        "supported_formats": ["CSV", "XLSX", "PDF", "JSON"],
        "filters": ["device_type", "lifecycle_state", "operational_state"],
    },
    "availability_sla": {
        "name": "Availability / SLA",
        "description": "Observed availability derived from authoritative OFFLINE/RESTORED events.",
        "sensitive_fields": [],
        "supported_formats": ["CSV", "XLSX", "PDF", "JSON"],
        "filters": ["start", "end"],
    },
    "outages": {
        "name": "Outages",
        "description": "Authoritative availability transition events.",
        "sensitive_fields": [],
        "supported_formats": ["CSV", "XLSX", "PDF", "JSON"],
        "filters": ["start", "end", "event_type"],
    },
    "alarms": {
        "name": "Alarms",
        "description": "Current alarm workflow state and occurrence counts.",
        "sensitive_fields": [],
        "supported_formats": ["CSV", "XLSX", "PDF", "JSON"],
        "filters": ["state", "severity"],
    },
    "lifecycle": {
        "name": "Lifecycle",
        "description": "Scoped managed-device lifecycle state; recycle-bin payload is not exposed.",
        "sensitive_fields": [],
        "supported_formats": ["CSV", "XLSX", "PDF", "JSON"],
        "filters": ["lifecycle_state"],
    },
    "audit": {
        "name": "Audit",
        "description": "Global append-only audit evidence. GLOBAL scope and audit.read are required.",
        "sensitive_fields": ["actor_username", "source_ip"],
        "supported_formats": ["CSV", "XLSX", "PDF", "JSON"],
        "filters": ["start", "end", "action", "result"],
    },
    "customer_service": {
        "name": "Customer / Service",
        "description": "CustomerService-authoritative service and derived VLAN/topology presentation.",
        "sensitive_fields": [],
        "supported_formats": ["CSV", "XLSX", "PDF", "JSON"],
        "filters": ["status"],
    },
}

REPORT_REQUIRED_PERMISSION = {
    "inventory": P.DEVICE_READ,
    "availability_sla": P.DEVICE_READ,
    "outages": P.ALARM_READ,
    "alarms": P.ALARM_READ,
    "lifecycle": P.DEVICE_READ,
    "audit": P.AUDIT_READ,
    "customer_service": P.CUSTOMER_READ,
}

MAX_REPORT_ROWS = 250_000


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def report_root() -> Path:
    root = Path(settings.data_root).resolve() / "reports"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _safe_report_slug(value: str, *, fallback: str = "report") -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-._")
    normalized = re.sub(r"-+", "-", normalized)
    return (normalized[:120] or fallback).lower()


async def _report_scope_label(db: AsyncSession, filters: dict[str, Any]) -> str | None:
    lookups = (
        ("group_id", DeviceGroup, "Group"),
        ("sector_id", Sector, "Sector"),
        ("location_id", Location, "Location"),
        ("city_id", City, "City"),
        ("network_id", Network, "Network"),
    )
    for key, model, prefix in lookups:
        raw = filters.get(key)
        if not raw:
            continue
        try:
            row_id = UUID(str(raw))
        except (TypeError, ValueError):
            continue
        name = await db.scalar(select(model.name).where(model.id == row_id))
        if name:
            return f"{prefix} {name}"
    service_vlan = filters.get("service_vlan_id")
    customer_vlan = filters.get("customer_vlan_id")
    if service_vlan not in {None, ""} and customer_vlan not in {None, ""}:
        return f"S-VLAN {service_vlan} / C-VLAN {customer_vlan}"
    if customer_vlan not in {None, ""}:
        return f"C-VLAN {customer_vlan}"
    if service_vlan not in {None, ""}:
        return f"S-VLAN {service_vlan}"
    return None


async def _report_display_name(
    db: AsyncSession, *, report_type: str, filters: dict[str, Any], requested_at: datetime,
    definition_id: UUID | None = None, schedule_id: UUID | None = None,
) -> tuple[str, str]:
    source_kind = "AD_HOC"
    source_name: str | None = None
    if schedule_id is not None:
        source_name = await db.scalar(select(ReportSchedule.name).where(ReportSchedule.id == schedule_id))
        if source_name:
            source_kind = "SCHEDULE"
    if source_name is None and definition_id is not None:
        source_name = await db.scalar(select(ReportDefinition.name).where(ReportDefinition.id == definition_id))
        if source_name:
            source_kind = "DEFINITION"
    if source_name is None:
        source_name = str(REPORT_CATALOG.get(report_type, {}).get("name") or report_type.replace("_", " ").title())
        scope_label = await _report_scope_label(db, filters or {})
        if scope_label:
            source_name = f"{source_name} — {scope_label}"
    timestamp = requested_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"{source_name} — {timestamp}", source_kind


def report_artifact_filename(job: ReportJob) -> str:
    display_name = job.display_name
    slug = _safe_report_slug(display_name, fallback=job.report_type or "report")
    stamp = job.requested_at.astimezone(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    return f"{slug}_{stamp}_{str(job.id)[:8]}.{job.format.lower()}"


def _parse_time(value: Any, *, default: datetime) -> datetime:
    if not value:
        return default
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _uuid_filter(filters: dict[str, Any], key: str) -> UUID | None:
    value = filters.get(key)
    if value in {None, ""}:
        return None
    try:
        return UUID(str(value))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be a valid identifier.") from exc


def _vlan_filter(filters: dict[str, Any], key: str) -> int | None:
    value = filters.get(key)
    if value in {None, ""}:
        return None
    try:
        vlan = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be a VLAN number.") from exc
    if vlan < 2 or vlan > 4094:
        raise ValueError(f"{key} must be between 2 and 4094.")
    return vlan


async def _device_report_filter_clause(db: AsyncSession, filters: dict[str, Any], *, device_col=Device.id):
    clauses = []
    context = effective_group_context_subquery()
    geo = []
    for key, column in (("network_id", context.c.network_id), ("city_id", context.c.city_id), ("location_id", context.c.location_id), ("sector_id", context.c.sector_id)):
        value = _uuid_filter(filters, key)
        if value is not None:
            geo.append(column == value)
    service_vlan_id = _vlan_filter(filters, "service_vlan_id")
    customer_vlan_id = _vlan_filter(filters, "customer_vlan_id")
    if service_vlan_id is not None:
        geo.append(select(1).where(City.id == context.c.city_id, City.service_vlan_id == service_vlan_id).exists())
    if geo:
        clauses.append(select(1).select_from(context).where(context.c.device_id == device_col, *geo).exists())
    if customer_vlan_id is not None:
        sector_vlan = select(1).select_from(context).join(Sector, Sector.id == context.c.sector_id).where(
            context.c.device_id == device_col, Sector.deleted_at.is_(None),
            Sector.customer_vlan_start.is_not(None), Sector.customer_vlan_end.is_not(None),
            Sector.customer_vlan_start <= customer_vlan_id, Sector.customer_vlan_end >= customer_vlan_id,
        ).exists()
        service_vlan = select(1).where(
            CustomerService.deleted_at.is_(None), CustomerService.customer_vlan_id == customer_vlan_id,
            or_(CustomerService.access_point_device_id == device_col, CustomerService.cpe_device_id == device_col),
        ).exists()
        clauses.append(or_(sector_vlan, service_vlan))
    group_id = _uuid_filter(filters, "group_id")
    if group_id is not None:
        population = await effective_group_population_subquery(db, group_id)
        clauses.append(select(1).select_from(population).where(population.c.device_id == device_col).exists())
    return and_(*clauses) if clauses else None


async def effective_permission_codes(db: AsyncSession, user_id: UUID) -> set[str]:
    role_codes = set((await db.scalars(
        select(Permission.code)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(UserRole, UserRole.role_id == RolePermission.role_id)
        .where(UserRole.user_id == user_id)
    )).all())
    direct_codes = set((await db.scalars(
        select(Permission.code)
        .join(UserPermission, UserPermission.permission_id == Permission.id)
        .where(UserPermission.user_id == user_id)
    )).all())
    return role_codes | direct_codes


def validate_report_filter_permissions(filters: dict[str, Any] | None, permissions: set[str]) -> None:
    filters = filters or {}
    if any(filters.get(key) for key in ("network_id", "city_id", "location_id", "sector_id", "service_vlan_id", "customer_vlan_id")) and P.GEO_READ not in permissions:
        raise PermissionError("geo.read is required to filter reports by geography.")
    if filters.get("group_id") and P.GROUP_READ not in permissions:
        raise PermissionError("group.read is required to filter reports by group.")


def validate_report_request(
    *, report_type: str, format: str, include_sensitive: bool, scope: EffectiveResourceScope, permissions: set[str],
) -> tuple[str, str]:
    report_type = report_type.strip().lower()
    fmt = format.strip().upper()
    item = REPORT_CATALOG.get(report_type)
    if item is None:
        raise ValueError("Unknown report type.")
    if fmt not in item["supported_formats"]:
        raise ValueError("Unsupported report format.")
    required = REPORT_REQUIRED_PERMISSION[report_type]
    if P.REPORT_READ not in permissions or P.REPORT_EXPORT not in permissions or required not in permissions:
        raise PermissionError("Required report/source permission is missing.")
    if include_sensitive and P.REPORT_SENSITIVE not in permissions:
        raise PermissionError("report.sensitive is required for sensitive fields.")
    if report_type == "audit" and not scope.global_access:
        raise PermissionError("Audit reports require GLOBAL resource scope.")
    return report_type, fmt


async def _inventory_rows(db: AsyncSession, scope: EffectiveResourceScope, filters: dict[str, Any], include_sensitive: bool):
    clause = await device_scope_clause(db, scope)
    context = effective_group_context_subquery()
    stmt = (
        select(Device, DeviceType.code, DeviceIP.ip_address, Network.name, City.name, Location.name, Sector.name)
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .outerjoin(DeviceIP, and_(DeviceIP.device_id == Device.id, DeviceIP.is_primary.is_(True), DeviceIP.deleted_at.is_(None)))
        .outerjoin(context, context.c.device_id == Device.id)
        .outerjoin(Network, Network.id == context.c.network_id)
        .outerjoin(City, City.id == context.c.city_id)
        .outerjoin(Location, Location.id == context.c.location_id)
        .outerjoin(Sector, Sector.id == context.c.sector_id)
        .where(Device.deleted_at.is_(None), clause)
    )
    extra = await _device_report_filter_clause(db, filters)
    if extra is not None:
        stmt = stmt.where(extra)
    if filters.get("device_type"):
        stmt = stmt.where(DeviceType.code == str(filters["device_type"]).upper())
    if filters.get("lifecycle_state"):
        stmt = stmt.where(Device.lifecycle_state == str(filters["lifecycle_state"]).upper())
    if filters.get("operational_state"):
        stmt = stmt.where(Device.operational_state == str(filters["operational_state"]).upper())
    result = []
    for device, dtype, management_ip, network, city, location, sector in (await db.execute(stmt.order_by(Device.display_name, Device.id).limit(MAX_REPORT_ROWS + 1))).all():
        row = {
            "device_type": dtype, "display_name": device.display_name,
            "vendor": device.vendor, "model": device.model, "lifecycle_state": device.lifecycle_state,
            "operational_state": device.operational_state, "network": network, "city": city,
            "location": location, "sector": sector,
        }
        if include_sensitive:
            row.update({"management_ip": management_ip, "serial_number": device.serial_number})
        result.append(row)
    return result


async def _outage_rows(db: AsyncSession, scope: EffectiveResourceScope, filters: dict[str, Any]):
    clause = await device_scope_clause(db, scope)
    now = utcnow(); start = _parse_time(filters.get("start"), default=now - timedelta(days=30)); end = _parse_time(filters.get("end"), default=now)
    types = ["DEVICE_AVAILABILITY_OFFLINE", "DEVICE_AVAILABILITY_RESTORED"]
    if filters.get("event_type"):
        event_type = str(filters["event_type"]).upper()
        if event_type in types:
            types = [event_type]
    stmt = select(OperationalEvent, Device.display_name).join(Device, Device.id == OperationalEvent.device_id).where(
        clause, OperationalEvent.event_type.in_(types), OperationalEvent.occurred_at >= start, OperationalEvent.occurred_at <= end,
    )
    extra = await _device_report_filter_clause(db, filters)
    if extra is not None:
        stmt = stmt.where(extra)
    stmt = stmt.order_by(OperationalEvent.occurred_at.desc(), OperationalEvent.id).limit(MAX_REPORT_ROWS + 1)
    return [{"event_id": str(event.id), "device": name, "event_type": event.event_type, "severity": event.severity, "occurred_at": event.occurred_at.isoformat(), "summary": event.summary} for event, name in (await db.execute(stmt)).all()]


async def _availability_sla_rows(db: AsyncSession, scope: EffectiveResourceScope, filters: dict[str, Any]):
    clause = await device_scope_clause(db, scope)
    now = utcnow(); start = _parse_time(filters.get("start"), default=now - timedelta(days=30)); end = _parse_time(filters.get("end"), default=now)
    if start >= end:
        raise ValueError("SLA start must be before end.")
    device_stmt = select(Device.id, Device.display_name).where(Device.deleted_at.is_(None), clause)
    extra = await _device_report_filter_clause(db, filters)
    if extra is not None:
        device_stmt = device_stmt.where(extra)
    devices = list((await db.execute(device_stmt.order_by(Device.display_name, Device.id).limit(MAX_REPORT_ROWS + 1))).all())
    ids = [row.id for row in devices]
    if not ids:
        return []
    event_types = ["DEVICE_AVAILABILITY_OFFLINE", "DEVICE_AVAILABILITY_RESTORED"]
    prior_ranked = select(
        OperationalEvent.device_id.label("device_id"), OperationalEvent.event_type.label("event_type"),
        OperationalEvent.occurred_at.label("occurred_at"),
        func.row_number().over(partition_by=OperationalEvent.device_id, order_by=OperationalEvent.occurred_at.desc()).label("rn"),
    ).where(OperationalEvent.device_id.in_(ids), OperationalEvent.event_type.in_(event_types), OperationalEvent.occurred_at < start).subquery()
    prior = {row.device_id: row.event_type for row in (await db.execute(select(prior_ranked.c.device_id, prior_ranked.c.event_type).where(prior_ranked.c.rn == 1))).all()}
    ranged = (await db.execute(select(OperationalEvent.device_id, OperationalEvent.event_type, OperationalEvent.occurred_at).where(
        OperationalEvent.device_id.in_(ids), OperationalEvent.event_type.in_(event_types),
        OperationalEvent.occurred_at >= start, OperationalEvent.occurred_at <= end,
    ).order_by(OperationalEvent.device_id, OperationalEvent.occurred_at, OperationalEvent.id))).all()
    by_device: dict[UUID, list[Any]] = {device_id: [] for device_id in ids}
    for row in ranged:
        by_device.setdefault(row.device_id, []).append(row)
    total_seconds = max(1.0, (end - start).total_seconds())
    output = []
    for device_id, display_name in devices:
        offline = prior.get(device_id) == "DEVICE_AVAILABILITY_OFFLINE"
        cursor = start
        downtime = 0.0
        outages = 0
        if offline:
            outages = 1
        for event in by_device.get(device_id, []):
            at = max(start, min(end, event.occurred_at))
            if offline:
                downtime += max(0.0, (at - cursor).total_seconds())
            if event.event_type == "DEVICE_AVAILABILITY_OFFLINE":
                if not offline:
                    outages += 1
                offline = True
            else:
                offline = False
            cursor = at
        if offline:
            downtime += max(0.0, (end - cursor).total_seconds())
        availability = max(0.0, min(100.0, (1.0 - downtime / total_seconds) * 100.0))
        output.append({
            "device": display_name, "window_start": start.isoformat(), "window_end": end.isoformat(),
            "observed_seconds": round(total_seconds, 3), "offline_seconds": round(downtime, 3),
            "availability_percent": round(availability, 6), "outage_occurrences": outages,
        })
    return output


async def _alarm_rows(db: AsyncSession, scope: EffectiveResourceScope, filters: dict[str, Any]):
    clause = await device_scope_clause(db, scope)
    stmt = select(Alarm, Device.display_name).join(Device, Device.id == Alarm.device_id).where(clause)
    extra = await _device_report_filter_clause(db, filters)
    if extra is not None:
        stmt = stmt.where(extra)
    if filters.get("state"):
        stmt = stmt.where(Alarm.state == str(filters["state"]).upper())
    if filters.get("severity"):
        stmt = stmt.where(Alarm.severity == str(filters["severity"]).upper())
    rows = (await db.execute(stmt.order_by(Alarm.last_raised_at.desc(), Alarm.id).limit(MAX_REPORT_ROWS + 1))).all()
    return [{"alarm_id": str(alarm.id), "device": name, "alarm_type": alarm.alarm_type, "severity": alarm.severity, "state": alarm.state, "summary": alarm.summary, "first_raised_at": alarm.first_raised_at.isoformat(), "last_raised_at": alarm.last_raised_at.isoformat(), "last_cleared_at": alarm.last_cleared_at.isoformat() if alarm.last_cleared_at else None, "occurrence_count": alarm.occurrence_count} for alarm, name in rows]


async def _lifecycle_rows(db: AsyncSession, scope: EffectiveResourceScope, filters: dict[str, Any]):
    clause = await device_scope_clause(db, scope)
    stmt = select(Device, DeviceType.code).join(DeviceType, DeviceType.id == Device.device_type_id).where(Device.deleted_at.is_(None), clause)
    extra = await _device_report_filter_clause(db, filters)
    if extra is not None:
        stmt = stmt.where(extra)
    if filters.get("lifecycle_state"):
        stmt = stmt.where(Device.lifecycle_state == str(filters["lifecycle_state"]).upper())
    rows = (await db.execute(stmt.order_by(Device.display_name, Device.id).limit(MAX_REPORT_ROWS + 1))).all()
    return [{"device_type": dtype, "display_name": device.display_name, "lifecycle_state": device.lifecycle_state, "operational_state": device.operational_state, "created_at": device.created_at.isoformat(), "updated_at": device.updated_at.isoformat()} for device, dtype in rows]


async def _audit_rows(db: AsyncSession, filters: dict[str, Any], include_sensitive: bool):
    now = utcnow(); start = _parse_time(filters.get("start"), default=now - timedelta(days=30)); end = _parse_time(filters.get("end"), default=now)
    stmt = select(AuditLog).where(AuditLog.occurred_at >= start, AuditLog.occurred_at <= end)
    if filters.get("action"):
        stmt = stmt.where(AuditLog.action == str(filters["action"]))
    if filters.get("result"):
        stmt = stmt.where(AuditLog.result == str(filters["result"]).upper())
    output = []
    for row in (await db.scalars(stmt.order_by(AuditLog.occurred_at.desc(), AuditLog.id).limit(MAX_REPORT_ROWS + 1))).all():
        item = {"audit_id": str(row.id), "occurred_at": row.occurred_at.isoformat(), "action": row.action, "entity_type": row.entity_type, "entity_id": str(row.entity_id) if row.entity_id else None, "result": row.result, "description": row.description}
        if include_sensitive:
            item.update({"actor_username": row.actor_username_snapshot, "source_ip": row.source_ip})
        output.append(item)
    return output


async def _customer_service_rows(db: AsyncSession, scope: EffectiveResourceScope, filters: dict[str, Any]):
    AccessPoint = aliased(Device)
    CpeDevice = aliased(Device)
    stmt = (
        select(CustomerService, Customer, Sector, Location, City, Network, AccessPoint.display_name, CpeDevice.display_name)
        .join(Customer, Customer.id == CustomerService.customer_id)
        .join(Sector, Sector.id == CustomerService.sector_id)
        .join(Location, Location.id == Sector.location_id)
        .join(City, City.id == Location.city_id)
        .join(Network, Network.id == City.network_id)
        .outerjoin(AccessPoint, AccessPoint.id == CustomerService.access_point_device_id)
        .outerjoin(CpeDevice, CpeDevice.id == CustomerService.cpe_device_id)
        .where(CustomerService.deleted_at.is_(None), Customer.deleted_at.is_(None), customer_service_scope_clause(scope))
    )
    for key, column in (("network_id", Network.id), ("city_id", City.id), ("location_id", Location.id), ("sector_id", Sector.id)):
        value = _uuid_filter(filters, key)
        if value is not None:
            stmt = stmt.where(column == value)
    group_id = _uuid_filter(filters, "group_id")
    if group_id is not None:
        population = await effective_group_population_subquery(db, group_id)
        member_ids = select(population.c.device_id)
        stmt = stmt.where(or_(
            CustomerService.access_point_device_id.in_(member_ids),
            CustomerService.cpe_device_id.in_(member_ids),
        ))
    service_vlan_id = _vlan_filter(filters, "service_vlan_id")
    customer_vlan_id = _vlan_filter(filters, "customer_vlan_id")
    if service_vlan_id is not None: stmt = stmt.where(City.service_vlan_id == service_vlan_id)
    if customer_vlan_id is not None: stmt = stmt.where(CustomerService.customer_vlan_id == customer_vlan_id)
    if filters.get("status"):
        stmt = stmt.where(CustomerService.status == str(filters["status"]).upper())
    rows = (await db.execute(stmt.order_by(Customer.customer_code, CustomerService.service_code).limit(MAX_REPORT_ROWS + 1))).all()
    return [{
        "customer_code": customer.customer_code, "customer": customer.name, "customer_status": customer.status,
        "service_code": service.service_code, "service_status": service.status, "network": network.name,
        "city": city.name, "location": location.name, "sector": sector.name, "service_vlan": city.service_vlan_id,
        "customer_vlan": service.customer_vlan_id, "access_point": access_point_name, "cpe": cpe_name,
    } for service, customer, sector, location, city, network, access_point_name, cpe_name in rows]


async def build_report_rows(
    db: AsyncSession, *, report_type: str, filters: dict[str, Any], include_sensitive: bool,
    scope: EffectiveResourceScope, permissions: set[str],
) -> list[dict[str, Any]]:
    report_type, _ = validate_report_request(report_type=report_type, format="CSV", include_sensitive=include_sensitive, scope=scope, permissions=permissions)
    validate_report_filter_permissions(filters, permissions)
    if report_type == "inventory":
        rows = await _inventory_rows(db, scope, filters, include_sensitive)
    elif report_type == "availability_sla":
        rows = await _availability_sla_rows(db, scope, filters)
    elif report_type == "outages":
        rows = await _outage_rows(db, scope, filters)
    elif report_type == "alarms":
        rows = await _alarm_rows(db, scope, filters)
    elif report_type == "lifecycle":
        rows = await _lifecycle_rows(db, scope, filters)
    elif report_type == "audit":
        rows = await _audit_rows(db, filters, include_sensitive)
    else:
        rows = await _customer_service_rows(db, scope, filters)
    if len(rows) > MAX_REPORT_ROWS:
        raise ValueError(f"Report exceeds the {MAX_REPORT_ROWS}-row safety limit; narrow the filters.")
    return rows


def _columns(rows: list[dict[str, Any]]) -> list[str]:
    columns: list[str] = []
    for row in rows:
        for key in row:
            if key not in columns:
                columns.append(key)
    return columns or ["result"]


async def create_report_job(
    db: AsyncSession, *, owner_user_id: UUID, report_type: str, format: str, filters: dict[str, Any],
    include_sensitive: bool, definition_id: UUID | None = None, schedule_id: UUID | None = None,
) -> ReportJob:
    user = await db.scalar(select(User).where(User.id == owner_user_id, User.is_active.is_(True)))
    if user is None:
        raise PermissionError("Report owner is inactive or unavailable.")
    permissions = await effective_permission_codes(db, owner_user_id)
    scope = await load_effective_resource_scope(db, owner_user_id)
    report_type, fmt = validate_report_request(report_type=report_type, format=format, include_sensitive=include_sensitive, scope=scope, permissions=permissions)
    validate_report_filter_permissions(filters, permissions)
    now = utcnow()
    display_name, source_kind = await _report_display_name(
        db, report_type=report_type, filters=filters or {}, requested_at=now,
        definition_id=definition_id, schedule_id=schedule_id,
    )
    job = ReportJob(
        owner_user_id=owner_user_id, definition_id=definition_id, schedule_id=schedule_id,
        report_type=report_type, format=fmt, status="QUEUED", filters=filters or {}, include_sensitive=include_sensitive,
        scope_snapshot=scope_snapshot(scope), scope_fingerprint=scope_fingerprint(scope), permission_snapshot=sorted(permissions),
        requested_at=now, metadata_={"phase": "D4", "display_name": display_name, "source_kind": source_kind},
    )
    db.add(job); await db.flush()
    await record_audit(db, action="REPORT_QUEUED", entity_type="ReportJob", entity_id=job.id, description="Asynchronous report job queued.", metadata={"report_type": report_type, "format": fmt, "scheduled": bool(schedule_id)})
    return job


async def execute_report_job(db: AsyncSession, job_id: UUID) -> ReportJob:
    job = await db.scalar(select(ReportJob).where(ReportJob.id == job_id).with_for_update().execution_options(populate_existing=True))
    if job is None:
        raise ValueError("Report job not found.")
    if job.status == "COMPLETED":
        return job
    if job.status not in {"QUEUED", "RUNNING"}:
        raise ValueError("Report job is not executable.")
    user = await db.scalar(select(User).where(User.id == job.owner_user_id, User.is_active.is_(True)))
    if user is None:
        job.status = "CANCELLED"; job.error_code = "REPORT_OWNER_INACTIVE"; job.completed_at = utcnow(); return job
    permissions = await effective_permission_codes(db, user.id)
    scope = await load_effective_resource_scope(db, user.id)
    # A queued job is a capability snapshot, not a future authorization bypass.
    if scope_fingerprint(scope) != job.scope_fingerprint or sorted(permissions) != sorted(job.permission_snapshot or []):
        job.status = "CANCELLED"; job.error_code = "REPORT_AUTHORIZATION_CHANGED"; job.error_message = "Permissions or scope changed after the report was queued; submit a new report."; job.completed_at = utcnow(); return job
    validate_report_request(report_type=job.report_type, format=job.format, include_sensitive=job.include_sensitive, scope=scope, permissions=permissions)
    job.status = "RUNNING"; job.started_at = utcnow(); await db.flush()
    rows = await build_report_rows(db, report_type=job.report_type, filters=job.filters or {}, include_sensitive=job.include_sensitive, scope=scope, permissions=permissions)
    columns = _columns(rows)
    content = write_tabular_bytes(columns, rows, job.format)
    root = report_root(); name = report_artifact_filename(job); path = (root / name).resolve()
    if path.parent != root:
        raise RuntimeError("REPORT_PATH_INVALID")
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_bytes(content); temp.replace(path)
    job.row_count = len(rows); job.artifact_name = name; job.artifact_size = len(content); job.artifact_sha256 = sha256(content).hexdigest()
    job.status = "COMPLETED"; job.completed_at = utcnow(); job.expires_at = job.completed_at + timedelta(days=30)
    await record_audit(db, action="REPORT_COMPLETED", entity_type="ReportJob", entity_id=job.id, description="Asynchronous report generated from scope-filtered source data.", metadata={"report_type": job.report_type, "format": job.format, "row_count": job.row_count, "sha256": job.artifact_sha256})
    if job.schedule_id:
        schedule = await db.scalar(select(ReportSchedule).where(ReportSchedule.id == job.schedule_id))
        if schedule and schedule.channel_type and schedule.destination:
            key = f"report:{job.id}:schedule:{schedule.id}"
            exists_row = await db.scalar(select(ReportDelivery.id).where(ReportDelivery.idempotency_key == key))
            if exists_row is None:
                db.add(ReportDelivery(report_job_id=job.id, schedule_id=schedule.id, owner_user_id=job.owner_user_id, channel_type=schedule.channel_type, destination=schedule.destination, status="PENDING", idempotency_key=key, attempt_count=0, next_attempt_at=utcnow(), scope_fingerprint=job.scope_fingerprint, metadata_={"report_type": job.report_type, "format": job.format}))
    return job


def media_type_for(format: str) -> str:
    return {"CSV": "text/csv", "XLSX": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "PDF": "application/pdf", "JSON": "application/json"}[format.upper()]
