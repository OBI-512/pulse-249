from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from io import BytesIO
from ipaddress import ip_address
from math import isfinite
from typing import Any
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    City, Customer, CustomerService, Device, DeviceGroup, DeviceIP,
    DeviceType, ImportJob, ImportRecord, Location, Network, Sector,
)
from app.security.resource_scope import EffectiveResourceScope
from app.security.scope_queries import (
    city_scope_clause, customer_scope_clause, device_scope_clause, group_scope_clause,
    customer_service_scope_clause, location_scope_clause, network_scope_clause, require_city, require_device, require_location,
    require_network, require_sector, sector_scope_clause,
)
from app.services.audit import record_audit
from app.services.authorization_snapshot import scope_fingerprint, scope_snapshot
from app.services.customer_services import CustomerServiceValidationError, _derive_service_path, _validate_customer_vlan, create_customer_service
from app.services.device_registration import register_domain_device
from app.services.group_effective import (
    effective_group_context_subquery, effective_group_population_context_subquery,
    effective_group_population_subquery,
)
from app.services.tabular_formats import MAX_IMPORT_ROWS, parse_tabular_bytes, write_tabular_bytes, write_tabular_template_bytes


IMPORT_TYPES = {"geography", "devices", "customers", "customer_services", "groups"}
IMPORT_PREVIEW_TTL = timedelta(days=7)
CONTROLLED_TYPES = {
    "ACCESS_POINT", "CPE", "SECTOR", "SWITCH", "ROUTER", "FIREWALL", "SERVER",
    "WIRELESS_BRIDGE", "NETWORK_DEVICE", "OTHER",
}

TEMPLATES: dict[str, list[str]] = {
    "geography": [
        "level", "name", "code", "network_code", "city_code", "location_code",
        "status", "service_vlan_id", "address", "latitude", "longitude", "role", "customer_vlan_start", "customer_vlan_end",
    ],
    "devices": [
        "device_type", "display_name", "management_ip", "network_code", "city_code",
        "location_code", "sector_code", "parent_management_ip", "hostname", "vendor", "model",
        "serial_number", "description", "management_protocol",
    ],
    "customers": ["customer_code", "name", "status"],
    "customer_services": ["customer_code", "service_code", "status", "access_point_management_ip", "customer_vlan_id", "router_management_ip"],
    "groups": [
        "code", "name", "description", "membership_mode", "scope_type", "network_code",
        "city_code", "location_code", "sector_code", "device_scope", "sector_role",
    ],
}


@dataclass(frozen=True)
class ValidationResult:
    status: str
    normalized: dict[str, Any]
    error_code: str | None = None
    error_message: str | None = None


class ImportPreviewExpired(ValueError):
    """Raised when a confirm request targets an expired preview."""


def _import_natural_key(entity_type: str, normalized: dict[str, Any]) -> tuple[Any, ...] | None:
    """Return the authoritative conflict key used to reject duplicates inside one file."""
    if not normalized:
        return None
    if entity_type == "geography":
        level = normalized.get("level")
        if level == "NETWORK":
            return (level, normalized.get("code"))
        if level == "CITY":
            return (level, normalized.get("network_id"), normalized.get("code"))
        if level == "LOCATION":
            return (level, normalized.get("city_id"), normalized.get("code"))
        if level == "SECTOR":
            return (level, normalized.get("location_id"), normalized.get("code"))
    if entity_type == "devices":
        return ("DEVICE", normalized.get("management_ip"))
    if entity_type == "customers":
        return ("CUSTOMER", normalized.get("customer_code"))
    if entity_type == "groups":
        return ("GROUP", normalized.get("code"))
    return None


def _import_conflict_keys(entity_type: str, normalized: dict[str, Any]) -> list[tuple[Any, ...]]:
    """Return every in-file uniqueness key that must fail before commit."""
    natural = _import_natural_key(entity_type, normalized)
    if entity_type != "customer_services":
        return [natural] if natural is not None else []
    keys: list[tuple[Any, ...]] = []
    for label, field in (
        ("CUSTOMER", "customer_id"),
        ("SERVICE_CODE", "service_code"),
        ("ACCESS_POINT", "access_point_device_id"),
        ("CPE", "cpe_device_id"),
    ):
        value = normalized.get(field)
        if value:
            keys.append(("CUSTOMER_SERVICE", label, value))
    return keys


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _text(row: dict[str, Any], key: str) -> str | None:
    value = row.get(key)
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _required(row: dict[str, Any], key: str) -> str:
    value = _text(row, key)
    if value is None:
        raise ValueError(f"{key} is required.")
    return value


def _integer(row: dict[str, Any], key: str) -> int | None:
    value = _text(row, key)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{key} must be an integer.") from exc


def _number(row: dict[str, Any], key: str) -> float | None:
    value = _text(row, key)
    if value is None:
        return None
    try:
        number = float(value)
    except ValueError as exc:
        raise ValueError(f"{key} must be a number.") from exc
    if not isfinite(number):
        raise ValueError(f"{key} must be a finite number.")
    return number


def _http_error(exc: HTTPException) -> tuple[str, str]:
    detail = exc.detail
    if isinstance(detail, dict):
        return str(detail.get("code") or "VALIDATION_ERROR"), str(detail.get("message") or "Validation failed.")
    return "VALIDATION_ERROR", str(detail)


async def _network_by_code(db: AsyncSession, code: str | None) -> Network | None:
    if not code:
        return None
    return await db.scalar(select(Network).where(Network.code == code, Network.deleted_at.is_(None)))


async def _city_by_codes(db: AsyncSession, network_code: str | None, city_code: str | None) -> City | None:
    if not city_code:
        return None
    stmt = select(City).join(Network, Network.id == City.network_id).where(
        City.code == city_code, City.deleted_at.is_(None), Network.deleted_at.is_(None)
    )
    if network_code:
        stmt = stmt.where(Network.code == network_code)
    rows = list((await db.scalars(stmt.limit(2))).all())
    return rows[0] if len(rows) == 1 else None


async def _location_by_codes(
    db: AsyncSession, network_code: str | None, city_code: str | None, location_code: str | None,
) -> Location | None:
    if not location_code:
        return None
    stmt = select(Location).join(City, City.id == Location.city_id).join(Network, Network.id == City.network_id).where(
        Location.code == location_code, Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None)
    )
    if city_code:
        stmt = stmt.where(City.code == city_code)
    if network_code:
        stmt = stmt.where(Network.code == network_code)
    rows = list((await db.scalars(stmt.limit(2))).all())
    return rows[0] if len(rows) == 1 else None


async def _sector_by_codes(
    db: AsyncSession, network_code: str | None, city_code: str | None,
    location_code: str | None, sector_code: str | None,
) -> Sector | None:
    if not sector_code:
        return None
    stmt = select(Sector).join(Location, Location.id == Sector.location_id).join(City, City.id == Location.city_id).join(Network, Network.id == City.network_id).where(
        Sector.code == sector_code, Sector.deleted_at.is_(None), Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None)
    )
    if location_code:
        stmt = stmt.where(Location.code == location_code)
    if city_code:
        stmt = stmt.where(City.code == city_code)
    if network_code:
        stmt = stmt.where(Network.code == network_code)
    rows = list((await db.scalars(stmt.limit(2))).all())
    return rows[0] if len(rows) == 1 else None


async def _validate_geography(db: AsyncSession, scope: EffectiveResourceScope, row: dict[str, Any]) -> ValidationResult:
    level = _required(row, "level").upper()
    if level not in {"NETWORK", "CITY", "LOCATION", "SECTOR"}:
        raise ValueError("level must be NETWORK, CITY, LOCATION, or SECTOR.")
    name = _required(row, "name")
    code = _required(row, "code")
    status = (_text(row, "status") or "ACTIVE").upper()
    if status not in {"ACTIVE", "INACTIVE"}:
        raise ValueError("status must be ACTIVE or INACTIVE.")
    service_vlan = _integer(row, "service_vlan_id")
    start = _integer(row, "customer_vlan_start")
    end = _integer(row, "customer_vlan_end")
    latitude = _number(row, "latitude")
    longitude = _number(row, "longitude")
    if level != "CITY" and service_vlan is not None:
        raise ValueError("service_vlan_id is authoritative only on CITY rows.")
    if level != "LOCATION" and (latitude is not None or longitude is not None):
        raise ValueError("latitude and longitude are authoritative only on LOCATION rows.")
    if latitude is not None and not -90 <= latitude <= 90:
        raise ValueError("latitude must be between -90 and 90.")
    if longitude is not None and not -180 <= longitude <= 180:
        raise ValueError("longitude must be between -180 and 180.")
    if level != "SECTOR" and (start is not None or end is not None or _text(row, "role") is not None):
        raise ValueError("role and customer VLAN range are authoritative only on SECTOR rows.")
    if service_vlan is not None and not 2 <= service_vlan <= 4094:
        raise ValueError("service_vlan_id must be between 2 and 4094.")
    if (start is None) != (end is None):
        raise ValueError("customer_vlan_start and customer_vlan_end must be set together.")
    if start is not None and (not 2 <= start <= end <= 4094):
        raise ValueError("customer VLAN range must be within 2-4094 and start <= end.")

    normalized: dict[str, Any] = {"level": level, "name": name, "code": code, "status": status}
    if level == "NETWORK":
        if not scope.global_access:
            return ValidationResult("ERROR", {}, "RESOURCE_NOT_FOUND", "Network scope not found.")
        existing = await db.scalar(select(Network).where(Network.code == code, Network.deleted_at.is_(None)))
        if existing:
            same = existing.name == name and existing.status == status
            return ValidationResult("NOOP" if same else "ERROR", {**normalized, "existing_id": str(existing.id)}, None if same else "DUPLICATE_CONFLICT", None if same else "Network code already exists with different values.")
        return ValidationResult("VALID", normalized)

    network_code = _required(row, "network_code")
    network = await _network_by_code(db, network_code)
    if network is None:
        return ValidationResult("ERROR", {}, "PARENT_NOT_FOUND", "Parent network not found; parent rows must exist before import.")
    try:
        await require_network(db, scope, network.id)
    except HTTPException as exc:
        code_, message = _http_error(exc)
        return ValidationResult("ERROR", {}, code_, message)
    normalized["network_id"] = str(network.id)
    normalized["network_code"] = network_code

    if level == "CITY":
        existing = await db.scalar(select(City).where(City.network_id == network.id, City.code == code, City.deleted_at.is_(None)))
        if service_vlan is not None:
            used = await db.scalar(select(City.id).where(City.service_vlan_id == service_vlan, City.deleted_at.is_(None)).limit(1))
            if used is not None and (existing is None or used != existing.id):
                return ValidationResult("ERROR", {}, "SERVICE_VLAN_IN_USE", "Service VLAN is already assigned or reserved by another city.")
        normalized["service_vlan_id"] = service_vlan
        if existing:
            same = existing.name == name and existing.status == status and existing.service_vlan_id == service_vlan
            return ValidationResult("NOOP" if same else "ERROR", {**normalized, "existing_id": str(existing.id)}, None if same else "DUPLICATE_CONFLICT", None if same else "City code already exists with different values.")
        return ValidationResult("VALID", normalized)

    city_code = _required(row, "city_code")
    city = await _city_by_codes(db, network_code, city_code)
    if city is None or city.network_id != network.id:
        return ValidationResult("ERROR", {}, "PARENT_NOT_FOUND", "Parent city not found; parent rows must exist before import.")
    try:
        await require_city(db, scope, city.id)
    except HTTPException as exc:
        code_, message = _http_error(exc)
        return ValidationResult("ERROR", {}, code_, message)
    normalized.update({"city_id": str(city.id), "city_code": city_code})

    if level == "LOCATION":
        address = _text(row, "address")
        normalized.update({"address": address, "latitude": latitude, "longitude": longitude})
        existing = await db.scalar(select(Location).where(Location.city_id == city.id, Location.code == code, Location.deleted_at.is_(None)))
        if existing:
            same = existing.name == name and existing.status == status and existing.address == address and existing.latitude == latitude and existing.longitude == longitude
            return ValidationResult("NOOP" if same else "ERROR", {**normalized, "existing_id": str(existing.id)}, None if same else "DUPLICATE_CONFLICT", None if same else "Location code already exists with different values.")
        return ValidationResult("VALID", normalized)

    location_code = _required(row, "location_code")
    location = await _location_by_codes(db, network_code, city_code, location_code)
    if location is None or location.city_id != city.id:
        return ValidationResult("ERROR", {}, "PARENT_NOT_FOUND", "Parent location not found; parent rows must exist before import.")
    try:
        await require_location(db, scope, location.id)
    except HTTPException as exc:
        code_, message = _http_error(exc)
        return ValidationResult("ERROR", {}, code_, message)
    role = (_text(row, "role") or "CUSTOMER_ACCESS").upper()
    if role not in {"CUSTOMER_ACCESS", "BACKHAUL"}:
        raise ValueError("role must be CUSTOMER_ACCESS or BACKHAUL.")
    if start is not None:
        overlap = await db.scalar(
            select(Sector.id).join(Location, Location.id == Sector.location_id).where(
                Location.city_id == city.id, Sector.deleted_at.is_(None),
                Sector.customer_vlan_start.is_not(None), Sector.customer_vlan_end.is_not(None),
                Sector.customer_vlan_start <= end, Sector.customer_vlan_end >= start,
            ).limit(1)
        )
    else:
        overlap = None
    existing = await db.scalar(select(Sector).where(Sector.location_id == location.id, Sector.code == code, Sector.deleted_at.is_(None)))
    if overlap is not None and (existing is None or overlap != existing.id):
        return ValidationResult("ERROR", {}, "CUSTOMER_VLAN_RANGE_OVERLAP", "Customer VLAN ranges cannot overlap between sectors in the same city.")
    normalized.update({
        "location_id": str(location.id), "location_code": location_code, "role": role,
        "customer_vlan_start": start, "customer_vlan_end": end,
    })
    if existing:
        same = (
            existing.name == name and existing.status == status and existing.role == role
            and existing.customer_vlan_start == start and existing.customer_vlan_end == end
        )
        return ValidationResult("NOOP" if same else "ERROR", {**normalized, "existing_id": str(existing.id)}, None if same else "DUPLICATE_CONFLICT", None if same else "Sector code already exists with different values.")
    return ValidationResult("VALID", normalized)


async def _validate_device(db: AsyncSession, scope: EffectiveResourceScope, row: dict[str, Any]) -> ValidationResult:
    type_code = _required(row, "device_type").upper()
    if type_code not in CONTROLLED_TYPES:
        raise ValueError("device_type is not one of the controlled device types.")
    dtype = await db.scalar(select(DeviceType).where(DeviceType.code == type_code, DeviceType.is_active.is_(True)))
    if dtype is None:
        return ValidationResult("ERROR", {}, "DEVICE_TYPE_NOT_FOUND", "Controlled device type is not seeded.")
    display_name = _required(row, "display_name")
    management_ip = _required(row, "management_ip")
    try:
        management_ip = str(ip_address(management_ip))
    except ValueError as exc:
        raise ValueError("management_ip is invalid.") from exc
    existing_ip = await db.scalar(select(DeviceIP).where(DeviceIP.ip_address == management_ip, DeviceIP.deleted_at.is_(None)))
    if existing_ip:
        existing = await db.scalar(select(Device).where(Device.id == existing_ip.device_id, Device.deleted_at.is_(None)))
        same = existing is not None and existing.display_name == display_name and existing.device_type_id == dtype.id
        return ValidationResult("NOOP" if same else "ERROR", {"existing_id": str(existing.id) if existing else None, "management_ip": management_ip}, None if same else "DUPLICATE_CONFLICT", None if same else "Management IP is already registered to a different device definition.")

    network_code, city_code = _text(row, "network_code"), _text(row, "city_code")
    location_code, sector_code = _text(row, "location_code"), _text(row, "sector_code")
    location = await _location_by_codes(db, network_code, city_code, location_code) if location_code else None
    sector = await _sector_by_codes(db, network_code, city_code, location_code, sector_code) if sector_code else None
    parent_ip = _text(row, "parent_management_ip")
    parent_id: UUID | None = None
    if parent_ip:
        try:
            parent_ip = str(ip_address(parent_ip))
        except ValueError as exc:
            raise ValueError("parent_management_ip is invalid.") from exc
        parent_row = await db.scalar(select(DeviceIP).where(DeviceIP.ip_address == parent_ip, DeviceIP.deleted_at.is_(None)))
        if parent_row is None:
            return ValidationResult("ERROR", {}, "PARENT_DEVICE_NOT_FOUND", "Parent device management IP was not found.")
        try:
            await require_device(db, scope, parent_row.device_id)
        except HTTPException as exc:
            code_, message = _http_error(exc)
            return ValidationResult("ERROR", {}, code_, message)
        parent_id = parent_row.device_id

    if type_code == "SECTOR":
        if sector is None:
            return ValidationResult("ERROR", {}, "SECTOR_NOT_FOUND", "SECTOR device requires an existing sector_code.")
        try:
            await require_sector(db, scope, sector.id)
        except HTTPException as exc:
            code_, message = _http_error(exc)
            return ValidationResult("ERROR", {}, code_, message)
        location_id, sector_id = None, sector.id
    elif type_code in {"CPE", "ACCESS_POINT"}:
        if parent_id is None:
            return ValidationResult("ERROR", {}, "PARENT_DEVICE_REQUIRED", f"{type_code} requires parent_management_ip.")
        if location_code or sector_code:
            return ValidationResult("ERROR", {}, "HIERARCHY_INPUT_FORBIDDEN", f"{type_code} geography is derived from its parent.")
        location_id = sector_id = None
    else:
        if location is None:
            return ValidationResult("ERROR", {}, "LOCATION_NOT_FOUND", "Independent device types require an existing location_code.")
        try:
            await require_location(db, scope, location.id)
        except HTTPException as exc:
            code_, message = _http_error(exc)
            return ValidationResult("ERROR", {}, code_, message)
        location_id, sector_id = location.id, None

    normalized = {
        "device_type_id": str(dtype.id), "device_type": type_code, "display_name": display_name,
        "management_ip": management_ip, "location_id": str(location_id) if location_id else None,
        "sector_id": str(sector_id) if sector_id else None, "parent_device_id": str(parent_id) if parent_id else None,
    }
    for key in ("hostname", "vendor", "model", "serial_number", "description", "management_protocol"):
        normalized[key] = _text(row, key)
    return ValidationResult("VALID", normalized)


async def _validate_customer(db: AsyncSession, scope: EffectiveResourceScope, row: dict[str, Any]) -> ValidationResult:
    # Customer import deliberately does not create CustomerService or writable device/VLAN association.
    customer_code = _required(row, "customer_code")
    name = _required(row, "name")
    status = (_text(row, "status") or "ACTIVE").upper()
    if status not in {"ACTIVE", "INACTIVE", "SUSPENDED"}:
        raise ValueError("status must be ACTIVE, INACTIVE, or SUSPENDED.")
    existing = await db.scalar(select(Customer).where(Customer.customer_code == customer_code, Customer.deleted_at.is_(None)))
    if existing:
        # Restricted actors can only treat an existing customer as a visible NOOP.
        visible = await db.scalar(select(Customer.id).where(Customer.id == existing.id, customer_scope_clause(scope)))
        if visible is None:
            return ValidationResult("ERROR", {}, "RESOURCE_NOT_FOUND", "Customer not found.")
        same = existing.name == name and existing.status == status
        return ValidationResult("NOOP" if same else "ERROR", {"existing_id": str(existing.id), "customer_code": customer_code, "name": name, "status": status}, None if same else "DUPLICATE_CONFLICT", None if same else "Customer code already exists with different values.")
    if not scope.global_access:
        # A customer has no authorized geography until CustomerService exists. Creating one from a restricted
        # scope would create an unanchored resource and is therefore fail-closed.
        return ValidationResult("ERROR", {}, "GLOBAL_SCOPE_REQUIRED", "Creating a customer without a CustomerService requires GLOBAL scope.")
    return ValidationResult("VALID", {"customer_code": customer_code, "name": name, "status": status})


async def _validate_group(db: AsyncSession, scope: EffectiveResourceScope, row: dict[str, Any]) -> ValidationResult:
    code = _required(row, "code")
    name = _required(row, "name")
    membership_mode = (_text(row, "membership_mode") or "MANUAL").upper()
    scope_type = (_text(row, "scope_type") or "GLOBAL").upper()
    device_scope = (_text(row, "device_scope") or "ANY").upper()
    sector_role = _text(row, "sector_role")
    sector_role = sector_role.upper() if sector_role else None
    if membership_mode not in {"MANUAL", "DYNAMIC"}:
        raise ValueError("membership_mode must be MANUAL or DYNAMIC.")
    if scope_type not in {"GLOBAL", "NETWORK", "CITY", "LOCATION", "SECTOR"}:
        raise ValueError("scope_type is invalid.")
    if device_scope not in {"ANY", *CONTROLLED_TYPES}:
        raise ValueError("device_scope is invalid.")
    if sector_role not in {None, "CUSTOMER_ACCESS", "BACKHAUL"} or (sector_role and device_scope != "SECTOR"):
        raise ValueError("sector_role requires device_scope SECTOR and must be CUSTOMER_ACCESS or BACKHAUL.")

    context: dict[str, str | None] = {"network_id": None, "city_id": None, "location_id": None, "sector_id": None}
    if scope_type == "GLOBAL":
        if not scope.global_access:
            return ValidationResult("ERROR", {}, "RESOURCE_NOT_FOUND", "Group scope not found.")
    else:
        network_code, city_code = _text(row, "network_code"), _text(row, "city_code")
        location_code, sector_code = _text(row, "location_code"), _text(row, "sector_code")
        target = None
        guard = None
        field = None
        if scope_type == "NETWORK":
            target, guard, field = await _network_by_code(db, network_code), require_network, "network_id"
        elif scope_type == "CITY":
            target, guard, field = await _city_by_codes(db, network_code, city_code), require_city, "city_id"
        elif scope_type == "LOCATION":
            target, guard, field = await _location_by_codes(db, network_code, city_code, location_code), require_location, "location_id"
        elif scope_type == "SECTOR":
            target, guard, field = await _sector_by_codes(db, network_code, city_code, location_code, sector_code), require_sector, "sector_id"
        if target is None:
            return ValidationResult("ERROR", {}, "GROUP_CONTEXT_NOT_FOUND", "Group scope context was not found.")
        try:
            await guard(db, scope, target.id)
        except HTTPException as exc:
            code_, message = _http_error(exc)
            return ValidationResult("ERROR", {}, code_, message)
        context[field] = str(target.id)

    normalized = {
        "code": code, "name": name, "description": _text(row, "description"), "group_kind": "CUSTOM",
        "membership_mode": membership_mode, "scope_type": scope_type, "device_scope": device_scope,
        "sector_role": sector_role, **context,
    }
    existing = await db.scalar(select(DeviceGroup).where(DeviceGroup.code == code, DeviceGroup.deleted_at.is_(None)))
    if existing:
        visible = await db.scalar(select(DeviceGroup.id).where(DeviceGroup.id == existing.id, group_scope_clause(scope)))
        if visible is None:
            return ValidationResult("ERROR", {}, "RESOURCE_NOT_FOUND", "Group not found.")
        same = all(getattr(existing, key) == value for key, value in normalized.items() if key not in {"description", "network_id", "city_id", "location_id", "sector_id"})
        same = same and existing.description == normalized["description"]
        for key in ("network_id", "city_id", "location_id", "sector_id"):
            value = normalized[key]
            same = same and getattr(existing, key) == (UUID(value) if value else None)
        return ValidationResult("NOOP" if same else "ERROR", {**normalized, "existing_id": str(existing.id)}, None if same else "DUPLICATE_CONFLICT", None if same else "Group code already exists with different values.")
    return ValidationResult("VALID", normalized)


async def _device_by_management_ip(db: AsyncSession, value: str, *, expected_type: str | None = None) -> Device | None:
    try:
        normalized_ip = str(ip_address(value))
    except ValueError as exc:
        raise ValueError("management IP is invalid.") from exc
    stmt = (
        select(Device)
        .join(DeviceIP, DeviceIP.device_id == Device.id)
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .where(DeviceIP.ip_address == normalized_ip, DeviceIP.deleted_at.is_(None), Device.deleted_at.is_(None))
    )
    if expected_type:
        stmt = stmt.where(DeviceType.code == expected_type)
    return await db.scalar(stmt.limit(1))


async def _validate_customer_service_import(db: AsyncSession, scope: EffectiveResourceScope, row: dict[str, Any]) -> ValidationResult:
    customer_code = _required(row, "customer_code")
    service_code = _required(row, "service_code")
    status = (_text(row, "status") or "ACTIVE").upper()
    if status not in {"ACTIVE", "INACTIVE", "SUSPENDED"}:
        raise ValueError("status must be ACTIVE, INACTIVE, or SUSPENDED.")
    customer_vlan_id = _integer(row, "customer_vlan_id")
    if customer_vlan_id is None:
        raise ValueError("customer_vlan_id is required.")
    customer = await db.scalar(select(Customer).where(Customer.customer_code == customer_code, Customer.deleted_at.is_(None)))
    if customer is None:
        return ValidationResult("ERROR", {}, "CUSTOMER_NOT_FOUND", "Customer code was not found.")
    if not scope.global_access:
        visible = await db.scalar(select(Customer.id).where(Customer.id == customer.id, customer_scope_clause(scope)))
        if visible is None:
            return ValidationResult("ERROR", {}, "RESOURCE_NOT_FOUND", "Customer not found.")

    ap_ip = _required(row, "access_point_management_ip")
    ap = await _device_by_management_ip(db, ap_ip, expected_type="ACCESS_POINT")
    if ap is None:
        return ValidationResult("ERROR", {}, "ACCESS_POINT_NOT_FOUND", "Access Point management IP was not found.")
    try:
        await require_device(db, scope, ap.id)
    except HTTPException as exc:
        code_, message = _http_error(exc); return ValidationResult("ERROR", {}, code_, message)

    router_ip = _text(row, "router_management_ip")
    router = await _device_by_management_ip(db, router_ip, expected_type="ROUTER") if router_ip else None
    if router_ip and router is None:
        return ValidationResult("ERROR", {}, "ROUTER_NOT_FOUND", "Router management IP was not found.")
    if router is not None:
        try:
            await require_device(db, scope, router.id)
        except HTTPException as exc:
            code_, message = _http_error(exc); return ValidationResult("ERROR", {}, code_, message)

    existing_customer = await db.scalar(select(CustomerService).where(CustomerService.customer_id == customer.id, CustomerService.deleted_at.is_(None)))
    existing_code = await db.scalar(select(CustomerService).where(CustomerService.service_code == service_code, CustomerService.deleted_at.is_(None)))

    try:
        sector_id, cpe_id = await _derive_service_path(db, customer_id=customer.id, access_point_device_id=ap.id, router_device_id=router.id if router else None)
        if not scope.global_access:
            await require_sector(db, scope, sector_id)
            await require_device(db, scope, cpe_id)
    except CustomerServiceValidationError as exc:
        return ValidationResult("ERROR", {}, exc.code, exc.message)
    except HTTPException as exc:
        code_, message = _http_error(exc); return ValidationResult("ERROR", {}, code_, message)

    if existing_customer or existing_code:
        existing = existing_customer or existing_code
        same = bool(
            existing
            and existing.customer_id == customer.id
            and existing.service_code == service_code
            and existing.status == status
            and existing.access_point_device_id == ap.id
            and existing.cpe_device_id == cpe_id
            and existing.sector_id == sector_id
            and existing.router_device_id == (router.id if router else None)
            and existing.customer_vlan_id == customer_vlan_id
        )
        return ValidationResult(
            "NOOP" if same else "ERROR", {"existing_id": str(existing.id) if existing else None},
            None if same else "DUPLICATE_CONFLICT",
            None if same else "Customer or service code already has an active service with different values.",
        )

    existing_ap = await db.scalar(select(CustomerService.id).where(CustomerService.access_point_device_id == ap.id, CustomerService.deleted_at.is_(None)))
    existing_cpe = await db.scalar(select(CustomerService.id).where(CustomerService.cpe_device_id == cpe_id, CustomerService.deleted_at.is_(None)))
    if existing_ap is not None or existing_cpe is not None:
        return ValidationResult("ERROR", {}, "ENDPOINT_IN_USE", "The derived Access Point or CPE is already assigned to another active customer service.")

    try:
        await _validate_customer_vlan(db, sector_id=sector_id, customer_vlan_id=customer_vlan_id)
    except CustomerServiceValidationError as exc:
        return ValidationResult("ERROR", {}, exc.code, exc.message)

    return ValidationResult("VALID", {
        "customer_id": str(customer.id), "customer_code": customer_code, "service_code": service_code, "status": status,
        "access_point_device_id": str(ap.id), "access_point_management_ip": str(ip_address(ap_ip)),
        "router_device_id": str(router.id) if router else None, "router_management_ip": str(ip_address(router_ip)) if router_ip else None,
        "customer_vlan_id": customer_vlan_id, "sector_id": str(sector_id), "cpe_device_id": str(cpe_id),
    })


def _prepare_row_for_subtype(entity_type: str, row: dict[str, Any], expected_subtype: str | None) -> dict[str, Any]:
    if not expected_subtype or expected_subtype.upper() in {"", "ALL"}:
        return dict(row)
    subtype = expected_subtype.upper()
    prepared = dict(row)
    if entity_type == "geography":
        if subtype not in {"NETWORK", "CITY", "LOCATION", "SECTOR"}:
            raise ValueError("Unsupported geography import subtype.")
        supplied = str(prepared.get("level") or "").strip().upper()
        if supplied and supplied != subtype:
            raise ValueError(f"Import row level {supplied} does not match selected subtype {subtype}.")
        prepared["level"] = subtype
    elif entity_type == "devices":
        if subtype not in CONTROLLED_TYPES:
            raise ValueError("Unsupported device import subtype.")
        supplied = str(prepared.get("device_type") or "").strip().upper()
        if supplied and supplied != subtype:
            raise ValueError(f"Import row device_type {supplied} does not match selected subtype {subtype}.")
        prepared["device_type"] = subtype
    return prepared


async def validate_import_row(db: AsyncSession, scope: EffectiveResourceScope, entity_type: str, row: dict[str, Any]) -> ValidationResult:
    try:
        if entity_type == "geography":
            return await _validate_geography(db, scope, row)
        if entity_type == "devices":
            return await _validate_device(db, scope, row)
        if entity_type == "customers":
            return await _validate_customer(db, scope, row)
        if entity_type == "customer_services":
            return await _validate_customer_service_import(db, scope, row)
        if entity_type == "groups":
            return await _validate_group(db, scope, row)
        raise ValueError("Unsupported entity_type.")
    except ValueError as exc:
        return ValidationResult("ERROR", {}, "ROW_VALIDATION_ERROR", str(exc))


async def create_import_preview(
    db: AsyncSession, *, actor_id: UUID, scope: EffectiveResourceScope, entity_type: str,
    filename: str, data: bytes, file_format: str | None = None, idempotency_key: str | None = None, expected_subtype: str | None = None,
) -> ImportJob:
    entity = entity_type.strip().lower()
    if entity not in IMPORT_TYPES:
        raise ValueError("Unsupported import entity type.")
    digest = sha256(data).hexdigest()
    if idempotency_key:
        existing = await db.scalar(select(ImportJob).where(
            ImportJob.created_by_user_id == actor_id, ImportJob.idempotency_key == idempotency_key,
        ))
        if existing:
            if existing.file_sha256 != digest or existing.entity_type != entity:
                raise ValueError("Idempotency key was already used for different import content.")
            return existing
    parsed = parse_tabular_bytes(data, filename=filename, file_format=file_format)
    if len(parsed.rows) > MAX_IMPORT_ROWS:
        raise ValueError(f"Import exceeds the {MAX_IMPORT_ROWS}-row limit.")
    snapshot = scope_snapshot(scope)
    job = ImportJob(
        source_type="UPLOAD", entity_type=entity, file_format=parsed.format.upper(), filename=filename,
        file_sha256=digest, status="PENDING", total_records=len(parsed.rows), created_by_user_id=actor_id,
        scope_snapshot=snapshot, scope_fingerprint=scope_fingerprint(scope), idempotency_key=idempotency_key,
        preview_expires_at=utcnow() + IMPORT_PREVIEW_TTL,
        validation_summary={"valid": 0, "noop": 0, "errors": 0}, metadata_={"phase": "D3", "subtype": (expected_subtype or "ALL").upper()},
    )
    db.add(job)
    await db.flush()
    counts = {"VALID": 0, "NOOP": 0, "ERROR": 0}
    seen_keys: dict[tuple[Any, ...], int] = {}
    for index, source_row in enumerate(parsed.rows, start=2 if parsed.format == "csv" else 1):
        try:
            prepared_row = _prepare_row_for_subtype(entity, source_row, expected_subtype)
            result = await validate_import_row(db, scope, entity, prepared_row)
        except ValueError as exc:
            prepared_row = dict(source_row)
            result = ValidationResult("ERROR", {}, "SUBTYPE_MISMATCH", str(exc))
        conflict_keys = _import_conflict_keys(entity, result.normalized) if result.status != "ERROR" else []
        duplicate = next(((key, seen_keys[key]) for key in conflict_keys if key in seen_keys), None)
        if duplicate is not None:
            _, first_row = duplicate
            result = ValidationResult(
                "ERROR", result.normalized, "DUPLICATE_IN_FILE",
                f"Duplicate authoritative value in import file; first occurrence is row {first_row}.",
            )
        else:
            for key in conflict_keys:
                seen_keys[key] = index
        counts[result.status] += 1
        db.add(ImportRecord(
            import_job_id=job.id, row_number=index, status=result.status,
            error_code=result.error_code, error_message=result.error_message,
            source_data=prepared_row, normalized_data=result.normalized, metadata_={},
        ))
    job.error_records = counts["ERROR"]
    job.status = "PREVIEWED"
    job.validation_summary = {"valid": counts["VALID"], "noop": counts["NOOP"], "errors": counts["ERROR"]}
    await record_audit(
        db, action="IMPORT_PREVIEW_CREATED", entity_type="ImportJob", entity_id=job.id,
        description="Import file parsed and validated without mutating business data.",
        metadata={"import_entity_type": entity, "rows": len(parsed.rows), "errors": counts["ERROR"]},
    )
    return job


async def _apply_geography(db: AsyncSession, data: dict[str, Any]) -> None:
    level = data["level"]
    if level == "NETWORK":
        db.add(Network(name=data["name"], code=data["code"], status=data["status"]))
    elif level == "CITY":
        db.add(City(network_id=UUID(data["network_id"]), name=data["name"], code=data["code"], status=data["status"], service_vlan_id=data.get("service_vlan_id")))
    elif level == "LOCATION":
        db.add(Location(city_id=UUID(data["city_id"]), name=data["name"], code=data["code"], status=data["status"], address=data.get("address"), latitude=data.get("latitude"), longitude=data.get("longitude"), metadata_={}))
    else:
        db.add(Sector(location_id=UUID(data["location_id"]), name=data["name"], code=data["code"], status=data["status"], role=data["role"], customer_vlan_start=data.get("customer_vlan_start"), customer_vlan_end=data.get("customer_vlan_end"), metadata_={}))


async def _apply_device(db: AsyncSession, data: dict[str, Any]) -> None:
    await register_domain_device(
        db, device_type_id=UUID(data["device_type_id"]), display_name=data["display_name"], management_ip=data["management_ip"],
        location_id=UUID(data["location_id"]) if data.get("location_id") else None,
        sector_id=UUID(data["sector_id"]) if data.get("sector_id") else None,
        parent_device_id=UUID(data["parent_device_id"]) if data.get("parent_device_id") else None,
        hostname=data.get("hostname"), vendor=data.get("vendor"), model=data.get("model"), serial_number=data.get("serial_number"),
        description=data.get("description"), management_protocol=data.get("management_protocol"), credential_reference=None,
        metadata={"import_source": "PHASE_D"}, ip_source="IMPORT",
    )


async def _apply_customer(db: AsyncSession, data: dict[str, Any]) -> None:
    customer = Customer(customer_code=data["customer_code"], name=data["name"], status=data["status"], metadata_={})
    db.add(customer)
    await db.flush()
    await record_audit(db, action="CUSTOMER_CREATED", entity_type="Customer", entity_id=customer.id, description="Customer created by transactional import.", metadata={"registration_source": "PHASE_D_IMPORT"})


async def _apply_customer_service(db: AsyncSession, data: dict[str, Any]) -> None:
    await create_customer_service(
        db, customer_id=UUID(data["customer_id"]), service_code=data["service_code"], status=data["status"],
        access_point_device_id=UUID(data["access_point_device_id"]), router_device_id=UUID(data["router_device_id"]) if data.get("router_device_id") else None,
        customer_vlan_id=int(data["customer_vlan_id"]), require_customer_vlan=True, metadata={"import_source": "PHASE_D"},
    )


async def _apply_group(db: AsyncSession, data: dict[str, Any]) -> None:
    kwargs = {key: UUID(value) if value else None for key, value in (("network_id", data.get("network_id")), ("city_id", data.get("city_id")), ("location_id", data.get("location_id")), ("sector_id", data.get("sector_id")))}
    group = DeviceGroup(
        code=data["code"], name=data["name"], description=data.get("description"), group_kind="CUSTOM",
        membership_mode=data["membership_mode"], system_key=None, scope_type=data["scope_type"],
        device_scope=data["device_scope"], sector_role=data.get("sector_role"), metadata_={}, **kwargs,
    )
    db.add(group)
    await db.flush()
    await record_audit(db, action="DEVICE_GROUP_CREATED", entity_type="DeviceGroup", entity_id=group.id, description="Custom device group created by transactional import.", metadata={"registration_source": "PHASE_D_IMPORT"})


async def commit_import(
    db: AsyncSession, *, job: ImportJob, actor_id: UUID, scope: EffectiveResourceScope, expected_file_sha256: str,
) -> ImportJob:
    locked = await db.scalar(select(ImportJob).where(ImportJob.id == job.id).with_for_update().execution_options(populate_existing=True))
    if locked is None or locked.created_by_user_id != actor_id:
        raise ValueError("Import job not found.")
    if locked.status == "COMMITTED":
        return locked
    if locked.status != "PREVIEWED":
        raise ValueError("Only PREVIEWED imports can be committed.")
    if locked.preview_expires_at is None or locked.preview_expires_at <= utcnow():
        locked.status = "EXPIRED"
        raise ImportPreviewExpired("Import preview expired; upload the file again.")
    if locked.file_sha256 != expected_file_sha256:
        raise ValueError("Import file checksum does not match the preview.")
    if locked.scope_fingerprint != scope_fingerprint(scope):
        raise ValueError("Authorization scope changed after preview; preview the import again.")
    records = list((await db.scalars(select(ImportRecord).where(ImportRecord.import_job_id == locked.id).order_by(ImportRecord.row_number).with_for_update())).all())
    if any(record.status == "ERROR" for record in records):
        raise ValueError("Import contains row-level validation errors and cannot be committed.")

    # Revalidate every non-NOOP row against current data immediately before the single transaction writes.
    for record in records:
        if record.status == "NOOP":
            continue
        expected_subtype = str((locked.metadata_ or {}).get("subtype") or "ALL")
        prepared = _prepare_row_for_subtype(locked.entity_type or "", record.source_data, expected_subtype)
        check = await validate_import_row(db, scope, locked.entity_type or "", prepared)
        if check.status == "ERROR":
            raise ValueError(f"Row {record.row_number} is no longer valid: {check.error_code}: {check.error_message}")
        if check.status == "NOOP":
            record.status = "NOOP"
            record.normalized_data = check.normalized
        else:
            record.normalized_data = check.normalized

    locked.status = "COMMITTING"
    imported = 0
    for record in records:
        if record.status == "NOOP":
            continue
        if locked.entity_type == "geography":
            await _apply_geography(db, record.normalized_data)
        elif locked.entity_type == "devices":
            await _apply_device(db, record.normalized_data)
        elif locked.entity_type == "customers":
            await _apply_customer(db, record.normalized_data)
        elif locked.entity_type == "customer_services":
            await _apply_customer_service(db, record.normalized_data)
        elif locked.entity_type == "groups":
            await _apply_group(db, record.normalized_data)
        else:
            raise ValueError("Unsupported import type.")
        record.status = "APPLIED"
        imported += 1
    locked.imported_records = imported
    locked.status = "COMMITTED"
    locked.committed_at = utcnow()
    await record_audit(
        db, action="IMPORT_COMMITTED", entity_type="ImportJob", entity_id=locked.id,
        description="Validated import committed transactionally.",
        metadata={"import_entity_type": locked.entity_type, "applied_rows": imported, "total_rows": locked.total_records},
    )
    return locked


def template_bytes(entity_type: str, format: str = "CSV", subtype: str | None = None) -> tuple[bytes, str, str]:
    entity = entity_type.strip().lower()
    if entity not in TEMPLATES:
        raise ValueError("Unsupported template type.")
    selected = (subtype or "ALL").strip().upper()
    columns = list(TEMPLATES[entity])
    if entity == "geography" and selected != "ALL":
        allowed = {
            "NETWORK": ["name", "code", "status"],
            "CITY": ["name", "code", "network_code", "status", "service_vlan_id"],
            "LOCATION": ["name", "code", "network_code", "city_code", "status", "address"],
            "SECTOR": ["name", "code", "network_code", "city_code", "location_code", "status", "role", "customer_vlan_start", "customer_vlan_end"],
        }
        if selected not in allowed:
            raise ValueError("Unsupported geography template subtype.")
        columns = allowed[selected]
    elif entity == "devices" and selected != "ALL":
        if selected not in CONTROLLED_TYPES:
            raise ValueError("Unsupported device template subtype.")
        columns = [column for column in columns if column != "device_type"]
    elif selected not in {"ALL", ""}:
        raise ValueError("This import type does not have subtypes.")
    data = write_tabular_template_bytes(columns, format, title=f"FTTW {entity.replace('_', ' ').title()} Import")
    ext = format.lower()
    media = {"CSV": "text/csv", "XLSX": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "JSON": "application/json"}[format.upper()]
    suffix = f"_{selected.lower()}" if selected != "ALL" else ""
    return data, f"fttw_{entity}{suffix}_import_template.{ext}", media


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


async def _device_export_filter_clause(db: AsyncSession, filters: dict[str, Any], *, device_col=Device.id):
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
        geo.append(exists(select(1).where(City.id == context.c.city_id, City.service_vlan_id == service_vlan_id)))
    if geo:
        clauses.append(exists(select(1).select_from(context).where(context.c.device_id == device_col, *geo)))
    if customer_vlan_id is not None:
        sector_vlan = exists(
            select(1).select_from(context).join(Sector, Sector.id == context.c.sector_id).where(
                context.c.device_id == device_col, Sector.deleted_at.is_(None),
                Sector.customer_vlan_start.is_not(None), Sector.customer_vlan_end.is_not(None),
                Sector.customer_vlan_start <= customer_vlan_id, Sector.customer_vlan_end >= customer_vlan_id,
            )
        )
        service_vlan = exists(select(1).where(
            CustomerService.deleted_at.is_(None), CustomerService.customer_vlan_id == customer_vlan_id,
            or_(CustomerService.access_point_device_id == device_col, CustomerService.cpe_device_id == device_col),
        ))
        clauses.append(or_(sector_vlan, service_vlan))
    group_id = _uuid_filter(filters, "group_id")
    if group_id is not None:
        population = await effective_group_population_subquery(db, group_id)
        clauses.append(exists(select(1).select_from(population).where(population.c.device_id == device_col)))
    return and_(*clauses) if clauses else None


def _geo_filter(filters: dict[str, Any], key: str, column):
    value = _uuid_filter(filters, key)
    return column == value if value is not None else None


async def export_rows(db: AsyncSession, scope: EffectiveResourceScope, entity_type: str, filters: dict[str, Any] | None = None) -> tuple[list[str], list[dict[str, Any]]]:
    entity = entity_type.strip().lower()
    filters = filters or {}
    subtype = str(filters.get("subtype") or "ALL").upper()
    if entity == "geography":
        if subtype not in {"ALL", "NETWORK", "CITY", "LOCATION", "SECTOR"}:
            raise ValueError("Unsupported geography export subtype.")
        columns = ["level", "name", "code", "network_code", "city_code", "location_code", "status", "service_vlan_id", "address", "latitude", "longitude", "role", "customer_vlan_start", "customer_vlan_end"]
        rows: list[dict[str, Any]] = []
        network_id, city_id, location_id, sector_id = (_uuid_filter(filters, key) for key in ("network_id", "city_id", "location_id", "sector_id"))
        group_id = _uuid_filter(filters, "group_id")
        service_vlan_id = _vlan_filter(filters, "service_vlan_id")
        customer_vlan_id = _vlan_filter(filters, "customer_vlan_id")
        group_context = await effective_group_population_context_subquery(db, group_id) if group_id is not None else None
        if subtype in {"ALL", "NETWORK"}:
            stmt = select(Network).where(Network.deleted_at.is_(None), network_scope_clause(scope))
            if network_id: stmt = stmt.where(Network.id == network_id)
            if group_id is not None:
                stmt = stmt.where(exists(select(1).select_from(group_context).where(group_context.c.network_id == Network.id)))
            if service_vlan_id is not None:
                stmt = stmt.where(exists(select(1).where(City.network_id == Network.id, City.deleted_at.is_(None), City.service_vlan_id == service_vlan_id)))
            if customer_vlan_id is not None:
                stmt = stmt.where(exists(select(1).select_from(Sector).join(Location, Location.id == Sector.location_id).join(City, City.id == Location.city_id).where(City.network_id == Network.id, Sector.customer_vlan_start <= customer_vlan_id, Sector.customer_vlan_end >= customer_vlan_id)))
            if city_id: stmt = stmt.where(exists(select(1).where(City.id == city_id, City.network_id == Network.id)))
            if location_id: stmt = stmt.where(exists(select(1).select_from(Location).join(City, City.id == Location.city_id).where(Location.id == location_id, City.network_id == Network.id)))
            if sector_id: stmt = stmt.where(exists(select(1).select_from(Sector).join(Location, Location.id == Sector.location_id).join(City, City.id == Location.city_id).where(Sector.id == sector_id, City.network_id == Network.id)))
            for network in (await db.scalars(stmt.order_by(Network.code))).all():
                rows.append({"level": "NETWORK", "name": network.name, "code": network.code, "status": network.status})
        if subtype in {"ALL", "CITY"}:
            stmt = select(City, Network.code).select_from(City).join(Network, Network.id == City.network_id).where(City.deleted_at.is_(None), city_scope_clause(scope))
            if network_id: stmt = stmt.where(Network.id == network_id)
            if city_id: stmt = stmt.where(City.id == city_id)
            if group_id is not None:
                stmt = stmt.where(exists(select(1).select_from(group_context).where(group_context.c.city_id == City.id)))
            if service_vlan_id is not None: stmt = stmt.where(City.service_vlan_id == service_vlan_id)
            if customer_vlan_id is not None:
                stmt = stmt.where(exists(select(1).select_from(Sector).join(Location, Location.id == Sector.location_id).where(Location.city_id == City.id, Sector.customer_vlan_start <= customer_vlan_id, Sector.customer_vlan_end >= customer_vlan_id)))
            if location_id: stmt = stmt.where(exists(select(1).where(Location.id == location_id, Location.city_id == City.id)))
            if sector_id: stmt = stmt.where(exists(select(1).select_from(Sector).join(Location, Location.id == Sector.location_id).where(Sector.id == sector_id, Location.city_id == City.id)))
            for city, network_code in (await db.execute(stmt.order_by(Network.code, City.code))).all():
                rows.append({"level": "CITY", "name": city.name, "code": city.code, "network_code": network_code, "status": city.status, "service_vlan_id": city.service_vlan_id})
        if subtype in {"ALL", "LOCATION"}:
            stmt = select(Location, City.code, Network.code).select_from(Location).join(City, City.id == Location.city_id).join(Network, Network.id == City.network_id).where(Location.deleted_at.is_(None), location_scope_clause(scope))
            if network_id: stmt = stmt.where(Network.id == network_id)
            if city_id: stmt = stmt.where(City.id == city_id)
            if location_id: stmt = stmt.where(Location.id == location_id)
            if group_id is not None:
                stmt = stmt.where(exists(select(1).select_from(group_context).where(group_context.c.location_id == Location.id)))
            if service_vlan_id is not None: stmt = stmt.where(City.service_vlan_id == service_vlan_id)
            if customer_vlan_id is not None:
                stmt = stmt.where(exists(select(1).where(Sector.location_id == Location.id, Sector.customer_vlan_start <= customer_vlan_id, Sector.customer_vlan_end >= customer_vlan_id)))
            if sector_id: stmt = stmt.where(exists(select(1).where(Sector.id == sector_id, Sector.location_id == Location.id)))
            for loc, city_code, network_code in (await db.execute(stmt.order_by(Network.code, City.code, Location.code))).all():
                rows.append({"level": "LOCATION", "name": loc.name, "code": loc.code, "network_code": network_code, "city_code": city_code, "status": loc.status, "address": loc.address, "latitude": loc.latitude, "longitude": loc.longitude})
        if subtype in {"ALL", "SECTOR"}:
            stmt = select(Sector, Location.code, City.code, Network.code).select_from(Sector).join(Location, Location.id == Sector.location_id).join(City, City.id == Location.city_id).join(Network, Network.id == City.network_id).where(Sector.deleted_at.is_(None), sector_scope_clause(scope))
            if network_id: stmt = stmt.where(Network.id == network_id)
            if city_id: stmt = stmt.where(City.id == city_id)
            if location_id: stmt = stmt.where(Location.id == location_id)
            if sector_id: stmt = stmt.where(Sector.id == sector_id)
            if group_id is not None:
                stmt = stmt.where(exists(select(1).select_from(group_context).where(group_context.c.sector_id == Sector.id)))
            if service_vlan_id is not None: stmt = stmt.where(City.service_vlan_id == service_vlan_id)
            if customer_vlan_id is not None:
                stmt = stmt.where(Sector.customer_vlan_start <= customer_vlan_id, Sector.customer_vlan_end >= customer_vlan_id)
            for sec, loc_code, city_code, network_code in (await db.execute(stmt.order_by(Network.code, City.code, Location.code, Sector.code))).all():
                rows.append({"level": "SECTOR", "name": sec.name, "code": sec.code, "network_code": network_code, "city_code": city_code, "location_code": loc_code, "status": sec.status, "role": sec.role, "customer_vlan_start": sec.customer_vlan_start, "customer_vlan_end": sec.customer_vlan_end})
        return columns, rows

    if entity == "devices":
        if subtype != "ALL" and subtype not in CONTROLLED_TYPES:
            raise ValueError("Unsupported device export subtype.")
        columns = ["device_type", "display_name", "management_ip", "hostname", "vendor", "model", "serial_number", "lifecycle_state", "operational_state", "network", "city", "location", "sector"]
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
            .where(Device.deleted_at.is_(None), await device_scope_clause(db, scope))
        )
        extra = await _device_export_filter_clause(db, filters)
        if extra is not None: stmt = stmt.where(extra)
        if subtype != "ALL": stmt = stmt.where(DeviceType.code == subtype)
        stmt = stmt.order_by(Device.display_name, Device.id)
        rows = [{"device_type": dtype, "display_name": device.display_name, "management_ip": ip, "hostname": device.hostname, "vendor": device.vendor, "model": device.model, "serial_number": device.serial_number, "lifecycle_state": device.lifecycle_state, "operational_state": device.operational_state, "network": network, "city": city, "location": location, "sector": sector} for device, dtype, ip, network, city, location, sector in (await db.execute(stmt)).all()]
        return columns, rows

    if entity in {"customers", "customer_services"}:
        columns = ["customer_code", "name", "status", "service_code", "service_status", "service_vlan", "customer_vlan", "network", "city", "location", "sector", "access_point", "cpe"]
        AccessPoint = Device.__table__.alias("export_service_ap")
        Cpe = Device.__table__.alias("export_service_cpe")
        stmt = (
            select(Customer, CustomerService, City.service_vlan_id, Network.name, City.name, Location.name, Sector.name, AccessPoint.c.display_name, Cpe.c.display_name)
            .outerjoin(CustomerService, and_(CustomerService.customer_id == Customer.id, CustomerService.deleted_at.is_(None)))
            .outerjoin(Sector, Sector.id == CustomerService.sector_id).outerjoin(Location, Location.id == Sector.location_id)
            .outerjoin(City, City.id == Location.city_id).outerjoin(Network, Network.id == City.network_id)
            .outerjoin(AccessPoint, AccessPoint.c.id == CustomerService.access_point_device_id).outerjoin(Cpe, Cpe.c.id == CustomerService.cpe_device_id)
            .where(Customer.deleted_at.is_(None), customer_scope_clause(scope))
        )
        if entity == "customer_services": stmt = stmt.where(CustomerService.id.is_not(None), customer_service_scope_clause(scope))
        for key, column in (("network_id", Network.id), ("city_id", City.id), ("location_id", Location.id), ("sector_id", Sector.id)):
            value = _uuid_filter(filters, key)
            if value is not None: stmt = stmt.where(column == value)
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
        stmt = stmt.order_by(Customer.customer_code, CustomerService.service_code.nullslast())
        rows = [{
            "customer_code": customer.customer_code, "name": customer.name, "status": customer.status,
            "service_code": service.service_code if service else None, "service_status": service.status if service else None,
            "service_vlan": service_vlan, "customer_vlan": service.customer_vlan_id if service else None,
            "network": network, "city": city, "location": location, "sector": sector, "access_point": ap_name, "cpe": cpe_name,
        } for customer, service, service_vlan, network, city, location, sector, ap_name, cpe_name in (await db.execute(stmt)).all()]
        return columns, rows

    if entity == "groups":
        columns = ["code", "name", "description", "group_kind", "membership_mode", "scope_type", "device_scope", "sector_role"]
        stmt = select(DeviceGroup).where(DeviceGroup.deleted_at.is_(None), group_scope_clause(scope))
        group_id = _uuid_filter(filters, "group_id")
        if group_id is not None: stmt = stmt.where(DeviceGroup.id == group_id)
        network_id, city_id, location_id, sector_id = (_uuid_filter(filters, key) for key in ("network_id", "city_id", "location_id", "sector_id"))
        if sector_id is not None:
            stmt = stmt.where(DeviceGroup.scope_type == "SECTOR", DeviceGroup.sector_id == sector_id)
        elif location_id is not None:
            stmt = stmt.where(or_(and_(DeviceGroup.scope_type == "LOCATION", DeviceGroup.location_id == location_id), and_(DeviceGroup.scope_type == "SECTOR", exists(select(1).where(Sector.id == DeviceGroup.sector_id, Sector.location_id == location_id)))))
        elif city_id is not None:
            stmt = stmt.where(or_(and_(DeviceGroup.scope_type == "CITY", DeviceGroup.city_id == city_id), and_(DeviceGroup.scope_type == "LOCATION", exists(select(1).where(Location.id == DeviceGroup.location_id, Location.city_id == city_id))), and_(DeviceGroup.scope_type == "SECTOR", exists(select(1).select_from(Sector).join(Location, Location.id == Sector.location_id).where(Sector.id == DeviceGroup.sector_id, Location.city_id == city_id)))))
        elif network_id is not None:
            stmt = stmt.where(or_(and_(DeviceGroup.scope_type == "NETWORK", DeviceGroup.network_id == network_id), and_(DeviceGroup.scope_type == "CITY", exists(select(1).where(City.id == DeviceGroup.city_id, City.network_id == network_id))), and_(DeviceGroup.scope_type == "LOCATION", exists(select(1).select_from(Location).join(City, City.id == Location.city_id).where(Location.id == DeviceGroup.location_id, City.network_id == network_id))), and_(DeviceGroup.scope_type == "SECTOR", exists(select(1).select_from(Sector).join(Location, Location.id == Sector.location_id).join(City, City.id == Location.city_id).where(Sector.id == DeviceGroup.sector_id, City.network_id == network_id)))))
        rows = [{column: getattr(group, column) for column in columns} for group in (await db.scalars(stmt.order_by(DeviceGroup.code))).all()]
        return columns, rows
    raise ValueError("Unsupported export entity type.")


async def export_bytes(db: AsyncSession, scope: EffectiveResourceScope, entity_type: str, format: str, filters: dict[str, Any] | None = None) -> tuple[bytes, str, str, int]:
    columns, rows = await export_rows(db, scope, entity_type, filters)
    fmt = format.upper()
    data = write_tabular_bytes(columns, rows, fmt)
    media = {"CSV": "text/csv", "XLSX": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "JSON": "application/json"}[fmt]
    return data, f"fttw_{entity_type}_{utcnow().strftime('%Y%m%d_%H%M%S')}.{fmt.lower()}", media, len(rows)
