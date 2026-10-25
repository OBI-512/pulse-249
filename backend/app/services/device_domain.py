from __future__ import annotations

from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import City, Device, DeviceHierarchyLink, DevicePlacement, DeviceType, Location, Network, Sector
from .hierarchy import (
    EffectiveHierarchy,
    HierarchyValidationError,
    device_type_code,
    resolve_effective_hierarchy,
    synchronize_derived_placement,
)


CONTROLLED_DEVICE_TYPES = {
    "ACCESS_POINT", "CPE", "SECTOR", "SWITCH", "ROUTER", "FIREWALL",
    "SERVER", "WIRELESS_BRIDGE", "NETWORK_DEVICE", "OTHER",
}


def _domain_error(code: str, message: str, status_code: int = 422) -> HTTPException:
    return HTTPException(status_code, {"code": code, "message": message})


def _raise_hierarchy_error(exc: HierarchyValidationError) -> None:
    raise _domain_error(exc.code, exc.message)


async def get_type_code(db: AsyncSession, device_type_id: UUID) -> str:
    row = await db.scalar(select(DeviceType).where(DeviceType.id == device_type_id))
    if row is None or not row.is_active or row.code not in CONTROLLED_DEVICE_TYPES:
        raise _domain_error("UNSUPPORTED_DEVICE_TYPE", "Only the controlled FTTW device types are allowed.")
    return row.code


async def validate_location(db: AsyncSession, location_id: UUID):
    # Resolve IDs first, then lock the active hierarchy in root-to-leaf order.
    # Re-read every link under lock so a concurrent recycle/move cannot turn a
    # validated placement into a child of a tombstoned geography row.
    location_city_id = await db.scalar(
        select(Location.city_id).where(Location.id == location_id)
    )
    if location_city_id is None:
        raise _domain_error("LOCATION_NOT_FOUND", "Location does not exist.", 404)
    city_network_id = await db.scalar(
        select(City.network_id).where(City.id == location_city_id)
    )
    if city_network_id is None:
        raise _domain_error("LOCATION_CITY_NOT_FOUND", "Location has no valid city.")

    network = await db.scalar(
        select(Network)
        .where(Network.id == city_network_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if network is None:
        raise _domain_error("CITY_NETWORK_NOT_FOUND", "City has no valid network.")
    if network.deleted_at is not None or network.status != "ACTIVE":
        raise _domain_error("NETWORK_NOT_AVAILABLE", "The selected location belongs to a network that is not active or has been recycled.", 409)
    city = await db.scalar(
        select(City)
        .where(City.id == location_city_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if city is None or city.network_id != network.id:
        raise _domain_error("LOCATION_CITY_NOT_FOUND", "Location has no valid city.")
    if city.deleted_at is not None or city.status != "ACTIVE":
        raise _domain_error("CITY_NOT_AVAILABLE", "The selected location belongs to a city that is not active or has been recycled.", 409)
    location = await db.scalar(
        select(Location)
        .where(Location.id == location_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if location is None:
        raise _domain_error("LOCATION_NOT_FOUND", "Location does not exist.", 404)
    if location.city_id != city.id:
        raise _domain_error("LOCATION_CITY_NOT_FOUND", "Location has no valid city.")
    if location.deleted_at is not None or location.status != "ACTIVE":
        raise _domain_error("LOCATION_NOT_AVAILABLE", "The selected location is not active or has been recycled.", 409)
    return location, city, network


async def _upsert_placement(
    db: AsyncSession, *, device_id: UUID, hierarchy: EffectiveHierarchy, metadata: dict
) -> DevicePlacement:
    placement = await db.scalar(select(DevicePlacement).where(DevicePlacement.device_id == device_id))
    if placement is None:
        placement = DevicePlacement(
            device_id=device_id,
            network_id=hierarchy.network_id,
            city_id=hierarchy.city_id,
            location_id=hierarchy.location_id,
            sector_id=hierarchy.sector_id,
            metadata_=metadata,
        )
        db.add(placement)
        return placement
    placement.network_id = hierarchy.network_id
    placement.city_id = hierarchy.city_id
    placement.location_id = hierarchy.location_id
    placement.sector_id = hierarchy.sector_id
    placement.metadata_ = {**(placement.metadata_ or {}), **metadata}
    return placement


async def _ensure_hierarchy_link(
    db: AsyncSession, *, child_device_id: UUID, parent_device_id: UUID, relationship_type: str
) -> DeviceHierarchyLink:
    existing_child = await db.scalar(
        select(DeviceHierarchyLink).where(DeviceHierarchyLink.child_device_id == child_device_id)
    )
    if existing_child is not None:
        if (
            existing_child.parent_device_id == parent_device_id
            and existing_child.relationship_type == relationship_type
        ):
            return existing_child
        raise _domain_error("HIERARCHY_CHILD_ALREADY_LINKED", "The device already has a different hierarchy parent.", 409)

    if relationship_type == "CPE_ACCESS_POINT":
        existing_ap = await db.scalar(
            select(DeviceHierarchyLink).where(
                DeviceHierarchyLink.parent_device_id == parent_device_id,
                DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
            )
        )
        if existing_ap is not None:
            raise _domain_error("CPE_ALREADY_HAS_ACCESS_POINT", "Each CPE can have only one access point.", 409)

    link = DeviceHierarchyLink(
        child_device_id=child_device_id,
        parent_device_id=parent_device_id,
        relationship_type=relationship_type,
    )
    db.add(link)
    return link


async def _bind_sector_device(
    db: AsyncSession, *, device: Device, sector_id: UUID | None, location_id: UUID | None
) -> DevicePlacement:
    if sector_id is None:
        raise _domain_error("SECTOR_ID_REQUIRED", "A SECTOR device must bind explicitly to an existing sector.")
    sector_location_id = await db.scalar(
        select(Sector.location_id).where(Sector.id == sector_id)
    )
    if sector_location_id is None:
        raise _domain_error("SECTOR_NOT_FOUND", "The selected sector does not exist.", 404)
    location, city, network = await validate_location(db, sector_location_id)
    sector = await db.scalar(
        select(Sector)
        .where(Sector.id == sector_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if sector is None or sector.location_id != location.id:
        raise _domain_error("SECTOR_NOT_FOUND", "The selected sector does not exist.", 404)
    if sector.deleted_at is not None or sector.status != "ACTIVE":
        raise _domain_error("SECTOR_NOT_AVAILABLE", "The selected logical sector is not active or has been recycled.", 409)
    hierarchy = EffectiveHierarchy(
        network_id=network.id,
        city_id=city.id,
        location_id=location.id,
        sector_id=sector.id,
        source="SECTOR",
    )

    if location_id is not None and location_id != hierarchy.location_id:
        raise _domain_error("SECTOR_LOCATION_MISMATCH", "The supplied location does not match the selected sector.")
    if sector.sector_device_id not in {None, device.id}:
        raise _domain_error("SECTOR_ALREADY_HAS_DEVICE", "The sector is already bound to another SECTOR device.", 409)

    sector.sector_device_id = device.id
    return await _upsert_placement(
        db,
        device_id=device.id,
        hierarchy=hierarchy,
        metadata={"placement_mode": "DERIVED", "derived_from": "SECTOR"},
    )


async def _create_cpe_placement(
    db: AsyncSession,
    *,
    device: Device,
    parent_device_id: UUID | None,
    location_id: UUID | None,
    sector_id: UUID | None,
) -> DevicePlacement:
    if parent_device_id is None:
        raise _domain_error("PARENT_DEVICE_REQUIRED", "CPE requires a SECTOR device parent.")
    if location_id is not None or sector_id is not None:
        raise _domain_error("HIERARCHY_INPUT_FORBIDDEN", "CPE geography is derived from its SECTOR device parent.")

    parent_type_id = await db.scalar(
        select(Device.device_type_id).where(Device.id == parent_device_id)
    )
    if parent_type_id is None:
        raise _domain_error("PARENT_DEVICE_NOT_FOUND", "Parent device does not exist.", 404)
    try:
        parent_type = await db.scalar(
            select(DeviceType.code).where(DeviceType.id == parent_type_id)
        )
        if parent_type != "SECTOR":
            raise _domain_error("INVALID_PARENT_DEVICE_TYPE", "CPE must be attached to a SECTOR device.")
        sector_probe = (
            await db.execute(
                select(Sector.id, Sector.location_id).where(
                    Sector.sector_device_id == parent_device_id
                )
            )
        ).one_or_none()
        if sector_probe is None:
            raise _domain_error("SECTOR_DEVICE_BINDING_NOT_FOUND", "The parent SECTOR device is not bound to a Sector.", 404)
        sector_probe_id, sector_location_id = sector_probe
        location, city, network = await validate_location(db, sector_location_id)
        # Lock logical Sector before its managed device, matching Sector bundle
        # operations and serializing role changes/CPE attachment.
        sector = await db.scalar(
            select(Sector)
            .where(Sector.id == sector_probe_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        parent = await db.scalar(
            select(Device)
            .where(
                Device.id == parent_device_id,
                Device.deleted_at.is_(None),
                Device.lifecycle_state != "DECOMMISSIONED",
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if (
            sector is None
            or parent is None
            or sector.sector_device_id != parent.id
            or sector.location_id != location.id
            or sector.deleted_at is not None
            or sector.status != "ACTIVE"
            or await device_type_code(db, parent) != "SECTOR"
        ):
            raise _domain_error("PARENT_DEVICE_NOT_FOUND", "Parent device does not exist.", 404)
        if sector.role != "CUSTOMER_ACCESS":
            raise _domain_error("BACKHAUL_SECTOR_NOT_CUSTOMER_SERVING", "Only customer-access sectors can have customer CPEs.")
        hierarchy = EffectiveHierarchy(
            network_id=network.id,
            city_id=city.id,
            location_id=location.id,
            sector_id=sector.id,
            source="SECTOR_CPE",
        )
    except HierarchyValidationError as exc:
        _raise_hierarchy_error(exc)

    await _ensure_hierarchy_link(
        db,
        child_device_id=device.id,
        parent_device_id=parent.id,
        relationship_type="SECTOR_CPE",
    )
    return await synchronize_derived_placement(
        db, device_id=device.id, hierarchy=hierarchy, derived_from="SECTOR_CPE"
    )


async def _create_access_point_placement(
    db: AsyncSession,
    *,
    device: Device,
    parent_device_id: UUID | None,
    location_id: UUID | None,
    sector_id: UUID | None,
) -> DevicePlacement:
    if parent_device_id is None:
        raise _domain_error("PARENT_DEVICE_REQUIRED", "ACCESS_POINT requires a CPE parent.")
    if location_id is not None or sector_id is not None:
        raise _domain_error("HIERARCHY_INPUT_FORBIDDEN", "Access-point geography is derived from its CPE parent.")

    parent = await db.scalar(
        select(Device)
        .where(
            Device.id == parent_device_id,
            Device.deleted_at.is_(None),
            Device.lifecycle_state != "DECOMMISSIONED",
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if parent is None:
        raise _domain_error("PARENT_DEVICE_NOT_FOUND", "Parent device does not exist.", 404)
    try:
        if await device_type_code(db, parent) != "CPE":
            raise _domain_error("INVALID_PARENT_DEVICE_TYPE", "ACCESS_POINT must be attached to a CPE device.")
        hierarchy = await resolve_effective_hierarchy(db, parent)
        location, city, network = await validate_location(db, hierarchy.location_id)
        if hierarchy.sector_id is None:
            raise _domain_error("CPE_SECTOR_NOT_FOUND", "The selected CPE is not attached to a valid customer-access sector.", 409)
        sector = await db.scalar(
            select(Sector).where(
                Sector.id == hierarchy.sector_id,
                Sector.deleted_at.is_(None),
                Sector.status == "ACTIVE",
                Sector.role == "CUSTOMER_ACCESS",
            )
        )
        if sector is None or sector.location_id != location.id:
            raise _domain_error("CPE_SECTOR_NOT_AVAILABLE", "The selected CPE is not attached to an active customer-access sector.", 409)
        sector_device = await db.scalar(
            select(Device).where(
                Device.id == sector.sector_device_id,
                Device.deleted_at.is_(None),
                Device.lifecycle_state != "DECOMMISSIONED",
            )
        )
        if sector_device is None:
            raise _domain_error("SECTOR_DEVICE_NOT_AVAILABLE", "The selected CPE's physical SECTOR device is not available.", 409)
        if hierarchy.network_id != network.id or hierarchy.city_id != city.id:
            raise _domain_error("CPE_HIERARCHY_INVALID", "The selected CPE hierarchy is inconsistent.", 409)
    except HierarchyValidationError as exc:
        _raise_hierarchy_error(exc)

    await _ensure_hierarchy_link(
        db,
        child_device_id=device.id,
        parent_device_id=parent.id,
        relationship_type="CPE_ACCESS_POINT",
    )
    return await synchronize_derived_placement(
        db, device_id=device.id, hierarchy=hierarchy, derived_from="CPE_ACCESS_POINT"
    )


async def create_domain_placement(
    db: AsyncSession,
    device: Device,
    type_code: str,
    *,
    location_id: UUID | None,
    parent_device_id: UUID | None,
    sector_id: UUID | None = None,
    sector_role: str | None = None,
) -> DevicePlacement:
    """Register a device into its only valid physical-domain context.

    Sector creation is explicit through the geography API. A SECTOR device
    therefore binds to an existing Sector rather than silently creating one.
    ``sector_role`` remains only for backward-compatible callers.
    """
    del sector_role

    if type_code == "SECTOR":
        if parent_device_id is not None:
            raise _domain_error("PARENT_NOT_SUPPORTED", "A SECTOR device cannot have a device parent.")
        return await _bind_sector_device(
            db, device=device, sector_id=sector_id, location_id=location_id
        )
    if type_code == "CPE":
        return await _create_cpe_placement(
            db,
            device=device,
            parent_device_id=parent_device_id,
            location_id=location_id,
            sector_id=sector_id,
        )
    if type_code == "ACCESS_POINT":
        return await _create_access_point_placement(
            db,
            device=device,
            parent_device_id=parent_device_id,
            location_id=location_id,
            sector_id=sector_id,
        )

    if parent_device_id is not None:
        raise _domain_error("PARENT_NOT_SUPPORTED", f"{type_code} is independently placed and cannot have a hierarchy parent.")
    if sector_id is not None:
        raise _domain_error("SECTOR_ASSIGNMENT_NOT_SUPPORTED", f"{type_code} is location-placed and cannot use customer-sector placement.")
    if location_id is None:
        raise _domain_error("LOCATION_REQUIRED", f"{type_code} requires a location.")

    location, city, network = await validate_location(db, location_id)
    return await _upsert_placement(
        db,
        device_id=device.id,
        hierarchy=EffectiveHierarchy(
            network_id=network.id,
            city_id=city.id,
            location_id=location.id,
            sector_id=None,
            source="PLACEMENT",
        ),
        metadata={"placement_mode": "INDEPENDENT", "domain": type_code},
    )
