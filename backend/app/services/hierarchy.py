"""Authoritative resolution for the FTTW customer device hierarchy.

The geographic hierarchy is owned by Network/City/Location/Sector.  The
customer device hierarchy is owned by DeviceHierarchyLink.  DevicePlacement
is deliberately not consulted for CPE and access-point resolution because it
is a compatibility projection for those device types, not the source of
truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import (
    City,
    Device,
    DeviceHierarchyLink,
    DevicePlacement,
    DeviceType,
    Location,
    Network,
    Sector,
)


class HierarchyValidationError(ValueError):
    """A device cannot be resolved in the authoritative FTTW hierarchy."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


@dataclass(frozen=True)
class EffectiveHierarchy:
    """The effective geographic context for a device."""

    network_id: UUID
    city_id: UUID
    location_id: UUID
    sector_id: UUID | None
    source: str


async def device_type_code(db: AsyncSession, device: Device) -> str:
    code = await db.scalar(
        select(DeviceType.code).where(DeviceType.id == device.device_type_id)
    )
    if code is None:
        raise HierarchyValidationError(
            "DEVICE_TYPE_NOT_FOUND",
            "The device has no valid device type.",
        )
    return code


async def sector_geography(
    db: AsyncSession,
    sector: Sector,
) -> EffectiveHierarchy:
    """Resolve and validate the complete branch that owns a logical sector."""

    location = await db.get(Location, sector.location_id)
    if location is None:
        raise HierarchyValidationError(
            "SECTOR_LOCATION_NOT_FOUND",
            "The sector is not associated with a valid location.",
        )

    city = await db.get(City, location.city_id)
    if city is None:
        raise HierarchyValidationError(
            "LOCATION_CITY_NOT_FOUND",
            "The sector location is not associated with a valid city.",
        )

    network = await db.get(Network, city.network_id)
    if network is None:
        raise HierarchyValidationError(
            "CITY_NETWORK_NOT_FOUND",
            "The sector city is not associated with a valid network.",
        )

    return EffectiveHierarchy(
        network_id=network.id,
        city_id=city.id,
        location_id=location.id,
        sector_id=sector.id,
        source="SECTOR",
    )


async def sector_for_sector_device(
    db: AsyncSession,
    sector_device_id: UUID,
    *,
    for_update: bool = False,
) -> Sector:
    statement = select(Sector).where(Sector.sector_device_id == sector_device_id)
    if for_update:
        statement = statement.with_for_update()
    sector = await db.scalar(statement)
    if sector is None:
        raise HierarchyValidationError(
            "SECTOR_DEVICE_NOT_BOUND",
            "The SECTOR device is not bound to a logical sector.",
        )
    return sector


async def _resolve_independent_placement(
    db: AsyncSession,
    device_id: UUID,
) -> EffectiveHierarchy:
    placement = await db.scalar(
        select(DevicePlacement).where(DevicePlacement.device_id == device_id)
    )
    if placement is None:
        raise HierarchyValidationError(
            "PLACEMENT_NOT_FOUND",
            "The independently placed device has no physical placement.",
        )

    network = await db.get(Network, placement.network_id)
    city = await db.get(City, placement.city_id)
    location = await db.get(Location, placement.location_id)

    if network is None or city is None or location is None:
        raise HierarchyValidationError(
            "PLACEMENT_REFERENCE_NOT_FOUND",
            "The device placement references missing geographic records.",
        )
    if city.network_id != network.id:
        raise HierarchyValidationError(
            "PLACEMENT_CITY_NETWORK_MISMATCH",
            "The placement city does not belong to its placement network.",
        )
    if location.city_id != city.id:
        raise HierarchyValidationError(
            "PLACEMENT_LOCATION_CITY_MISMATCH",
            "The placement location does not belong to its placement city.",
        )

    if placement.sector_id is not None:
        sector = await db.get(Sector, placement.sector_id)
        if sector is None or sector.location_id != location.id:
            raise HierarchyValidationError(
                "PLACEMENT_SECTOR_LOCATION_MISMATCH",
                "The placement sector does not belong to its placement location.",
            )

    return EffectiveHierarchy(
        network_id=network.id,
        city_id=city.id,
        location_id=location.id,
        sector_id=placement.sector_id,
        source="PLACEMENT",
    )


async def resolve_effective_hierarchy(
    db: AsyncSession,
    device: Device,
) -> EffectiveHierarchy:
    """Resolve a device without trusting copied CPE/AP placement values."""

    type_code = await device_type_code(db, device)

    if type_code == "SECTOR":
        sector = await sector_for_sector_device(db, device.id)
        return await sector_geography(db, sector)

    if type_code == "CPE":
        link = await db.scalar(
            select(DeviceHierarchyLink).where(
                DeviceHierarchyLink.child_device_id == device.id,
                DeviceHierarchyLink.relationship_type == "SECTOR_CPE",
            )
        )
        if link is None:
            raise HierarchyValidationError(
                "CPE_PARENT_LINK_MISSING",
                "The CPE does not have a SECTOR_CPE parent link.",
            )

        parent = await db.get(Device, link.parent_device_id)
        if parent is None or await device_type_code(db, parent) != "SECTOR":
            raise HierarchyValidationError(
                "CPE_PARENT_INVALID",
                "The CPE parent must be a valid SECTOR device.",
            )

        sector = await sector_for_sector_device(db, parent.id)
        return await sector_geography(db, sector)

    if type_code == "ACCESS_POINT":
        link = await db.scalar(
            select(DeviceHierarchyLink).where(
                DeviceHierarchyLink.child_device_id == device.id,
                DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
            )
        )
        if link is None:
            raise HierarchyValidationError(
                "ACCESS_POINT_PARENT_LINK_MISSING",
                "The access point does not have a CPE_ACCESS_POINT parent link.",
            )

        parent = await db.get(Device, link.parent_device_id)
        if parent is None or await device_type_code(db, parent) != "CPE":
            raise HierarchyValidationError(
                "ACCESS_POINT_PARENT_INVALID",
                "The access point parent must be a valid CPE device.",
            )

        return await resolve_effective_hierarchy(db, parent)

    return await _resolve_independent_placement(db, device.id)


async def synchronize_derived_placement(
    db: AsyncSession,
    *,
    device_id: UUID,
    hierarchy: EffectiveHierarchy,
    derived_from: str,
) -> DevicePlacement:
    """Maintain the compatibility placement projection for CPE/AP devices."""

    placement = await db.scalar(
        select(DevicePlacement).where(DevicePlacement.device_id == device_id)
    )
    metadata = {
        **((placement.metadata_ if placement is not None else {}) or {}),
        "placement_mode": "DERIVED",
        "derived_from": derived_from,
    }

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
    placement.metadata_ = metadata
    return placement
