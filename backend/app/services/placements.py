from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import (
    City,
    DevicePlacement,
    Location,
    Network,
    Sector, Device, DeviceType, DeviceHierarchyLink,
)
from .hierarchy import HierarchyValidationError, resolve_effective_hierarchy, synchronize_derived_placement
from .audit import record_audit
from .audit_summaries import business_summary, changed_summary, display_snapshot


class PlacementValidationError(ValueError):
    """Raised when a physical placement violates hierarchy rules."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


async def validate_placement_hierarchy(
    db: AsyncSession,
    *,
    network_id: UUID,
    city_id: UUID,
    location_id: UUID,
    sector_id: UUID | None = None,
) -> None:
    """
    Validate the physical hierarchy represented by a DevicePlacement.

    Required hierarchy:

        Network
          └── City
                └── Location
                      └── Sector (optional)

    The individual foreign keys are not sufficient because PostgreSQL
    currently permits a valid Network, City, Location and Sector from
    different branches of the hierarchy to be combined.
    """

    network = await db.scalar(
        select(Network).where(Network.id == network_id).with_for_update()
    )
    if network is None:
        raise PlacementValidationError(
            "NETWORK_NOT_FOUND",
            "The specified network does not exist.",
        )

    city = await db.scalar(
        select(City).where(City.id == city_id).with_for_update()
    )
    city_network_id = city.network_id if city is not None else None

    if city_network_id is None:
        raise PlacementValidationError(
            "CITY_NOT_FOUND",
            "The specified city does not exist.",
        )

    if city_network_id != network_id:
        raise PlacementValidationError(
            "CITY_NETWORK_MISMATCH",
            "The specified city does not belong to the specified network.",
        )

    location = await db.scalar(
        select(Location).where(Location.id == location_id).with_for_update()
    )
    location_city_id = location.city_id if location is not None else None

    if location_city_id is None:
        raise PlacementValidationError(
            "LOCATION_NOT_FOUND",
            "The specified location does not exist.",
        )

    if location_city_id != city_id:
        raise PlacementValidationError(
            "LOCATION_CITY_MISMATCH",
            "The specified location does not belong to the specified city.",
        )

    if sector_id is not None:
        sector = await db.scalar(
            select(Sector).where(Sector.id == sector_id).with_for_update()
        )
        sector_location_id = sector.location_id if sector is not None else None

        if sector_location_id is None:
            raise PlacementValidationError(
                "SECTOR_NOT_FOUND",
                "The specified sector does not exist.",
            )

        if sector_location_id != location_id:
            raise PlacementValidationError(
                "SECTOR_LOCATION_MISMATCH",
                "The specified sector does not belong to the specified location.",
            )


async def update_device_placement(
    db: AsyncSession,
    device_id: UUID,
    updates: dict,
) -> DevicePlacement:
    """
    Update an existing device placement atomically at the service layer.

    Important architectural rule:

        Organizational movement must never call this function.

    This function represents an explicit physical-placement operation.
    """

    device = await db.scalar(
        select(Device).where(Device.id == device_id).with_for_update()
    )
    if device is None:
        raise PlacementValidationError(
            "DEVICE_NOT_FOUND",
            "Device not found.",
        )

    result = await db.execute(
        select(DevicePlacement).where(
            DevicePlacement.device_id == device_id
        ).with_for_update()
    )

    placement = result.scalar_one_or_none()

    if placement is None:
        raise PlacementValidationError(
            "PLACEMENT_NOT_FOUND",
            "Device placement not found.",
        )

    before = business_summary(placement)

    type_code = await db.scalar(select(DeviceType.code).where(DeviceType.id == device.device_type_id))
    geography_fields = {"network_id", "city_id", "location_id", "sector_id"}
    if type_code in {"CPE", "ACCESS_POINT"}:
        if any(k in updates for k in geography_fields):
            raise PlacementValidationError(
                "HIERARCHY_MANAGED_PARENT",
                "CPE and access-point hierarchy is managed through their parent-device relationship.",
            )
        try:
            hierarchy = await resolve_effective_hierarchy(db, device)
        except HierarchyValidationError as exc:
            raise PlacementValidationError(exc.code, exc.message) from exc
        placement = await synchronize_derived_placement(
            db,
            device_id=device_id,
            hierarchy=hierarchy,
            derived_from="SECTOR_CPE" if type_code == "CPE" else "CPE_ACCESS_POINT",
        )
    elif type_code == "SECTOR" and any(k in updates for k in geography_fields):
        raise PlacementValidationError(
            "SECTOR_PLACEMENT_MANAGED",
            "A SECTOR device derives its placement from the logical sector it represents.",
        )

    # ---------------------------------------------------------------
    # Merge the requested changes with the existing physical state.
    # This allows PATCH while ensuring the FINAL state is validated.
    # ---------------------------------------------------------------

    network_id = updates.get("network_id", placement.network_id)
    city_id = updates.get("city_id", placement.city_id)
    location_id = updates.get("location_id", placement.location_id)
    sector_id = updates.get("sector_id", placement.sector_id)

    await validate_placement_hierarchy(
        db,
        network_id=network_id,
        city_id=city_id,
        location_id=location_id,
        sector_id=sector_id,
    )

    # ---------------------------------------------------------------
    # Apply only validated changes.
    # ---------------------------------------------------------------

    if "metadata" in updates:
        if type_code in {"SECTOR", "CPE", "ACCESS_POINT"}:
            # Keep the compatibility row explicitly marked as derived.  Caller
            # metadata is retained without giving it authority over hierarchy.
            placement.metadata_ = {
                **(placement.metadata_ or {}),
                "user_metadata": updates["metadata"],
            }
        else:
            placement.metadata_ = updates["metadata"]

    for field in (
        "network_id",
        "city_id",
        "location_id",
        "sector_id",
    ):
        if field in updates:
            setattr(placement, field, updates[field])

    await db.flush()
    after = business_summary(placement)
    before_changes, after_changes, changed_fields = changed_summary(before, after)
    metadata_requested = "metadata" in updates
    if changed_fields or metadata_requested:
        await record_audit(
            db,
            action="DEVICE_PLACEMENT_UPDATED",
            entity_type="DevicePlacement",
            entity_id=placement.id,
            description="Device placement updated through the validated placement service.",
            entity_display_snapshot=display_snapshot(placement),
            metadata={
                "changed_fields": [
                    *changed_fields,
                    *(["metadata"] if metadata_requested else []),
                ]
            },
            before_summary=before_changes,
            after_summary=after_changes,
        )
    await db.refresh(placement)

    return placement
