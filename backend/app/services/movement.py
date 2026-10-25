"""Transactional physical movement operations for the authoritative FTTW hierarchy."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import (
    CustomerService,
    Device,
    DeviceHierarchyLink,
    DeviceType,
    Location,
    City,
    Network,
    Sector,
)
from .audit import record_audit
from .audit_summaries import business_summary, display_snapshot
from .crud import lock_active_rows
from .groups import reconcile_physical_move_memberships
from .hierarchy import (
    HierarchyValidationError,
    device_type_code,
    resolve_effective_hierarchy,
    sector_for_sector_device,
    sector_geography,
    synchronize_derived_placement,
)


class MovementValidationError(ValueError):
    """A requested physical move violates the authoritative domain model."""

    def __init__(self, code: str, message: str, status_code: int = 422):
        self.code = code
        self.message = message
        self.status_code = status_code
        super().__init__(message)


def _movement_error_from_hierarchy(error: HierarchyValidationError) -> MovementValidationError:
    return MovementValidationError(error.code, error.message)


async def _require_device_type(
    db: AsyncSession,
    device: Device,
    expected_type: str,
    *,
    missing_code: str,
) -> None:
    if await device_type_code(db, device) != expected_type:
        raise MovementValidationError(
            missing_code,
            f"The selected device must have controlled type {expected_type}.",
        )


def _sector_naming(location: Location, sequence_number: int) -> tuple[str, str]:
    """Return the location-derived sector code and display name.

    The movement convention is intentionally explicit: ``<location-code>-SECTOR-<n>``
    and ``<location-name> Sector <n>``.  The sequence is local to a location.
    """

    code = f"{location.code}-SECTOR-{sequence_number:02d}"
    name = f"{location.name} Sector {sequence_number}"
    if len(code) > 50 or len(name) > 150:
        raise MovementValidationError(
            "SECTOR_NAMING_INVALID",
            "The destination location code or name is too long for the sector naming convention.",
        )
    return code, name


async def _next_sector_sequence(db: AsyncSession, location_id: UUID) -> int:
    maximum = await db.scalar(
        select(func.max(Sector.sequence_number)).where(Sector.location_id == location_id)
    )
    return (maximum or 0) + 1


async def _sector_for_device(
    db: AsyncSession,
    device: Device,
) -> Sector:
    try:
        # Use the same row lock as role transitions: moving a CPE creates a
        # customer dependency on the destination sector just like initial
        # registration does.
        return await sector_for_sector_device(db, device.id, for_update=True)
    except HierarchyValidationError as exc:
        raise _movement_error_from_hierarchy(exc) from exc


async def _synchronize_cpe_and_ap_placements(
    db: AsyncSession,
    cpe: Device,
) -> DeviceHierarchyLink | None:
    """Refresh derived placement projections after a CPE parent changes."""

    try:
        cpe_hierarchy = await resolve_effective_hierarchy(db, cpe)
    except HierarchyValidationError as exc:
        raise _movement_error_from_hierarchy(exc) from exc
    await synchronize_derived_placement(
        db,
        device_id=cpe.id,
        hierarchy=cpe_hierarchy,
        derived_from="SECTOR_CPE",
    )

    ap_link = await db.scalar(
        select(DeviceHierarchyLink).where(
            DeviceHierarchyLink.parent_device_id == cpe.id,
            DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
        )
    )
    if ap_link is None:
        return None

    access_point = await db.get(Device, ap_link.child_device_id)
    if access_point is None:
        raise MovementValidationError(
            "ACCESS_POINT_NOT_FOUND",
            "The CPE references an access point that no longer exists.",
            404,
        )
    await _require_device_type(
        db,
        access_point,
        "ACCESS_POINT",
        missing_code="INVALID_ACCESS_POINT_TYPE",
    )
    await synchronize_derived_placement(
        db,
        device_id=access_point.id,
        hierarchy=cpe_hierarchy,
        derived_from="CPE_ACCESS_POINT",
    )
    return ap_link




async def rebind_sector_device(
    db: AsyncSession,
    *,
    sector_device_id: UUID,
    destination_sector_id: UUID,
) -> Device:
    """Bind an existing physical SECTOR device to a different free logical sector.

    Rebinding is deliberately conservative.  A SECTOR device with attached CPEs
    cannot be rebound because that would silently move an active customer
    hierarchy to a different logical sector.
    """

    device = await db.scalar(
        select(Device)
        .where(Device.id == sector_device_id, Device.deleted_at.is_(None))
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if device is None:
        raise MovementValidationError(
            "SECTOR_DEVICE_NOT_FOUND", "The SECTOR device does not exist.", 404
        )
    await _require_device_type(
        db, device, "SECTOR", missing_code="INVALID_SECTOR_DEVICE_TYPE"
    )

    source = await db.scalar(
        select(Sector)
        .where(
            Sector.sector_device_id == device.id,
            Sector.deleted_at.is_(None),
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if source is None:
        raise MovementValidationError(
            "SECTOR_DEVICE_NOT_BOUND",
            "The physical SECTOR device is not bound to a logical sector.",
            409,
        )

    if source.id == destination_sector_id:
        return device

    destination = await db.scalar(
        select(Sector)
        .where(
            Sector.id == destination_sector_id,
            Sector.deleted_at.is_(None),
            Sector.status == "ACTIVE",
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if destination is None:
        raise MovementValidationError(
            "SECTOR_NOT_AVAILABLE",
            "The selected logical sector is not active or no longer exists.",
            404,
        )
    geography = (
        await db.execute(
            select(Location, City, Network)
            .join(City, City.id == Location.city_id)
            .join(Network, Network.id == City.network_id)
            .where(
                Location.id == destination.location_id,
                Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None),
                Location.status == "ACTIVE", City.status == "ACTIVE", Network.status == "ACTIVE",
            )
        )
    ).first()
    if geography is None:
        raise MovementValidationError(
            "SECTOR_GEOGRAPHY_NOT_AVAILABLE",
            "The selected logical sector belongs to geography that is not active or has been recycled.",
            409,
        )
    if destination.sector_device_id not in {None, device.id}:
        raise MovementValidationError(
            "SECTOR_ALREADY_HAS_DEVICE",
            "The selected logical sector already has a physical SECTOR device.",
            409,
        )

    attached_cpe = await db.scalar(
        select(DeviceHierarchyLink.id).where(
            DeviceHierarchyLink.parent_device_id == device.id,
            DeviceHierarchyLink.relationship_type == "SECTOR_CPE",
            DeviceHierarchyLink.deleted_at.is_(None),
        )
    )
    if attached_cpe is not None:
        raise MovementValidationError(
            "SECTOR_HAS_ATTACHED_CPES",
            "Move or remove all attached CPEs before rebinding this physical SECTOR device to another logical sector.",
            409,
        )

    before = {"logical_sector_id": str(source.id)}
    source.sector_device_id = None
    destination.sector_device_id = device.id
    await db.flush()

    hierarchy = await sector_geography(db, destination)
    await synchronize_derived_placement(
        db,
        device_id=device.id,
        hierarchy=hierarchy,
        derived_from="SECTOR",
    )
    memberships_removed = await reconcile_physical_move_memberships(db, [device.id])
    await record_audit(
        db,
        action="SECTOR_DEVICE_REBOUND",
        entity_type="Device",
        entity_id=device.id,
        description="Physical SECTOR device rebound to a different free logical sector.",
        entity_display_snapshot=display_snapshot(device),
        metadata={
            "old_sector_id": str(source.id),
            "new_sector_id": str(destination.id),
            "memberships_removed": memberships_removed,
        },
        before_summary=before,
        after_summary={"logical_sector_id": str(destination.id)},
    )
    await db.flush()
    return device


async def move_sector_to_location(
    db: AsyncSession,
    *,
    sector_id: UUID,
    destination_location_id: UUID,
    sequence_number: int | None = None,
) -> Sector:
    """Move an empty logical sector and its managed SECTOR device atomically."""

    sector = await db.scalar(
        select(Sector).where(Sector.id == sector_id).with_for_update()
    )
    if sector is None:
        raise MovementValidationError("SECTOR_NOT_FOUND", "The sector does not exist.", 404)
    destination = await db.scalar(
        select(Location)
        .where(Location.id == destination_location_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if destination is None:
        raise MovementValidationError("LOCATION_NOT_FOUND", "The destination location does not exist.", 404)
    if sector.location_id == destination.id:
        raise MovementValidationError(
            "SECTOR_ALREADY_AT_LOCATION",
            "The sector is already assigned to the destination location.",
            409,
        )

    managed_device = None
    if sector.sector_device_id is not None:
        managed_device = await db.scalar(
            select(Device)
            .where(Device.id == sector.sector_device_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if managed_device is None:
            raise MovementValidationError(
                "SECTOR_DEVICE_NOT_FOUND",
                "The sector has an invalid managed device reference.",
                404,
            )
        await _require_device_type(
            db,
            managed_device,
            "SECTOR",
            missing_code="INVALID_SECTOR_DEVICE_TYPE",
        )
        attached_cpe_ids = (
            await db.scalars(
                select(DeviceHierarchyLink.child_device_id)
                .where(
                    DeviceHierarchyLink.parent_device_id == managed_device.id,
                    DeviceHierarchyLink.relationship_type == "SECTOR_CPE",
                )
                .order_by(DeviceHierarchyLink.id)
                .with_for_update()
            )
        ).all()
        if attached_cpe_ids:
            raise MovementValidationError(
                "SECTOR_HAS_ATTACHED_CPES",
                "Move or remove all attached CPEs before moving this sector.",
                409,
            )

    destination_sequence = sequence_number or await _next_sector_sequence(db, destination.id)
    new_code, new_name = _sector_naming(destination, destination_sequence)
    code_conflict = await db.scalar(
        select(Sector.id).where(
            Sector.location_id == destination.id,
            Sector.code == new_code,
            Sector.id != sector.id,
        )
    )
    if code_conflict is not None:
        raise MovementValidationError(
            "SECTOR_NAMING_CONFLICT",
            "The destination already has a sector with the generated code.",
            409,
        )
    sequence_conflict = await db.scalar(
        select(Sector.id).where(
            Sector.location_id == destination.id,
            Sector.sequence_number == destination_sequence,
            Sector.id != sector.id,
        )
    )
    if sequence_conflict is not None:
        raise MovementValidationError(
            "SECTOR_SEQUENCE_CONFLICT",
            "The destination already uses the requested sector sequence number.",
            409,
        )

    sector_before = business_summary(sector)
    old_location_id = sector.location_id
    old_code = sector.code
    old_name = sector.name
    sector.location_id = destination.id
    sector.sequence_number = destination_sequence
    sector.code = new_code
    sector.name = new_name
    await db.flush()

    memberships_removed = 0
    if managed_device is not None:
        hierarchy = await sector_geography(db, sector)
        await synchronize_derived_placement(
            db,
            device_id=managed_device.id,
            hierarchy=hierarchy,
            derived_from="SECTOR",
        )
        # Seeded/managed sector devices use the sector code for both display
        # name and hostname.  Preserve operator-defined names.
        if managed_device.display_name == old_code:
            managed_device.display_name = new_code
        if managed_device.hostname == old_code.lower():
            managed_device.hostname = new_code.lower()
        memberships_removed = await reconcile_physical_move_memberships(
            db, [managed_device.id]
        )

    await record_audit(
        db,
        action="SECTOR_MOVED",
        entity_type="Sector",
        entity_id=sector.id,
        description="Sector moved to a new physical location after confirming it has no attached CPEs.",
        entity_display_snapshot=display_snapshot(sector),
        metadata={
            "old_location_id": str(old_location_id),
            "new_location_id": str(destination.id),
            "old_code": old_code,
            "new_code": new_code,
            "old_name": old_name,
            "new_name": new_name,
            "sequence_number": destination_sequence,
            "memberships_removed": memberships_removed,
        },
        before_summary=sector_before,
        after_summary=business_summary(sector),
    )
    await db.flush()
    return sector


async def move_cpe_to_sector(
    db: AsyncSession,
    *,
    cpe_device_id: UUID,
    destination_sector_device_id: UUID,
) -> Device:
    """Move a CPE by changing its authoritative SECTOR_CPE parent link."""

    # Probe the hierarchy first only to build a complete lock set.  The rows
    # are re-read after the destination Sector, devices, and links are locked
    # in deterministic UUID order.  This is the same serialization point used
    # by recycle and Sector role transitions.
    parent_probe = (
        await db.execute(
            select(
                DeviceHierarchyLink.id,
                DeviceHierarchyLink.parent_device_id,
            ).where(
                DeviceHierarchyLink.child_device_id == cpe_device_id,
                DeviceHierarchyLink.relationship_type == "SECTOR_CPE",
            )
        )
    ).one_or_none()
    if parent_probe is None:
        raise MovementValidationError(
            "CPE_PARENT_LINK_MISSING",
            "The CPE has no authoritative SECTOR_CPE parent link.",
        )
    ap_probe = (
        await db.execute(
            select(DeviceHierarchyLink.id, DeviceHierarchyLink.child_device_id).where(
                DeviceHierarchyLink.parent_device_id == cpe_device_id,
                DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
            )
        )
    ).one_or_none()
    destination_sector_probe = (
        await db.execute(
            select(Sector.id).where(
                Sector.sector_device_id == destination_sector_device_id
            )
        )
    ).scalar_one_or_none()
    if destination_sector_probe is None:
        raise MovementValidationError(
            "SECTOR_DEVICE_NOT_BOUND",
            "The SECTOR device is not bound to a logical sector.",
        )

    sectors = await lock_active_rows(db, Sector, [destination_sector_probe])
    destination_sector = sectors.get(destination_sector_probe)
    if (
        destination_sector is None
        or destination_sector.sector_device_id != destination_sector_device_id
    ):
        raise MovementValidationError(
            "SECTOR_DEVICE_NOT_BOUND",
            "The SECTOR device is not bound to an active logical sector.",
            404,
        )

    device_ids = {
        cpe_device_id,
        destination_sector_device_id,
        parent_probe.parent_device_id,
    }
    if ap_probe is not None:
        device_ids.add(ap_probe.child_device_id)
    devices = await lock_active_rows(db, Device, device_ids)
    cpe = devices.get(cpe_device_id)
    if cpe is None:
        raise MovementValidationError("CPE_NOT_FOUND", "The CPE does not exist.", 404)
    destination_device = devices.get(destination_sector_device_id)
    if destination_device is None:
        raise MovementValidationError(
            "DESTINATION_SECTOR_DEVICE_NOT_FOUND",
            "The destination SECTOR device does not exist.",
            404,
        )
    await _require_device_type(db, cpe, "CPE", missing_code="INVALID_CPE_TYPE")
    await _require_device_type(
        db,
        destination_device,
        "SECTOR",
        missing_code="INVALID_DESTINATION_SECTOR_DEVICE_TYPE",
    )
    if destination_sector.role != "CUSTOMER_ACCESS":
        raise MovementValidationError(
            "BACKHAUL_SECTOR_NOT_CUSTOMER_SERVING",
            "A customer-serving CPE cannot be moved to a BACKHAUL sector.",
        )

    locked_links = await lock_active_rows(
        db,
        DeviceHierarchyLink,
        [parent_probe.id, *([ap_probe.id] if ap_probe is not None else [])],
    )
    parent_link = locked_links.get(parent_probe.id)
    if (
        parent_link is None
        or parent_link.child_device_id != cpe.id
        or parent_link.parent_device_id != parent_probe.parent_device_id
        or parent_link.relationship_type != "SECTOR_CPE"
    ):
        raise MovementValidationError(
            "MOVEMENT_DEPENDENCY_CHANGED",
            "The CPE hierarchy changed while the move was being validated.",
            409,
        )
    if parent_link.parent_device_id == destination_device.id:
        raise MovementValidationError(
            "CPE_ALREADY_IN_DESTINATION_SECTOR",
            "The CPE is already attached to the destination sector.",
            409,
        )

    ap_link = locked_links.get(ap_probe.id) if ap_probe is not None else None
    current_ap_link_id = await db.scalar(
        select(DeviceHierarchyLink.id).where(
            DeviceHierarchyLink.parent_device_id == cpe.id,
            DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
        )
    )
    if current_ap_link_id != (ap_link.id if ap_link is not None else None):
        raise MovementValidationError(
            "MOVEMENT_DEPENDENCY_CHANGED",
            "The CPE access-point hierarchy changed while the move was being validated.",
            409,
        )
    services = (
        await db.scalars(
            select(CustomerService)
            .where(CustomerService.cpe_device_id == cpe.id)
            .order_by(CustomerService.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).all()
    if services:
        if ap_link is None:
            raise MovementValidationError(
                "CUSTOMER_SERVICE_AP_MISMATCH",
                "A customer-service CPE must retain its attached access point during a move.",
            )
        if any(service.access_point_device_id != ap_link.child_device_id for service in services):
            raise MovementValidationError(
                "CUSTOMER_SERVICE_AP_MISMATCH",
                "A customer service references an access point not attached to this CPE.",
            )

    old_sector_device_id = parent_link.parent_device_id
    parent_link.parent_device_id = destination_device.id
    await db.flush()
    ap_link = await _synchronize_cpe_and_ap_placements(db, cpe)
    for service in services:
        previous_sector_id = service.sector_id
        service.sector_id = destination_sector.id
        await record_audit(
            db,
            action="CUSTOMER_SERVICE_SECTOR_SYNCHRONIZED",
            entity_type="CustomerService",
            entity_id=service.id,
            description="Customer-service sector synchronized after its CPE moved.",
            entity_display_snapshot=display_snapshot(service),
            metadata={"sector_id": str(destination_sector.id), "cpe_device_id": str(cpe.id)},
            before_summary={"sector_id": str(previous_sector_id)},
            after_summary={"sector_id": str(service.sector_id)},
        )

    memberships_removed = await reconcile_physical_move_memberships(
        db,
        [cpe.id, ap_link.child_device_id] if ap_link is not None else [cpe.id],
    )
    await record_audit(
        db,
        action="CPE_MOVED",
        entity_type="Device",
        entity_id=cpe.id,
        description="CPE moved through its authoritative SECTOR_CPE parent link.",
        entity_display_snapshot=display_snapshot(cpe),
        metadata={
            "old_sector_device_id": str(old_sector_device_id),
            "new_sector_device_id": str(destination_device.id),
            "new_sector_id": str(destination_sector.id),
            "access_point_device_id": str(ap_link.child_device_id) if ap_link else None,
            "memberships_removed": memberships_removed,
        },
        before_summary={"sector_device_id": str(old_sector_device_id)},
        after_summary={
            "sector_device_id": str(destination_device.id),
            "sector_id": str(destination_sector.id),
        },
    )
    await db.flush()
    return cpe


async def reassign_access_point(
    db: AsyncSession,
    *,
    access_point_device_id: UUID,
    destination_cpe_device_id: UUID,
) -> Device:
    """Reassign an AP to a CPE while keeping hierarchy and service data valid."""

    parent_probe = (
        await db.execute(
            select(
                DeviceHierarchyLink.id,
                DeviceHierarchyLink.parent_device_id,
            ).where(
                DeviceHierarchyLink.child_device_id == access_point_device_id,
                DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
            )
        )
    ).one_or_none()
    if parent_probe is None:
        raise MovementValidationError(
            "ACCESS_POINT_PARENT_LINK_MISSING",
            "The access point has no authoritative CPE_ACCESS_POINT parent link.",
        )
    destination_parent_probe = (
        await db.execute(
            select(
                DeviceHierarchyLink.id,
                DeviceHierarchyLink.parent_device_id,
            ).where(
                DeviceHierarchyLink.child_device_id == destination_cpe_device_id,
                DeviceHierarchyLink.relationship_type == "SECTOR_CPE",
            )
        )
    ).one_or_none()
    if destination_parent_probe is None:
        raise MovementValidationError(
            "CPE_PARENT_LINK_MISSING",
            "The destination CPE has no authoritative SECTOR_CPE parent link.",
        )
    destination_sector_probe = await db.scalar(
        select(Sector.id).where(
            Sector.sector_device_id == destination_parent_probe.parent_device_id
        )
    )
    if destination_sector_probe is None:
        raise MovementValidationError(
            "SECTOR_NOT_FOUND", "The destination CPE sector does not exist.", 404
        )
    sectors = await lock_active_rows(db, Sector, [destination_sector_probe])
    destination_sector = sectors.get(destination_sector_probe)
    if destination_sector is None:
        raise MovementValidationError(
            "SECTOR_NOT_FOUND", "The destination CPE sector does not exist.", 404
        )

    devices = await lock_active_rows(
        db,
        Device,
        {
            access_point_device_id,
            destination_cpe_device_id,
            parent_probe.parent_device_id,
            destination_parent_probe.parent_device_id,
        },
    )
    access_point = devices.get(access_point_device_id)
    if access_point is None:
        raise MovementValidationError("ACCESS_POINT_NOT_FOUND", "The access point does not exist.", 404)
    destination_cpe = devices.get(destination_cpe_device_id)
    if destination_cpe is None:
        raise MovementValidationError(
            "DESTINATION_CPE_NOT_FOUND", "The destination CPE does not exist.", 404
        )
    await _require_device_type(
        db, access_point, "ACCESS_POINT", missing_code="INVALID_ACCESS_POINT_TYPE"
    )
    await _require_device_type(
        db, destination_cpe, "CPE", missing_code="INVALID_DESTINATION_CPE_TYPE"
    )
    try:
        destination_hierarchy = await resolve_effective_hierarchy(db, destination_cpe)
    except HierarchyValidationError as exc:
        raise _movement_error_from_hierarchy(exc) from exc
    if destination_hierarchy.sector_id != destination_sector.id:
        raise MovementValidationError("SECTOR_NOT_FOUND", "The destination CPE sector does not exist.", 404)
    if destination_sector.role != "CUSTOMER_ACCESS":
        raise MovementValidationError(
            "BACKHAUL_SECTOR_NOT_CUSTOMER_SERVING",
            "An access point cannot be reassigned to a CPE in a BACKHAUL sector.",
        )

    locked_links = await lock_active_rows(
        db,
        DeviceHierarchyLink,
        [parent_probe.id, destination_parent_probe.id],
    )
    parent_link = locked_links.get(parent_probe.id)
    destination_parent_link = locked_links.get(destination_parent_probe.id)
    if (
        parent_link is None
        or parent_link.child_device_id != access_point.id
        or parent_link.parent_device_id != parent_probe.parent_device_id
        or destination_parent_link is None
        or destination_parent_link.child_device_id != destination_cpe.id
        or destination_parent_link.parent_device_id
        != destination_parent_probe.parent_device_id
    ):
        raise MovementValidationError(
            "MOVEMENT_DEPENDENCY_CHANGED",
            "The access-point hierarchy changed while the move was being validated.",
            409,
        )
    source_cpe = devices.get(parent_link.parent_device_id)
    if source_cpe is None:
        raise MovementValidationError("CPE_NOT_FOUND", "The access point parent CPE does not exist.", 404)
    await _require_device_type(db, source_cpe, "CPE", missing_code="ACCESS_POINT_PARENT_INVALID")
    if source_cpe.id == destination_cpe.id:
        raise MovementValidationError(
            "ACCESS_POINT_ALREADY_ON_DESTINATION_CPE",
            "The access point is already attached to the destination CPE.",
            409,
        )
    destination_ap = await db.scalar(
        select(DeviceHierarchyLink.id).where(
            DeviceHierarchyLink.parent_device_id == destination_cpe.id,
            DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
        )
    )
    if destination_ap is not None:
        raise MovementValidationError(
            "CPE_ALREADY_HAS_ACCESS_POINT",
            "Each CPE can have at most one access point.",
            409,
        )

    # Lock every possibly affected service in one deterministic statement.
    # A concurrent service update/recycle must finish before hierarchy and
    # service references are changed together.
    locked_services = (
        await db.scalars(
            select(CustomerService)
            .where(
                or_(
                    CustomerService.access_point_device_id == access_point.id,
                    CustomerService.cpe_device_id.in_(
                        [source_cpe.id, destination_cpe.id]
                    ),
                )
            )
            .order_by(CustomerService.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).all()
    services = [
        service
        for service in locked_services
        if service.access_point_device_id == access_point.id
    ]
    source_cpe_services = [
        service
        for service in locked_services
        if service.cpe_device_id == source_cpe.id
    ]
    if any(service.cpe_device_id != source_cpe.id for service in services) or any(
        service.access_point_device_id != access_point.id for service in source_cpe_services
    ):
        raise MovementValidationError(
            "CUSTOMER_SERVICE_HIERARCHY_MISMATCH",
            "Customer-service data is not consistent with the current access-point parent chain.",
        )
    destination_cpe_service = next(
        (
            service.id
            for service in locked_services
            if service.cpe_device_id == destination_cpe.id
        ),
        None,
    )
    if destination_cpe_service is not None:
        raise MovementValidationError(
            "DESTINATION_CPE_SERVICE_CONFLICT",
            "The destination CPE already belongs to a customer service.",
            409,
        )

    parent_link.parent_device_id = destination_cpe.id
    await db.flush()
    await synchronize_derived_placement(
        db,
        device_id=access_point.id,
        hierarchy=destination_hierarchy,
        derived_from="CPE_ACCESS_POINT",
    )
    for service in services:
        service_before = {
            "cpe_device_id": str(service.cpe_device_id),
            "sector_id": str(service.sector_id),
        }
        service.cpe_device_id = destination_cpe.id
        service.sector_id = destination_sector.id
        await record_audit(
            db,
            action="CUSTOMER_SERVICE_CPE_SYNCHRONIZED",
            entity_type="CustomerService",
            entity_id=service.id,
            description="Customer service synchronized after its access point was reassigned.",
            entity_display_snapshot=display_snapshot(service),
            metadata={
                "cpe_device_id": str(destination_cpe.id),
                "sector_id": str(destination_sector.id),
            },
            before_summary=service_before,
            after_summary={
                "cpe_device_id": str(service.cpe_device_id),
                "sector_id": str(service.sector_id),
            },
        )
    memberships_removed = await reconcile_physical_move_memberships(db, [access_point.id])
    await record_audit(
        db,
        action="AP_REASSIGNED",
        entity_type="Device",
        entity_id=access_point.id,
        description="Access point reassigned through its authoritative CPE_ACCESS_POINT parent link.",
        entity_display_snapshot=display_snapshot(access_point),
        metadata={
            "old_cpe_device_id": str(source_cpe.id),
            "new_cpe_device_id": str(destination_cpe.id),
            "new_sector_id": str(destination_sector.id),
            "memberships_removed": memberships_removed,
        },
        before_summary={"cpe_device_id": str(source_cpe.id)},
        after_summary={
            "cpe_device_id": str(destination_cpe.id),
            "sector_id": str(destination_sector.id),
        },
    )
    await db.flush()
    return access_point
