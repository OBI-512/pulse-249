from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .audit import record_audit
from .audit_summaries import business_summary, changed_summary, display_snapshot

from ..models import (
    City,
    Customer,
    CustomerService,
    Device,
    Location,
    Sector, DeviceType, DeviceHierarchyLink,
)
from .hierarchy import (
    HierarchyValidationError,
    resolve_effective_hierarchy,
    sector_for_sector_device,
)


class CustomerServiceValidationError(ValueError):
    """Raised when a CustomerService violates business rules."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


_CUSTOMER_VLAN_UNSET = object()


async def _derive_service_path(
    db: AsyncSession,
    *,
    customer_id: UUID,
    access_point_device_id: UUID,
    router_device_id: UUID | None,
) -> tuple[UUID, UUID]:
    """Return (sector_id, cpe_device_id) from the authoritative AP hierarchy."""

    customer = await db.scalar(select(Customer).where(Customer.id == customer_id, Customer.deleted_at.is_(None)).with_for_update())
    if customer is None:
        raise CustomerServiceValidationError("CUSTOMER_NOT_FOUND", "The customer does not exist.")

    endpoint_ids = {access_point_device_id}
    if router_device_id is not None:
        endpoint_ids.add(router_device_id)
    endpoints = {
        row.id: row for row in (
            await db.scalars(select(Device).where(Device.id.in_(endpoint_ids), Device.deleted_at.is_(None)).order_by(Device.id).with_for_update())
        ).all()
    }
    ap = endpoints.get(access_point_device_id)
    if ap is None:
        raise CustomerServiceValidationError("ACCESS_POINT_DEVICE_NOT_FOUND", "The access point device does not exist.")
    ap_type = await db.scalar(select(DeviceType.code).where(DeviceType.id == ap.device_type_id))
    if ap_type != "ACCESS_POINT":
        raise CustomerServiceValidationError("INVALID_ACCESS_POINT_TYPE", "The selected device is not an ACCESS_POINT.")

    ap_links = list((await db.scalars(
        select(DeviceHierarchyLink).where(
            DeviceHierarchyLink.child_device_id == ap.id,
            DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
            DeviceHierarchyLink.deleted_at.is_(None),
        ).with_for_update()
    )).all())
    if len(ap_links) != 1:
        raise CustomerServiceValidationError(
            "ACCESS_POINT_CPE_LINK_INVALID",
            "The selected access point must have exactly one authoritative CPE parent.",
        )
    cpe = await db.scalar(select(Device).where(Device.id == ap_links[0].parent_device_id, Device.deleted_at.is_(None)).with_for_update())
    if cpe is None:
        raise CustomerServiceValidationError("CPE_DEVICE_NOT_FOUND", "The access point's CPE does not exist.")
    cpe_type = await db.scalar(select(DeviceType.code).where(DeviceType.id == cpe.device_type_id))
    if cpe_type != "CPE":
        raise CustomerServiceValidationError("INVALID_CPE_TYPE", "The access point parent is not a CPE.")

    cpe_links = list((await db.scalars(
        select(DeviceHierarchyLink).where(
            DeviceHierarchyLink.child_device_id == cpe.id,
            DeviceHierarchyLink.relationship_type == "SECTOR_CPE",
            DeviceHierarchyLink.deleted_at.is_(None),
        )
    )).all())
    if len(cpe_links) != 1:
        raise CustomerServiceValidationError(
            "CPE_SECTOR_LINK_INVALID",
            "The derived CPE must have exactly one authoritative SECTOR parent.",
        )
    sector_device = await db.scalar(select(Device).where(Device.id == cpe_links[0].parent_device_id, Device.deleted_at.is_(None)).with_for_update())
    if sector_device is None:
        raise CustomerServiceValidationError("CPE_SECTOR_PARENT_MISSING", "The CPE sector parent does not exist.")
    try:
        sector = await sector_for_sector_device(db, sector_device.id)
        ap_hierarchy = await resolve_effective_hierarchy(db, ap)
    except HierarchyValidationError as exc:
        raise CustomerServiceValidationError(exc.code, exc.message) from exc
    locked_sector = await db.scalar(
        select(Sector).where(Sector.id == sector.id, Sector.deleted_at.is_(None)).with_for_update()
    )
    if locked_sector is None:
        raise CustomerServiceValidationError("SECTOR_NOT_FOUND", "The derived service sector does not exist.")
    sector = locked_sector
    if sector.role == "BACKHAUL":
        raise CustomerServiceValidationError("BACKHAUL_SECTOR_NOT_CUSTOMER_SERVING", "Backhaul sectors cannot serve customers.")
    if ap_hierarchy.sector_id != sector.id:
        raise CustomerServiceValidationError("ACCESS_POINT_SECTOR_MISMATCH", "The access point hierarchy does not resolve to the derived sector.")

    if router_device_id is not None:
        router = endpoints.get(router_device_id)
        if router is None:
            raise CustomerServiceValidationError("ROUTER_DEVICE_NOT_FOUND", "The router device does not exist.")
        router_type = await db.scalar(select(DeviceType.code).where(DeviceType.id == router.device_type_id))
        if router_type != "ROUTER":
            raise CustomerServiceValidationError("INVALID_ROUTER_TYPE", "The selected router endpoint must be a ROUTER device.")

    if access_point_device_id == cpe.id or router_device_id in {access_point_device_id, cpe.id}:
        raise CustomerServiceValidationError("SERVICE_ENDPOINT_CONFLICT", "Customer-service endpoints cannot reference the same device.")
    return sector.id, cpe.id


async def _validate_customer_vlan(
    db: AsyncSession,
    *,
    sector_id: UUID,
    customer_vlan_id: int | None,
    exclude_service_id: UUID | None = None,
) -> int:
    if customer_vlan_id is None:
        raise CustomerServiceValidationError("CUSTOMER_VLAN_REQUIRED", "Customer VLAN is required for the customer service.")
    if customer_vlan_id < 2 or customer_vlan_id > 4094:
        raise CustomerServiceValidationError("CUSTOMER_VLAN_OUT_OF_RANGE", "Customer VLAN must be between 2 and 4094.")

    row = (await db.execute(
        select(Sector, Location.city_id)
        .join(Location, Location.id == Sector.location_id)
        .where(Sector.id == sector_id)
    )).first()
    if row is None:
        raise CustomerServiceValidationError("SECTOR_NOT_FOUND", "The derived service sector does not exist.")
    sector, city_id = row
    city = await db.scalar(select(City).where(City.id == city_id).with_for_update())
    if city is None:
        raise CustomerServiceValidationError("CITY_NOT_FOUND", "The service city does not exist.")
    if city.service_vlan_id is None:
        raise CustomerServiceValidationError("CITY_SERVICE_VLAN_NOT_CONFIGURED", "The service city does not have a Service VLAN configured.")
    if sector.customer_vlan_start is None or sector.customer_vlan_end is None:
        raise CustomerServiceValidationError("SECTOR_CUSTOMER_VLAN_RANGE_NOT_CONFIGURED", "The service sector does not have a Customer VLAN range configured.")
    if not (sector.customer_vlan_start <= customer_vlan_id <= sector.customer_vlan_end):
        raise CustomerServiceValidationError(
            "CUSTOMER_VLAN_OUTSIDE_SECTOR_RANGE",
            f"Customer VLAN must be within the sector range {sector.customer_vlan_start}-{sector.customer_vlan_end}.",
        )

    conflict_filters = [
        Location.city_id == city.id,
        CustomerService.customer_vlan_id == customer_vlan_id,
    ]
    if exclude_service_id is not None:
        conflict_filters.append(CustomerService.id != exclude_service_id)
    conflict = await db.scalar(
        select(CustomerService.id)
        .join(Sector, Sector.id == CustomerService.sector_id)
        .join(Location, Location.id == Sector.location_id)
        .where(*conflict_filters)
        .limit(1)
    )
    if conflict is not None:
        raise CustomerServiceValidationError(
            "CUSTOMER_VLAN_IN_USE_IN_CITY",
            "The Customer VLAN is already assigned or reserved by another customer service in this city.",
        )
    return city.service_vlan_id


async def _validate_service_references(
    db: AsyncSession,
    *,
    customer_id: UUID,
    sector_id: UUID,
    cpe_device_id: UUID,
    access_point_device_id: UUID,
    router_device_id: UUID | None,
) -> None:
    """Validate stored CustomerService references against authoritative AP topology."""
    derived_sector_id, derived_cpe_device_id = await _derive_service_path(
        db,
        customer_id=customer_id,
        access_point_device_id=access_point_device_id,
        router_device_id=router_device_id,
    )

    if cpe_device_id != derived_cpe_device_id:
        raise CustomerServiceValidationError(
            "CPE_AP_MISMATCH",
            "The stored CPE does not match the access point's authoritative CPE parent.",
        )

    if sector_id != derived_sector_id:
        raise CustomerServiceValidationError(
            "CPE_SECTOR_MISMATCH",
            "The stored sector does not match the access point's authoritative service sector.",
        )

async def create_customer_service(
    db: AsyncSession,
    *,
    customer_id: UUID,
    service_code: str,
    status: str,
    access_point_device_id: UUID,
    router_device_id: UUID | None,
    metadata: dict,
    customer_vlan_id: int | None = None,
    require_customer_vlan: bool = False,
    sector_id: UUID | None = None,
    cpe_device_id: UUID | None = None,
) -> CustomerService:
    """
    Create a CustomerService without mutating DeviceRelationship.

    CustomerService and DeviceRelationship are intentionally independent
    domains.
    """

    derived_sector_id, derived_cpe_device_id = await _derive_service_path(
        db,
        customer_id=customer_id,
        access_point_device_id=access_point_device_id,
        router_device_id=router_device_id,
    )
    # Backward-compatible service-layer arguments are accepted only so older
    # internal callers/tests fail closed instead of silently overriding the
    # AP-derived topology. The public API no longer exposes these inputs.
    if cpe_device_id is not None and cpe_device_id != derived_cpe_device_id:
        raise CustomerServiceValidationError(
            "CPE_AP_MISMATCH",
            "The supplied CPE does not match the access point's authoritative CPE parent.",
        )
    if sector_id is not None and sector_id != derived_sector_id:
        raise CustomerServiceValidationError(
            "CPE_SECTOR_MISMATCH",
            "The supplied sector does not match the access point's authoritative service sector.",
        )

    sector_id = derived_sector_id
    cpe_device_id = derived_cpe_device_id
    if customer_vlan_id is not None or require_customer_vlan:
        await _validate_customer_vlan(db, sector_id=sector_id, customer_vlan_id=customer_vlan_id)

    obj = CustomerService(
        customer_id=customer_id,
        sector_id=sector_id,
        service_code=service_code,
        status=status,
        cpe_device_id=cpe_device_id,
        access_point_device_id=access_point_device_id,
        router_device_id=router_device_id,
        customer_vlan_id=customer_vlan_id,
        metadata_=metadata,
    )

    db.add(obj)

    await db.flush()
    await record_audit(
        db,
        action="CUSTOMER_SERVICE_CREATED",
        entity_type="CustomerService",
        entity_id=obj.id,
        description="Customer service created.",
        entity_display_snapshot=display_snapshot(obj),
        after_summary=business_summary(obj),
    )
    await db.refresh(obj)

    return obj


async def update_customer_service(
    db: AsyncSession,
    obj: CustomerService,
    *,
    status: str,
    access_point_device_id: UUID,
    router_device_id: UUID | None,
    metadata: dict,
    customer_vlan_id: int | None | object = _CUSTOMER_VLAN_UNSET,
    sector_id: UUID | None = None,
    cpe_device_id: UUID | None = None,
) -> CustomerService:
    """
    Update a CustomerService without mutating DeviceRelationship.

    Customer identity remains immutable through this operation.
    """

    before = business_summary(obj)
    metadata_changed = obj.metadata_ != metadata

    derived_sector_id, derived_cpe_device_id = await _derive_service_path(
        db,
        customer_id=obj.customer_id,
        access_point_device_id=access_point_device_id,
        router_device_id=router_device_id,
    )
    if cpe_device_id is not None and cpe_device_id != derived_cpe_device_id:
        raise CustomerServiceValidationError(
            "CPE_AP_MISMATCH",
            "The supplied CPE does not match the access point's authoritative CPE parent.",
        )
    if sector_id is not None and sector_id != derived_sector_id:
        raise CustomerServiceValidationError(
            "CPE_SECTOR_MISMATCH",
            "The supplied sector does not match the access point's authoritative service sector.",
        )

    sector_id = derived_sector_id
    cpe_device_id = derived_cpe_device_id
    effective_customer_vlan_id = (
        obj.customer_vlan_id if customer_vlan_id is _CUSTOMER_VLAN_UNSET else customer_vlan_id
    )
    if effective_customer_vlan_id is not None:
        await _validate_customer_vlan(
            db,
            sector_id=sector_id,
            customer_vlan_id=effective_customer_vlan_id,
            exclude_service_id=obj.id,
        )

    obj.sector_id = sector_id
    obj.status = status
    obj.cpe_device_id = cpe_device_id
    obj.access_point_device_id = access_point_device_id
    obj.router_device_id = router_device_id
    obj.customer_vlan_id = effective_customer_vlan_id
    obj.metadata_ = metadata

    await db.flush()
    after = business_summary(obj)
    before_changes, after_changes, changed_fields = changed_summary(before, after)
    if changed_fields or metadata_changed:
        await record_audit(
            db,
            action="CUSTOMER_SERVICE_UPDATED",
            entity_type="CustomerService",
            entity_id=obj.id,
            description="Customer service updated.",
            entity_display_snapshot=display_snapshot(obj),
            metadata={
                "changed_fields": [
                    *changed_fields,
                    *(["metadata"] if metadata_changed else []),
                ]
            },
            before_summary=before_changes,
            after_summary=after_changes,
        )
    await db.refresh(obj)

    return obj
