"""Authoritative, paged option sources for physical assignment workflows.

These endpoints intentionally centralize the eligibility rules shared by
Candidate Review, New Device, Existing Device editing, Customer services and
other operator-facing selectors.  Search only narrows the eligible universe;
it never defines eligibility.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from ..deps import get_db
from ...models import City, Device, DeviceHierarchyLink, DeviceIP, DeviceType, Location, Network, Sector
from ...schemas.assignment import AssignmentOptionRead
from ...schemas.pagination import PageResult
from ...security.authorization import authorize_request
from ...security.resource_scope import scope_for_actor
from ...security.scope_queries import device_scope_clause, location_scope_clause, sector_scope_clause

router = APIRouter(
    prefix="/assignment-options",
    tags=["Assignment Options"],
    dependencies=[Depends(authorize_request)],
)


def _pattern(search: str | None) -> str | None:
    value = (search or "").strip()
    return f"%{value}%" if value else None


def _page(items, total: int, page: int, page_size: int):
    return PageResult(items=items, total=total, page=page, page_size=page_size)


@router.get("/locations", response_model=PageResult[AssignmentOptionRead])
async def eligible_locations(
    search: str | None = Query(None, max_length=200),
    selected_id: UUID | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    filters = [
        Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None),
        location_scope_clause(scope),
        Location.status == "ACTIVE", City.status == "ACTIVE", Network.status == "ACTIVE",
    ]
    pattern = _pattern(search)
    if pattern:
        filters.append(or_(Location.name.ilike(pattern), Location.code.ilike(pattern), City.name.ilike(pattern), Network.name.ilike(pattern)))
    stmt = (
        select(Location, City, Network)
        .join(City, City.id == Location.city_id)
        .join(Network, Network.id == City.network_id)
        .where(*filters)
    )
    total = int((await db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery()))) or 0)
    rows = (await db.execute(stmt.order_by(Network.name, City.name, Location.name, Location.id).offset((page - 1) * page_size).limit(page_size))).all()
    items = [AssignmentOptionRead(
        id=location.id,
        label=location.name,
        description=f"{city.name} / {network.name}",
        network_id=network.id, network_name=network.name,
        city_id=city.id, city_name=city.name,
        location_id=location.id, location_name=location.name,
    ) for location, city, network in rows]
    if selected_id is not None and not any(item.id == selected_id for item in items):
        row = (await db.execute(
            select(Location, City, Network)
            .join(City, City.id == Location.city_id)
            .join(Network, Network.id == City.network_id)
            .where(Location.id == selected_id, Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None), location_scope_clause(scope))
        )).first()
        if row:
            location, city, network = row
            items.insert(0, AssignmentOptionRead(
                id=location.id, label=location.name, description=f"{city.name} / {network.name}",
                network_id=network.id, network_name=network.name, city_id=city.id, city_name=city.name,
                location_id=location.id, location_name=location.name,
            ))
    return _page(items, total, page, page_size)


@router.get("/logical-sectors", response_model=PageResult[AssignmentOptionRead])
async def eligible_logical_sectors(
    search: str | None = Query(None, max_length=200),
    selected_id: UUID | None = None,
    current_sector_device_id: UUID | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    filters = [
        Sector.deleted_at.is_(None), sector_scope_clause(scope), Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None),
        Sector.status == "ACTIVE", Location.status == "ACTIVE", City.status == "ACTIVE", Network.status == "ACTIVE",
        or_(Sector.sector_device_id.is_(None), Sector.sector_device_id == current_sector_device_id),
    ]
    pattern = _pattern(search)
    if pattern:
        filters.append(or_(Sector.name.ilike(pattern), Sector.code.ilike(pattern), Location.name.ilike(pattern), City.name.ilike(pattern), Network.name.ilike(pattern)))
    stmt = (
        select(Sector, Location, City, Network)
        .join(Location, Location.id == Sector.location_id)
        .join(City, City.id == Location.city_id)
        .join(Network, Network.id == City.network_id)
        .where(*filters)
    )
    total = int((await db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery()))) or 0)
    rows = (await db.execute(stmt.order_by(Network.name, City.name, Location.name, Sector.sequence_number.nullslast(), Sector.name, Sector.id).offset((page - 1) * page_size).limit(page_size))).all()
    items = [AssignmentOptionRead(
        id=sector.id,
        label=sector.name,
        description=f"{sector.role.replace('_', ' ').title()} · {location.name} / {city.name} / {network.name}",
        network_id=network.id, network_name=network.name,
        city_id=city.id, city_name=city.name,
        location_id=location.id, location_name=location.name,
        logical_sector_id=sector.id, logical_sector_name=sector.name, sector_role=sector.role,
        physical_sector_device_id=sector.sector_device_id,
    ) for sector, location, city, network in rows]
    if selected_id is not None and not any(item.id == selected_id for item in items):
        row = (await db.execute(
            select(Sector, Location, City, Network)
            .join(Location, Location.id == Sector.location_id).join(City, City.id == Location.city_id).join(Network, Network.id == City.network_id)
            .where(Sector.id == selected_id, Sector.deleted_at.is_(None), Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None), sector_scope_clause(scope))
        )).first()
        if row:
            sector, location, city, network = row
            items.insert(0, AssignmentOptionRead(
                id=sector.id, label=sector.name,
                description=f"{sector.role.replace('_', ' ').title()} · {location.name} / {city.name} / {network.name}",
                network_id=network.id, network_name=network.name, city_id=city.id, city_name=city.name,
                location_id=location.id, location_name=location.name, logical_sector_id=sector.id,
                logical_sector_name=sector.name, sector_role=sector.role, physical_sector_device_id=sector.sector_device_id,
            ))
    return _page(items, total, page, page_size)


@router.get("/parent-devices", response_model=PageResult[AssignmentOptionRead])
async def eligible_parent_devices(
    child_type: str = Query(..., pattern="^(CPE|ACCESS_POINT)$"),
    search: str | None = Query(None, max_length=200),
    selected_id: UUID | None = None,
    current_child_device_id: UUID | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    management_ip = (
        select(DeviceIP.ip_address)
        .where(DeviceIP.device_id == Device.id, DeviceIP.deleted_at.is_(None))
        .order_by(DeviceIP.is_management.desc(), DeviceIP.is_primary.desc(), DeviceIP.id)
        .limit(1).scalar_subquery()
    )
    pattern = _pattern(search)

    if child_type == "CPE":
        stmt = (
            select(Device, management_ip.label("management_ip"), Sector, Location, City, Network)
            .join(DeviceType, DeviceType.id == Device.device_type_id)
            .join(Sector, Sector.sector_device_id == Device.id)
            .join(Location, Location.id == Sector.location_id)
            .join(City, City.id == Location.city_id)
            .join(Network, Network.id == City.network_id)
            .where(
                DeviceType.code == "SECTOR", Device.deleted_at.is_(None), Device.lifecycle_state != "DECOMMISSIONED",
                Sector.deleted_at.is_(None), Sector.status == "ACTIVE", Sector.role == "CUSTOMER_ACCESS", sector_scope_clause(scope),
                Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None),
                Location.status == "ACTIVE", City.status == "ACTIVE", Network.status == "ACTIVE",
            )
        )
        if pattern:
            stmt = stmt.where(or_(Device.display_name.ilike(pattern), management_ip.ilike(pattern), Sector.name.ilike(pattern), Location.name.ilike(pattern), City.name.ilike(pattern), Network.name.ilike(pattern)))
        total = int((await db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery()))) or 0)
        rows = (await db.execute(stmt.order_by(Device.display_name, Device.id).offset((page - 1) * page_size).limit(page_size))).all()
        items = [AssignmentOptionRead(
            id=device.id, label=device.display_name,
            description=" · ".join(filter(None, [ip, sector.name, location.name, city.name, network.name])),
            network_id=network.id, network_name=network.name, city_id=city.id, city_name=city.name,
            location_id=location.id, location_name=location.name, logical_sector_id=sector.id,
            logical_sector_name=sector.name, sector_role=sector.role,
            physical_sector_device_id=device.id, physical_sector_device_name=device.display_name,
            management_ip=ip, device_type_code="SECTOR",
        ) for device, ip, sector, location, city, network in rows]
    else:
        SectorDevice = aliased(Device)
        SectorType = aliased(DeviceType)
        SectorLink = aliased(DeviceHierarchyLink)
        ApLink = aliased(DeviceHierarchyLink)
        stmt = (
            select(Device, management_ip.label("management_ip"), SectorDevice, Sector, Location, City, Network)
            .join(DeviceType, DeviceType.id == Device.device_type_id)
            .join(SectorLink, and_(SectorLink.child_device_id == Device.id, SectorLink.relationship_type == "SECTOR_CPE", SectorLink.deleted_at.is_(None)))
            .join(SectorDevice, SectorDevice.id == SectorLink.parent_device_id)
            .join(SectorType, SectorType.id == SectorDevice.device_type_id)
            .join(Sector, Sector.sector_device_id == SectorDevice.id)
            .join(Location, Location.id == Sector.location_id)
            .join(City, City.id == Location.city_id)
            .join(Network, Network.id == City.network_id)
            .where(
                DeviceType.code == "CPE", Device.deleted_at.is_(None), Device.lifecycle_state != "DECOMMISSIONED",
                SectorType.code == "SECTOR", SectorDevice.deleted_at.is_(None), SectorDevice.lifecycle_state != "DECOMMISSIONED",
                Sector.deleted_at.is_(None), Sector.status == "ACTIVE", Sector.role == "CUSTOMER_ACCESS", sector_scope_clause(scope),
                Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None),
                Location.status == "ACTIVE", City.status == "ACTIVE", Network.status == "ACTIVE",
            )
        )
        existing_ap = select(ApLink.id).where(
            ApLink.parent_device_id == Device.id,
            ApLink.relationship_type == "CPE_ACCESS_POINT",
            ApLink.deleted_at.is_(None),
        )
        if current_child_device_id is not None:
            existing_ap = existing_ap.where(ApLink.child_device_id != current_child_device_id)
        stmt = stmt.where(~existing_ap.exists())
        if pattern:
            stmt = stmt.where(or_(Device.display_name.ilike(pattern), management_ip.ilike(pattern), SectorDevice.display_name.ilike(pattern), Sector.name.ilike(pattern), Location.name.ilike(pattern), City.name.ilike(pattern), Network.name.ilike(pattern)))
        total = int((await db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery()))) or 0)
        rows = (await db.execute(stmt.order_by(Device.display_name, Device.id).offset((page - 1) * page_size).limit(page_size))).all()
        items = [AssignmentOptionRead(
            id=device.id, label=device.display_name,
            description=" · ".join(filter(None, [ip, sector_device.display_name, location.name, city.name, network.name])),
            network_id=network.id, network_name=network.name, city_id=city.id, city_name=city.name,
            location_id=location.id, location_name=location.name, logical_sector_id=sector.id,
            logical_sector_name=sector.name, sector_role=sector.role,
            physical_sector_device_id=sector_device.id, physical_sector_device_name=sector_device.display_name,
            management_ip=ip, device_type_code="CPE",
        ) for device, ip, sector_device, sector, location, city, network in rows]

    # A selected/current value remains displayable even if it has since become
    # ineligible; the mutation endpoint still revalidates before saving.
    if selected_id is not None and not any(item.id == selected_id for item in items):
        selected_clause = await device_scope_clause(db, scope, device_col=Device.id)
        device = await db.scalar(select(Device).where(Device.id == selected_id, Device.deleted_at.is_(None), selected_clause))
        if device is not None:
            items.insert(0, AssignmentOptionRead(id=device.id, label=device.display_name, description="Current assignment"))
    return _page(items, total, page, page_size)




@router.get("/physical-sectors", response_model=PageResult[AssignmentOptionRead])
async def physical_sector_options(
    search: str | None = Query(None, max_length=200),
    network_id: UUID | None = None,
    city_id: UUID | None = None,
    location_id: UUID | None = None,
    selected_id: UUID | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    """Browse all existing physical SECTOR devices for filtering/display.

    Unlike CPE-parent eligibility this endpoint intentionally includes both
    CUSTOMER_ACCESS and BACKHAUL roles and decommissioned devices so historical
    inventory filters remain complete. Recycled objects are never returned.
    """
    scope = await scope_for_actor(db, actor)
    stmt = (
        select(Device, Sector, Location, City, Network)
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .join(Sector, Sector.sector_device_id == Device.id)
        .join(Location, Location.id == Sector.location_id)
        .join(City, City.id == Location.city_id)
        .join(Network, Network.id == City.network_id)
        .where(
            DeviceType.code == "SECTOR",
            Device.deleted_at.is_(None),
            Sector.deleted_at.is_(None), sector_scope_clause(scope),
            Location.deleted_at.is_(None),
            City.deleted_at.is_(None),
            Network.deleted_at.is_(None),
        )
    )
    if network_id is not None:
        stmt = stmt.where(Network.id == network_id)
    if city_id is not None:
        stmt = stmt.where(City.id == city_id)
    if location_id is not None:
        stmt = stmt.where(Location.id == location_id)
    pattern = _pattern(search)
    if pattern:
        stmt = stmt.where(or_(
            Device.display_name.ilike(pattern), Sector.name.ilike(pattern), Sector.code.ilike(pattern),
            Location.name.ilike(pattern), City.name.ilike(pattern), Network.name.ilike(pattern),
        ))
    total = int((await db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery()))) or 0)
    rows = (await db.execute(
        stmt.order_by(Device.display_name, Device.id).offset((page - 1) * page_size).limit(page_size)
    )).all()
    items = [AssignmentOptionRead(
        id=device.id, label=device.display_name,
        description=f"{sector.role.replace('_', ' ').title()} · {location.name} / {city.name} / {network.name}",
        network_id=network.id, network_name=network.name, city_id=city.id, city_name=city.name,
        location_id=location.id, location_name=location.name, logical_sector_id=sector.id,
        logical_sector_name=sector.name, sector_role=sector.role,
        physical_sector_device_id=device.id, physical_sector_device_name=device.display_name,
        device_type_code="SECTOR",
    ) for device, sector, location, city, network in rows]
    if selected_id is not None and not any(item.id == selected_id for item in items):
        row = (await db.execute(
            select(Device, Sector, Location, City, Network)
            .join(Sector, Sector.sector_device_id == Device.id)
            .join(Location, Location.id == Sector.location_id)
            .join(City, City.id == Location.city_id)
            .join(Network, Network.id == City.network_id)
            .where(Device.id == selected_id, Device.deleted_at.is_(None), Sector.deleted_at.is_(None), sector_scope_clause(scope))
        )).first()
        if row:
            device, sector, location, city, network = row
            items.insert(0, AssignmentOptionRead(
                id=device.id, label=device.display_name,
                description=f"{sector.role.replace('_', ' ').title()} · {location.name} / {city.name} / {network.name}",
                network_id=network.id, network_name=network.name, city_id=city.id, city_name=city.name,
                location_id=location.id, location_name=location.name, logical_sector_id=sector.id,
                logical_sector_name=sector.name, sector_role=sector.role,
                physical_sector_device_id=device.id, physical_sector_device_name=device.display_name,
                device_type_code="SECTOR",
            ))
    return _page(items, total, page, page_size)


@router.get("/sectors", response_model=PageResult[AssignmentOptionRead])
async def sector_display_options(
    search: str | None = Query(None, max_length=200),
    location_id: UUID | None = None,
    bound_only: bool = False,
    selected_id: UUID | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    """Sector selector labels use the bound physical device name when present."""
    scope = await scope_for_actor(db, actor)
    Physical = aliased(Device)
    stmt = (
        select(Sector, Physical, Location, City, Network)
        .join(Location, Location.id == Sector.location_id)
        .join(City, City.id == Location.city_id)
        .join(Network, Network.id == City.network_id)
        .outerjoin(Physical, and_(Physical.id == Sector.sector_device_id, Physical.deleted_at.is_(None)))
        .where(
            Sector.deleted_at.is_(None), sector_scope_clause(scope), Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None),
            Sector.status == "ACTIVE", Location.status == "ACTIVE", City.status == "ACTIVE", Network.status == "ACTIVE",
        )
    )
    if location_id is not None:
        stmt = stmt.where(Sector.location_id == location_id)
    if bound_only:
        stmt = stmt.where(Sector.sector_device_id.is_not(None), Physical.id.is_not(None))
    label_expr = func.coalesce(Physical.display_name, Sector.name)
    pattern = _pattern(search)
    if pattern:
        stmt = stmt.where(or_(
            label_expr.ilike(pattern), Sector.name.ilike(pattern), Sector.code.ilike(pattern),
            Location.name.ilike(pattern), City.name.ilike(pattern), Network.name.ilike(pattern),
        ))
    total = int((await db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery()))) or 0)
    rows = (await db.execute(
        stmt.order_by(label_expr, Sector.id).offset((page - 1) * page_size).limit(page_size)
    )).all()
    items = [AssignmentOptionRead(
        id=sector.id, label=(physical.display_name if physical is not None else sector.name),
        description=f"{sector.role.replace('_', ' ').title()} · {location.name} / {city.name} / {network.name}",
        network_id=network.id, network_name=network.name, city_id=city.id, city_name=city.name,
        location_id=location.id, location_name=location.name, logical_sector_id=sector.id,
        logical_sector_name=sector.name, sector_role=sector.role,
        physical_sector_device_id=physical.id if physical is not None else None,
        physical_sector_device_name=physical.display_name if physical is not None else None,
    ) for sector, physical, location, city, network in rows]
    if selected_id is not None and not any(item.id == selected_id for item in items):
        row = (await db.execute(
            select(Sector, Physical, Location, City, Network)
            .join(Location, Location.id == Sector.location_id)
            .join(City, City.id == Location.city_id)
            .join(Network, Network.id == City.network_id)
            .outerjoin(Physical, and_(Physical.id == Sector.sector_device_id, Physical.deleted_at.is_(None)))
            .where(Sector.id == selected_id, Sector.deleted_at.is_(None), sector_scope_clause(scope))
        )).first()
        if row:
            sector, physical, location, city, network = row
            items.insert(0, AssignmentOptionRead(
                id=sector.id, label=(physical.display_name if physical is not None else sector.name),
                description=f"{sector.role.replace('_', ' ').title()} · {location.name} / {city.name} / {network.name}",
                network_id=network.id, network_name=network.name, city_id=city.id, city_name=city.name,
                location_id=location.id, location_name=location.name, logical_sector_id=sector.id,
                logical_sector_name=sector.name, sector_role=sector.role,
                physical_sector_device_id=physical.id if physical is not None else None,
                physical_sector_device_name=physical.display_name if physical is not None else None,
            ))
    return _page(items, total, page, page_size)


@router.get("/customer-service-sectors", response_model=PageResult[AssignmentOptionRead])
async def customer_service_sectors(
    search: str | None = Query(None, max_length=200),
    selected_id: UUID | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    Physical = aliased(Device)
    stmt = (
        select(Sector, Physical, Location, City, Network)
        .join(Physical, Physical.id == Sector.sector_device_id)
        .join(Location, Location.id == Sector.location_id).join(City, City.id == Location.city_id).join(Network, Network.id == City.network_id)
        .where(
            Sector.role == "CUSTOMER_ACCESS", Sector.deleted_at.is_(None), Sector.status == "ACTIVE", sector_scope_clause(scope),
            Physical.deleted_at.is_(None), Physical.lifecycle_state != "DECOMMISSIONED",
            Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None),
            Location.status == "ACTIVE", City.status == "ACTIVE", Network.status == "ACTIVE",
        )
    )
    pattern = _pattern(search)
    if pattern:
        stmt = stmt.where(or_(Physical.display_name.ilike(pattern), Sector.name.ilike(pattern), Location.name.ilike(pattern), City.name.ilike(pattern), Network.name.ilike(pattern)))
    total = int((await db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery()))) or 0)
    rows = (await db.execute(stmt.order_by(Physical.display_name, Sector.id).offset((page - 1) * page_size).limit(page_size))).all()
    items = [AssignmentOptionRead(
        id=sector.id, label=physical.display_name,
        description=f"{location.name} / {city.name} / {network.name}",
        network_id=network.id, network_name=network.name, city_id=city.id, city_name=city.name,
        location_id=location.id, location_name=location.name, logical_sector_id=sector.id,
        logical_sector_name=sector.name, sector_role=sector.role,
        physical_sector_device_id=physical.id, physical_sector_device_name=physical.display_name,
    ) for sector, physical, location, city, network in rows]
    if selected_id is not None and not any(item.id == selected_id for item in items):
        row = (await db.execute(
            select(Sector, Physical, Location, City, Network)
            .join(Physical, Physical.id == Sector.sector_device_id)
            .join(Location, Location.id == Sector.location_id).join(City, City.id == Location.city_id).join(Network, Network.id == City.network_id)
            .where(Sector.id == selected_id, Sector.deleted_at.is_(None), Physical.deleted_at.is_(None), sector_scope_clause(scope))
        )).first()
        if row:
            sector, physical, location, city, network = row
            items.insert(0, AssignmentOptionRead(
                id=sector.id, label=physical.display_name, description=f"{location.name} / {city.name} / {network.name}",
                network_id=network.id, network_name=network.name, city_id=city.id, city_name=city.name,
                location_id=location.id, location_name=location.name, logical_sector_id=sector.id,
                logical_sector_name=sector.name, sector_role=sector.role,
                physical_sector_device_id=physical.id, physical_sector_device_name=physical.display_name,
            ))
    return _page(items, total, page, page_size)
