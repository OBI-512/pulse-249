from ipaddress import ip_address
import logging
from typing import Annotated
from uuid import UUID
import time

import httpx

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import String, and_, case, cast, exists, func, select, or_
from sqlalchemy.orm import aliased
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ..recycle_support import recycle_from_delete_endpoint
from ...security.authorization import authorize_request, user_has_permission
from ...security.resource_scope import scope_for_actor
from ...security.scope_queries import device_scope_clause, require_group
from ...models import (
    Customer,
    CustomerService,
    Device,
    DeviceHierarchyLink,
    DeviceIP,
    DeviceInterface,
    DeviceType,
    DevicePlacement,
    Network,
    City,
    Location,
    Sector,
)
from ...schemas.device import (
    DeviceCreate,
    DeviceIPCreate,
    DeviceIPRead,
    DeviceIPUpdate,
    DeviceInterfaceCreate,
    DeviceInterfaceRead,
    DeviceInterfaceUpdate,
    DeviceRead,
    DeviceInventoryRead,
    DeviceManagementRead,
    DeviceVlanFilterOption,
    DeviceAccessibilityResponse,
    DeviceStatusUpdate,
    DeviceTypeRead,
    DeviceUpdate,
)
from ...services.audit import record_audit, record_failure_audit
from ...core.audit_context import get_audit_context
from ...core.exceptions import APIError
from ...security.permissions import Permission as PermissionCode
from ...services.audit_summaries import business_summary, changed_summary, display_snapshot
from ...services.crud import get_active_for_update_or_404, get_or_404
from ...services.device_registration import register_domain_device
from ...services.device_ips import apply_ip_flags, ensure_ip_recycle_permitted
from ...services.hierarchy import HierarchyValidationError, resolve_effective_hierarchy
from ...services.movement import (
    MovementValidationError,
    move_cpe_to_sector,
    reassign_access_point,
    rebind_sector_device,
)
from ...services.placements import PlacementValidationError, update_device_placement
from ...schemas.device import LIFECYCLE_STATES
from ...services.groups import effective_group_device_ids
from ...services.group_effective import effective_group_context_subquery, effective_group_population_subquery
from ...schemas.pagination import PageResult


router = APIRouter()

def _inventory_search_filters(*, device_type_id=None, operational_state=None, lifecycle_state=None, vendor=None, management_protocol=None, search=None):
    filters = []
    if device_type_id:
        filters.append(Device.device_type_id == device_type_id)
    if operational_state:
        filters.append(Device.operational_state == operational_state)
    if lifecycle_state:
        filters.append(Device.lifecycle_state == lifecycle_state)
    if vendor:
        filters.append(Device.vendor.ilike(f"%{vendor}%"))
    if management_protocol:
        filters.append(Device.management_protocol == management_protocol)
    if search:
        pattern = f"%{search}%"
        ip_exists = select(DeviceIP.id).where(
            DeviceIP.device_id == Device.id, DeviceIP.ip_address.ilike(pattern)
        ).exists()
        filters.append(or_(
            Device.display_name.ilike(pattern), Device.hostname.ilike(pattern),
            Device.serial_number.ilike(pattern), ip_exists,
        ))
    return filters


def _sort_direction(expr, direction: str):
    return expr.desc() if direction.lower() == "desc" else expr.asc()



@router.get("/types", response_model=list[DeviceTypeRead])
async def list_device_types(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(DeviceType)
        .where(DeviceType.is_active.is_(True))
        .order_by(DeviceType.name)
    )
    return result.scalars().all()


@router.get("/operational-summary")
async def device_operational_summary(
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    scope_clause = await device_scope_clause(db, scope, device_col=Device.id)
    rows = (
        await db.execute(
            select(DeviceType.code, Device.operational_state, func.count(Device.id))
            .join(DeviceType, DeviceType.id == Device.device_type_id)
            .where(Device.deleted_at.is_(None), scope_clause)
            .group_by(DeviceType.code, Device.operational_state)
        )
    ).all()
    states = {"UP": 0, "DOWN": 0, "DEGRADED": 0, "UNKNOWN": 0}
    by_type: dict[str, dict[str, object]] = {}
    total = 0
    for raw_type, raw_state, raw_count in rows:
        count = int(raw_count or 0)
        state = (raw_state or "UNKNOWN").upper()
        if state not in states:
            state = "UNKNOWN"
        type_code = (raw_type or "OTHER").upper()
        type_summary = by_type.setdefault(
            type_code,
            {"total": 0, "states": {"UP": 0, "DOWN": 0, "DEGRADED": 0, "UNKNOWN": 0}},
        )
        type_summary["total"] = int(type_summary["total"]) + count
        type_states = type_summary["states"]
        assert isinstance(type_states, dict)
        type_states[state] = int(type_states[state]) + count
        states[state] += count
        total += count
    return {"total": total, "states": states, "by_type": by_type}


@router.get("/inventory/page", response_model=PageResult[DeviceInventoryRead])
async def list_device_inventory_page(
    db: AsyncSession = Depends(get_db),
    device_type_id: UUID | None = None,
    operational_state: str | None = None,
    lifecycle_state: str | None = None,
    vendor: str | None = None,
    management_protocol: str | None = None,
    search: str | None = Query(None, max_length=200),
    sort_by: str = Query("display_name", max_length=40),
    sort_direction: str = Query("asc", pattern="^(?i:asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    actor=Depends(authorize_request),
    *,
    service_vlan_id: Annotated[int | None, Query(ge=2, le=4094)] = None,
    customer_vlan_id: Annotated[int | None, Query(ge=2, le=4094)] = None,
):
    """Return the authorized inventory with effective VLAN context.

    S-VLAN is inherited from the effective City. C-VLAN is an allocated
    CustomerService VLAN for CPE/AP devices and the configured C-VLAN range
    for physical SECTOR devices. Independent device types have no C-VLAN.
    """
    scope = await scope_for_actor(db, actor)
    scope_clause = await device_scope_clause(db, scope, device_col=Device.id)
    context = effective_group_context_subquery()
    management_ip = (
        select(DeviceIP.ip_address)
        .where(DeviceIP.device_id == Device.id)
        .order_by(DeviceIP.is_management.desc(), DeviceIP.is_primary.desc(), DeviceIP.id)
        .limit(1).scalar_subquery()
    )
    filters = _inventory_search_filters(
        device_type_id=device_type_id, operational_state=operational_state,
        lifecycle_state=lifecycle_state, vendor=vendor,
        management_protocol=management_protocol, search=search,
    )
    effective_customer_vlan = case(
        (DeviceType.code == "SECTOR", Sector.customer_vlan_start),
        else_=CustomerService.customer_vlan_id,
    )
    stmt = (
        select(
            Device,
            management_ip.label("management_ip"),
            DeviceType.code.label("device_type_code"),
            City.service_vlan_id.label("service_vlan_id"),
            CustomerService.customer_vlan_id.label("customer_vlan_id"),
            Sector.customer_vlan_start.label("customer_vlan_start"),
            Sector.customer_vlan_end.label("customer_vlan_end"),
        )
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .outerjoin(context, context.c.device_id == Device.id)
        .outerjoin(City, City.id == context.c.city_id)
        .outerjoin(Sector, Sector.id == context.c.sector_id)
        .outerjoin(CustomerService, and_(
            CustomerService.deleted_at.is_(None),
            or_(CustomerService.cpe_device_id == Device.id, CustomerService.access_point_device_id == Device.id),
        ))
        .where(Device.deleted_at.is_(None), scope_clause, *filters)
    )
    if service_vlan_id is not None:
        stmt = stmt.where(City.service_vlan_id == service_vlan_id)
    if customer_vlan_id is not None:
        stmt = stmt.where(or_(
            and_(
                DeviceType.code.in_(["CPE", "ACCESS_POINT"]),
                CustomerService.customer_vlan_id == customer_vlan_id,
            ),
            and_(
                DeviceType.code == "SECTOR",
                Sector.customer_vlan_start.is_not(None),
                Sector.customer_vlan_end.is_not(None),
                Sector.customer_vlan_start <= customer_vlan_id,
                Sector.customer_vlan_end >= customer_vlan_id,
            ),
        ))

    count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())
    total = int((await db.scalar(count_stmt)) or 0)
    sort_map = {
        "display_name": Device.display_name, "type": DeviceType.name,
        "management_ip": management_ip, "lifecycle_state": Device.lifecycle_state,
        "operational_state": Device.operational_state, "vendor": Device.vendor,
        "service_vlan_id": City.service_vlan_id, "customer_vlan_id": effective_customer_vlan,
    }
    sort_expr = sort_map.get(sort_by)
    if sort_expr is None:
        raise HTTPException(422, detail={"code":"INVALID_DEVICE_SORT","message":"Unsupported device inventory sort column."})
    sort_clause = _sort_direction(sort_expr, sort_direction)
    if sort_by in {"service_vlan_id", "customer_vlan_id"}:
        sort_clause = sort_clause.nullslast()
    stmt = stmt.order_by(sort_clause, Device.id.asc()).offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(stmt)).all()

    items: list[DeviceInventoryRead] = []
    for device, ip, type_code, s_vlan, c_vlan, c_vlan_start, c_vlan_end in rows:
        c_vlan_display: str | None = None
        if type_code == "SECTOR" and c_vlan_start is not None and c_vlan_end is not None:
            c_vlan_display = f"{c_vlan_start}-{c_vlan_end}"
        elif type_code in {"CPE", "ACCESS_POINT"} and c_vlan is not None:
            c_vlan_display = str(c_vlan)
        items.append(DeviceInventoryRead.model_validate(device).model_copy(update={
            "management_ip": ip,
            "service_vlan_id": s_vlan,
            "customer_vlan_id": c_vlan,
            "customer_vlan_start": c_vlan_start,
            "customer_vlan_end": c_vlan_end,
            "customer_vlan_display": c_vlan_display,
        }))
    return PageResult(items=items, total=total, page=page, page_size=page_size)


@router.get("/inventory", response_model=list[DeviceInventoryRead])
async def list_device_inventory(
    db: AsyncSession = Depends(get_db),
    device_type_id: UUID | None = None,
    operational_state: str | None = None,
    lifecycle_state: str | None = None,
    vendor: str | None = None,
    management_protocol: str | None = None,
    search: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    scope_clause = await device_scope_clause(db, scope, device_col=Device.id)
    management_ip = (
        select(DeviceIP.ip_address)
        .where(DeviceIP.device_id == Device.id)
        .order_by(DeviceIP.is_management.desc(), DeviceIP.is_primary.desc(), DeviceIP.id)
        .limit(1)
        .scalar_subquery()
    )
    stmt = select(Device, management_ip.label("management_ip")).where(Device.deleted_at.is_(None), scope_clause).order_by(Device.display_name)

    if device_type_id:
        stmt = stmt.where(Device.device_type_id == device_type_id)
    if operational_state:
        stmt = stmt.where(Device.operational_state == operational_state)
    if lifecycle_state:
        stmt = stmt.where(Device.lifecycle_state == lifecycle_state)
    if vendor:
        stmt = stmt.where(Device.vendor.ilike(f"%{vendor}%"))
    if management_protocol:
        stmt = stmt.where(Device.management_protocol == management_protocol)
    if search:
        pattern = f"%{search}%"
        ip_exists = select(DeviceIP.id).where(
            DeviceIP.device_id == Device.id,
            DeviceIP.ip_address.ilike(pattern),
        ).exists()
        stmt = stmt.where(
            or_(
                Device.display_name.ilike(pattern),
                Device.hostname.ilike(pattern),
                Device.serial_number.ilike(pattern),
                ip_exists,
            )
        )

    result = await db.execute(stmt.offset(offset).limit(limit))
    return [
        DeviceInventoryRead.model_validate(device).model_copy(update={"management_ip": ip})
        for device, ip in result.all()
    ]



@router.get("/management/vlan-options", response_model=PageResult[DeviceVlanFilterOption])
async def list_device_management_vlan_options(
    kind: str = Query(..., pattern="^(service|customer)$"),
    network_id: UUID | None = None,
    city_id: UUID | None = None,
    location_id: UUID | None = None,
    sector_id: UUID | None = None,
    physical_sector_device_id: UUID | None = None,
    group_id: UUID | None = None,
    device_type_id: UUID | None = None,
    lifecycle_state: str | None = None,
    operational_state: str | None = None,
    service_vlan_id: Annotated[int | None, Query(ge=2, le=4094)] = None,
    customer_vlan_id: Annotated[int | None, Query(ge=2, le=4094)] = None,
    management_search: Annotated[str | None, Query(max_length=200)] = None,
    search: Annotated[str | None, Query(max_length=20)] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    """Return database-paginated VLAN options from authoritative effective context.

    S-VLAN is owned by City. C-VLAN candidates combine actual CustomerService
    allocations with configured physical-sector ranges. Group filtering uses a
    SQL effective-population subquery; device IDs are never materialized into
    the application process. The selector being populated is excluded from its
    own facet so an operator can replace it without clearing it first.
    """
    scope = await scope_for_actor(db, actor)
    scope_clause = await device_scope_clause(db, scope, device_col=Device.id)
    context = effective_group_context_subquery()
    management_ip = (
        select(DeviceIP.ip_address).where(DeviceIP.device_id == Device.id)
        .order_by(DeviceIP.is_management.desc(), DeviceIP.is_primary.desc(), DeviceIP.id)
        .limit(1).scalar_subquery()
    )
    base = (
        select(
            Device.id.label("device_id"),
            DeviceType.code.label("device_type_code"),
            context.c.network_id.label("network_id"),
            context.c.city_id.label("city_id"),
            context.c.location_id.label("location_id"),
            context.c.sector_id.label("sector_id"),
            City.service_vlan_id.label("service_vlan_id"),
            CustomerService.customer_vlan_id.label("customer_vlan_id"),
            Sector.customer_vlan_start.label("customer_vlan_start"),
            Sector.customer_vlan_end.label("customer_vlan_end"),
        )
        .select_from(Device)
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .outerjoin(context, context.c.device_id == Device.id)
        .outerjoin(City, City.id == context.c.city_id)
        .outerjoin(Sector, Sector.id == context.c.sector_id)
        .outerjoin(CustomerService, and_(
            CustomerService.deleted_at.is_(None),
            or_(CustomerService.cpe_device_id == Device.id, CustomerService.access_point_device_id == Device.id),
        ))
        .where(Device.deleted_at.is_(None), scope_clause)
    )
    if group_id is not None:
        actor_id = getattr(actor, "id", None)
        if actor_id is not None and not await user_has_permission(db, user_id=actor_id, permission_code=PermissionCode.GROUP_READ):
            raise HTTPException(403, detail={"code":"GROUP_FILTER_PERMISSION_DENIED","message":"group.read is required to filter by group."})
        await require_group(db, scope, group_id)
        population = await effective_group_population_subquery(db, group_id)
        base = base.where(exists(select(1).select_from(population).where(population.c.device_id == Device.id)))
    if network_id is not None: base = base.where(context.c.network_id == network_id)
    if city_id is not None: base = base.where(context.c.city_id == city_id)
    if location_id is not None: base = base.where(context.c.location_id == location_id)
    if sector_id is not None: base = base.where(context.c.sector_id == sector_id)
    if physical_sector_device_id is not None: base = base.where(Sector.sector_device_id == physical_sector_device_id)
    if device_type_id is not None: base = base.where(Device.device_type_id == device_type_id)
    if lifecycle_state: base = base.where(Device.lifecycle_state == lifecycle_state)
    if operational_state: base = base.where(Device.operational_state == operational_state)
    if management_search and management_search.strip():
        pattern = f"%{management_search.strip()}%"
        base = base.where(or_(Device.display_name.ilike(pattern), Device.hostname.ilike(pattern), management_ip.ilike(pattern)))
    if kind != "service" and service_vlan_id is not None:
        base = base.where(City.service_vlan_id == service_vlan_id)
    if kind != "customer" and customer_vlan_id is not None:
        base = base.where(or_(
            and_(DeviceType.code.in_(["CPE", "ACCESS_POINT"]), CustomerService.customer_vlan_id == customer_vlan_id),
            and_(DeviceType.code == "SECTOR", Sector.customer_vlan_start.is_not(None), Sector.customer_vlan_end.is_not(None), Sector.customer_vlan_start <= customer_vlan_id, Sector.customer_vlan_end >= customer_vlan_id),
        ))
    base = base.distinct().subquery("vlan_filter_base")

    if kind == "service":
        values = select(base.c.service_vlan_id.label("vlan")).where(base.c.service_vlan_id.is_not(None)).distinct().subquery("vlan_values")
    else:
        allocated = select(base.c.customer_vlan_id.label("vlan")).where(base.c.customer_vlan_id.is_not(None))
        series = select(func.generate_series(2, 4094).label("vlan")).subquery("vlan_series")
        ranged = select(series.c.vlan).where(exists(
            select(1).select_from(base).where(
                base.c.device_type_code == "SECTOR",
                base.c.customer_vlan_start.is_not(None),
                base.c.customer_vlan_end.is_not(None),
                base.c.customer_vlan_start <= series.c.vlan,
                base.c.customer_vlan_end >= series.c.vlan,
            )
        ))
        values = allocated.union(ranged).subquery("vlan_values")

    stmt = select(values.c.vlan).where(values.c.vlan.is_not(None))
    if search and search.strip():
        stmt = stmt.where(cast(values.c.vlan, String).ilike(f"%{search.strip()}%"))
    total = int((await db.scalar(select(func.count()).select_from(stmt.subquery()))) or 0)
    rows = (await db.scalars(stmt.order_by(values.c.vlan.asc()).offset((page - 1) * page_size).limit(page_size))).all()
    return PageResult(
        items=[DeviceVlanFilterOption(id=str(int(value)), label=str(int(value))) for value in rows],
        total=total, page=page, page_size=page_size,
    )


@router.get("/management/page", response_model=PageResult[DeviceManagementRead])
async def list_device_management_page(
    db: AsyncSession = Depends(get_db),
    network_id: UUID | None = None,
    city_id: UUID | None = None,
    location_id: UUID | None = None,
    physical_sector_device_id: UUID | None = None,
    group_id: UUID | None = None,
    device_id: UUID | None = None,
    device_type_id: UUID | None = None,
    sector_role: str | None = Query(None, pattern="^(CUSTOMER_ACCESS|BACKHAUL)$"),
    available_for_ap_parent: bool = False,
    ap_child_device_id: UUID | None = None,
    exclude_decommissioned: bool = False,
    lifecycle_state: str | None = None,
    operational_state: str | None = None,
    search: str | None = Query(None, max_length=200),
    sort_by: str = Query("display_name", max_length=50),
    sort_direction: str = Query("asc", pattern="^(?i:asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    actor=Depends(authorize_request),
    *,
    service_vlan_id: Annotated[int | None, Query(ge=2, le=4094)] = None,
    customer_vlan_id: Annotated[int | None, Query(ge=2, le=4094)] = None,
):
    scope = await scope_for_actor(db, actor)
    scope_clause = await device_scope_clause(db, scope, device_col=Device.id)
    management_ip = (select(DeviceIP.ip_address).where(DeviceIP.device_id == Device.id)
        .order_by(DeviceIP.is_management.desc(), DeviceIP.is_primary.desc(), DeviceIP.id).limit(1).scalar_subquery())
    ParentLink = aliased(DeviceHierarchyLink); GrandparentLink = aliased(DeviceHierarchyLink)
    parent_id = ParentLink.parent_device_id; grandparent_id = GrandparentLink.parent_device_id
    physical_sector_id = case(
        (DeviceType.code == "SECTOR", Device.id), (DeviceType.code == "CPE", parent_id),
        (DeviceType.code == "ACCESS_POINT", grandparent_id), else_=None,
    )
    ParentDevice = aliased(Device); PhysicalSectorDevice = aliased(Device)
    stmt = (select(
        Device, DeviceType.code.label("device_type_code"), management_ip.label("management_ip"),
        DevicePlacement.network_id, Network.name.label("network_name"), DevicePlacement.city_id, City.name.label("city_name"),
        DevicePlacement.location_id, Location.name.label("location_name"), DevicePlacement.sector_id, Sector.name.label("sector_name"), Sector.role.label("sector_role"),
        physical_sector_id.label("physical_sector_device_id"), PhysicalSectorDevice.display_name.label("physical_sector_device_name"),
        parent_id.label("parent_device_id"), ParentDevice.display_name.label("parent_device_name"),
        CustomerService.customer_id.label("customer_id"), Customer.name.label("customer_name"),
        City.service_vlan_id.label("service_vlan_id"), CustomerService.customer_vlan_id.label("customer_vlan_id"),
        Sector.customer_vlan_start.label("customer_vlan_start"), Sector.customer_vlan_end.label("customer_vlan_end"),
    ).join(DeviceType, DeviceType.id == Device.device_type_id)
      .outerjoin(ParentLink, and_(ParentLink.child_device_id == Device.id, ParentLink.deleted_at.is_(None), or_(
          and_(DeviceType.code == "CPE", ParentLink.relationship_type == "SECTOR_CPE"),
          and_(DeviceType.code == "ACCESS_POINT", ParentLink.relationship_type == "CPE_ACCESS_POINT"))))
      .outerjoin(GrandparentLink, and_(DeviceType.code == "ACCESS_POINT", GrandparentLink.child_device_id == ParentLink.parent_device_id,
          GrandparentLink.relationship_type == "SECTOR_CPE", GrandparentLink.deleted_at.is_(None)))
      .outerjoin(DevicePlacement, DevicePlacement.device_id == Device.id)
      .outerjoin(Network, Network.id == DevicePlacement.network_id).outerjoin(City, City.id == DevicePlacement.city_id)
      .outerjoin(Location, Location.id == DevicePlacement.location_id).outerjoin(Sector, Sector.id == DevicePlacement.sector_id)
      .outerjoin(ParentDevice, ParentDevice.id == parent_id).outerjoin(PhysicalSectorDevice, PhysicalSectorDevice.id == physical_sector_id)
      .outerjoin(CustomerService, and_(
          CustomerService.deleted_at.is_(None),
          or_(CustomerService.cpe_device_id == Device.id, CustomerService.access_point_device_id == Device.id),
      ))
      .outerjoin(Customer, and_(Customer.id == CustomerService.customer_id, Customer.deleted_at.is_(None)))
      .where(Device.deleted_at.is_(None), scope_clause))
    if group_id is not None:
        effective_ids = await effective_group_device_ids(db, group_id)
        if not effective_ids:
            return PageResult(items=[], total=0, page=page, page_size=page_size)
        stmt = stmt.where(Device.id.in_(effective_ids))
    if network_id is not None: stmt = stmt.where(DevicePlacement.network_id == network_id)
    if city_id is not None: stmt = stmt.where(DevicePlacement.city_id == city_id)
    if location_id is not None: stmt = stmt.where(DevicePlacement.location_id == location_id)
    if physical_sector_device_id is not None: stmt = stmt.where(physical_sector_id == physical_sector_device_id)
    if device_id is not None: stmt = stmt.where(Device.id == device_id)
    if device_type_id is not None: stmt = stmt.where(Device.device_type_id == device_type_id)
    if service_vlan_id is not None: stmt = stmt.where(City.service_vlan_id == service_vlan_id)
    if customer_vlan_id is not None:
        stmt = stmt.where(or_(
            and_(
                DeviceType.code.in_(["CPE", "ACCESS_POINT"]),
                CustomerService.customer_vlan_id == customer_vlan_id,
            ),
            and_(
                DeviceType.code == "SECTOR",
                Sector.customer_vlan_start.is_not(None),
                Sector.customer_vlan_end.is_not(None),
                Sector.customer_vlan_start <= customer_vlan_id,
                Sector.customer_vlan_end >= customer_vlan_id,
            ),
        ))
    if sector_role:
        stmt = stmt.where(
            Sector.role == sector_role,
            Sector.sector_device_id == Device.id,
            Sector.deleted_at.is_(None),
            Sector.status == "ACTIVE",
            Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None),
            Location.status == "ACTIVE", City.status == "ACTIVE", Network.status == "ACTIVE",
        )
    if available_for_ap_parent:
        existing_ap_filters = [
            DeviceHierarchyLink.parent_device_id == Device.id,
            DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
            DeviceHierarchyLink.deleted_at.is_(None),
        ]
        if ap_child_device_id is not None:
            existing_ap_filters.append(DeviceHierarchyLink.child_device_id != ap_child_device_id)
        existing_ap = select(DeviceHierarchyLink.id).where(*existing_ap_filters).exists()
        stmt = stmt.where(
            ~existing_ap,
            Sector.role == "CUSTOMER_ACCESS",
            Sector.deleted_at.is_(None), Sector.status == "ACTIVE",
            PhysicalSectorDevice.deleted_at.is_(None), PhysicalSectorDevice.lifecycle_state != "DECOMMISSIONED",
            Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None),
            Location.status == "ACTIVE", City.status == "ACTIVE", Network.status == "ACTIVE",
        )
    if exclude_decommissioned: stmt = stmt.where(Device.lifecycle_state != "DECOMMISSIONED")
    if lifecycle_state: stmt = stmt.where(Device.lifecycle_state == lifecycle_state)
    if operational_state: stmt = stmt.where(Device.operational_state == operational_state)
    if search:
        pattern = f"%{search}%"
        stmt = stmt.where(or_(Device.display_name.ilike(pattern), Device.hostname.ilike(pattern), management_ip.ilike(pattern)))
    count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())
    total = int((await db.scalar(count_stmt)) or 0)
    sort_map = {
        "display_name": Device.display_name, "device_type_code": DeviceType.code, "management_ip": management_ip,
        "network_name": Network.name, "city_name": City.name, "location_name": Location.name,
        "physical_sector_device_name": PhysicalSectorDevice.display_name, "service_vlan_id": City.service_vlan_id,
        "customer_vlan_id": CustomerService.customer_vlan_id, "lifecycle_state": Device.lifecycle_state,
        "operational_state": Device.operational_state,
    }
    sort_expr = sort_map.get(sort_by)
    if sort_expr is None:
        raise HTTPException(422, detail={"code":"INVALID_DEVICE_MANAGEMENT_SORT","message":"Unsupported device-management sort column."})
    stmt = stmt.order_by(_sort_direction(sort_expr, sort_direction).nullslast(), Device.id.asc()).offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(stmt)).all()
    items = [DeviceManagementRead(
        id=device.id, device_type_id=device.device_type_id, device_type_code=type_code, display_name=device.display_name,
        management_ip=ip, lifecycle_state=device.lifecycle_state, operational_state=device.operational_state, manual_degraded_override=bool(device.manual_degraded_override),
        network_id=network_id_value, network_name=network_name, city_id=city_id_value, city_name=city_name,
        location_id=location_id_value, location_name=location_name, sector_id=sector_id_value, sector_name=sector_name, sector_role=sector_role,
        physical_sector_device_id=physical_sector_device_id_value, physical_sector_device_name=physical_sector_device_name,
        parent_device_id=parent_device_id_value, parent_device_name=parent_device_name,
        customer_id=customer_id_value, customer_name=customer_name,
        service_vlan_id=service_vlan_id, customer_vlan_id=customer_vlan_id,
        customer_vlan_start=customer_vlan_start, customer_vlan_end=customer_vlan_end,
    ) for (device, type_code, ip, network_id_value, network_name, city_id_value, city_name, location_id_value, location_name,
           sector_id_value, sector_name, sector_role, physical_sector_device_id_value, physical_sector_device_name,
           parent_device_id_value, parent_device_name, customer_id_value, customer_name, service_vlan_id, customer_vlan_id,
           customer_vlan_start, customer_vlan_end) in rows]
    return PageResult(items=items, total=total, page=page, page_size=page_size)


@router.get("/management", response_model=list[DeviceManagementRead])
async def list_device_management(
    db: AsyncSession = Depends(get_db),
    network_id: UUID | None = None,
    city_id: UUID | None = None,
    location_id: UUID | None = None,
    physical_sector_device_id: UUID | None = None,
    group_id: UUID | None = None,
    device_type_id: UUID | None = None,
    lifecycle_state: str | None = None,
    operational_state: str | None = None,
    search: str | None = None,
    limit: int = Query(500, ge=1, le=500),
    offset: int = Query(0, ge=0),
    actor=Depends(authorize_request),
):
    """Return inventory rows enriched with effective physical context.

    Geography still comes from DevicePlacement, but the management-facing
    "Sector" is the physical SECTOR device in the authoritative hierarchy:
    SECTOR -> itself, CPE -> parent SECTOR device, AP -> parent CPE's SECTOR
    parent. Independent location devices do not have a physical sector.
    Group filtering uses effective membership, including nested child groups.
    """
    scope = await scope_for_actor(db, actor)
    scope_clause = await device_scope_clause(db, scope, device_col=Device.id)
    management_ip = (
        select(DeviceIP.ip_address)
        .where(DeviceIP.device_id == Device.id)
        .order_by(DeviceIP.is_management.desc(), DeviceIP.is_primary.desc(), DeviceIP.id)
        .limit(1)
        .scalar_subquery()
    )
    ParentLink = aliased(DeviceHierarchyLink)
    GrandparentLink = aliased(DeviceHierarchyLink)
    parent_id = ParentLink.parent_device_id
    grandparent_id = GrandparentLink.parent_device_id
    physical_sector_id = case(
        (DeviceType.code == "SECTOR", Device.id),
        (DeviceType.code == "CPE", parent_id),
        (DeviceType.code == "ACCESS_POINT", grandparent_id),
        else_=None,
    )
    ParentDevice = aliased(Device)
    PhysicalSectorDevice = aliased(Device)
    stmt = (
        select(
            Device, DeviceType.code.label("device_type_code"), management_ip.label("management_ip"),
            DevicePlacement.network_id, Network.name.label("network_name"),
            DevicePlacement.city_id, City.name.label("city_name"),
            DevicePlacement.location_id, Location.name.label("location_name"),
            DevicePlacement.sector_id, Sector.name.label("sector_name"), Sector.role.label("sector_role"),
            physical_sector_id.label("physical_sector_device_id"),
            PhysicalSectorDevice.display_name.label("physical_sector_device_name"),
            parent_id.label("parent_device_id"), ParentDevice.display_name.label("parent_device_name"),
            CustomerService.customer_id.label("customer_id"), Customer.name.label("customer_name"),
        City.service_vlan_id.label("service_vlan_id"), CustomerService.customer_vlan_id.label("customer_vlan_id"),
        )
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .outerjoin(
            ParentLink,
            and_(
                ParentLink.child_device_id == Device.id,
                ParentLink.deleted_at.is_(None),
                or_(
                    and_(DeviceType.code == "CPE", ParentLink.relationship_type == "SECTOR_CPE"),
                    and_(DeviceType.code == "ACCESS_POINT", ParentLink.relationship_type == "CPE_ACCESS_POINT"),
                ),
            ),
        )
        .outerjoin(
            GrandparentLink,
            and_(
                DeviceType.code == "ACCESS_POINT",
                GrandparentLink.child_device_id == ParentLink.parent_device_id,
                GrandparentLink.relationship_type == "SECTOR_CPE",
                GrandparentLink.deleted_at.is_(None),
            ),
        )
        .outerjoin(DevicePlacement, DevicePlacement.device_id == Device.id)
        .outerjoin(Network, Network.id == DevicePlacement.network_id)
        .outerjoin(City, City.id == DevicePlacement.city_id)
        .outerjoin(Location, Location.id == DevicePlacement.location_id)
        .outerjoin(Sector, Sector.id == DevicePlacement.sector_id)
        .outerjoin(ParentDevice, ParentDevice.id == parent_id)
        .outerjoin(PhysicalSectorDevice, PhysicalSectorDevice.id == physical_sector_id)
        .outerjoin(CustomerService, and_(
            CustomerService.deleted_at.is_(None),
            or_(CustomerService.cpe_device_id == Device.id, CustomerService.access_point_device_id == Device.id),
        ))
        .outerjoin(Customer, and_(Customer.id == CustomerService.customer_id, Customer.deleted_at.is_(None)))
        .where(Device.deleted_at.is_(None), scope_clause)
        .order_by(
            Network.name.nullslast(), City.name.nullslast(), Location.name.nullslast(),
            PhysicalSectorDevice.display_name.nullslast(), Device.display_name,
        )
    )
    if group_id is not None:
        effective_ids = await effective_group_device_ids(db, group_id)
        if not effective_ids:
            return []
        stmt = stmt.where(Device.id.in_(effective_ids))
    if network_id is not None: stmt = stmt.where(DevicePlacement.network_id == network_id)
    if city_id is not None: stmt = stmt.where(DevicePlacement.city_id == city_id)
    if location_id is not None: stmt = stmt.where(DevicePlacement.location_id == location_id)
    if physical_sector_device_id is not None: stmt = stmt.where(physical_sector_id == physical_sector_device_id)
    if device_type_id is not None: stmt = stmt.where(Device.device_type_id == device_type_id)
    if lifecycle_state: stmt = stmt.where(Device.lifecycle_state == lifecycle_state)
    if operational_state: stmt = stmt.where(Device.operational_state == operational_state)
    if search:
        pattern = f"%{search}%"
        stmt = stmt.where(or_(Device.display_name.ilike(pattern), Device.hostname.ilike(pattern), management_ip.ilike(pattern)))

    rows = (await db.execute(stmt.offset(offset).limit(limit))).all()
    return [
        DeviceManagementRead(
            id=device.id, device_type_id=device.device_type_id, device_type_code=type_code,
            display_name=device.display_name, management_ip=ip, lifecycle_state=device.lifecycle_state,
            operational_state=device.operational_state, manual_degraded_override=bool(device.manual_degraded_override), network_id=network_id_value, network_name=network_name,
            city_id=city_id_value, city_name=city_name, location_id=location_id_value, location_name=location_name,
            sector_id=sector_id_value, sector_name=sector_name, sector_role=sector_role,
            physical_sector_device_id=physical_sector_device_id_value,
            physical_sector_device_name=physical_sector_device_name,
            parent_device_id=parent_device_id_value, parent_device_name=parent_device_name,
            customer_id=customer_id_value, customer_name=customer_name,
            service_vlan_id=service_vlan_id, customer_vlan_id=customer_vlan_id,
        )
        for (
            device, type_code, ip, network_id_value, network_name, city_id_value, city_name,
            location_id_value, location_name, sector_id_value, sector_name, sector_role,
            physical_sector_device_id_value, physical_sector_device_name, parent_device_id_value, parent_device_name,
            customer_id_value, customer_name, service_vlan_id, customer_vlan_id,
        ) in rows
    ]


@router.get("", response_model=list[DeviceRead])
async def list_devices(
    db: AsyncSession = Depends(get_db),
    device_type_id: UUID | None = None,
    operational_state: str | None = None,
    lifecycle_state: str | None = None,
    vendor: str | None = None,
    management_protocol: str | None = None,
    search: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    scope_clause = await device_scope_clause(db, scope, device_col=Device.id)
    stmt = select(Device).where(Device.deleted_at.is_(None), scope_clause).order_by(Device.display_name)

    if device_type_id:
        stmt = stmt.where(Device.device_type_id == device_type_id)
    if operational_state:
        stmt = stmt.where(Device.operational_state == operational_state)
    if lifecycle_state:
        stmt = stmt.where(Device.lifecycle_state == lifecycle_state)
    if vendor:
        stmt = stmt.where(Device.vendor.ilike(f"%{vendor}%"))
    if management_protocol:
        stmt = stmt.where(Device.management_protocol == management_protocol)
    if search:
        pattern = f"%{search}%"
        stmt = stmt.where(
            Device.display_name.ilike(pattern)
            | Device.hostname.ilike(pattern)
            | Device.serial_number.ilike(pattern)
        )

    result = await db.execute(stmt.offset(offset).limit(limit))
    return result.scalars().all()
