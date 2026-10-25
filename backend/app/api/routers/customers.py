from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import String, and_, cast, func, or_, select
from sqlalchemy.orm import aliased
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ..recycle_support import recycle_from_delete_endpoint
from ...security.authorization import authorize_request, user_has_permission
from ...security.resource_scope import require_global_scope, scope_for_actor
from ...security.scope_queries import (
    customer_scope_clause, customer_service_scope_clause, device_scope_clause,
    require_customer, require_customer_service, require_device, require_group, require_sector,
    sector_scope_clause,
)
from ...models import City, Customer, CustomerService, Device, DeviceHierarchyLink, Location, Sector
from ...schemas.customer import (
    CustomerCreate,
    CustomerRead,
    CustomerListRead,
    CustomerFilterOption,
    CustomerUpdate,
    ServiceCreate,
    ServiceEndpointOption,
    ServiceRead,
    ServiceUpdate,
)
from ...services.crud import get_active_for_update_or_404, get_or_404
from ...services.audit import record_audit
from ...services.audit_summaries import business_summary, changed_summary, display_snapshot
from ...services.group_effective import effective_group_population_subquery
from ...security.permissions import Permission as PermissionCode
from ...schemas.pagination import PageResult
from ...services.customer_services import (
    CustomerServiceValidationError,
    create_customer_service,
    update_customer_service,
)


router = APIRouter(
    prefix="/customers",
    tags=["Customers"],
    dependencies=[Depends(authorize_request)],
)


async def _service_read(db: AsyncSession, service: CustomerService) -> ServiceRead:
    CPE = aliased(Device)
    AP = aliased(Device)
    PhysicalSector = aliased(Device)
    row = (await db.execute(
        select(
            func.coalesce(PhysicalSector.display_name, Sector.name).label("sector_name"),
            CPE.display_name.label("cpe_name"),
            AP.display_name.label("access_point_name"),
            City.service_vlan_id,
        )
        .select_from(Sector)
        .join(Location, Location.id == Sector.location_id)
        .join(City, City.id == Location.city_id)
        .outerjoin(PhysicalSector, PhysicalSector.id == Sector.sector_device_id)
        .join(CPE, CPE.id == service.cpe_device_id)
        .join(AP, AP.id == service.access_point_device_id)
        .where(Sector.id == service.sector_id)
    )).first()
    if row is None:
        return ServiceRead.model_validate(service)
    sector_name, cpe_name, access_point_name, service_vlan_id = row
    return ServiceRead.model_validate(service).model_copy(update={
        "sector_name": sector_name,
        "cpe_name": cpe_name,
        "access_point_name": access_point_name,
        "service_vlan_id": service_vlan_id,
    })


# ---------------------------------------------------------------------------
# Customers
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=list[CustomerRead],
)
async def list_customers(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    result = await db.execute(
        select(Customer)
        .where(Customer.deleted_at.is_(None), customer_scope_clause(scope))
        .offset(offset)
        .limit(limit)
    )

    return result.scalars().all()


@router.post(
    "",
    response_model=CustomerRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_customer(
    payload: CustomerCreate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await require_global_scope(db, actor, message="Global resource scope is required to create an unanchored customer.")
    data = payload.model_dump()

    data["metadata_"] = data.pop("metadata")

    obj = Customer(**data)

    db.add(obj)

    await db.flush()
    await record_audit(
        db,
        action="CUSTOMER_CREATED",
        entity_type="Customer",
        entity_id=obj.id,
        description="Customer created.",
        entity_display_snapshot=display_snapshot(obj),
        after_summary=business_summary(obj),
    )

    await db.commit()
    await db.refresh(obj)

    return obj


@router.get("/page", response_model=PageResult[CustomerListRead])
async def list_customer_page(
    search: str | None = Query(None, max_length=200),
    customer_name: str | None = Query(None, max_length=200),
    service_code: str | None = Query(None, max_length=100),
    sector_id: UUID | None = None,
    status_filter: str | None = Query(None, alias="status", max_length=40),
    sort_by: str = Query("name", max_length=40),
    sort_direction: str = Query("asc", pattern="^(?i:asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
    *,
    service_vlan_id: Annotated[int | None, Query(ge=2, le=4094)] = None,
    customer_vlan_id: Annotated[int | None, Query(ge=2, le=4094)] = None,
):
    scope = await scope_for_actor(db, actor)
    Service = aliased(CustomerService)
    PhysicalSector = aliased(Device)
    sector_display = func.coalesce(PhysicalSector.display_name, Sector.name)
    service_join = and_(Service.customer_id == Customer.id, Service.deleted_at.is_(None))
    sector_join = and_(Sector.id == Service.sector_id, Sector.deleted_at.is_(None))
    stmt = (select(Customer, Service.service_code, Service.sector_id, sector_display.label("sector_name"), City.service_vlan_id, Service.customer_vlan_id)
        .outerjoin(Service, service_join)
        .outerjoin(Sector, sector_join)
        .outerjoin(Location, Location.id == Sector.location_id)
        .outerjoin(City, City.id == Location.city_id)
        .outerjoin(PhysicalSector, and_(PhysicalSector.id == Sector.sector_device_id, PhysicalSector.deleted_at.is_(None))))
    filters = [Customer.deleted_at.is_(None), customer_scope_clause(scope)]
    if status_filter:
        filters.append(Customer.status == status_filter.upper())
    if customer_name:
        filters.append(Customer.name == customer_name)
    if service_code:
        filters.append(Service.service_code == service_code)
    if sector_id:
        filters.append(Service.sector_id == sector_id)
    if service_vlan_id is not None:
        filters.append(City.service_vlan_id == service_vlan_id)
    if customer_vlan_id is not None:
        filters.append(Service.customer_vlan_id == customer_vlan_id)
    if search:
        pattern = f"%{search.strip()}%"
        filters.append(or_(Customer.name.ilike(pattern), Customer.customer_code.ilike(pattern),
                           Service.service_code.ilike(pattern), Sector.name.ilike(pattern),
                           PhysicalSector.display_name.ilike(pattern)))
    stmt = stmt.where(*filters)
    count_stmt = (select(func.count(func.distinct(Customer.id))).select_from(Customer)
        .outerjoin(Service, service_join).outerjoin(Sector, sector_join)
        .outerjoin(Location, Location.id == Sector.location_id).outerjoin(City, City.id == Location.city_id)
        .outerjoin(PhysicalSector, and_(PhysicalSector.id == Sector.sector_device_id, PhysicalSector.deleted_at.is_(None)))
        .where(*filters))
    total = int((await db.scalar(count_stmt)) or 0)
    sort_map = {"name": Customer.name, "service_code": Service.service_code, "sector_name": sector_display,
                "service_vlan_id": City.service_vlan_id, "customer_vlan_id": Service.customer_vlan_id,
                "customer_code": Customer.customer_code, "status": Customer.status}
    expr = sort_map.get(sort_by)
    if expr is None:
        raise HTTPException(422, detail={"code":"INVALID_CUSTOMER_SORT","message":"Unsupported customer sort column."})
    order = expr.desc() if sort_direction.lower() == "desc" else expr.asc()
    rows = (await db.execute(stmt.order_by(order.nullslast(), Customer.id.asc())
        .offset((page - 1) * page_size).limit(page_size))).all()
    items = [CustomerListRead.model_validate(customer).model_copy(update={
        "service_code": row_service_code, "sector_id": row_sector_id, "sector_name": sector_name,
        "service_vlan_id": service_vlan_id, "customer_vlan_id": customer_vlan_id,
    }) for customer, row_service_code, row_sector_id, sector_name, service_vlan_id, customer_vlan_id in rows]
    return PageResult(items=items, total=total, page=page, page_size=page_size)


@router.get("/filter-options/{kind}", response_model=PageResult[CustomerFilterOption])
async def customer_filter_options(
    kind: str,
    search: str | None = Query(None, max_length=200),
    selected_id: str | None = Query(None, max_length=200),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
    *,
    customer_name: Annotated[str | None, Query(max_length=200)] = None,
    service_code: Annotated[str | None, Query(max_length=100)] = None,
    sector_id: Annotated[UUID | None, Query()] = None,
    service_vlan_id: Annotated[int | None, Query(ge=2, le=4094)] = None,
    customer_vlan_id: Annotated[int | None, Query(ge=2, le=4094)] = None,
    network_id: Annotated[UUID | None, Query()] = None,
    city_id: Annotated[UUID | None, Query()] = None,
    location_id: Annotated[UUID | None, Query()] = None,
    group_id: Annotated[UUID | None, Query()] = None,
):
    if kind not in {"customer-name", "service-id", "sector", "service-vlan", "customer-vlan"}:
        raise HTTPException(422, detail={"code":"INVALID_CUSTOMER_FILTER_KIND","message":"Unsupported customer filter option."})

    scope = await scope_for_actor(db, actor)
    PhysicalSector = aliased(Device)
    sector_label = func.coalesce(PhysicalSector.display_name, Sector.name)

    base = (
        select(
            Customer.name.label("customer_name"),
            CustomerService.service_code.label("service_code"),
            Sector.id.label("sector_id"),
            sector_label.label("sector_label"),
            Location.name.label("location_name"),
            City.service_vlan_id.label("service_vlan_id"),
            CustomerService.customer_vlan_id.label("customer_vlan_id"),
        )
        .select_from(Customer)
        .outerjoin(CustomerService, and_(
            CustomerService.customer_id == Customer.id,
            CustomerService.deleted_at.is_(None),
        ))
        .outerjoin(Sector, and_(Sector.id == CustomerService.sector_id, Sector.deleted_at.is_(None)))
        .outerjoin(Location, and_(Location.id == Sector.location_id, Location.deleted_at.is_(None)))
        .outerjoin(City, and_(City.id == Location.city_id, City.deleted_at.is_(None)))
        .outerjoin(PhysicalSector, and_(
            PhysicalSector.id == Sector.sector_device_id,
            PhysicalSector.deleted_at.is_(None),
        ))
        .where(Customer.deleted_at.is_(None), customer_scope_clause(scope))
    )

    if network_id is not None:
        base = base.where(City.network_id == network_id)
    if city_id is not None:
        base = base.where(City.id == city_id)
    if location_id is not None:
        base = base.where(Location.id == location_id)
    if group_id is not None:
        actor_id = getattr(actor, "id", None)
        if actor_id is not None and not await user_has_permission(db, user_id=actor_id, permission_code=PermissionCode.GROUP_READ):
            raise HTTPException(403, detail={"code":"GROUP_FILTER_PERMISSION_DENIED","message":"group.read is required to filter by group."})
        await require_group(db, scope, group_id)
        population = await effective_group_population_subquery(db, group_id)
        device_ids = select(population.c.device_id)
        base = base.where(or_(
            CustomerService.access_point_device_id.in_(device_ids),
            CustomerService.cpe_device_id.in_(device_ids),
        ))

    # Faceted selectors are constrained by every other active selector. The
    # selector being populated is intentionally excluded so operators can
    # replace its current value without first clearing it.
    if kind != "customer-name" and customer_name:
        base = base.where(Customer.name == customer_name)
    if kind != "service-id" and service_code:
        base = base.where(CustomerService.service_code == service_code)
    if kind != "sector" and sector_id:
        base = base.where(CustomerService.sector_id == sector_id)
    if kind != "service-vlan" and service_vlan_id is not None:
        base = base.where(City.service_vlan_id == service_vlan_id)
    if kind != "customer-vlan" and customer_vlan_id is not None:
        base = base.where(CustomerService.customer_vlan_id == customer_vlan_id)

    pattern = f"%{search.strip()}%" if search and search.strip() else None
    offset = (page - 1) * page_size

    if kind == "customer-name":
        # Use a named subquery to keep labels stable across supported SQLAlchemy dialects.
        sub = base.subquery("customer_filter_base")
        stmt = select(sub.c.customer_name.label("id"), sub.c.customer_name.label("label")).where(sub.c.customer_name.is_not(None))
        if pattern:
            stmt = stmt.where(sub.c.customer_name.ilike(pattern))
        stmt = stmt.distinct()
        description_col = None
    elif kind == "service-id":
        sub = base.subquery("customer_filter_base")
        stmt = select(sub.c.service_code.label("id"), sub.c.service_code.label("label")).where(sub.c.service_code.is_not(None))
        if pattern:
            stmt = stmt.where(sub.c.service_code.ilike(pattern))
        stmt = stmt.distinct()
        description_col = None
    elif kind == "sector":
        sub = base.subquery("customer_filter_base")
        stmt = select(
            cast(sub.c.sector_id, String).label("id"),
            sub.c.sector_label.label("label"),
            sub.c.location_name.label("description"),
        ).where(sub.c.sector_id.is_not(None))
        if pattern:
            stmt = stmt.where(or_(sub.c.sector_label.ilike(pattern), sub.c.location_name.ilike(pattern)))
        stmt = stmt.distinct()
        description_col = "description"
    elif kind == "service-vlan":
        sub = base.subquery("customer_filter_base")
        vlan_text = cast(sub.c.service_vlan_id, String)
        stmt = select(vlan_text.label("id"), vlan_text.label("label")).where(sub.c.service_vlan_id.is_not(None))
        if pattern:
            stmt = stmt.where(vlan_text.ilike(pattern))
        stmt = stmt.distinct()
        description_col = None
    else:
        sub = base.subquery("customer_filter_base")
        vlan_text = cast(sub.c.customer_vlan_id, String)
        stmt = select(vlan_text.label("id"), vlan_text.label("label")).where(sub.c.customer_vlan_id.is_not(None))
        if pattern:
            stmt = stmt.where(vlan_text.ilike(pattern))
        stmt = stmt.distinct()
        description_col = None

    total = int((await db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery()))) or 0)
    rows = (await db.execute(stmt.order_by("label").offset(offset).limit(page_size))).all()
    if description_col:
        items = [CustomerFilterOption(id=row.id, label=row.label, description=row.description) for row in rows]
    else:
        items = [CustomerFilterOption(id=row.id, label=row.label) for row in rows]
    return PageResult(items=items, total=total, page=page, page_size=page_size)


@router.get("/service-options", response_model=list[ServiceEndpointOption])
async def list_service_endpoint_options(
    sector_id: UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
    *,
    search: str | None = Query(None, max_length=200),
):
    scope = await scope_for_actor(db, actor)
    CpeLink = aliased(DeviceHierarchyLink)
    CPE = aliased(Device)
    SectorLink = aliased(DeviceHierarchyLink)
    SectorDevice = aliased(Device)
    AP = aliased(Device)

    scope_clause = await device_scope_clause(db, scope, device_col=AP.id)
    cpe_scope_clause = await device_scope_clause(db, scope, device_col=CPE.id)
    sector_access_clause = sector_scope_clause(scope, sector_col=Sector.id, location_col=Sector.location_id)
    filters = [
        AP.deleted_at.is_(None),
        AP.lifecycle_state != "DECOMMISSIONED",
        CPE.deleted_at.is_(None),
        CPE.lifecycle_state != "DECOMMISSIONED",
        Sector.deleted_at.is_(None),
        Sector.role == "CUSTOMER_ACCESS",
        scope_clause,
        cpe_scope_clause,
        sector_access_clause,
        ~select(CustomerService.id).where(CustomerService.access_point_device_id == AP.id, CustomerService.deleted_at.is_(None)).exists(),
        ~select(CustomerService.id).where(CustomerService.cpe_device_id == CPE.id, CustomerService.deleted_at.is_(None)).exists(),
    ]

    # Legacy-compatible optional sector filter.
    # This does not alter topology; Sector is still derived through AP -> CPE -> Sector.
    normalized_sector_id = sector_id if isinstance(sector_id, UUID) else None
    if normalized_sector_id is not None:
        filters.append(Sector.id == normalized_sector_id)

    # Safe for both FastAPI resolution and established direct router calls.
    normalized_search = search.strip() if isinstance(search, str) else ""
    if normalized_search:
        pattern = f"%{normalized_search}%"
        filters.append(or_(AP.display_name.ilike(pattern), CPE.display_name.ilike(pattern), Sector.name.ilike(pattern)))

    rows = (await db.execute(
        select(
            AP.id, AP.display_name, CPE.id, CPE.display_name, Sector.id,
            func.coalesce(SectorDevice.display_name, Sector.name),
            City.id, City.name, City.service_vlan_id, Sector.customer_vlan_start, Sector.customer_vlan_end,
        )
        .select_from(AP)
        .join(CpeLink, and_(
            CpeLink.child_device_id == AP.id,
            CpeLink.relationship_type == "CPE_ACCESS_POINT",
            CpeLink.deleted_at.is_(None),
        ))
        .join(CPE, CPE.id == CpeLink.parent_device_id)
        .join(SectorLink, and_(
            SectorLink.child_device_id == CPE.id,
            SectorLink.relationship_type == "SECTOR_CPE",
            SectorLink.deleted_at.is_(None),
        ))
        .join(SectorDevice, SectorDevice.id == SectorLink.parent_device_id)
        .join(Sector, Sector.sector_device_id == SectorDevice.id)
        .join(Location, Location.id == Sector.location_id)
        .join(City, City.id == Location.city_id)
        .where(*filters)
        .order_by(AP.display_name, AP.id)
        .limit(250)
    )).all()
    return [
        ServiceEndpointOption(
            access_point_device_id=ap_id,
            access_point_name=ap_name,
            cpe_device_id=cpe_id,
            cpe_name=cpe_name,
            sector_id=sector_id,
            sector_name=sector_name,
            city_id=city_id,
            city_name=city_name,
            service_vlan_id=service_vlan_id,
            customer_vlan_start=customer_vlan_start,
            customer_vlan_end=customer_vlan_end,
        )
        for (
            ap_id, ap_name, cpe_id, cpe_name, sector_id, sector_name, city_id, city_name,
            service_vlan_id, customer_vlan_start, customer_vlan_end
        ) in rows
    ]


@router.get(
    "/{customer_id}",
    response_model=CustomerRead,
)
async def get_customer(
    customer_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    return await require_customer(db, scope, customer_id)


@router.patch(
    "/{customer_id}",
    response_model=CustomerRead,
)
async def update_customer(
    customer_id: UUID,
    payload: CustomerUpdate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    obj = await require_customer(db, scope, customer_id, for_update=True)

    before = business_summary(obj)

    data = payload.model_dump(
        exclude_unset=True
    )

    metadata_requested = "metadata" in data
    if metadata_requested:
        obj.metadata_ = data.pop("metadata")

    for key, value in data.items():
        setattr(obj, key, value)

    after = business_summary(obj)
    before_changes, after_changes, changed_fields = changed_summary(before, after)
    if changed_fields or metadata_requested:
        await record_audit(
            db,
            action="CUSTOMER_UPDATED",
            entity_type="Customer",
            entity_id=obj.id,
            description="Customer updated.",
            entity_display_snapshot=display_snapshot(obj),
            metadata={
                "changed_fields": [
                    *changed_fields,
                    *(["metadata"] if metadata_requested else []),
                ]
            },
            before_summary=before_changes,
            after_summary=after_changes,
        )

    await db.commit()
    await db.refresh(obj)

    return obj


@router.delete(
    "/{customer_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_customer(
    customer_id: UUID,
    reason: str | None = None,
    confirmed: bool = False,
    actor=Depends(authorize_request),
    db: AsyncSession = Depends(get_db),
):
    scope = await scope_for_actor(db, actor)
    await require_customer(db, scope, customer_id)
    await recycle_from_delete_endpoint(
        db,
        entity_type="CUSTOMER",
        entity_id=customer_id,
        actor=actor,
        reason=reason,
        confirmed=confirmed,
    )
    return None


# ---------------------------------------------------------------------------
# Customer Services
# ---------------------------------------------------------------------------


@router.get(
    "/{customer_id}/services",
    response_model=list[ServiceRead],
)
async def list_services(
    customer_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    await require_customer(db, scope, customer_id)

    CPE = aliased(Device)
    AP = aliased(Device)
    PhysicalSector = aliased(Device)
    rows = (await db.execute(
        select(
            CustomerService, func.coalesce(PhysicalSector.display_name, Sector.name).label("sector_name"),
            CPE.display_name.label("cpe_name"), AP.display_name.label("access_point_name"), City.service_vlan_id,
        )
        .join(Sector, Sector.id == CustomerService.sector_id)
        .join(Location, Location.id == Sector.location_id)
        .join(City, City.id == Location.city_id)
        .outerjoin(PhysicalSector, PhysicalSector.id == Sector.sector_device_id)
        .join(CPE, CPE.id == CustomerService.cpe_device_id)
        .join(AP, AP.id == CustomerService.access_point_device_id)
        .where(CustomerService.customer_id == customer_id, CustomerService.deleted_at.is_(None), customer_service_scope_clause(scope))
        .order_by(CustomerService.service_code)
    )).all()
    return [ServiceRead.model_validate(service).model_copy(update={
        "sector_name": sector_name, "cpe_name": cpe_name, "access_point_name": access_point_name,
        "service_vlan_id": service_vlan_id,
    }) for service, sector_name, cpe_name, access_point_name, service_vlan_id in rows]


@router.post(
    "/{customer_id}/services",
    response_model=ServiceRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_service(
    customer_id: UUID,
    payload: ServiceCreate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    # The path customer_id is authoritative.
    #
    # The body also contains customer_id because of the existing schema.
    # They must agree rather than silently allowing the body to select
    # another customer.

    # Payload/path consistency is independent of resource existence and keeps
    # the established API contract.
    if payload.customer_id != customer_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "CUSTOMER_ID_MISMATCH",
                "message": (
                    "The customer_id in the request body must match "
                    "the customer_id in the URL."
                ),
            },
        )

    scope = await scope_for_actor(db, actor)
    if not scope.global_access:
        # Restricted actors are checked before domain validation so resources
        # outside their WHERE boundary remain non-enumerable. GLOBAL actors
        # retain the legacy domain-specific CUSTOMER/SECTOR/DEVICE errors.
        await require_customer(db, scope, customer_id)
        await require_device(db, scope, payload.access_point_device_id)
        if payload.router_device_id is not None:
            await require_device(db, scope, payload.router_device_id)

    try:
        obj = await create_customer_service(
            db,
            customer_id=customer_id,
            service_code=payload.service_code,
            status=payload.status,
            access_point_device_id=payload.access_point_device_id,
            router_device_id=payload.router_device_id,
            customer_vlan_id=payload.customer_vlan_id,
            require_customer_vlan=True,
            metadata=payload.metadata,
        )
        if not scope.global_access:
            await require_sector(db, scope, obj.sector_id)
            await require_device(db, scope, obj.cpe_device_id)

    except CustomerServiceValidationError as exc:
        raise HTTPException(
            status_code=404
            if exc.code in {
                "CUSTOMER_NOT_FOUND",
                "SECTOR_NOT_FOUND",
                "CPE_DEVICE_NOT_FOUND",
                "ACCESS_POINT_DEVICE_NOT_FOUND",
                "ROUTER_DEVICE_NOT_FOUND",
            }
            else 400,
            detail={
                "code": exc.code,
                "message": exc.message,
            },
        ) from exc

    await db.commit()
    await db.refresh(obj)

    return await _service_read(db, obj)


@router.get(
    "/services/{service_id}",
    response_model=ServiceRead,
)
async def get_service(
    service_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    obj = await require_customer_service(db, scope, service_id)
    return await _service_read(db, obj)


@router.patch(
    "/services/{service_id}",
    response_model=ServiceRead,
)
async def update_service(
    service_id: UUID,
    payload: ServiceUpdate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    obj = await require_customer_service(db, scope, service_id, for_update=True)

    data = payload.model_dump(
        exclude_unset=True
    )

    status_value = data.get("status", obj.status)
    access_point_device_id = data.get("access_point_device_id", obj.access_point_device_id)
    router_device_id = data.get("router_device_id", obj.router_device_id)
    if "customer_vlan_id" in data and data["customer_vlan_id"] is None:
        raise HTTPException(422, detail={"code":"CUSTOMER_VLAN_REQUIRED","message":"Customer VLAN cannot be cleared from a configured service."})
    customer_vlan_id = data.get("customer_vlan_id", obj.customer_vlan_id)
    metadata = data.get("metadata", obj.metadata_)

    await require_device(db, scope, access_point_device_id)
    if router_device_id is not None:
        await require_device(db, scope, router_device_id)

    try:
        obj = await update_customer_service(
            db,
            obj,
            status=status_value,
            access_point_device_id=access_point_device_id,
            router_device_id=router_device_id,
            customer_vlan_id=customer_vlan_id,
            metadata=metadata,
        )
        if not scope.global_access:
            await require_sector(db, scope, obj.sector_id)
            await require_device(db, scope, obj.cpe_device_id)

    except CustomerServiceValidationError as exc:
        raise HTTPException(
            status_code=404
            if exc.code in {
                "SECTOR_NOT_FOUND",
                "CPE_DEVICE_NOT_FOUND",
                "ACCESS_POINT_DEVICE_NOT_FOUND",
                "ROUTER_DEVICE_NOT_FOUND",
            }
            else 400,
            detail={
                "code": exc.code,
                "message": exc.message,
            },
        ) from exc

    await db.commit()
    await db.refresh(obj)

    return await _service_read(db, obj)


@router.delete(
    "/services/{service_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_service(
    service_id: UUID,
    reason: str | None = None,
    confirmed: bool = False,
    actor=Depends(authorize_request),
    db: AsyncSession = Depends(get_db),
):
    scope = await scope_for_actor(db, actor)
    await require_customer_service(db, scope, service_id)
    await recycle_from_delete_endpoint(
        db,
        entity_type="CUSTOMER_SERVICE",
        entity_id=service_id,
        actor=actor,
        reason=reason,
        confirmed=confirmed,
    )
    return None


@router.get(
    "/services/{service_id}/topology",
)
async def get_service_topology(
    service_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    service = await require_customer_service(db, scope, service_id)

    device_ids = [
        service.cpe_device_id,
        service.access_point_device_id,
        service.router_device_id,
    ]

    device_ids = [
        device_id
        for device_id in device_ids
        if device_id is not None
    ]

    devices = []

    if device_ids:
        result = await db.execute(
            select(Device).where(
                Device.id.in_(device_ids),
                await device_scope_clause(db, scope, device_col=Device.id),
            )
        )

        devices = result.scalars().all()

    return {
        "service_id": service.id,
        "service_code": service.service_code,
        "customer_id": service.customer_id,
        "sector_id": service.sector_id,
        "cpe_device_id": service.cpe_device_id,
        "access_point_device_id": service.access_point_device_id,
        "router_device_id": service.router_device_id,
        "devices": devices,
    }
