from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import String, and_, cast, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ..recycle_support import recycle_from_delete_endpoint
from ...models import City, CustomerService, Device, Location, Network, Sector
from ...schemas.geo import (
    CityCreate,
    CityListRow,
    CityRead,
    CityUpdate,
    GeographyScopeOptionsRead,
    LocationCreate,
    LocationListRow,
    LocationRead,
    LocationUpdate,
    SectorCreate,
    SectorListRow,
    SectorRead,
    SectorRoleTransition,
    SectorUpdate,
)
from ...schemas.pagination import PageResult
from ...security.authorization import authorize_request, user_has_permission
from ...security.resource_scope import scope_for_actor
from ...security.scope_queries import (
    city_scope_clause, location_scope_clause, network_scope_clause, require_city,
    require_group, require_location, require_network, require_sector, sector_scope_clause,
)
from ...services.audit import record_audit
from ...services.audit_summaries import business_summary, changed_summary, display_snapshot
from ...services.crud import get_active_for_update_or_404, get_or_404
from ...services.group_effective import effective_group_population_context_subquery
from ...security.permissions import Permission as PermissionCode
from ...services.sector_roles import SectorRoleTransitionError, transition_sector_role

router = APIRouter(tags=["Geography"], dependencies=[Depends(authorize_request)])


async def _ensure_service_vlan_available(db: AsyncSession, vlan_id: int, *, exclude_city_id: UUID | None = None) -> None:
    filters = [City.service_vlan_id == vlan_id]
    if exclude_city_id is not None:
        filters.append(City.id != exclude_city_id)
    existing = await db.scalar(select(City.id).where(*filters).limit(1))
    if existing is not None:
        raise HTTPException(409, detail={"code":"SERVICE_VLAN_IN_USE","message":"Service VLAN is already assigned or reserved by another city."})


async def _validate_sector_vlan_range(
    db: AsyncSession,
    *,
    location_id: UUID,
    vlan_start: int | None,
    vlan_end: int | None,
    exclude_sector_id: UUID | None = None,
) -> None:
    if (vlan_start is None) != (vlan_end is None):
        raise HTTPException(422, detail={"code":"CUSTOMER_VLAN_RANGE_INCOMPLETE","message":"Customer VLAN start and end must be set together."})
    if vlan_start is None:
        if exclude_sector_id is not None:
            allocated = await db.scalar(
                select(CustomerService.id)
                .where(
                    CustomerService.sector_id == exclude_sector_id,
                    CustomerService.customer_vlan_id.is_not(None),
                )
                .limit(1)
            )
            if allocated is not None:
                raise HTTPException(409, detail={"code":"CUSTOMER_VLAN_RANGE_HAS_ALLOCATIONS","message":"The Customer VLAN range cannot be cleared while customer VLANs are allocated in this sector."})
        return
    if vlan_start > vlan_end:
        raise HTTPException(422, detail={"code":"CUSTOMER_VLAN_RANGE_INVALID","message":"Customer VLAN start must be less than or equal to end."})
    location = await db.scalar(select(Location).where(Location.id == location_id))
    if location is None:
        raise HTTPException(404, detail={"code":"LOCATION_NOT_FOUND","message":"Location not found."})
    city = await db.scalar(select(City).where(City.id == location.city_id).with_for_update())
    if city is None:
        raise HTTPException(404, detail={"code":"CITY_NOT_FOUND","message":"City not found."})
    filters = [
        Location.city_id == location.city_id,
        Sector.customer_vlan_start.is_not(None),
        Sector.customer_vlan_end.is_not(None),
        Sector.customer_vlan_start <= vlan_end,
        Sector.customer_vlan_end >= vlan_start,
    ]
    if exclude_sector_id is not None:
        filters.append(Sector.id != exclude_sector_id)
    overlap = await db.scalar(
        select(Sector.id)
        .join(Location, Location.id == Sector.location_id)
        .where(*filters)
        .limit(1)
    )
    if overlap is not None:
        raise HTTPException(409, detail={"code":"CUSTOMER_VLAN_RANGE_OVERLAP","message":"Customer VLAN ranges cannot overlap between sectors in the same city."})

    allocated = (
        await db.scalar(
            select(CustomerService.id)
            .where(
                CustomerService.sector_id == exclude_sector_id,
                or_(CustomerService.customer_vlan_id < vlan_start, CustomerService.customer_vlan_id > vlan_end),
            )
            .limit(1)
        )
        if exclude_sector_id is not None
        else None
    )
    if allocated is not None:
        raise HTTPException(409, detail={"code":"CUSTOMER_VLAN_RANGE_EXCLUDES_ALLOCATED","message":"The new range would exclude an existing customer VLAN allocation in this sector."})


def _validate_page(page: int, page_size: int) -> None:
    if page < 1 or page_size < 1 or page_size > 500:
        raise HTTPException(422, detail={"code": "INVALID_PAGINATION", "message": "Page size must be between 1 and 500."})


@router.get("/geography/scope-options", response_model=GeographyScopeOptionsRead)
async def list_geography_scope_options(
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    networks = (await db.scalars(select(Network).where(Network.deleted_at.is_(None), Network.status == "ACTIVE", network_scope_clause(scope)).order_by(Network.name, Network.id))).all()
    cities = (await db.scalars(select(City).where(City.deleted_at.is_(None), City.status == "ACTIVE", city_scope_clause(scope)).order_by(City.name, City.id))).all()
    locations = (await db.scalars(select(Location).where(Location.deleted_at.is_(None), Location.status == "ACTIVE", location_scope_clause(scope)).order_by(Location.name, Location.id))).all()
    sectors = (await db.scalars(select(Sector).where(Sector.deleted_at.is_(None), Sector.status == "ACTIVE", sector_scope_clause(scope)).order_by(Sector.name, Sector.id))).all()
    return GeographyScopeOptionsRead(networks=list(networks), cities=list(cities), locations=list(locations), sectors=list(sectors))


@router.get("/cities/page", response_model=PageResult[CityListRow])
async def list_cities_page(
    db: AsyncSession = Depends(get_db),
    search: str | None = None,
    network_id: UUID | None = None,
    status_filter: str | None = Query(None, alias="status"),
    sort_by: str = "name",
    sort_direction: str = "asc",
    page: int = 1,
    page_size: int = 50,
    actor=Depends(authorize_request),
    *,
    group_id: UUID | None = None,
    service_vlan_id: Annotated[int | None, Query(ge=2, le=4094)] = None,
    customer_vlan_id: Annotated[int | None, Query(ge=2, le=4094)] = None,
    service_vlan_only: bool = False,
):
    _validate_page(page, page_size)
    scope = await scope_for_actor(db, actor)
    location_count = select(func.count(Location.id)).where(Location.city_id == City.id, Location.deleted_at.is_(None)).correlate(City).scalar_subquery()
    stmt = (
        select(City, Network.name.label("network_name"), location_count.label("location_count"))
        .join(Network, Network.id == City.network_id)
        .where(City.deleted_at.is_(None), Network.deleted_at.is_(None), city_scope_clause(scope))
    )
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(or_(City.name.ilike(pattern), City.code.ilike(pattern), City.description.ilike(pattern), Network.name.ilike(pattern), cast(City.service_vlan_id, String).ilike(pattern)))
    if network_id:
        stmt = stmt.where(City.network_id == network_id)
    if group_id is not None:
        actor_id = getattr(actor, "id", None)
        if actor_id is not None and not await user_has_permission(db, user_id=actor_id, permission_code=PermissionCode.GROUP_READ):
            raise HTTPException(403, detail={"code":"GROUP_FILTER_PERMISSION_DENIED","message":"group.read is required to filter by group."})
        await require_group(db, scope, group_id)
        group_context = await effective_group_population_context_subquery(db, group_id)
        stmt = stmt.where(exists(select(1).select_from(group_context).where(group_context.c.city_id == City.id)))
    if service_vlan_only:
        stmt = stmt.where(City.service_vlan_id.is_not(None))
    if service_vlan_id is not None:
        stmt = stmt.where(City.service_vlan_id == service_vlan_id)
    if customer_vlan_id is not None:
        stmt = stmt.where(exists(select(1).select_from(Sector).join(Location, Location.id == Sector.location_id).where(
            Location.city_id == City.id, Sector.deleted_at.is_(None), Location.deleted_at.is_(None),
            Sector.customer_vlan_start.is_not(None), Sector.customer_vlan_end.is_not(None),
            Sector.customer_vlan_start <= customer_vlan_id, Sector.customer_vlan_end >= customer_vlan_id,
        )))
    if status_filter:
        stmt = stmt.where(City.status == status_filter)
    sort_map = {"name": City.name, "code": City.code, "network_name": Network.name, "status": City.status, "location_count": location_count}
    sort_expr = sort_map.get(sort_by)
    if sort_expr is None or sort_direction not in {"asc", "desc"}:
        raise HTTPException(422, detail={"code": "INVALID_CITY_SORT", "message": "Unsupported City sort."})
    total = int((await db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery()))) or 0)
    order = sort_expr.desc() if sort_direction == "desc" else sort_expr.asc()
    rows = (await db.execute(stmt.order_by(order.nullslast(), City.id.asc()).offset((page - 1) * page_size).limit(page_size))).all()
    items = [CityListRow(**CityRead.model_validate(city).model_dump(), network_name=network_name, location_count=int(count or 0)) for city, network_name, count in rows]
    return PageResult(items=items, total=total, page=page, page_size=page_size)


@router.get("/locations/page", response_model=PageResult[LocationListRow])
async def list_locations_page(
    db: AsyncSession = Depends(get_db),
    search: str | None = None,
    network_id: UUID | None = None,
    city_id: UUID | None = None,
    status_filter: str | None = Query(None, alias="status"),
    sort_by: str = "name",
    sort_direction: str = "asc",
    page: int = 1,
    page_size: int = 50,
    actor=Depends(authorize_request),
    *,
    group_id: UUID | None = None,
    service_vlan_id: Annotated[int | None, Query(ge=2, le=4094)] = None,
    customer_vlan_id: Annotated[int | None, Query(ge=2, le=4094)] = None,
):
    _validate_page(page, page_size)
    scope = await scope_for_actor(db, actor)
    sector_count = select(func.count(Sector.id)).where(Sector.location_id == Location.id, Sector.deleted_at.is_(None)).correlate(Location).scalar_subquery()
    stmt = (
        select(Location, City.network_id.label("network_id"), Network.name.label("network_name"), City.name.label("city_name"), City.service_vlan_id.label("service_vlan_id"), sector_count.label("sector_count"))
        .join(City, City.id == Location.city_id)
        .join(Network, Network.id == City.network_id)
        .where(Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None), location_scope_clause(scope))
    )
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(or_(Location.name.ilike(pattern), Location.code.ilike(pattern), Location.address.ilike(pattern), Location.description.ilike(pattern), City.name.ilike(pattern), Network.name.ilike(pattern)))
    if network_id:
        stmt = stmt.where(City.network_id == network_id)
    if city_id:
        stmt = stmt.where(Location.city_id == city_id)
    if group_id is not None:
        actor_id = getattr(actor, "id", None)
        if actor_id is not None and not await user_has_permission(db, user_id=actor_id, permission_code=PermissionCode.GROUP_READ):
            raise HTTPException(403, detail={"code":"GROUP_FILTER_PERMISSION_DENIED","message":"group.read is required to filter by group."})
        await require_group(db, scope, group_id)
        group_context = await effective_group_population_context_subquery(db, group_id)
        stmt = stmt.where(exists(select(1).select_from(group_context).where(group_context.c.location_id == Location.id)))
    if service_vlan_id is not None:
        stmt = stmt.where(City.service_vlan_id == service_vlan_id)
    if customer_vlan_id is not None:
        stmt = stmt.where(exists(select(1).where(
            Sector.location_id == Location.id, Sector.deleted_at.is_(None),
            Sector.customer_vlan_start.is_not(None), Sector.customer_vlan_end.is_not(None),
            Sector.customer_vlan_start <= customer_vlan_id, Sector.customer_vlan_end >= customer_vlan_id,
        )))
    if status_filter:
        stmt = stmt.where(Location.status == status_filter)
    sort_map = {"name": Location.name, "code": Location.code, "network_name": Network.name, "city_name": City.name, "status": Location.status, "sector_count": sector_count}
    sort_expr = sort_map.get(sort_by)
    if sort_expr is None or sort_direction not in {"asc", "desc"}:
        raise HTTPException(422, detail={"code": "INVALID_LOCATION_SORT", "message": "Unsupported Location sort."})
    total = int((await db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery()))) or 0)
    order = sort_expr.desc() if sort_direction == "desc" else sort_expr.asc()
    rows = (await db.execute(stmt.order_by(order.nullslast(), Location.id.asc()).offset((page - 1) * page_size).limit(page_size))).all()
    items = [LocationListRow(**LocationRead.model_validate(location).model_dump(), network_id=net_id, network_name=network_name, city_name=city_name, service_vlan_id=service_vlan_id_value, sector_count=int(count or 0)) for location, net_id, network_name, city_name, service_vlan_id_value, count in rows]
    return PageResult(items=items, total=total, page=page, page_size=page_size)


@router.get("/sectors/page", response_model=PageResult[SectorListRow])
async def list_sectors_page(
    db: AsyncSession = Depends(get_db),
    search: str | None = None,
    network_id: UUID | None = None,
    city_id: UUID | None = None,
    location_id: UUID | None = None,
    role: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    bound: bool | None = None,
    sort_by: str = "name",
    sort_direction: str = "asc",
    page: int = 1,
    page_size: int = 50,
    actor=Depends(authorize_request),
    *,
    group_id: UUID | None = None,
    service_vlan_id: Annotated[int | None, Query(ge=2, le=4094)] = None,
    customer_vlan_id: Annotated[int | None, Query(ge=2, le=4094)] = None,
):
    _validate_page(page, page_size)
    scope = await scope_for_actor(db, actor)
    stmt = (
        select(
            Sector,
            City.network_id.label("network_id"),
            Network.name.label("network_name"),
            Location.city_id.label("city_id"),
            City.name.label("city_name"),
            City.service_vlan_id.label("service_vlan_id"),
            Location.name.label("location_name"),
            Device.display_name.label("physical_sector_device_name"),
        )
        .join(Location, Location.id == Sector.location_id)
        .join(City, City.id == Location.city_id)
        .join(Network, Network.id == City.network_id)
        .outerjoin(Device, Device.id == Sector.sector_device_id)
        .where(Sector.deleted_at.is_(None), Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None), sector_scope_clause(scope))
    )
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(or_(Sector.name.ilike(pattern), Sector.code.ilike(pattern), Sector.description.ilike(pattern), Location.name.ilike(pattern), City.name.ilike(pattern), Network.name.ilike(pattern), Device.display_name.ilike(pattern)))
    if network_id: stmt = stmt.where(City.network_id == network_id)
    if city_id: stmt = stmt.where(Location.city_id == city_id)
    if location_id: stmt = stmt.where(Sector.location_id == location_id)
    if group_id is not None:
        actor_id = getattr(actor, "id", None)
        if actor_id is not None and not await user_has_permission(db, user_id=actor_id, permission_code=PermissionCode.GROUP_READ):
            raise HTTPException(403, detail={"code":"GROUP_FILTER_PERMISSION_DENIED","message":"group.read is required to filter by group."})
        await require_group(db, scope, group_id)
        group_context = await effective_group_population_context_subquery(db, group_id)
        stmt = stmt.where(exists(select(1).select_from(group_context).where(group_context.c.sector_id == Sector.id)))
    if service_vlan_id is not None: stmt = stmt.where(City.service_vlan_id == service_vlan_id)
    if customer_vlan_id is not None:
        stmt = stmt.where(and_(
            Sector.customer_vlan_start.is_not(None), Sector.customer_vlan_end.is_not(None),
            Sector.customer_vlan_start <= customer_vlan_id, Sector.customer_vlan_end >= customer_vlan_id,
        ))
    if role: stmt = stmt.where(Sector.role == role)
    if status_filter: stmt = stmt.where(Sector.status == status_filter)
    if bound is True: stmt = stmt.where(Sector.sector_device_id.is_not(None))
    elif bound is False: stmt = stmt.where(Sector.sector_device_id.is_(None))
    sort_map = {
        "name": Sector.name, "code": Sector.code, "role": Sector.role, "network_name": Network.name,
        "city_name": City.name, "location_name": Location.name, "physical_sector_device_name": Device.display_name,
        "sequence_number": Sector.sequence_number, "status": Sector.status,
    }
    sort_expr = sort_map.get(sort_by)
    if sort_expr is None or sort_direction not in {"asc", "desc"}:
        raise HTTPException(422, detail={"code": "INVALID_SECTOR_SORT", "message": "Unsupported Sector sort."})
    total = int((await db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery()))) or 0)
    order = sort_expr.desc() if sort_direction == "desc" else sort_expr.asc()
    rows = (await db.execute(stmt.order_by(order.nullslast(), Sector.id.asc()).offset((page - 1) * page_size).limit(page_size))).all()
    items = [SectorListRow(
        **SectorRead.model_validate(sector).model_dump(), network_id=network_id_value, network_name=network_name,
        city_id=city_id_value, city_name=city_name, service_vlan_id=service_vlan_id_value, location_name=location_name,
        physical_sector_device_name=physical_name,
    ) for sector, network_id_value, network_name, city_id_value, city_name, service_vlan_id_value, location_name, physical_name in rows]
    return PageResult(items=items, total=total, page=page, page_size=page_size)


@router.get("/networks/{network_id}/cities", response_model=list[CityRead])
async def list_cities(
    network_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    await require_network(db, scope, network_id)
    return list((await db.scalars(select(City).where(City.network_id == network_id, City.deleted_at.is_(None), city_scope_clause(scope)).order_by(City.name, City.id))).all())


@router.post("/networks/{network_id}/cities", response_model=CityRead, status_code=status.HTTP_201_CREATED)
async def create_city(
    network_id: UUID,
    payload: CityCreate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    parent = await require_network(db, scope, network_id, for_update=True)
    if parent.deleted_at is not None: raise HTTPException(404, detail={"code":"NETWORK_NOT_FOUND","message":"Network not found."})
    await _ensure_service_vlan_available(db, payload.service_vlan_id)
    obj = City(network_id=network_id, **payload.model_dump())
    db.add(obj); await db.flush()
    await record_audit(db, action="CITY_CREATED", entity_type="City", entity_id=obj.id, description="City created.", entity_display_snapshot=display_snapshot(obj), after_summary=business_summary(obj))
    await db.commit(); await db.refresh(obj); return obj


@router.get("/cities/{city_id}", response_model=CityRead)
async def get_city(
    city_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    return await require_city(db, await scope_for_actor(db, actor), city_id)


@router.patch("/cities/{city_id}", response_model=CityRead)
async def update_city(
    city_id: UUID,
    payload: CityUpdate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    obj = await require_city(db, await scope_for_actor(db, actor), city_id, for_update=True)
    if obj.deleted_at is not None: raise HTTPException(404, detail={"code":"CITY_NOT_FOUND","message":"City not found."})
    before = business_summary(obj)
    data = payload.model_dump(exclude_unset=True)
    if "service_vlan_id" in data:
        if data["service_vlan_id"] is None:
            raise HTTPException(422, detail={"code":"SERVICE_VLAN_REQUIRED","message":"Service VLAN cannot be cleared once the city is configured."})
        await _ensure_service_vlan_available(db, data["service_vlan_id"], exclude_city_id=obj.id)
    for key, value in data.items(): setattr(obj, key, value)
    after = business_summary(obj); before_changes, after_changes, changed_fields = changed_summary(before, after)
    if changed_fields:
        await record_audit(db, action="CITY_UPDATED", entity_type="City", entity_id=obj.id, description="City updated.", entity_display_snapshot=display_snapshot(obj), metadata={"changed_fields": changed_fields}, before_summary=before_changes, after_summary=after_changes)
    await db.commit(); await db.refresh(obj); return obj


@router.delete("/cities/{city_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_city(city_id: UUID, reason: str | None = None, confirmed: bool = False, actor=Depends(authorize_request), db: AsyncSession = Depends(get_db)):
    await require_city(db, await scope_for_actor(db, actor), city_id)
    await recycle_from_delete_endpoint(db, entity_type="CITY", entity_id=city_id, actor=actor, reason=reason, confirmed=confirmed); return None


@router.get("/cities/{city_id}/locations", response_model=list[LocationRead])
async def list_locations(
    city_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    await require_city(db, scope, city_id)
    return list((await db.scalars(select(Location).where(Location.city_id == city_id, Location.deleted_at.is_(None), location_scope_clause(scope)).order_by(Location.name, Location.id))).all())


@router.post("/cities/{city_id}/locations", response_model=LocationRead, status_code=status.HTTP_201_CREATED)
async def create_location(
    city_id: UUID,
    payload: LocationCreate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    parent = await require_city(db, scope, city_id, for_update=True)
    if parent.deleted_at is not None: raise HTTPException(404, detail={"code":"CITY_NOT_FOUND","message":"City not found."})
    obj = Location(city_id=city_id, metadata_=payload.metadata, **payload.model_dump(exclude={"metadata"}))
    db.add(obj); await db.flush()
    await record_audit(db, action="LOCATION_CREATED", entity_type="Location", entity_id=obj.id, description="Location created.", entity_display_snapshot=display_snapshot(obj), after_summary=business_summary(obj))
    await db.commit(); await db.refresh(obj); return obj


@router.get("/locations/{location_id}", response_model=LocationRead)
async def get_location(
    location_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    return await require_location(db, await scope_for_actor(db, actor), location_id)


@router.patch("/locations/{location_id}", response_model=LocationRead)
async def update_location(
    location_id: UUID,
    payload: LocationUpdate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    obj = await require_location(db, await scope_for_actor(db, actor), location_id, for_update=True)
    if obj.deleted_at is not None: raise HTTPException(404, detail={"code":"LOCATION_NOT_FOUND","message":"Location not found."})
    before = business_summary(obj)
    data = payload.model_dump(exclude_unset=True); metadata_requested = "metadata" in data
    if metadata_requested: obj.metadata_ = data.pop("metadata") or {}
    for key, value in data.items(): setattr(obj, key, value)
    after = business_summary(obj); before_changes, after_changes, changed_fields = changed_summary(before, after)
    if changed_fields or metadata_requested:
        await record_audit(db, action="LOCATION_UPDATED", entity_type="Location", entity_id=obj.id, description="Location updated.", entity_display_snapshot=display_snapshot(obj), metadata={"changed_fields": [*changed_fields, *(["metadata"] if metadata_requested else [])]}, before_summary=before_changes, after_summary=after_changes)
    await db.commit(); await db.refresh(obj); return obj


@router.delete("/locations/{location_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_location(location_id: UUID, reason: str | None = None, confirmed: bool = False, actor=Depends(authorize_request), db: AsyncSession = Depends(get_db)):
    await require_location(db, await scope_for_actor(db, actor), location_id)
    await recycle_from_delete_endpoint(db, entity_type="LOCATION", entity_id=location_id, actor=actor, reason=reason, confirmed=confirmed); return None


@router.get("/locations/{location_id}/sectors", response_model=list[SectorRead])
async def list_sectors(
    location_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    await require_location(db, scope, location_id)
    return list((await db.scalars(select(Sector).where(Sector.location_id == location_id, Sector.deleted_at.is_(None), sector_scope_clause(scope)).order_by(Sector.name, Sector.id))).all())


@router.post("/locations/{location_id}/sectors", response_model=SectorRead, status_code=status.HTTP_201_CREATED)
async def create_sector(
    location_id: UUID,
    payload: SectorCreate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    parent = await require_location(db, scope, location_id, for_update=True)
    if parent.deleted_at is not None: raise HTTPException(404, detail={"code":"LOCATION_NOT_FOUND","message":"Location not found."})
    await _validate_sector_vlan_range(
        db, location_id=location_id, vlan_start=payload.customer_vlan_start, vlan_end=payload.customer_vlan_end
    )
    obj = Sector(location_id=location_id, metadata_=payload.metadata, **payload.model_dump(exclude={"metadata"}))
    db.add(obj); await db.flush()
    await record_audit(db, action="SECTOR_CREATED", entity_type="Sector", entity_id=obj.id, description="Sector created.", entity_display_snapshot=display_snapshot(obj), after_summary=business_summary(obj))
    await db.commit(); await db.refresh(obj); return obj


@router.get("/sectors/{sector_id}", response_model=SectorRead)
async def get_sector(
    sector_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    return await require_sector(db, await scope_for_actor(db, actor), sector_id)


@router.patch("/sectors/{sector_id}", response_model=SectorRead)
async def update_sector(
    sector_id: UUID,
    payload: SectorUpdate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    existing = await require_sector(db, scope, sector_id, for_update=True)
    if existing.deleted_at is not None: raise HTTPException(404, detail={"code":"SECTOR_NOT_FOUND","message":"Sector not found."})
    data = payload.model_dump(exclude_unset=True); role_requested = "role" in data; target_role = data.pop("role", None)
    effective_vlan_start = data.get("customer_vlan_start", existing.customer_vlan_start)
    effective_vlan_end = data.get("customer_vlan_end", existing.customer_vlan_end)
    await _validate_sector_vlan_range(
        db, location_id=existing.location_id, vlan_start=effective_vlan_start, vlan_end=effective_vlan_end, exclude_sector_id=existing.id
    )
    if role_requested:
        try: obj = await transition_sector_role(db, sector_id=sector_id, target_role=target_role)
        except SectorRoleTransitionError as exc: raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.message}) from exc
    else: obj = await get_active_for_update_or_404(db, Sector, sector_id)
    before = business_summary(obj); metadata_requested = "metadata" in data
    if metadata_requested: obj.metadata_ = data.pop("metadata") or {}
    for key, value in data.items(): setattr(obj, key, value)
    after = business_summary(obj); before_changes, after_changes, changed_fields = changed_summary(before, after)
    if changed_fields or metadata_requested:
        await record_audit(db, action="SECTOR_UPDATED", entity_type="Sector", entity_id=obj.id, description="Sector updated.", entity_display_snapshot=display_snapshot(obj), metadata={"changed_fields": [*changed_fields, *(["metadata"] if metadata_requested else [])]}, before_summary=before_changes, after_summary=after_changes)
    await db.commit(); await db.refresh(obj); return obj


@router.delete("/sectors/{sector_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sector(sector_id: UUID, reason: str | None = None, confirmed: bool = False, actor=Depends(authorize_request), db: AsyncSession = Depends(get_db)):
    await require_sector(db, await scope_for_actor(db, actor), sector_id)
    await recycle_from_delete_endpoint(db, entity_type="SECTOR", entity_id=sector_id, actor=actor, reason=reason, confirmed=confirmed); return None


@router.post("/sectors/{sector_id}/role-transition", response_model=SectorRead)
async def change_sector_role(
    sector_id: UUID,
    payload: SectorRoleTransition,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    await require_sector(db, scope, sector_id, for_update=True)
    try: obj = await transition_sector_role(db, sector_id=sector_id, target_role=payload.role)
    except SectorRoleTransitionError as exc: raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.message}) from exc
    await db.commit(); await db.refresh(obj); return obj
