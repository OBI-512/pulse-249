from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ..recycle_support import recycle_from_delete_endpoint
from ...models import City, CustomerService, Location, Network, Sector
from ...schemas.network import NetworkCreate, NetworkListRow, NetworkRead, NetworkUpdate
from ...schemas.pagination import PageResult
from ...security.authorization import authorize_request, user_has_permission
from ...security.resource_scope import scope_for_actor
from ...security.scope_queries import network_scope_clause, require_group, require_network
from ...services.audit import record_audit
from ...services.audit_summaries import business_summary, changed_summary, display_snapshot
from ...services.crud import get_active_for_update_or_404, get_or_404
from ...services.group_effective import effective_group_population_context_subquery
from ...security.permissions import Permission as PermissionCode

router = APIRouter(prefix="/networks", tags=["Networks"], dependencies=[Depends(authorize_request)])


@router.get("", response_model=list[NetworkRead])
async def list_networks(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    result = await db.execute(
        select(Network)
        .where(Network.deleted_at.is_(None), network_scope_clause(scope))
        .order_by(Network.name, Network.id)
        .offset(offset)
        .limit(limit)
    )
    return result.scalars().all()


@router.get("/page", response_model=PageResult[NetworkListRow])
async def list_networks_page(
    db: AsyncSession = Depends(get_db),
    search: str | None = None,
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
    if page < 1 or page_size < 1 or page_size > 500:
        raise HTTPException(422, detail={"code": "INVALID_PAGINATION", "message": "Page size must be between 1 and 500."})
    city_count = (
        select(func.count(City.id))
        .where(City.network_id == Network.id, City.deleted_at.is_(None))
        .correlate(Network)
        .scalar_subquery()
    )
    scope = await scope_for_actor(db, actor)
    stmt = select(Network, city_count.label("city_count")).where(Network.deleted_at.is_(None), network_scope_clause(scope))
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(or_(Network.name.ilike(pattern), Network.code.ilike(pattern), Network.description.ilike(pattern)))
    if group_id is not None:
        actor_id = getattr(actor, "id", None)
        if actor_id is not None and not await user_has_permission(db, user_id=actor_id, permission_code=PermissionCode.GROUP_READ):
            raise HTTPException(403, detail={"code":"GROUP_FILTER_PERMISSION_DENIED","message":"group.read is required to filter by group."})
        await require_group(db, scope, group_id)
        group_context = await effective_group_population_context_subquery(db, group_id)
        stmt = stmt.where(exists(select(1).select_from(group_context).where(group_context.c.network_id == Network.id)))
    if service_vlan_id is not None:
        stmt = stmt.where(exists(select(1).where(City.network_id == Network.id, City.deleted_at.is_(None), City.service_vlan_id == service_vlan_id)))
    if customer_vlan_id is not None:
        eligible_sector = exists(
            select(1).select_from(Sector).join(Location, Location.id == Sector.location_id).join(City, City.id == Location.city_id).where(
                City.network_id == Network.id, Sector.deleted_at.is_(None), Location.deleted_at.is_(None), City.deleted_at.is_(None),
                Sector.customer_vlan_start.is_not(None), Sector.customer_vlan_end.is_not(None),
                Sector.customer_vlan_start <= customer_vlan_id, Sector.customer_vlan_end >= customer_vlan_id,
            )
        )
        stmt = stmt.where(eligible_sector)
    if status_filter:
        stmt = stmt.where(Network.status == status_filter)
    sort_map = {"name": Network.name, "code": Network.code, "status": Network.status, "city_count": city_count}
    sort_expr = sort_map.get(sort_by)
    if sort_expr is None or sort_direction not in {"asc", "desc"}:
        raise HTTPException(422, detail={"code": "INVALID_NETWORK_SORT", "message": "Unsupported Network sort."})
    total = int((await db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery()))) or 0)
    order = sort_expr.desc() if sort_direction == "desc" else sort_expr.asc()
    rows = (await db.execute(stmt.order_by(order.nullslast(), Network.id.asc()).offset((page - 1) * page_size).limit(page_size))).all()
    items = [NetworkListRow(**NetworkRead.model_validate(network).model_dump(), city_count=int(count or 0)) for network, count in rows]
    return PageResult(items=items, total=total, page=page, page_size=page_size)


@router.post("", response_model=NetworkRead, status_code=status.HTTP_201_CREATED)
async def create_network(
    payload: NetworkCreate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    if not scope.global_access:
        raise HTTPException(403, detail={"code":"RESOURCE_SCOPE_DENIED","message":"GLOBAL scope is required to create a Network."})
    obj = Network(**payload.model_dump())
    db.add(obj)
    await db.flush()
    await record_audit(
        db,
        action="NETWORK_CREATED",
        entity_type="Network",
        entity_id=obj.id,
        description="Network created.",
        entity_display_snapshot=display_snapshot(obj),
        after_summary=business_summary(obj),
    )
    await db.commit()
    await db.refresh(obj)
    return obj


@router.get("/{network_id}", response_model=NetworkRead)
async def get_network(
    network_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    return await require_network(db, scope, network_id)


@router.patch("/{network_id}", response_model=NetworkRead)
async def update_network(
    network_id: UUID,
    payload: NetworkUpdate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    obj = await require_network(db, scope, network_id, for_update=True)
    if obj.deleted_at is not None:
        raise HTTPException(404, detail={"code":"NETWORK_NOT_FOUND","message":"Network not found."})
    before = business_summary(obj)
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(obj, key, value)
    after = business_summary(obj)
    before_changes, after_changes, changed_fields = changed_summary(before, after)
    if changed_fields:
        await record_audit(
            db,
            action="NETWORK_UPDATED",
            entity_type="Network",
            entity_id=obj.id,
            description="Network updated.",
            entity_display_snapshot=display_snapshot(obj),
            metadata={"changed_fields": changed_fields},
            before_summary=before_changes,
            after_summary=after_changes,
        )
    await db.commit()
    await db.refresh(obj)
    return obj


@router.delete("/{network_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_network(
    network_id: UUID,
    reason: str | None = None,
    confirmed: bool = False,
    actor=Depends(authorize_request),
    db: AsyncSession = Depends(get_db),
):
    scope = await scope_for_actor(db, actor)
    await require_network(db, scope, network_id)
    await recycle_from_delete_endpoint(
        db,
        entity_type="NETWORK",
        entity_id=network_id,
        actor=actor,
        reason=reason,
        confirmed=confirmed,
    )
    return None
