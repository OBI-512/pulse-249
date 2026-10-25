from __future__ import annotations

from sqlalchemy import and_, exists, false, or_, select, true, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import (
    City,
    Customer,
    CustomerService,
    Device,
    DeviceCandidate,
    DeviceGroup,
    DeviceGroupMembership,
    DeviceRelationship,
    Location,
    Network,
    Sector,
)
from ..services.group_effective import direct_group_device_select, effective_group_context_subquery
from .resource_scope import EffectiveResourceScope, geography_access_clause


def network_scope_clause(scope: EffectiveResourceScope, network_col=Network.id):
    if scope.global_access:
        return true()
    return network_col.in_(tuple(scope.network_ids)) if scope.network_ids else false()


def city_scope_clause(scope: EffectiveResourceScope, *, city_col=City.id, network_col=City.network_id):
    if scope.global_access:
        return true()
    clauses = []
    if scope.network_ids:
        clauses.append(network_col.in_(tuple(scope.network_ids)))
    if scope.city_ids:
        clauses.append(city_col.in_(tuple(scope.city_ids)))
    return or_(*clauses) if clauses else false()


def location_scope_clause(
    scope: EffectiveResourceScope,
    *,
    location_col=Location.id,
    city_col=Location.city_id,
):
    if scope.global_access:
        return true()
    clauses = []
    if scope.location_ids:
        clauses.append(location_col.in_(tuple(scope.location_ids)))
    if scope.city_ids or scope.network_ids:
        city_access = select(City.id).where(City.id == city_col)
        nested = []
        if scope.city_ids:
            nested.append(City.id.in_(tuple(scope.city_ids)))
        if scope.network_ids:
            nested.append(City.network_id.in_(tuple(scope.network_ids)))
        city_access = city_access.where(or_(*nested)).exists()
        clauses.append(city_access)
    return or_(*clauses) if clauses else false()


def sector_scope_clause(scope: EffectiveResourceScope, *, sector_col=Sector.id, location_col=Sector.location_id):
    if scope.global_access:
        return true()
    clauses = []
    if scope.sector_ids:
        clauses.append(sector_col.in_(tuple(scope.sector_ids)))
    if scope.location_ids or scope.city_ids or scope.network_ids:
        location_access = select(Location.id).where(Location.id == location_col)
        nested = []
        if scope.location_ids:
            nested.append(Location.id.in_(tuple(scope.location_ids)))
        if scope.city_ids or scope.network_ids:
            city_access = select(City.id).where(City.id == Location.city_id)
            city_nested = []
            if scope.city_ids:
                city_nested.append(City.id.in_(tuple(scope.city_ids)))
            if scope.network_ids:
                city_nested.append(City.network_id.in_(tuple(scope.network_ids)))
            city_access = city_access.where(or_(*city_nested)).exists()
            nested.append(city_access)
        location_access = location_access.where(or_(*nested)).exists()
        clauses.append(location_access)
    return or_(*clauses) if clauses else false()


def _group_population_subquery(scope: EffectiveResourceScope):
    if not scope.group_ids:
        return None
    # Query the selected/descendant groups directly. Manual groups use membership;
    # dynamic groups evaluate their query definition at request time.
    group_rows = select(DeviceGroup).where(
        DeviceGroup.id.in_(tuple(scope.group_ids)),
        DeviceGroup.deleted_at.is_(None),
    )
    return group_rows


async def group_device_population_select(db: AsyncSession, scope: EffectiveResourceScope):
    if not scope.group_ids:
        return None
    groups = list((await db.scalars(select(DeviceGroup).where(
        DeviceGroup.id.in_(tuple(scope.group_ids)),
        DeviceGroup.deleted_at.is_(None),
    ))).all())
    if not groups:
        return None
    selects = [direct_group_device_select(group) for group in groups]
    if len(selects) == 1:
        return selects[0]
    return union_all(*selects)


async def device_scope_clause(
    db: AsyncSession,
    scope: EffectiveResourceScope,
    *,
    device_col=Device.id,
):
    if scope.global_access:
        return true()

    clauses = []
    context = effective_group_context_subquery()
    geo_clause = geography_access_clause(
        scope,
        network_col=context.c.network_id,
        city_col=context.c.city_id,
        location_col=context.c.location_id,
        sector_col=context.c.sector_id,
    )
    if geo_clause is not False:
        clauses.append(
            exists(select(1).select_from(context).where(context.c.device_id == device_col, geo_clause))
        )

    population = await group_device_population_select(db, scope)
    if population is not None:
        group_devices = population.subquery("authorized_group_devices")
        clauses.append(exists(select(1).select_from(group_devices).where(group_devices.c.device_id == device_col)))
    return or_(*clauses) if clauses else false()


def group_scope_clause(scope: EffectiveResourceScope, *, group=DeviceGroup):
    if scope.global_access:
        return true()
    clauses = []
    if scope.group_ids:
        clauses.append(group.id.in_(tuple(scope.group_ids)))
    if scope.network_ids:
        clauses.append(and_(group.scope_type == "NETWORK", group.network_id.in_(tuple(scope.network_ids))))
    if scope.city_ids:
        clauses.append(and_(group.scope_type == "CITY", group.city_id.in_(tuple(scope.city_ids))))
    if scope.location_ids:
        clauses.append(and_(group.scope_type == "LOCATION", group.location_id.in_(tuple(scope.location_ids))))
    if scope.sector_ids:
        clauses.append(and_(group.scope_type == "SECTOR", group.sector_id.in_(tuple(scope.sector_ids))))
    # A broader geographic actor can see organizational groups anchored below it.
    if scope.network_ids:
        clauses.append(and_(group.scope_type == "CITY", exists(select(1).where(
            City.id == group.city_id, City.network_id.in_(tuple(scope.network_ids))
        ))))
        clauses.append(and_(group.scope_type == "LOCATION", exists(select(1).select_from(Location).join(City, City.id == Location.city_id).where(
            Location.id == group.location_id, City.network_id.in_(tuple(scope.network_ids))
        ))))
        clauses.append(and_(group.scope_type == "SECTOR", exists(select(1).select_from(Sector).join(Location, Location.id == Sector.location_id).join(City, City.id == Location.city_id).where(
            Sector.id == group.sector_id, City.network_id.in_(tuple(scope.network_ids))
        ))))
    if scope.city_ids:
        clauses.append(and_(group.scope_type == "LOCATION", exists(select(1).where(
            Location.id == group.location_id, Location.city_id.in_(tuple(scope.city_ids))
        ))))
        clauses.append(and_(group.scope_type == "SECTOR", exists(select(1).select_from(Sector).join(Location, Location.id == Sector.location_id).where(
            Sector.id == group.sector_id, Location.city_id.in_(tuple(scope.city_ids))
        ))))
    if scope.location_ids:
        clauses.append(and_(group.scope_type == "SECTOR", exists(select(1).where(
            Sector.id == group.sector_id, Sector.location_id.in_(tuple(scope.location_ids))
        ))))
    return or_(*clauses) if clauses else false()


def customer_scope_clause(scope: EffectiveResourceScope, *, customer_col=Customer.id):
    if scope.global_access:
        return true()
    service = CustomerService.__table__.alias("authorized_customer_service")
    sector = Sector.__table__.alias("authorized_customer_sector")
    location = Location.__table__.alias("authorized_customer_location")
    city = City.__table__.alias("authorized_customer_city")
    geo = geography_access_clause(
        scope,
        network_col=city.c.network_id,
        city_col=city.c.id,
        location_col=location.c.id,
        sector_col=sector.c.id,
    )
    return exists(
        select(1)
        .select_from(service.join(sector, sector.c.id == service.c.sector_id).join(location, location.c.id == sector.c.location_id).join(city, city.c.id == location.c.city_id))
        .where(service.c.customer_id == customer_col, service.c.deleted_at.is_(None), geo)
    )


def customer_service_scope_clause(scope: EffectiveResourceScope, *, service=CustomerService):
    if scope.global_access:
        return true()
    sector = Sector.__table__.alias("authorized_service_sector")
    location = Location.__table__.alias("authorized_service_location")
    city = City.__table__.alias("authorized_service_city")
    geo = geography_access_clause(
        scope,
        network_col=city.c.network_id,
        city_col=city.c.id,
        location_col=location.c.id,
        sector_col=sector.c.id,
    )
    return exists(
        select(1).select_from(
            sector.join(location, location.c.id == sector.c.location_id).join(city, city.c.id == location.c.city_id)
        ).where(sector.c.id == service.sector_id, geo)
    )


def candidate_geography_scope_clause(scope: EffectiveResourceScope, *, candidate=DeviceCandidate):
    if scope.global_access:
        return true()
    clauses = []
    if scope.sector_ids:
        clauses.append(candidate.sector_id.in_(tuple(scope.sector_ids)))
    if scope.location_ids:
        clauses.append(candidate.location_id.in_(tuple(scope.location_ids)))
    if scope.city_ids:
        clauses.append(candidate.city_id.in_(tuple(scope.city_ids)))
    if scope.network_ids:
        clauses.append(candidate.network_id.in_(tuple(scope.network_ids)))
    # Ancestor grants also cover candidates that only have a descendant anchor.
    if scope.network_ids:
        clauses.append(exists(select(1).where(City.id == candidate.city_id, City.network_id.in_(tuple(scope.network_ids)))))
        clauses.append(exists(select(1).select_from(Location).join(City, City.id == Location.city_id).where(Location.id == candidate.location_id, City.network_id.in_(tuple(scope.network_ids)))))
        clauses.append(exists(select(1).select_from(Sector).join(Location, Location.id == Sector.location_id).join(City, City.id == Location.city_id).where(Sector.id == candidate.sector_id, City.network_id.in_(tuple(scope.network_ids)))))
    if scope.city_ids:
        clauses.append(exists(select(1).where(Location.id == candidate.location_id, Location.city_id.in_(tuple(scope.city_ids)))))
        clauses.append(exists(select(1).select_from(Sector).join(Location, Location.id == Sector.location_id).where(Sector.id == candidate.sector_id, Location.city_id.in_(tuple(scope.city_ids)))))
    if scope.location_ids:
        clauses.append(exists(select(1).where(Sector.id == candidate.sector_id, Sector.location_id.in_(tuple(scope.location_ids)))))
    return or_(*clauses) if clauses else false()


async def relationship_scope_clause(db: AsyncSession, scope: EffectiveResourceScope, *, relationship=DeviceRelationship):
    if scope.global_access:
        return true()
    source_ok = await device_scope_clause(db, scope, device_col=relationship.source_device_id)
    target_ok = await device_scope_clause(db, scope, device_col=relationship.target_device_id)
    return and_(source_ok, target_ok)


async def origin_scope_clause(db: AsyncSession, scope: EffectiveResourceScope, metadata_col):
    from .resource_scope import expanded_authorization_scope_keys, scope_metadata_matches_clause
    if scope.global_access:
        return true()
    keys = await expanded_authorization_scope_keys(db, scope)
    return scope_metadata_matches_clause(metadata_col, keys)


async def candidate_scope_clause(db: AsyncSession, scope: EffectiveResourceScope, *, candidate=DeviceCandidate):
    if scope.global_access:
        return true()
    geography = candidate_geography_scope_clause(scope, candidate=candidate)
    origin = await origin_scope_clause(db, scope, candidate.metadata_)
    # Once a candidate has explicit geography, that geography is authoritative.
    # Immutable origin provenance is only the fail-closed authorization anchor for
    # pre-placement candidates; it must not keep a candidate visible after it is
    # assigned into unrelated geography.
    has_geography = or_(
        candidate.network_id.is_not(None), candidate.city_id.is_not(None),
        candidate.location_id.is_not(None), candidate.sector_id.is_not(None),
    )
    return or_(and_(has_geography, geography), and_(~has_geography, origin))


async def require_network(db: AsyncSession, scope: EffectiveResourceScope, network_id, *, for_update: bool = False):
    stmt = select(Network).where(Network.id == network_id, network_scope_clause(scope))
    if for_update:
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    row = await db.scalar(stmt)
    if row is None:
        from .resource_scope import not_found_scope_error
        raise not_found_scope_error("Network")
    return row


async def require_city(db: AsyncSession, scope: EffectiveResourceScope, city_id, *, for_update: bool = False):
    stmt = select(City).where(City.id == city_id, city_scope_clause(scope))
    if for_update:
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    row = await db.scalar(stmt)
    if row is None:
        from .resource_scope import not_found_scope_error
        raise not_found_scope_error("City")
    return row


async def require_location(db: AsyncSession, scope: EffectiveResourceScope, location_id, *, for_update: bool = False):
    stmt = select(Location).where(Location.id == location_id, location_scope_clause(scope))
    if for_update:
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    row = await db.scalar(stmt)
    if row is None:
        from .resource_scope import not_found_scope_error
        raise not_found_scope_error("Location")
    return row


async def require_sector(db: AsyncSession, scope: EffectiveResourceScope, sector_id, *, for_update: bool = False):
    stmt = select(Sector).where(Sector.id == sector_id, sector_scope_clause(scope))
    if for_update:
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    row = await db.scalar(stmt)
    if row is None:
        from .resource_scope import not_found_scope_error
        raise not_found_scope_error("Sector")
    return row


async def require_device(db: AsyncSession, scope: EffectiveResourceScope, device_id, *, for_update: bool = False):
    clause = await device_scope_clause(db, scope, device_col=Device.id)
    stmt = select(Device).where(Device.id == device_id, clause)
    if for_update:
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    row = await db.scalar(stmt)
    if row is None:
        from .resource_scope import not_found_scope_error
        raise not_found_scope_error("Device")
    return row


async def require_group(db: AsyncSession, scope: EffectiveResourceScope, group_id, *, for_update: bool = False):
    stmt = select(DeviceGroup).where(DeviceGroup.id == group_id, group_scope_clause(scope))
    if for_update:
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    row = await db.scalar(stmt)
    if row is None:
        from .resource_scope import not_found_scope_error
        raise not_found_scope_error("Device group")
    return row


async def require_customer(db: AsyncSession, scope: EffectiveResourceScope, customer_id, *, for_update: bool = False):
    stmt = select(Customer).where(Customer.id == customer_id, customer_scope_clause(scope))
    if for_update:
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    row = await db.scalar(stmt)
    if row is None:
        from .resource_scope import not_found_scope_error
        raise not_found_scope_error("Customer")
    return row


async def require_customer_service(db: AsyncSession, scope: EffectiveResourceScope, service_id, *, for_update: bool = False):
    stmt = select(CustomerService).where(CustomerService.id == service_id, customer_service_scope_clause(scope))
    if for_update:
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    row = await db.scalar(stmt)
    if row is None:
        from .resource_scope import not_found_scope_error
        raise not_found_scope_error("Customer service")
    return row


async def require_candidate(db: AsyncSession, scope: EffectiveResourceScope, candidate_id, *, for_update: bool = False):
    clause = await candidate_scope_clause(db, scope, candidate=DeviceCandidate)
    stmt = select(DeviceCandidate).where(DeviceCandidate.id == candidate_id, clause)
    if for_update:
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    row = await db.scalar(stmt)
    if row is None:
        from .resource_scope import not_found_scope_error
        raise not_found_scope_error("Device candidate")
    return row
