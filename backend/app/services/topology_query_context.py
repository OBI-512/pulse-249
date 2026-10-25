from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
from uuid import UUID

from sqlalchemy import and_, exists, false, func, or_, select, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import (
    City,
    Device,
    DeviceGroup,
    DeviceHierarchyLink,
    DeviceIP,
    DeviceType,
    Location,
    Network,
    Sector,
)
from ..schemas.topology import TopologyFilterOption, TopologyFilterOptionPage, TopologyHierarchyNode
from .crud import get_or_404
from .groups import (
    descendant_group_ids,
    direct_group_device_select,
    effective_group_context_subquery,
)

SourceType = Literal["network", "group"]
FilterKind = Literal["network", "service_vlan", "city", "location", "sector", "customer_vlan", "cpe", "access_point"]
NodeKind = Literal["root", "network", "city", "location", "sector", "sector_device", "cpe"]

from .topology_query_models import TopologyQuery, GeographyUniverse, PathScope

async def _group_population_subquery(db: AsyncSession, group_id: UUID):
    await get_or_404(db, DeviceGroup, group_id)
    group_ids = {group_id, *(await descendant_group_ids(db, group_id))}
    groups = list((await db.scalars(
        select(DeviceGroup).where(DeviceGroup.id.in_(group_ids), DeviceGroup.deleted_at.is_(None))
    )).all())
    populations = [direct_group_device_select(group) for group in groups]
    if not populations:
        return select(Device.id.label("device_id")).where(False).subquery("topology_empty_group_population")
    if len(populations) == 1:
        return populations[0].subquery("topology_group_population")
    return union_all(*populations).subquery("topology_group_population")


async def _source_context_subquery(db: AsyncSession, query: TopologyQuery):
    context = effective_group_context_subquery()
    if query.source_type == "network":
        await get_or_404(db, Network, query.source_id)
        stmt = select(
            context.c.device_id,
            context.c.network_id,
            context.c.city_id,
            context.c.location_id,
            context.c.sector_id,
            context.c.sector_role,
        ).where(context.c.network_id == query.source_id)
        if query.resource_scope_restricted:
            device_access = []
            if query.device_location_ids:
                device_access.append(and_(
                    context.c.location_id.in_(query.device_location_ids),
                    context.c.sector_id.is_(None),
                ))
            if query.device_sector_ids:
                device_access.append(context.c.sector_id.in_(query.device_sector_ids))
            stmt = stmt.where(or_(*device_access) if device_access else false())
        return stmt.distinct().subquery("topology_source_context")

    population = await _group_population_subquery(db, query.source_id)
    return (
        select(
            context.c.device_id,
            context.c.network_id,
            context.c.city_id,
            context.c.location_id,
            context.c.sector_id,
            context.c.sector_role,
        )
        .join(population, population.c.device_id == context.c.device_id)
        .distinct()
        .subquery("topology_source_context")
    )


async def _geography_universe(db: AsyncSession, query: TopologyQuery, context) -> GeographyUniverse:
    if query.source_type == "network":
        network = await get_or_404(db, Network, query.source_id)
        networks = [network]
        city_stmt = select(City).where(City.network_id == network.id, City.deleted_at.is_(None))
        if query.resource_scope_restricted:
            city_stmt = city_stmt.where(City.id.in_(query.path_city_ids) if query.path_city_ids else false())
        cities = list((await db.scalars(city_stmt.order_by(City.name))).all())
        city_ids = [row.id for row in cities]
        location_stmt = select(Location).where(Location.city_id.in_(city_ids), Location.deleted_at.is_(None)) if city_ids else None
        if location_stmt is not None and query.resource_scope_restricted:
            location_stmt = location_stmt.where(Location.id.in_(query.path_location_ids) if query.path_location_ids else false())
        locations = list((await db.scalars(location_stmt.order_by(Location.name))).all()) if location_stmt is not None else []
        location_ids = [row.id for row in locations]
        sector_stmt = select(Sector).where(Sector.location_id.in_(location_ids), Sector.deleted_at.is_(None)) if location_ids else None
        if sector_stmt is not None and query.resource_scope_restricted:
            sector_stmt = sector_stmt.where(Sector.id.in_(query.path_sector_ids) if query.path_sector_ids else false())
        sectors = list((await db.scalars(sector_stmt.order_by(Sector.sequence_number, Sector.name))).all()) if sector_stmt is not None else []
    else:
        network_ids = list((await db.scalars(select(context.c.network_id).distinct())).all())
        city_ids = list((await db.scalars(select(context.c.city_id).distinct())).all())
        location_ids = list((await db.scalars(select(context.c.location_id).distinct())).all())
        sector_ids = [item for item in (await db.scalars(select(context.c.sector_id).where(context.c.sector_id.is_not(None)).distinct())).all() if item is not None]
        networks = list((await db.scalars(
            select(Network).where(Network.id.in_(network_ids), Network.deleted_at.is_(None)).order_by(Network.name)
        )).all()) if network_ids else []
        cities = list((await db.scalars(
            select(City).where(City.id.in_(city_ids), City.deleted_at.is_(None)).order_by(City.name)
        )).all()) if city_ids else []
        locations = list((await db.scalars(
            select(Location).where(Location.id.in_(location_ids), Location.deleted_at.is_(None)).order_by(Location.name)
        )).all()) if location_ids else []
        sectors = list((await db.scalars(
            select(Sector).where(Sector.id.in_(sector_ids), Sector.deleted_at.is_(None)).order_by(Sector.sequence_number, Sector.name)
        )).all()) if sector_ids else []

    return GeographyUniverse(
        networks={row.id: row for row in networks},
        cities={row.id: row for row in cities},
        locations={row.id: row for row in locations},
        sectors={row.id: row for row in sectors},
    )


def _base_geography(query: TopologyQuery, universe: GeographyUniverse) -> tuple[set[UUID], set[UUID], set[UUID], set[UUID]]:
    network_ids = set(universe.networks)
    if query.source_type == "group" and query.network_ids:
        network_ids &= set(query.network_ids)

    city_ids = universe.city_ids_for_networks(network_ids)
    if query.service_vlan_ids:
        city_ids = {
            city_id for city_id in city_ids
            if city_id in universe.cities and universe.cities[city_id].service_vlan_id in set(query.service_vlan_ids)
        }
    if query.city_ids:
        city_ids &= set(query.city_ids)

    location_ids = universe.location_ids_for_cities(city_ids)
    if query.location_ids:
        location_ids &= set(query.location_ids)

    sector_ids = universe.sector_ids_for_locations(location_ids)
    if query.sector_ids:
        sector_ids &= set(query.sector_ids)

    # Deeper explicit filters also prune their ancestor path.  Without this,
    # selecting one City/Location/Sector in Group mode could leave unrelated
    # Networks/Cities visible as empty siblings.
    if query.sector_ids:
        location_ids = {universe.sectors[item].location_id for item in sector_ids if item in universe.sectors}
        city_ids = {universe.locations[item].city_id for item in location_ids if item in universe.locations}
        network_ids = {universe.cities[item].network_id for item in city_ids if item in universe.cities}
    elif query.location_ids:
        city_ids = {universe.locations[item].city_id for item in location_ids if item in universe.locations}
        network_ids = {universe.cities[item].network_id for item in city_ids if item in universe.cities}
    elif query.city_ids:
        network_ids = {universe.cities[item].network_id for item in city_ids if item in universe.cities}

    return network_ids, city_ids, location_ids, sector_ids


def _context_base_conditions(context, base: tuple[set[UUID], set[UUID], set[UUID], set[UUID]], *, restrict_to_sectors: bool = False):
    network_ids, city_ids, location_ids, sector_ids = base
    conditions = []
    if network_ids:
        conditions.append(context.c.network_id.in_(network_ids))
    else:
        conditions.append(False)
    if city_ids:
        conditions.append(context.c.city_id.in_(city_ids))
    else:
        conditions.append(False)
    if location_ids:
        conditions.append(context.c.location_id.in_(location_ids))
    else:
        conditions.append(False)
    if restrict_to_sectors:
        if sector_ids:
            conditions.append(context.c.sector_id.in_(sector_ids))
        else:
            conditions.append(False)
    return conditions


async def _management_ip_map(db: AsyncSession, device_ids: list[UUID]) -> dict[UUID, str]:
    if not device_ids:
        return {}
    rows = list((await db.scalars(
        select(DeviceIP)
        .where(DeviceIP.device_id.in_(device_ids), DeviceIP.deleted_at.is_(None))
        .order_by(DeviceIP.is_management.desc(), DeviceIP.is_primary.desc(), DeviceIP.id)
    )).all())
    result: dict[UUID, str] = {}
    for row in rows:
        result.setdefault(row.device_id, row.ip_address)
    return result


async def _device_context_rows(
    db: AsyncSession,
    context,
    base: tuple[set[UUID], set[UUID], set[UUID], set[UUID]],
    *,
    type_codes: tuple[str, ...] | None = None,
    ids: set[UUID] | None = None,
    keyword: str = "",
    restrict_to_sectors: bool = False,
):
    stmt = (
        select(
            Device.id,
            Device.display_name,
            Device.hostname,
            Device.management_protocol,
            Device.lifecycle_state,
            Device.operational_state,
            DeviceType.code.label("type_code"),
            context.c.network_id,
            context.c.city_id,
            context.c.location_id,
            context.c.sector_id,
        )
        .join(context, context.c.device_id == Device.id)
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .where(Device.deleted_at.is_(None), *_context_base_conditions(context, base, restrict_to_sectors=restrict_to_sectors))
    )
    if type_codes:
        stmt = stmt.where(DeviceType.code.in_(type_codes))
    if ids is not None:
        if not ids:
            return []
        stmt = stmt.where(Device.id.in_(ids))
    keyword = keyword.strip()
    if keyword:
        pattern = f"%{keyword}%"
        ip_match = exists(
            select(1).where(
                DeviceIP.device_id == Device.id,
                DeviceIP.deleted_at.is_(None),
                DeviceIP.ip_address.ilike(pattern),
            )
        )
        stmt = stmt.where(or_(
            Device.display_name.ilike(pattern),
            Device.hostname.ilike(pattern),
            Device.vendor.ilike(pattern),
            Device.model.ilike(pattern),
            ip_match,
        ))
    return (await db.execute(stmt)).all()


async def _ap_children_for_cpes(db: AsyncSession, context, base, cpe_ids: set[UUID]) -> set[UUID]:
    if not cpe_ids:
        return set()
    rows = (await db.scalars(
        select(DeviceHierarchyLink.child_device_id)
        .join(context, context.c.device_id == DeviceHierarchyLink.child_device_id)
        .join(Device, Device.id == DeviceHierarchyLink.child_device_id)
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .where(
            DeviceHierarchyLink.parent_device_id.in_(cpe_ids),
            DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
            DeviceHierarchyLink.deleted_at.is_(None),
            Device.deleted_at.is_(None),
            DeviceType.code == "ACCESS_POINT",
            *_context_base_conditions(context, base),
        )
    )).all()
    return set(rows)


async def _cpe_parents_for_aps(db: AsyncSession, context, base, ap_ids: set[UUID]) -> set[UUID]:
    if not ap_ids:
        return set()
    rows = (await db.execute(
        select(DeviceHierarchyLink.parent_device_id)
        .join(context, context.c.device_id == DeviceHierarchyLink.child_device_id)
        .where(
            DeviceHierarchyLink.child_device_id.in_(ap_ids),
            DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
            DeviceHierarchyLink.deleted_at.is_(None),
            *_context_base_conditions(context, base),
        )
    )).all()
    return {row.parent_device_id for row in rows}


def _group_visible_cpe_subquery(context, base, *, restrict_to_sectors: bool = False):
    """CPEs that can legitimately appear in a Group topology tree.

    A Group may contain an ACCESS_POINT without containing its parent CPE.
    The lazy hierarchy still renders that CPE as structural/path context.
    Filter options must use the same visible topology universe; otherwise a
    CPE can be visible in the tree but impossible to select in the CPE filter.
    """
    member_cpes = (
        select(Device.id.label("device_id"))
        .join(context, context.c.device_id == Device.id)
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .where(
            Device.deleted_at.is_(None),
            DeviceType.code == "CPE",
            *_context_base_conditions(context, base, restrict_to_sectors=restrict_to_sectors),
        )
    )

    ap_parents = (
        select(DeviceHierarchyLink.parent_device_id.label("device_id"))
        .join(context, context.c.device_id == DeviceHierarchyLink.child_device_id)
        .join(Device, Device.id == DeviceHierarchyLink.child_device_id)
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .where(
            DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
            DeviceHierarchyLink.deleted_at.is_(None),
            Device.deleted_at.is_(None),
            DeviceType.code == "ACCESS_POINT",
            *_context_base_conditions(context, base, restrict_to_sectors=restrict_to_sectors),
        )
    )

    visible = union_all(member_cpes, ap_parents).subquery("topology_group_visible_cpes_union")
    return select(visible.c.device_id).distinct().subquery("topology_group_visible_cpes")


def _text_match(value: str | None, keyword: str) -> bool:
    return bool(value and keyword.casefold() in value.casefold())
