from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
from uuid import UUID

from sqlalchemy import and_, exists, func, or_, select, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import (
    City,
    CustomerService,
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
from .topology_query_context import (
    _source_context_subquery, _geography_universe, _base_geography, _device_context_rows,
    _ap_children_for_cpes, _cpe_parents_for_aps, _group_visible_cpe_subquery, _text_match,
)

def _add_geo_subtree(
    universe: GeographyUniverse,
    base: tuple[set[UUID], set[UUID], set[UUID], set[UUID]],
    *,
    network_ids: set[UUID],
    city_ids: set[UUID],
    location_ids: set[UUID],
    sector_ids: set[UUID],
) -> tuple[set[UUID], set[UUID], set[UUID], set[UUID]]:
    base_networks, base_cities, base_locations, base_sectors = base
    full_networks = network_ids & base_networks
    full_cities = city_ids & base_cities
    full_locations = location_ids & base_locations
    full_sectors = sector_ids & base_sectors

    if full_networks:
        full_cities |= {row.id for row in universe.cities.values() if row.id in base_cities and row.network_id in full_networks}
    if full_cities:
        full_locations |= {row.id for row in universe.locations.values() if row.id in base_locations and row.city_id in full_cities}
    if full_locations:
        full_sectors |= {row.id for row in universe.sectors.values() if row.id in base_sectors and row.location_id in full_locations}
    return full_networks, full_cities, full_locations, full_sectors


def _ancestor_closure(
    universe: GeographyUniverse,
    *,
    network_ids: set[UUID],
    city_ids: set[UUID],
    location_ids: set[UUID],
    sector_ids: set[UUID],
) -> tuple[set[UUID], set[UUID], set[UUID], set[UUID]]:
    networks = set(network_ids)
    cities = set(city_ids)
    locations = set(location_ids)
    sectors = set(sector_ids)
    for sector_id in list(sectors):
        sector = universe.sectors.get(sector_id)
        if sector is not None:
            locations.add(sector.location_id)
    for location_id in list(locations):
        location = universe.locations.get(location_id)
        if location is not None:
            cities.add(location.city_id)
    for city_id in list(cities):
        city = universe.cities.get(city_id)
        if city is not None:
            networks.add(city.network_id)
    return networks, cities, locations, sectors


async def resolve_path_scope(db: AsyncSession, query: TopologyQuery):
    context = await _source_context_subquery(db, query)
    universe = await _geography_universe(db, query, context)
    base = _base_geography(query, universe)
    base_networks, base_cities, base_locations, base_sectors = base

    if not all((base_networks, base_cities, base_locations)):
        # A network can legitimately contain no cities/locations.  Preserve the
        # selected network root even though there is nothing below it.
        return context, universe, PathScope(
            network_ids=base_networks,
            city_ids=base_cities,
            location_ids=base_locations,
            sector_ids=base_sectors,
        )

    keyword = query.keyword.strip()
    explicit_device = bool(query.cpe_ids or query.access_point_ids or query.customer_vlan_ids)
    if not keyword and not explicit_device:
        return context, universe, PathScope(
            network_ids=base_networks,
            city_ids=base_cities,
            location_ids=base_locations,
            sector_ids=base_sectors,
            # A Sector filter represents that Sector subtree only; location-
            # level independent devices are siblings and must disappear.
            full_device_location_ids=set() if query.sector_ids else set(base_locations),
            full_device_sector_ids=set(base_sectors),
            restrict_devices=bool(query.sector_ids),
        )

    scope = PathScope(restrict_devices=explicit_device, keyword_active=bool(keyword))

    vlan_cpe_ids: set[UUID] = set()
    vlan_ap_ids: set[UUID] = set()
    if query.customer_vlan_ids:
        linked_source_device = exists(
            select(1).select_from(context).where(or_(
                context.c.device_id == CustomerService.cpe_device_id,
                context.c.device_id == CustomerService.access_point_device_id,
            ))
        )
        service_rows = (await db.execute(
            select(CustomerService.cpe_device_id, CustomerService.access_point_device_id)
            .where(
                CustomerService.deleted_at.is_(None),
                CustomerService.customer_vlan_id.in_(query.customer_vlan_ids),
                CustomerService.sector_id.in_(base_sectors) if base_sectors else False,
                linked_source_device,
            )
        )).all()
        vlan_cpe_ids = {row.cpe_device_id for row in service_rows}
        vlan_ap_ids = {row.access_point_device_id for row in service_rows}

    # Device filters are downstream and therefore the most specific constraint.
    if query.access_point_ids:
        ap_rows = await _device_context_rows(
            db, context, base, type_codes=("ACCESS_POINT",), ids=set(query.access_point_ids), restrict_to_sectors=bool(query.sector_ids)
        )
        scope.target_ap_ids = {row.id for row in ap_rows}
        if query.customer_vlan_ids:
            scope.target_ap_ids &= vlan_ap_ids
            ap_rows = [row for row in ap_rows if row.id in scope.target_ap_ids]
        if query.cpe_ids and scope.target_ap_ids:
            allowed_ap_ids = set((await db.scalars(
                select(DeviceHierarchyLink.child_device_id).where(
                    DeviceHierarchyLink.child_device_id.in_(scope.target_ap_ids),
                    DeviceHierarchyLink.parent_device_id.in_(query.cpe_ids),
                    DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
                    DeviceHierarchyLink.deleted_at.is_(None),
                )
            )).all())
            scope.target_ap_ids &= allowed_ap_ids
            ap_rows = [row for row in ap_rows if row.id in scope.target_ap_ids]
        scope.target_cpe_ids = await _cpe_parents_for_aps(db, context, base, scope.target_ap_ids)
        device_rows = ap_rows
    elif query.cpe_ids:
        if query.source_type == "group":
            visible_cpes = _group_visible_cpe_subquery(
                context,
                base,
                restrict_to_sectors=bool(query.sector_ids),
            )
            selected_visible_ids = set((await db.scalars(
                select(visible_cpes.c.device_id).where(
                    visible_cpes.c.device_id.in_(query.cpe_ids)
                )
            )).all())
            effective_context = effective_group_context_subquery()
            cpe_rows = await _device_context_rows(
                db,
                effective_context,
                base,
                type_codes=("CPE",),
                ids=selected_visible_ids,
                restrict_to_sectors=bool(query.sector_ids),
            )
        else:
            cpe_rows = await _device_context_rows(
                db,
                context,
                base,
                type_codes=("CPE",),
                ids=set(query.cpe_ids),
                restrict_to_sectors=bool(query.sector_ids),
            )
        scope.target_cpe_ids = {row.id for row in cpe_rows}
        if query.customer_vlan_ids:
            scope.target_cpe_ids &= vlan_cpe_ids
            cpe_rows = [row for row in cpe_rows if row.id in scope.target_cpe_ids]
        # Group mode deliberately limits descendants to APs that are actually
        # eligible for the selected Group.  A context-only CPE therefore
        # reveals the Group AP(s) beneath it without widening Group membership.
        scope.target_ap_ids = await _ap_children_for_cpes(db, context, base, scope.target_cpe_ids)
        device_rows = cpe_rows
    elif query.customer_vlan_ids:
        # C-VLAN is a customer-service/device-path filter.  It may legitimately
        # match the same C-VLAN in multiple cities; S-VLAN/geography filters in
        # ``base`` narrow those paths when selected.
        if query.source_type == "group":
            visible_cpes = _group_visible_cpe_subquery(
                context, base, restrict_to_sectors=bool(query.sector_ids),
            )
            visible_cpe_ids = set((await db.scalars(
                select(visible_cpes.c.device_id).where(visible_cpes.c.device_id.in_(vlan_cpe_ids))
            )).all())
            effective_context = effective_group_context_subquery()
            cpe_rows = await _device_context_rows(
                db, effective_context, base, type_codes=("CPE",), ids=visible_cpe_ids,
                restrict_to_sectors=bool(query.sector_ids),
            )
        else:
            cpe_rows = await _device_context_rows(
                db, context, base, type_codes=("CPE",), ids=vlan_cpe_ids,
                restrict_to_sectors=bool(query.sector_ids),
            )
        ap_rows = await _device_context_rows(
            db, context, base, type_codes=("ACCESS_POINT",), ids=vlan_ap_ids,
            restrict_to_sectors=bool(query.sector_ids),
        )
        scope.target_cpe_ids = {row.id for row in cpe_rows}
        scope.target_ap_ids = {row.id for row in ap_rows}
        device_rows = list(cpe_rows) + list(ap_rows)
    else:
        device_rows = []

    target_networks: set[UUID] = set()
    target_cities: set[UUID] = set()
    target_locations: set[UUID] = set()
    target_sectors: set[UUID] = set()
    for row in device_rows:
        target_networks.add(row.network_id)
        target_cities.add(row.city_id)
        target_locations.add(row.location_id)
        if row.sector_id is not None:
            target_sectors.add(row.sector_id)

    if explicit_device:
        n, c, l, s = _ancestor_closure(
            universe,
            network_ids=target_networks,
            city_ids=target_cities,
            location_ids=target_locations,
            sector_ids=target_sectors,
        )
        scope.network_ids = n & base_networks
        scope.city_ids = c & base_cities
        scope.location_ids = l & base_locations
        scope.sector_ids = s & base_sectors
        return context, universe, scope

    # Keyword is evaluated inside the already selected source/geography scope.
    matched_networks = {
        row.id for row in universe.networks.values()
        if row.id in base_networks and (_text_match(row.name, keyword) or _text_match(row.code, keyword))
    }
    matched_cities = {
        row.id for row in universe.cities.values()
        if row.id in base_cities and (_text_match(row.name, keyword) or _text_match(row.code, keyword))
    }
    matched_locations = {
        row.id for row in universe.locations.values()
        if row.id in base_locations and (
            _text_match(row.name, keyword) or _text_match(row.code, keyword) or _text_match(row.address, keyword)
        )
    }
    matched_sectors = {
        row.id for row in universe.sectors.values()
        if row.id in base_sectors and (_text_match(row.name, keyword) or _text_match(row.code, keyword))
    }

    # Physical SECTOR display names are operator-facing sector labels and must
    # therefore participate in keyword search as sector matches.
    if base_sectors:
        physical_rows = (await db.execute(
            select(Sector.id, Device.display_name)
            .join(Device, Device.id == Sector.sector_device_id)
            .where(Sector.id.in_(base_sectors), Device.deleted_at.is_(None))
        )).all()
        matched_sectors |= {sector_id for sector_id, display_name in physical_rows if _text_match(display_name, keyword)}

    full_networks, full_cities, full_locations, full_sectors = _add_geo_subtree(
        universe,
        base,
        network_ids=matched_networks,
        city_ids=matched_cities,
        location_ids=matched_locations,
        sector_ids=matched_sectors,
    )
    scope.full_device_location_ids = set(full_locations)
    scope.full_device_sector_ids = set(full_sectors)

    keyword_rows = await _device_context_rows(db, context, base, keyword=keyword, restrict_to_sectors=bool(query.sector_ids))
    keyword_cpe_ids: set[UUID] = set()
    keyword_ap_ids: set[UUID] = set()
    keyword_independent_ids: set[UUID] = set()
    keyword_device_paths: list = []
    for row in keyword_rows:
        if row.type_code == "SECTOR" and row.sector_id is not None:
            full_sectors.add(row.sector_id)
            scope.full_device_sector_ids.add(row.sector_id)
            continue
        keyword_device_paths.append(row)
        if row.type_code == "CPE":
            keyword_cpe_ids.add(row.id)
        elif row.type_code == "ACCESS_POINT":
            keyword_ap_ids.add(row.id)
        else:
            keyword_independent_ids.add(row.id)

    # A CPE keyword match includes its eligible AP descendant(s).  An AP match
    # is exact but keeps its CPE parent as path context.
    keyword_ap_ids |= await _ap_children_for_cpes(db, context, base, keyword_cpe_ids)
    keyword_cpe_ids |= await _cpe_parents_for_aps(db, context, base, keyword_ap_ids)
    scope.target_cpe_ids = keyword_cpe_ids
    scope.target_ap_ids = keyword_ap_ids
    scope.target_independent_ids = keyword_independent_ids

    path_networks = set(full_networks)
    path_cities = set(full_cities)
    path_locations = set(full_locations)
    path_sectors = set(full_sectors)
    for row in keyword_device_paths:
        path_networks.add(row.network_id)
        path_cities.add(row.city_id)
        path_locations.add(row.location_id)
        if row.sector_id is not None:
            path_sectors.add(row.sector_id)

    n, c, l, s = _ancestor_closure(
        universe,
        network_ids=path_networks,
        city_ids=path_cities,
        location_ids=path_locations,
        sector_ids=path_sectors,
    )
    scope.network_ids = n & base_networks
    scope.city_ids = c & base_cities
    scope.location_ids = l & base_locations
    scope.sector_ids = s & base_sectors
    scope.restrict_devices = True
    return context, universe, scope

