from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
from uuid import UUID

from sqlalchemy import String, and_, cast, exists, func, or_, select, union_all
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

from .topology_query_models import TopologyQuery
from .topology_query_context import (
    _context_base_conditions, _geography_universe, _group_visible_cpe_subquery,
    _management_ip_map, _source_context_subquery,
)

def _paginate_options(rows: list[TopologyFilterOption], page: int, page_size: int) -> TopologyFilterOptionPage:
    total = len(rows)
    start = (page - 1) * page_size
    return TopologyFilterOptionPage(items=rows[start:start + page_size], total=total, page=page, page_size=page_size)


async def filter_options(
    db: AsyncSession,
    query: TopologyQuery,
    *,
    kind: FilterKind,
    search: str,
    page: int,
    page_size: int,
) -> TopologyFilterOptionPage:
    context = await _source_context_subquery(db, query)
    universe = await _geography_universe(db, query, context)
    pattern = search.strip().casefold()

    # Only upstream selections constrain each selector.  This permits adding a
    # second value at the current level while ensuring downstream universes are
    # always dependent on the selected ancestors.
    network_ids = set(universe.networks)
    if query.source_type == "group" and query.network_ids:
        network_ids &= set(query.network_ids)
    city_ids = universe.city_ids_for_networks(network_ids)
    if kind != "service_vlan" and query.service_vlan_ids:
        city_ids = {city_id for city_id in city_ids if universe.cities.get(city_id) and universe.cities[city_id].service_vlan_id in set(query.service_vlan_ids)}
    if kind != "city" and query.city_ids:
        city_ids &= set(query.city_ids)
    location_ids = universe.location_ids_for_cities(city_ids)
    if kind != "location" and query.location_ids:
        location_ids &= set(query.location_ids)
    sector_ids = universe.sector_ids_for_locations(location_ids)
    if kind != "sector" and query.sector_ids:
        sector_ids &= set(query.sector_ids)

    if kind == "network":
        rows = [
            TopologyFilterOption(id=row.id, label=row.name, description=row.code)
            for row in universe.networks.values()
            if (not pattern or pattern in row.name.casefold() or pattern in row.code.casefold())
        ]
        return _paginate_options(sorted(rows, key=lambda item: item.label.casefold()), page, page_size)
    if kind == "service_vlan":
        eligible_city_ids = set(city_ids)
        values = sorted({
            int(row.service_vlan_id)
            for row in universe.cities.values()
            if row.id in eligible_city_ids and row.service_vlan_id is not None
        })
        rows = [
            TopologyFilterOption(id=str(value), label=str(value), description="Service VLAN")
            for value in values
            if not pattern or pattern in str(value).casefold()
        ]
        return _paginate_options(rows, page, page_size)
    if kind == "city":
        rows = [
            TopologyFilterOption(id=row.id, label=row.name, description=row.code)
            for row in universe.cities.values()
            if row.id in city_ids and (not pattern or pattern in row.name.casefold() or pattern in row.code.casefold())
        ]
        return _paginate_options(sorted(rows, key=lambda item: item.label.casefold()), page, page_size)
    if kind == "location":
        rows = [
            TopologyFilterOption(id=row.id, label=row.name, description=row.code)
            for row in universe.locations.values()
            if row.id in location_ids and (not pattern or pattern in row.name.casefold() or pattern in row.code.casefold())
        ]
        return _paginate_options(sorted(rows, key=lambda item: item.label.casefold()), page, page_size)
    if kind == "sector":
        physical_names: dict[UUID, str] = {}
        if sector_ids:
            physical_names = dict((await db.execute(
                select(Sector.id, Device.display_name)
                .join(Device, Device.id == Sector.sector_device_id)
                .where(Sector.id.in_(sector_ids), Device.deleted_at.is_(None))
            )).all())
        rows = []
        for row in universe.sectors.values():
            if row.id not in sector_ids:
                continue
            display = physical_names.get(row.id) or row.name
            if pattern and pattern not in display.casefold() and pattern not in row.name.casefold() and pattern not in row.code.casefold():
                continue
            rows.append(TopologyFilterOption(id=row.id, label=display, description=f"{row.code} · {row.role}"))
        return _paginate_options(sorted(rows, key=lambda item: item.label.casefold()), page, page_size)

    if kind == "customer_vlan":
        if not sector_ids:
            return TopologyFilterOptionPage(items=[], total=0, page=page, page_size=page_size)
        linked_source_device = exists(
            select(1).select_from(context).where(or_(
                context.c.device_id == CustomerService.cpe_device_id,
                context.c.device_id == CustomerService.access_point_device_id,
            ))
        )
        stmt = (
            select(CustomerService.customer_vlan_id)
            .join(Sector, Sector.id == CustomerService.sector_id)
            .join(Location, Location.id == Sector.location_id)
            .join(City, City.id == Location.city_id)
            .where(
                CustomerService.deleted_at.is_(None),
                CustomerService.customer_vlan_id.is_not(None),
                Sector.deleted_at.is_(None),
                Sector.id.in_(sector_ids),
                City.id.in_(city_ids),
                linked_source_device,
            )
            .distinct()
        )
        if search.strip():
            stmt = stmt.where(cast(CustomerService.customer_vlan_id, String).ilike(f"%{search.strip()}%"))
        values = [int(value) for value in (await db.scalars(stmt.order_by(CustomerService.customer_vlan_id))).all()]
        rows = [TopologyFilterOption(id=str(value), label=str(value), description="Customer VLAN") for value in values]
        return _paginate_options(rows, page, page_size)

    # Device selectors are server-paged and never download the device universe.
    base = (network_ids, city_ids, location_ids, sector_ids)
    type_code = "CPE" if kind == "cpe" else "ACCESS_POINT"

    if kind == "cpe" and query.source_type == "group":
        # Group topology can render a CPE as structural context when the Group
        # contains an AP below it.  The selector must expose the same visible
        # CPE universe, not only direct/effective Group-member CPEs.
        visible_cpes = _group_visible_cpe_subquery(
            context,
            base,
            restrict_to_sectors=bool(query.sector_ids),
        )
        effective_context = effective_group_context_subquery()
        stmt = (
            select(Device.id, Device.display_name, Device.hostname)
            .join(visible_cpes, visible_cpes.c.device_id == Device.id)
            .join(effective_context, effective_context.c.device_id == Device.id)
            .join(DeviceType, DeviceType.id == Device.device_type_id)
            .where(
                Device.deleted_at.is_(None),
                DeviceType.code == "CPE",
                *_context_base_conditions(
                    effective_context,
                    base,
                    restrict_to_sectors=bool(query.sector_ids),
                ),
            )
            .distinct()
        )
    else:
        stmt = (
            select(Device.id, Device.display_name, Device.hostname)
            .join(context, context.c.device_id == Device.id)
            .join(DeviceType, DeviceType.id == Device.device_type_id)
            .where(
                Device.deleted_at.is_(None),
                DeviceType.code == type_code,
                *_context_base_conditions(
                    context,
                    base,
                    restrict_to_sectors=bool(query.sector_ids),
                ),
            )
        )
    if kind == "access_point" and query.cpe_ids:
        stmt = stmt.join(
            DeviceHierarchyLink,
            and_(
                DeviceHierarchyLink.child_device_id == Device.id,
                DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
                DeviceHierarchyLink.deleted_at.is_(None),
            ),
        ).where(DeviceHierarchyLink.parent_device_id.in_(query.cpe_ids))
    if query.customer_vlan_ids:
        stmt = stmt.join(
            CustomerService,
            and_(
                CustomerService.deleted_at.is_(None),
                CustomerService.customer_vlan_id.in_(query.customer_vlan_ids),
                or_(
                    CustomerService.cpe_device_id == Device.id,
                    CustomerService.access_point_device_id == Device.id,
                ),
            ),
        )
    if search.strip():
        sql_pattern = f"%{search.strip()}%"
        ip_match = exists(select(1).where(
            DeviceIP.device_id == Device.id,
            DeviceIP.deleted_at.is_(None),
            DeviceIP.ip_address.ilike(sql_pattern),
        ))
        stmt = stmt.where(or_(Device.display_name.ilike(sql_pattern), Device.hostname.ilike(sql_pattern), ip_match))

    stmt = stmt.distinct()
    count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())
    total = int(await db.scalar(count_stmt) or 0)
    device_rows = (await db.execute(
        stmt.order_by(Device.display_name).offset((page - 1) * page_size).limit(page_size)
    )).all()
    ips = await _management_ip_map(db, [row.id for row in device_rows])
    items = [
        TopologyFilterOption(
            id=row.id,
            label=row.display_name,
            description=" · ".join(part for part in (row.hostname, ips.get(row.id)) if part) or type_code,
        )
        for row in device_rows
    ]
    return TopologyFilterOptionPage(items=items, total=total, page=page, page_size=page_size)

