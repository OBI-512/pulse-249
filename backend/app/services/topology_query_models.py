from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
from uuid import UUID

from sqlalchemy import and_, exists, func, or_, select, union_all
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



@dataclass(slots=True)
class TopologyQuery:
    source_type: SourceType
    source_id: UUID
    network_ids: tuple[UUID, ...] = ()
    service_vlan_ids: tuple[int, ...] = ()
    city_ids: tuple[UUID, ...] = ()
    location_ids: tuple[UUID, ...] = ()
    sector_ids: tuple[UUID, ...] = ()
    customer_vlan_ids: tuple[int, ...] = ()
    cpe_ids: tuple[UUID, ...] = ()
    access_point_ids: tuple[UUID, ...] = ()
    keyword: str = ""
    # Optional request-scope envelope for a Network source.  The path sets may
    # contain read-only ancestors so a restricted user can navigate from the
    # Network root down to their assigned City/Location/Sector.  Device sets
    # remain strictly downward-authorized and therefore never widen access.
    resource_scope_restricted: bool = False
    path_network_ids: tuple[UUID, ...] = ()
    path_city_ids: tuple[UUID, ...] = ()
    path_location_ids: tuple[UUID, ...] = ()
    path_sector_ids: tuple[UUID, ...] = ()
    device_location_ids: tuple[UUID, ...] = ()
    device_sector_ids: tuple[UUID, ...] = ()


@dataclass(slots=True)
class GeographyUniverse:
    networks: dict[UUID, Network]
    cities: dict[UUID, City]
    locations: dict[UUID, Location]
    sectors: dict[UUID, Sector]

    def city_ids_for_networks(self, network_ids: set[UUID]) -> set[UUID]:
        return {row.id for row in self.cities.values() if row.network_id in network_ids}

    def location_ids_for_cities(self, city_ids: set[UUID]) -> set[UUID]:
        return {row.id for row in self.locations.values() if row.city_id in city_ids}

    def sector_ids_for_locations(self, location_ids: set[UUID]) -> set[UUID]:
        return {row.id for row in self.sectors.values() if row.location_id in location_ids}


@dataclass(slots=True)
class PathScope:
    network_ids: set[UUID] = field(default_factory=set)
    city_ids: set[UUID] = field(default_factory=set)
    location_ids: set[UUID] = field(default_factory=set)
    sector_ids: set[UUID] = field(default_factory=set)
    # When a geography/keyword branch is a subtree match, all source-eligible
    # devices below these locations/sectors remain visible.  Device-specific
    # filters override this and keep only their exact paths.
    full_device_location_ids: set[UUID] = field(default_factory=set)
    full_device_sector_ids: set[UUID] = field(default_factory=set)
    target_independent_ids: set[UUID] = field(default_factory=set)
    target_cpe_ids: set[UUID] = field(default_factory=set)
    target_ap_ids: set[UUID] = field(default_factory=set)
    restrict_devices: bool = False
    keyword_active: bool = False
