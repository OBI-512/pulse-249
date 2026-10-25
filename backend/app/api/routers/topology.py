import asyncio
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import exists, or_, select
from sqlalchemy.orm import aliased
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...security.authorization import authorize_request
from ...security.resource_scope import EffectiveResourceScope, not_found_scope_error, scope_for_actor
from ...security.scope_queries import (
    city_scope_clause, location_scope_clause, network_scope_clause, require_group,
    require_location, require_network, require_sector, sector_scope_clause,
)
from ...models import City, CustomerService, Device, DeviceGroup, DeviceGroupMembership, DeviceGroupNesting, DeviceHierarchyLink, DeviceIP, DevicePlacement, DeviceRemoteAccessProfile, DeviceType, Location, Network, Sector
from ...schemas.topology import NetworkTopology, SectorLiveTopology, TopologyFilterOptionPage, TopologyGeographyNode, TopologyHierarchyChildren, TopologyNetwork, TopologyCity, TopologyDevice, TopologyLocation, TopologyScopeOptionsRead, TopologySector, TopologyService
from ...services.crud import get_or_404
from ...services.hierarchy import EffectiveHierarchy, HierarchyValidationError, resolve_effective_hierarchy
from ...services.groups import effective_group_device_ids
from ...services.onboarding import ProbeResult, probe_icmp
from ...services.remote_access import profile_is_ready
from ...services.topology_lazy import TopologyQuery, filter_options, hierarchy_children


router = APIRouter(prefix="/topology", tags=["Topology"], dependencies=[Depends(authorize_request)])


async def _topology_network_access_envelope(db: AsyncSession, scope: EffectiveResourceScope) -> dict[str, tuple[UUID, ...] | bool]:
    """Build downward authorization plus read-only ancestor path context.

    `path_*` may contain ancestors needed to render a cascade.  `device_*` is
    the actual downward-authorized geography used to restrict device payloads.
    """
    if scope.global_access:
        return {
            "resource_scope_restricted": False,
            "path_network_ids": (), "path_city_ids": (),
            "path_location_ids": (), "path_sector_ids": (),
            "device_location_ids": (), "device_sector_ids": (),
        }

    direct_networks = set(scope.network_ids)
    direct_cities = set(scope.city_ids)
    direct_locations = set(scope.location_ids)
    direct_sectors = set(scope.sector_ids)

    device_cities = set(direct_cities)
    if direct_networks:
        device_cities.update((await db.scalars(
            select(City.id).where(City.network_id.in_(direct_networks), City.deleted_at.is_(None), City.status == "ACTIVE")
        )).all())

    device_locations = set(direct_locations)
    if device_cities:
        device_locations.update((await db.scalars(
            select(Location.id).where(Location.city_id.in_(device_cities), Location.deleted_at.is_(None), Location.status == "ACTIVE")
        )).all())

    device_sectors = set(direct_sectors)
    if device_locations:
        device_sectors.update((await db.scalars(
            select(Sector.id).where(Sector.location_id.in_(device_locations), Sector.deleted_at.is_(None), Sector.status == "ACTIVE")
        )).all())

    # Ancestor closure is navigation context only.
    path_locations = set(device_locations)
    if direct_sectors:
        path_locations.update((await db.scalars(
            select(Sector.location_id).where(Sector.id.in_(direct_sectors), Sector.deleted_at.is_(None), Sector.status == "ACTIVE")
        )).all())

    path_cities = set(device_cities)
    if path_locations:
        path_cities.update((await db.scalars(
            select(Location.city_id).where(Location.id.in_(path_locations), Location.deleted_at.is_(None), Location.status == "ACTIVE")
        )).all())

    path_networks = set(direct_networks)
    if path_cities:
        path_networks.update((await db.scalars(
            select(City.network_id).where(City.id.in_(path_cities), City.deleted_at.is_(None), City.status == "ACTIVE")
        )).all())

    return {
        "resource_scope_restricted": True,
        "path_network_ids": tuple(sorted(path_networks, key=str)),
        "path_city_ids": tuple(sorted(path_cities, key=str)),
        "path_location_ids": tuple(sorted(path_locations, key=str)),
        "path_sector_ids": tuple(sorted(device_sectors, key=str)),
        "device_location_ids": tuple(sorted(device_locations, key=str)),
        "device_sector_ids": tuple(sorted(device_sectors, key=str)),
    }


async def _topology_network_query_access(db: AsyncSession, scope: EffectiveResourceScope, network_id: UUID):
    envelope = await _topology_network_access_envelope(db, scope)
    if not envelope["resource_scope_restricted"]:
        await require_network(db, scope, network_id)
        return envelope
    if network_id not in set(envelope["path_network_ids"]):
        raise not_found_scope_error("Network")
    network = await db.scalar(select(Network.id).where(
        Network.id == network_id, Network.deleted_at.is_(None), Network.status == "ACTIVE"
    ))
    if network is None:
        raise not_found_scope_error("Network")
    return envelope


@router.get("/scope-options", response_model=TopologyScopeOptionsRead)
async def get_topology_scope_options(
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    """Return topology geography plus ancestor path context.

    Authorization still inherits downward only. Ancestors returned here are
    navigation context for read-only selectors; they do not become writable
    scope and are not accepted by require_network/require_city/etc.
    """
    scope = await scope_for_actor(db, actor)

    if scope.global_access:
        source_networks = list((await db.scalars(
            select(Network).where(Network.deleted_at.is_(None), Network.status == "ACTIVE").order_by(Network.name, Network.id)
        )).all())
        networks = source_networks
        cities = list((await db.scalars(
            select(City).where(City.deleted_at.is_(None), City.status == "ACTIVE").order_by(City.name, City.id)
        )).all())
        locations = list((await db.scalars(
            select(Location).where(Location.deleted_at.is_(None), Location.status == "ACTIVE").order_by(Location.name, Location.id)
        )).all())
        sectors = list((await db.scalars(
            select(Sector).where(Sector.deleted_at.is_(None), Sector.status == "ACTIVE").order_by(Sector.name, Sector.id)
        )).all())
    else:
        source_networks = list((await db.scalars(
            select(Network).where(
                Network.deleted_at.is_(None), Network.status == "ACTIVE", network_scope_clause(scope),
            ).order_by(Network.name, Network.id)
        )).all())

        network_context = [network_scope_clause(scope)]
        if scope.city_ids:
            network_context.append(exists(select(1).where(City.id.in_(tuple(scope.city_ids)), City.network_id == Network.id)))
        if scope.location_ids:
            network_context.append(exists(
                select(1).select_from(Location).join(City, City.id == Location.city_id).where(
                    Location.id.in_(tuple(scope.location_ids)), City.network_id == Network.id,
                )
            ))
        if scope.sector_ids:
            network_context.append(exists(
                select(1).select_from(Sector).join(Location, Location.id == Sector.location_id).join(City, City.id == Location.city_id).where(
                    Sector.id.in_(tuple(scope.sector_ids)), City.network_id == Network.id,
                )
            ))
        networks = list((await db.scalars(
            select(Network).where(
                Network.deleted_at.is_(None), Network.status == "ACTIVE", or_(*network_context),
            ).order_by(Network.name, Network.id)
        )).all())

        city_context = [city_scope_clause(scope)]
        if scope.location_ids:
            city_context.append(exists(select(1).where(Location.id.in_(tuple(scope.location_ids)), Location.city_id == City.id)))
        if scope.sector_ids:
            city_context.append(exists(
                select(1).select_from(Sector).join(Location, Location.id == Sector.location_id).where(
                    Sector.id.in_(tuple(scope.sector_ids)), Location.city_id == City.id,
                )
            ))
        cities = list((await db.scalars(
            select(City).where(
                City.deleted_at.is_(None), City.status == "ACTIVE", or_(*city_context),
            ).order_by(City.name, City.id)
        )).all())

        location_context = [location_scope_clause(scope)]
        if scope.sector_ids:
            location_context.append(exists(select(1).where(Sector.id.in_(tuple(scope.sector_ids)), Sector.location_id == Location.id)))
        locations = list((await db.scalars(
            select(Location).where(
                Location.deleted_at.is_(None), Location.status == "ACTIVE", or_(*location_context),
            ).order_by(Location.name, Location.id)
        )).all())
        sectors = list((await db.scalars(
            select(Sector).where(
                Sector.deleted_at.is_(None), Sector.status == "ACTIVE", sector_scope_clause(scope),
            ).order_by(Sector.name, Sector.id)
        )).all())

    return {
        "source_networks": source_networks,
        "networks": networks,
        "cities": cities,
        "locations": locations,
        "sectors": sectors,
    }


async def _remote_ssh_ready_ids(db: AsyncSession, device_ids: list[UUID]) -> set[UUID]:
    if not device_ids:
        return set()
    profiles = list((await db.scalars(
        select(DeviceRemoteAccessProfile).where(DeviceRemoteAccessProfile.device_id.in_(device_ids))
    )).all())
    return {profile.device_id for profile in profiles if profile_is_ready(profile)}


def make_tree(devices, links, ips, type_codes, live_states=None, remote_ssh_ready_ids=None):
    live_states = live_states or {}
    remote_ssh_ready_ids = remote_ssh_ready_ids or set()
    by_id = {
        device.id: TopologyDevice(
            id=device.id,
            display_name=device.display_name,
            device_type_id=device.device_type_id,
            device_type_code=type_codes.get(device.device_type_id, "OTHER"),
            hostname=device.hostname,
            vendor=device.vendor,
            model=device.model,
            operational_state=device.operational_state,
            lifecycle_state=device.lifecycle_state,
            management_ip=ips.get(device.id),
            management_protocol=device.management_protocol,
            remote_ssh_ready=device.id in remote_ssh_ready_ids,
            live_state=(live_states.get(device.id) or {}).get("state"),
            live_state_source=(live_states.get(device.id) or {}).get("source"),
            live_checked_at=(live_states.get(device.id) or {}).get("checked_at"),
            live_response_time_ms=(live_states.get(device.id) or {}).get("response_time_ms"),
        )
        for device in devices
    }
    for link in links:
        child = by_id.get(link.child_device_id)
        parent = by_id.get(link.parent_device_id)
        if child is not None and parent is not None:
            child.parent_device_id = parent.id
            parent.children.append(child)
    return [node for node in by_id.values() if node.parent_device_id is None]


async def _device_types(db: AsyncSession) -> dict[UUID, str]:
    rows = (await db.scalars(select(DeviceType))).all()
    return {row.id: row.code for row in rows}


async def _effective_contexts(
    db: AsyncSession,
    devices: list[Device],
) -> dict[UUID, EffectiveHierarchy]:
    """Resolve topology geography in bounded bulk queries.

    CPE and AP geography still comes from authoritative hierarchy links, not
    their compatibility DevicePlacement projection. Invalid legacy branches
    are omitted, matching resolve_effective_hierarchy semantics.
    """
    if not devices:
        return {}
    type_codes = await _device_types(db)
    ids_by_code: dict[str, list[UUID]] = {}
    for device in devices:
        ids_by_code.setdefault(type_codes.get(device.device_type_id, "OTHER"), []).append(device.id)
    contexts: dict[UUID, EffectiveHierarchy] = {}

    independent_ids = [
        device_id for code, ids in ids_by_code.items()
        if code not in {"SECTOR", "CPE", "ACCESS_POINT"}
        for device_id in ids
    ]
    if independent_ids:
        rows = (await db.execute(
            select(DevicePlacement.device_id, DevicePlacement.network_id, DevicePlacement.city_id, DevicePlacement.location_id, DevicePlacement.sector_id)
            .join(City, City.id == DevicePlacement.city_id)
            .join(Location, Location.id == DevicePlacement.location_id)
            .where(DevicePlacement.device_id.in_(independent_ids))
            .where(City.network_id == DevicePlacement.network_id, Location.city_id == DevicePlacement.city_id)
        )).all()
        for device_id, network_id, city_id, location_id, sector_id in rows:
            contexts[device_id] = EffectiveHierarchy(network_id, city_id, location_id, sector_id, "PLACEMENT")

    sector_ids = ids_by_code.get("SECTOR", [])
    if sector_ids:
        rows = (await db.execute(
            select(Sector.sector_device_id, City.network_id, City.id, Location.id, Sector.id)
            .join(Location, Location.id == Sector.location_id)
            .join(City, City.id == Location.city_id)
            .where(Sector.sector_device_id.in_(sector_ids))
        )).all()
        for device_id, network_id, city_id, location_id, sector_id in rows:
            if device_id is not None:
                contexts[device_id] = EffectiveHierarchy(network_id, city_id, location_id, sector_id, "SECTOR")

    cpe_ids = ids_by_code.get("CPE", [])
    if cpe_ids:
        rows = (await db.execute(
            select(DeviceHierarchyLink.child_device_id, City.network_id, City.id, Location.id, Sector.id)
            .join(Sector, Sector.sector_device_id == DeviceHierarchyLink.parent_device_id)
            .join(Location, Location.id == Sector.location_id)
            .join(City, City.id == Location.city_id)
            .where(DeviceHierarchyLink.child_device_id.in_(cpe_ids), DeviceHierarchyLink.relationship_type == "SECTOR_CPE")
        )).all()
        for device_id, network_id, city_id, location_id, sector_id in rows:
            contexts[device_id] = EffectiveHierarchy(network_id, city_id, location_id, sector_id, "SECTOR")

    ap_ids = ids_by_code.get("ACCESS_POINT", [])
    if ap_ids:
        CpeLink = aliased(DeviceHierarchyLink)
        rows = (await db.execute(
            select(DeviceHierarchyLink.child_device_id, City.network_id, City.id, Location.id, Sector.id)
            .join(CpeLink, (CpeLink.child_device_id == DeviceHierarchyLink.parent_device_id) & (CpeLink.relationship_type == "SECTOR_CPE"))
            .join(Sector, Sector.sector_device_id == CpeLink.parent_device_id)
            .join(Location, Location.id == Sector.location_id)
            .join(City, City.id == Location.city_id)
            .where(DeviceHierarchyLink.child_device_id.in_(ap_ids), DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT")
        )).all()
        for device_id, network_id, city_id, location_id, sector_id in rows:
            contexts[device_id] = EffectiveHierarchy(network_id, city_id, location_id, sector_id, "SECTOR")

    return contexts


def _authoritative_links(
    links: list[DeviceHierarchyLink],
    devices_by_id: dict[UUID, Device],
    type_codes: dict[UUID, str],
) -> list[DeviceHierarchyLink]:
    valid: list[DeviceHierarchyLink] = []
    for link in links:
        child = devices_by_id.get(link.child_device_id)
        parent = devices_by_id.get(link.parent_device_id)
        if child is None or parent is None:
            continue
        child_type = type_codes.get(child.device_type_id)
        parent_type = type_codes.get(parent.device_type_id)
        if link.relationship_type == "SECTOR_CPE" and child_type == "CPE" and parent_type == "SECTOR":
            valid.append(link)
        elif link.relationship_type == "CPE_ACCESS_POINT" and child_type == "ACCESS_POINT" and parent_type == "CPE":
            valid.append(link)
    return valid




LIVE_PROBE_TIMEOUT_SECONDS = 1.0
LIVE_PROBE_CONCURRENCY = 24


def _effective_live_state(device: Device, management_ip: str | None, result: ProbeResult | None) -> tuple[str, str]:
    if not management_ip:
        return "UNKNOWN", "NO_MANAGEMENT_IP"
    if result is None:
        return "UNKNOWN", "PROBE_ERROR"
    if result.reachable:
        if device.operational_state.upper() == "DEGRADED":
            return "DEGRADED", "ICMP_REACHABLE_MANUAL_DEGRADED"
        return "UP", "ICMP_REACHABLE"
    message = (result.message or "").lower()
    if "probe failed" in message or "unavailable" in message:
        return "UNKNOWN", "PROBE_ERROR"
    return "DOWN", "ICMP_UNREACHABLE"


async def _probe_live_states(devices: list[Device], ips: dict[UUID, str]) -> dict[UUID, dict[str, object]]:
    checked_at = datetime.now(timezone.utc)
    semaphore = asyncio.Semaphore(LIVE_PROBE_CONCURRENCY)

    async def probe(device: Device) -> tuple[UUID, dict[str, object]]:
        management_ip = ips.get(device.id)
        result: ProbeResult | None = None
        if management_ip:
            try:
                async with semaphore:
                    result = await probe_icmp(management_ip, LIVE_PROBE_TIMEOUT_SECONDS)
            except Exception:
                result = None
        state, source = _effective_live_state(device, management_ip, result)
        return device.id, {
            "state": state,
            "source": source,
            "checked_at": checked_at,
            "response_time_ms": result.response_time_ms if result is not None else None,
        }

    pairs = await asyncio.gather(*(probe(device) for device in devices))
    return dict(pairs)

async def _management_ips(db: AsyncSession, device_ids: list[UUID]) -> dict[UUID, str]:
    if not device_ids:
        return {}
    rows = (
        await db.scalars(
            select(DeviceIP)
            .where(DeviceIP.device_id.in_(device_ids))
            .order_by(DeviceIP.is_management.desc(), DeviceIP.is_primary.desc(), DeviceIP.id)
        )
    ).all()
    result: dict[UUID, str] = {}
    for row in rows:
        result.setdefault(row.device_id, row.ip_address)
    return result


def _topology_service(service: CustomerService) -> TopologyService:
    return TopologyService(
        id=service.id,
        service_code=service.service_code,
        customer_id=service.customer_id,
        cpe_device_id=service.cpe_device_id,
        access_point_device_id=service.access_point_device_id,
        router_device_id=service.router_device_id,
        status=service.status,
    )


async def _build_topology(
    db: AsyncSession,
    *,
    network: NetworkTopology | Network,
    cities: list[City],
    locations: list[Location],
    sectors: list[Sector],
    devices: list[Device],
    contexts: dict[UUID, EffectiveHierarchy],
    services_by_sector: dict[UUID, list[CustomerService]],
) -> NetworkTopology:
    type_codes = await _device_types(db)
    selected_devices = [device for device in devices if device.id in contexts]
    device_by_id = {device.id: device for device in selected_devices}
    device_ids = list(device_by_id)
    all_links = (
        await db.scalars(select(DeviceHierarchyLink).where(DeviceHierarchyLink.child_device_id.in_(device_ids)))
    ).all() if device_ids else []
    links = _authoritative_links(all_links, device_by_id, type_codes)
    ips = await _management_ips(db, device_ids)
    remote_ssh_ready_ids = await _remote_ssh_ready_ids(db, device_ids)

    city_nodes: list[TopologyCity] = []
    for city in cities:
        location_nodes: list[TopologyLocation] = []
        for location in [item for item in locations if item.city_id == city.id]:
            independent = [
                device
                for device in selected_devices
                if contexts[device.id].location_id == location.id
                and contexts[device.id].sector_id is None
                and type_codes.get(device.device_type_id) not in {"SECTOR", "CPE", "ACCESS_POINT"}
            ]
            sector_nodes: list[TopologySector] = []
            for sector in [item for item in sectors if item.location_id == location.id]:
                sector_devices = [
                    device for device in selected_devices
                    if contexts[device.id].sector_id == sector.id
                ]
                sector_device_ids = {device.id for device in sector_devices}
                sector_links = [
                    link for link in links
                    if link.child_device_id in sector_device_ids and link.parent_device_id in sector_device_ids
                ]
                sector_nodes.append(
                    TopologySector(
                        id=sector.id,
                        name=(device_by_id.get(sector.sector_device_id).display_name if sector.sector_device_id in device_by_id else sector.name),
                        code=sector.code,
                        sequence_number=sector.sequence_number,
                        role=sector.role,
                        devices=make_tree(sector_devices, sector_links, ips, type_codes, remote_ssh_ready_ids=remote_ssh_ready_ids),
                        services=[_topology_service(service) for service in services_by_sector.get(sector.id, [])],
                    )
                )
            independent_ids = {device.id for device in independent}
            location_nodes.append(
                TopologyLocation(
                    id=location.id,
                    name=location.name,
                    code=location.code,
                    devices=make_tree(
                        independent,
                        [
                            link for link in links
                            if link.child_device_id in independent_ids and link.parent_device_id in independent_ids
                        ],
                        ips,
                        type_codes,
                        remote_ssh_ready_ids=remote_ssh_ready_ids,
                    ),
                    sectors=sector_nodes,
                )
            )
        city_nodes.append(TopologyCity(id=city.id, name=city.name, code=city.code, locations=location_nodes))

    return NetworkTopology(id=network.id, name=network.name, code=network.code, cities=city_nodes)


@router.get("/networks/{network_id}", response_model=NetworkTopology)
async def get_network_topology(
    network_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    network = await require_network(db, scope, network_id)
    cities = (await db.scalars(select(City).where(City.network_id == network.id).order_by(City.name))).all()
    city_ids = [city.id for city in cities]
    locations = (await db.scalars(select(Location).where(Location.city_id.in_(city_ids)).order_by(Location.name))).all() if city_ids else []
    location_ids = [location.id for location in locations]
    sectors = (await db.scalars(select(Sector).where(Sector.location_id.in_(location_ids)).order_by(Sector.sequence_number, Sector.name))).all() if location_ids else []
    sector_ids = [sector.id for sector in sectors]
    services = (await db.scalars(select(CustomerService).where(CustomerService.sector_id.in_(sector_ids)))).all() if sector_ids else []
    services_by_sector: dict[UUID, list[CustomerService]] = {}
    for service in services:
        services_by_sector.setdefault(service.sector_id, []).append(service)

    # Network topology is scoped without relying only on compatibility placement rows.
    # Authoritative hierarchy links must still reconstruct SECTOR -> CPE -> AP.
    placed_device_ids = set((await db.scalars(
        select(DevicePlacement.device_id).where(DevicePlacement.network_id == network.id)
    )).all())
    sector_device_ids = {
        sector.sector_device_id for sector in sectors if sector.sector_device_id is not None
    }
    cpe_links = list((await db.scalars(
        select(DeviceHierarchyLink).where(
            DeviceHierarchyLink.parent_device_id.in_(sector_device_ids),
            DeviceHierarchyLink.relationship_type == "SECTOR_CPE",
            DeviceHierarchyLink.deleted_at.is_(None),
        )
    )).all()) if sector_device_ids else []
    cpe_ids = {link.child_device_id for link in cpe_links}
    ap_links = list((await db.scalars(
        select(DeviceHierarchyLink).where(
            DeviceHierarchyLink.parent_device_id.in_(cpe_ids),
            DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
            DeviceHierarchyLink.deleted_at.is_(None),
        )
    )).all()) if cpe_ids else []
    ap_ids = {link.child_device_id for link in ap_links}
    device_ids = placed_device_ids | sector_device_ids | cpe_ids | ap_ids
    devices = list((await db.scalars(
        select(Device).where(Device.id.in_(device_ids))
    )).all()) if device_ids else []
    all_contexts = await _effective_contexts(db, devices)
    contexts = {
        device_id: context
        for device_id, context in all_contexts.items()
        if context.network_id == network.id
    }
    return await _build_topology(
        db,
        network=network,
        cities=cities,
        locations=locations,
        sectors=sectors,
        devices=devices,
        contexts=contexts,
        services_by_sector=services_by_sector,
    )




async def _sector_tree_payload(db: AsyncSession, sector: Sector, *, live: bool) -> TopologySector:
    device_ids: list[UUID] = []
    all_links: list[DeviceHierarchyLink] = []
    if sector.sector_device_id is not None:
        device_ids.append(sector.sector_device_id)
        cpe_links = list((await db.scalars(
            select(DeviceHierarchyLink).where(
                DeviceHierarchyLink.parent_device_id == sector.sector_device_id,
                DeviceHierarchyLink.relationship_type == "SECTOR_CPE",
            )
        )).all())
        cpe_ids = [link.child_device_id for link in cpe_links]
        device_ids.extend(cpe_ids)
        ap_links = list((await db.scalars(
            select(DeviceHierarchyLink).where(
                DeviceHierarchyLink.parent_device_id.in_(cpe_ids),
                DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
            )
        )).all()) if cpe_ids else []
        device_ids.extend(link.child_device_id for link in ap_links)
        all_links = [*cpe_links, *ap_links]

    sector_devices = list((await db.scalars(select(Device).where(Device.id.in_(device_ids)))).all()) if device_ids else []
    device_by_id = {device.id: device for device in sector_devices}
    type_codes = await _device_types(db)
    links = _authoritative_links(all_links, device_by_id, type_codes)
    ips = await _management_ips(db, list(device_by_id))
    remote_ssh_ready_ids = await _remote_ssh_ready_ids(db, list(device_by_id))
    live_states = await _probe_live_states(sector_devices, ips) if live else {}
    services = list((await db.scalars(select(CustomerService).where(CustomerService.sector_id == sector.id))).all())
    physical_sector = device_by_id.get(sector.sector_device_id) if sector.sector_device_id is not None else None
    return TopologySector(
        id=sector.id, name=physical_sector.display_name if physical_sector is not None else sector.name, code=sector.code, sequence_number=sector.sequence_number, role=sector.role,
        devices=make_tree(sector_devices, links, ips, type_codes, live_states, remote_ssh_ready_ids),
        services=[_topology_service(service) for service in services],
    )


@router.get("/locations/{location_id}/devices", response_model=list[TopologyDevice])
async def get_location_topology_devices(
    location_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
    *,
    live: bool = Query(default=False),
):
    scope = await scope_for_actor(db, actor)
    await require_location(db, scope, location_id)

    # Preserve the existing hierarchy-tree contract when live=false: return
    # only independent devices placed directly at the Location.  Location
    # View opts into live=true, which adds physical sector equipment while
    # still excluding downstream CPE/AP nodes and logical Sector objects.
    direct_devices = list((await db.scalars(
        select(Device)
        .join(DevicePlacement, DevicePlacement.device_id == Device.id)
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .where(
            DevicePlacement.location_id == location_id,
            DevicePlacement.sector_id.is_(None),
            Device.deleted_at.is_(None),
        )
        .where(DeviceType.code.notin_(["SECTOR", "CPE", "ACCESS_POINT"]))
        .order_by(Device.display_name)
    )).all())

    devices_by_id = {device.id: device for device in direct_devices}
    if live:
        sector_devices = list((await db.scalars(
            select(Device)
            .join(Sector, Sector.sector_device_id == Device.id)
            .where(
                Sector.location_id == location_id,
                Sector.deleted_at.is_(None),
                Sector.status == "ACTIVE",
                Sector.sector_device_id.is_not(None),
                Device.deleted_at.is_(None),
            )
            .order_by(Device.display_name)
        )).all())
        devices_by_id.update({device.id: device for device in sector_devices})

    devices = sorted(devices_by_id.values(), key=lambda item: (item.display_name.lower(), str(item.id)))
    type_codes = await _device_types(db)
    device_ids = [device.id for device in devices]
    ips = await _management_ips(db, device_ids)
    remote_ssh_ready_ids = await _remote_ssh_ready_ids(db, device_ids)
    live_states = await _probe_live_states(devices, ips) if live else {}
    return make_tree(devices, [], ips, type_codes, live_states, remote_ssh_ready_ids)


@router.get("/sectors/{sector_id}/tree", response_model=TopologySector)
async def get_sector_topology_tree(
    sector_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    sector = await require_sector(db, scope, sector_id)
    return await _sector_tree_payload(db, sector, live=False)


@router.get("/sectors/{sector_id}", response_model=SectorLiveTopology)
async def get_sector_live_topology(
    sector_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    sector = await require_sector(db, scope, sector_id)
    location = await get_or_404(db, Location, sector.location_id)
    city = await get_or_404(db, City, location.city_id)
    network = await get_or_404(db, Network, city.network_id)
    sector_payload = await _sector_tree_payload(db, sector, live=True)
    return SectorLiveTopology(
        network=TopologyGeographyNode(id=network.id, name=network.name, code=network.code),
        city=TopologyGeographyNode(id=city.id, name=city.name, code=city.code),
        location=TopologyGeographyNode(id=location.id, name=location.name, code=location.code),
        sector=sector_payload,
    )


@router.get("/groups/{group_id}", response_model=NetworkTopology)
async def get_group_topology(
    group_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    group = await require_group(db, scope, group_id)
    member_ids = list(await effective_group_device_ids(db, group.id))
    devices = list((await db.scalars(select(Device).where(Device.id.in_(member_ids), Device.deleted_at.is_(None)))).all()) if member_ids else []
    contexts = await _effective_contexts(db, devices)
    network_ids = list({context.network_id for context in contexts.values()})
    networks = list((await db.scalars(select(Network).where(Network.id.in_(network_ids), Network.deleted_at.is_(None)).order_by(Network.name))).all()) if network_ids else []
    payload = NetworkTopology(id=group.id, name=f"Group: {group.name}", code=group.code, cities=[], networks=[])
    for network in networks:
        network_devices = [d for d in devices if contexts.get(d.id) and contexts[d.id].network_id == network.id]
        network_contexts = {d.id: contexts[d.id] for d in network_devices}
        city_ids = list({c.city_id for c in network_contexts.values()})
        location_ids = list({c.location_id for c in network_contexts.values()})
        sector_ids = list({c.sector_id for c in network_contexts.values() if c.sector_id is not None})
        cities = list((await db.scalars(select(City).where(City.id.in_(city_ids), City.deleted_at.is_(None)).order_by(City.name))).all()) if city_ids else []
        locations = list((await db.scalars(select(Location).where(Location.id.in_(location_ids), Location.deleted_at.is_(None)).order_by(Location.name))).all()) if location_ids else []
        sectors = list((await db.scalars(select(Sector).where(Sector.id.in_(sector_ids), Sector.deleted_at.is_(None)).order_by(Sector.sequence_number, Sector.name))).all()) if sector_ids else []
        built = await _build_topology(db, network=network, cities=cities, locations=locations, sectors=sectors, devices=network_devices, contexts=network_contexts, services_by_sector={})
        payload.networks.append(TopologyNetwork(id=network.id, name=network.name, code=network.code, cities=built.cities))
    return payload



@router.get("/hierarchy/options", response_model=TopologyFilterOptionPage)
async def get_topology_filter_options(
    source_type: str = Query(..., pattern="^(network|group)$"),
    source_id: UUID = Query(...),
    kind: str = Query(..., pattern="^(network|service_vlan|city|location|sector|customer_vlan|cpe|access_point)$"),
    search: str = Query(default="", max_length=160),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=50),
    network_ids: list[UUID] = Query(default=[]),
    city_ids: list[UUID] = Query(default=[]),
    location_ids: list[UUID] = Query(default=[]),
    sector_ids: list[UUID] = Query(default=[]),
    cpe_ids: list[UUID] = Query(default=[]),
    access_point_ids: list[UUID] = Query(default=[]),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
    *,
    service_vlan_ids: list[int] = Query(default=[]),
    customer_vlan_ids: list[int] = Query(default=[]),
):
    scope = await scope_for_actor(db, actor)
    network_access = {}
    if source_type == "network":
        network_access = await _topology_network_query_access(db, scope, source_id)
    else:
        await require_group(db, scope, source_id)
    query = TopologyQuery(
        source_type=source_type,  # type: ignore[arg-type]
        source_id=source_id,
        network_ids=tuple(network_ids),
        service_vlan_ids=tuple(service_vlan_ids),
        city_ids=tuple(city_ids),
        location_ids=tuple(location_ids),
        sector_ids=tuple(sector_ids),
        customer_vlan_ids=tuple(customer_vlan_ids),
        cpe_ids=tuple(cpe_ids),
        access_point_ids=tuple(access_point_ids),
        **network_access,
    )
    return await filter_options(
        db, query, kind=kind, search=search, page=page, page_size=page_size  # type: ignore[arg-type]
    )


@router.get("/hierarchy/children", response_model=TopologyHierarchyChildren)
async def get_topology_hierarchy_children(
    source_type: str = Query(..., pattern="^(network|group)$"),
    source_id: UUID = Query(...),
    node_kind: str = Query(..., pattern="^(root|network|city|location|sector|sector_device|cpe)$"),
    node_id: UUID | None = Query(default=None),
    keyword: str = Query(default="", max_length=160),
    network_ids: list[UUID] = Query(default=[]),
    city_ids: list[UUID] = Query(default=[]),
    location_ids: list[UUID] = Query(default=[]),
    sector_ids: list[UUID] = Query(default=[]),
    cpe_ids: list[UUID] = Query(default=[]),
    access_point_ids: list[UUID] = Query(default=[]),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
    *,
    service_vlan_ids: list[int] = Query(default=[]),
    customer_vlan_ids: list[int] = Query(default=[]),
):
    scope = await scope_for_actor(db, actor)
    network_access = {}
    if source_type == "network":
        network_access = await _topology_network_query_access(db, scope, source_id)
    else:
        await require_group(db, scope, source_id)
    query = TopologyQuery(
        source_type=source_type,  # type: ignore[arg-type]
        source_id=source_id,
        network_ids=tuple(network_ids),
        service_vlan_ids=tuple(service_vlan_ids),
        city_ids=tuple(city_ids),
        location_ids=tuple(location_ids),
        sector_ids=tuple(sector_ids),
        customer_vlan_ids=tuple(customer_vlan_ids),
        cpe_ids=tuple(cpe_ids),
        access_point_ids=tuple(access_point_ids),
        keyword=keyword,
        **network_access,
    )
    items = await hierarchy_children(
        db, query, node_kind=node_kind, node_id=node_id  # type: ignore[arg-type]
    )
    return TopologyHierarchyChildren(items=items)
