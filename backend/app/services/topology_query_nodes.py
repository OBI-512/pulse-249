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
    DeviceRemoteAccessProfile,
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
FilterKind = Literal["network", "city", "location", "sector", "cpe", "access_point"]
NodeKind = Literal["root", "network", "city", "location", "sector", "sector_device", "cpe"]

from .topology_query_models import TopologyQuery, PathScope
from .topology_query_context import (
    _device_context_rows, _management_ip_map, _cpe_parents_for_aps,
)
from .topology_query_scope import resolve_path_scope
from .remote_access import profile_is_ready

async def _remote_ssh_ready_map(db: AsyncSession, device_ids: list[UUID]) -> dict[UUID, bool]:
    if not device_ids:
        return {}
    profiles = list((await db.scalars(
        select(DeviceRemoteAccessProfile).where(DeviceRemoteAccessProfile.device_id.in_(device_ids))
    )).all())
    return {profile.device_id: profile_is_ready(profile) for profile in profiles}


def _device_node_payload(
    device: Device,
    type_code: str,
    management_ip: str | None,
    *,
    kind: str,
    has_children: bool,
    context_only: bool = False,
    remote_ssh_ready: bool = False,
) -> TopologyHierarchyNode:
    return TopologyHierarchyNode(
        id=device.id,
        kind=kind,
        name=device.display_name,
        code=device.hostname,
        detail=" · ".join(part for part in (management_ip, type_code, device.lifecycle_state, device.operational_state) if part),
        has_children=has_children,
        context_only=context_only,
        device_type_code=type_code,
        hostname=device.hostname,
        management_ip=management_ip,
        management_protocol=device.management_protocol,
        remote_ssh_ready=remote_ssh_ready,
        lifecycle_state=device.lifecycle_state,
        operational_state=device.operational_state,
    )


async def _device_node(db: AsyncSession, device: Device, type_code: str, *, kind: str, has_children: bool, context_only: bool = False) -> TopologyHierarchyNode:
    ips = await _management_ip_map(db, [device.id])
    ready = await _remote_ssh_ready_map(db, [device.id])
    return _device_node_payload(
        device, type_code, ips.get(device.id), kind=kind, has_children=has_children,
        context_only=context_only, remote_ssh_ready=ready.get(device.id, False),
    )


async def _location_independent_nodes(db: AsyncSession, query: TopologyQuery, context, scope: PathScope, location_id: UUID) -> list[TopologyHierarchyNode]:
    base = (scope.network_ids, scope.city_ids, {location_id}, scope.sector_ids)
    rows = await _device_context_rows(
        db,
        context,
        base,
        type_codes=("SWITCH", "ROUTER", "FIREWALL", "SERVER", "WIRELESS_BRIDGE", "NETWORK_DEVICE", "OTHER"),
    )
    candidates = [row for row in rows if row.location_id == location_id and row.sector_id is None]
    if scope.restrict_devices and location_id not in scope.full_device_location_ids:
        candidates = [row for row in candidates if row.id in scope.target_independent_ids]
    if not candidates:
        return []
    devices = list((await db.scalars(select(Device).where(Device.id.in_([row.id for row in candidates])))).all())
    by_id = {row.id: row for row in devices}
    ips = await _management_ip_map(db, list(by_id))
    remote_ready = await _remote_ssh_ready_map(db, list(by_id))
    result = []
    for row in sorted(candidates, key=lambda item: item.display_name.casefold()):
        device = by_id.get(row.id)
        if device is not None:
            result.append(_device_node_payload(
                device, row.type_code, ips.get(device.id), kind="device", has_children=False,
                remote_ssh_ready=remote_ready.get(device.id, False),
            ))
    return result


async def _sector_members(db: AsyncSession, query: TopologyQuery, context, scope: PathScope, sector: Sector):
    base = (scope.network_ids, scope.city_ids, scope.location_ids, {sector.id})
    full_branch = (not scope.restrict_devices) or sector.id in scope.full_device_sector_ids

    if full_branch:
        if query.source_type == "network":
            source_rows = await _device_context_rows(
                db, context, base, type_codes=("SECTOR", "CPE", "ACCESS_POINT"), restrict_to_sectors=True
            )
            member_ids = {row.id for row in source_rows if row.sector_id == sector.id}
        else:
            source_rows = await _device_context_rows(
                db, context, base, type_codes=("SECTOR", "CPE", "ACCESS_POINT"), restrict_to_sectors=True
            )
            member_ids = {row.id for row in source_rows if row.sector_id == sector.id}
        target_cpes = {
            row.id for row in source_rows if row.sector_id == sector.id and row.type_code == "CPE"
        }
        target_aps = {
            row.id for row in source_rows if row.sector_id == sector.id and row.type_code == "ACCESS_POINT"
        }
        # AP membership needs its CPE structural ancestor even when that CPE is
        # not itself a group member.
        target_cpes |= await _cpe_parents_for_aps(db, context, base, target_aps)
    else:
        member_ids = set()
        target_cpes = set(scope.target_cpe_ids)
        target_aps = set(scope.target_ap_ids)
        target_cpes |= await _cpe_parents_for_aps(db, context, base, target_aps)

    # Keep only devices whose authoritative sector is this sector.
    validation_context = effective_group_context_subquery() if query.source_type == "group" else context
    if target_cpes:
        cpe_rows = await _device_context_rows(
            db, validation_context, base, type_codes=("CPE",), ids=target_cpes, restrict_to_sectors=True
        )
        target_cpes = {row.id for row in cpe_rows if row.sector_id == sector.id}
    if target_aps:
        ap_rows = await _device_context_rows(
            db, context, base, type_codes=("ACCESS_POINT",), ids=target_aps, restrict_to_sectors=True
        )
        target_aps = {row.id for row in ap_rows if row.sector_id == sector.id}

    if query.source_type == "network" and full_branch and sector.sector_device_id is not None:
        member_ids.add(sector.sector_device_id)
    include_sector_device = bool(
        sector.sector_device_id
        and (sector.sector_device_id in member_ids or target_cpes or target_aps)
    )
    return member_ids, target_cpes, target_aps, include_sector_device


async def hierarchy_children(db: AsyncSession, query: TopologyQuery, *, node_kind: NodeKind, node_id: UUID | None) -> list[TopologyHierarchyNode]:
    context, universe, scope = await resolve_path_scope(db, query)

    if node_kind == "root":
        if query.source_type == "network":
            rows = [
                row for row in universe.cities.values()
                if row.network_id == query.source_id and row.id in scope.city_ids
            ]
            return [
                TopologyHierarchyNode(id=row.id, kind="city", name=row.name, code=row.code, detail=row.code, has_children=True)
                for row in sorted(rows, key=lambda item: item.name.casefold())
            ]
        rows = [universe.networks[item] for item in scope.network_ids if item in universe.networks]
        return [
            TopologyHierarchyNode(id=row.id, kind="network", name=row.name, code=row.code, detail=row.code, has_children=True)
            for row in sorted(rows, key=lambda item: item.name.casefold())
        ]

    if node_id is None:
        return []

    if node_kind == "network":
        rows = [row for row in universe.cities.values() if row.network_id == node_id and row.id in scope.city_ids]
        return [TopologyHierarchyNode(id=row.id, kind="city", name=row.name, code=row.code, detail=row.code, has_children=True) for row in sorted(rows, key=lambda item: item.name.casefold())]

    if node_kind == "city":
        rows = [row for row in universe.locations.values() if row.city_id == node_id and row.id in scope.location_ids]
        return [TopologyHierarchyNode(id=row.id, kind="location", name=row.name, code=row.code, detail=row.code, has_children=True) for row in sorted(rows, key=lambda item: item.name.casefold())]

    if node_kind == "location":
        if node_id not in scope.location_ids:
            return []
        independent = await _location_independent_nodes(db, query, context, scope, node_id)
        sectors = [row for row in universe.sectors.values() if row.location_id == node_id and row.id in scope.sector_ids]
        physical_names: dict[UUID, str] = {}
        sector_device_ids = [row.sector_device_id for row in sectors if row.sector_device_id is not None]
        if sector_device_ids:
            devices = list((await db.scalars(select(Device).where(Device.id.in_(sector_device_ids), Device.deleted_at.is_(None)))).all())
            physical_names = {device.id: device.display_name for device in devices}
        sector_nodes = [
            TopologyHierarchyNode(
                id=row.id,
                kind="sector",
                name=physical_names.get(row.sector_device_id) or row.name,
                code=row.code,
                detail=f"{row.code} · {row.role}",
                has_children=True,
            )
            for row in sorted(sectors, key=lambda item: ((item.sequence_number or 0), item.name.casefold()))
        ]
        return [*independent, *sector_nodes]

    if node_kind == "sector":
        sector = universe.sectors.get(node_id)
        if sector is None or sector.id not in scope.sector_ids:
            return []
        member_ids, target_cpes, target_aps, include_sector_device = await _sector_members(db, query, context, scope, sector)
        if not include_sector_device or sector.sector_device_id is None:
            return []
        device = await db.scalar(select(Device).where(Device.id == sector.sector_device_id, Device.deleted_at.is_(None)))
        if device is None:
            return []
        context_only = query.source_type == "group" and device.id not in member_ids
        return [await _device_node(db, device, "SECTOR", kind="sector_device", has_children=bool(target_cpes or target_aps), context_only=context_only)]

    if node_kind == "sector_device":
        sector = await db.scalar(select(Sector).where(Sector.sector_device_id == node_id, Sector.deleted_at.is_(None)))
        if sector is None or sector.id not in scope.sector_ids:
            return []
        member_ids, target_cpes, target_aps, _ = await _sector_members(db, query, context, scope, sector)
        if not target_cpes:
            return []
        devices = list((await db.scalars(select(Device).where(Device.id.in_(target_cpes), Device.deleted_at.is_(None)))).all())
        child_parent_ids: set[UUID] = set()
        if target_aps:
            child_parent_ids = set((await db.scalars(
                select(DeviceHierarchyLink.parent_device_id).where(
                    DeviceHierarchyLink.parent_device_id.in_(target_cpes),
                    DeviceHierarchyLink.child_device_id.in_(target_aps),
                    DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
                    DeviceHierarchyLink.deleted_at.is_(None),
                )
            )).all())
        device_ids = [device.id for device in devices]
        ips = await _management_ip_map(db, device_ids)
        remote_ready = await _remote_ssh_ready_map(db, device_ids)
        result = []
        for device in sorted(devices, key=lambda item: item.display_name.casefold()):
            context_only = query.source_type == "group" and device.id not in member_ids
            result.append(_device_node_payload(
                device, "CPE", ips.get(device.id), kind="cpe",
                has_children=device.id in child_parent_ids, context_only=context_only,
                remote_ssh_ready=remote_ready.get(device.id, False),
            ))
        return result

    if node_kind == "cpe":
        if not scope.target_ap_ids and scope.restrict_devices:
            return []
        link_stmt = select(DeviceHierarchyLink.child_device_id).where(
            DeviceHierarchyLink.parent_device_id == node_id,
            DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
            DeviceHierarchyLink.deleted_at.is_(None),
        )
        ap_ids = set((await db.scalars(link_stmt)).all())
        if scope.restrict_devices:
            ap_ids &= scope.target_ap_ids
        else:
            # For group mode, only group-eligible APs are shown.  For network
            # mode the source context already contains all APs in the network.
            base = (scope.network_ids, scope.city_ids, scope.location_ids, scope.sector_ids)
            rows = await _device_context_rows(db, context, base, type_codes=("ACCESS_POINT",), ids=ap_ids)
            ap_ids = {row.id for row in rows}
        if not ap_ids:
            return []
        devices = list((await db.scalars(select(Device).where(Device.id.in_(ap_ids), Device.deleted_at.is_(None)))).all())
        device_ids = [device.id for device in devices]
        ips = await _management_ip_map(db, device_ids)
        remote_ready = await _remote_ssh_ready_map(db, device_ids)
        return [
            _device_node_payload(
                device, "ACCESS_POINT", ips.get(device.id), kind="access_point", has_children=False,
                remote_ssh_ready=remote_ready.get(device.id, False),
            )
            for device in sorted(devices, key=lambda item: item.display_name.casefold())
        ]

    return []
