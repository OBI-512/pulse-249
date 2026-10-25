from __future__ import annotations

from uuid import UUID

from sqlalchemy import and_, literal, select, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import (
    Device,
    DeviceGroup,
    DeviceGroupMembership,
    DeviceGroupNesting,
    DeviceGroupScope,
    DeviceHierarchyLink,
    DevicePlacement,
    DeviceType, Sector, City, Location,
)
from .hierarchy import HierarchyValidationError, resolve_effective_hierarchy
from .crud import lock_active_rows
from .audit import record_audit
from .audit_summaries import business_summary, display_snapshot

from .group_nesting import descendant_group_ids

def effective_group_context_subquery():
    """Return authoritative effective geography for dynamic group evaluation.

    Independent devices use active DevicePlacement. Physical SECTOR devices are
    resolved through the logical Sector binding. CPE/AP geography is derived
    exclusively from active DeviceHierarchyLink relationships.
    """
    independent = (
        select(
            Device.id.label("device_id"),
            DevicePlacement.network_id.label("network_id"),
            DevicePlacement.city_id.label("city_id"),
            DevicePlacement.location_id.label("location_id"),
            literal(None).cast(Sector.id.type).label("sector_id"),
            literal(None).cast(Sector.role.type).label("sector_role"),
        )
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .join(
            DevicePlacement,
            and_(
                DevicePlacement.device_id == Device.id,
                DevicePlacement.deleted_at.is_(None),
            ),
        )
        .where(
            Device.deleted_at.is_(None),
            DeviceType.code.notin_(("SECTOR", "CPE", "ACCESS_POINT")),
        )
    )

    sector_devices = (
        select(
            Device.id.label("device_id"),
            City.network_id.label("network_id"),
            Location.city_id.label("city_id"),
            Sector.location_id.label("location_id"),
            Sector.id.label("sector_id"),
            Sector.role.label("sector_role"),
        )
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .join(
            Sector,
            and_(
                Sector.sector_device_id == Device.id,
                Sector.deleted_at.is_(None),
            ),
        )
        .join(
            Location,
            and_(Location.id == Sector.location_id, Location.deleted_at.is_(None)),
        )
        .join(City, and_(City.id == Location.city_id, City.deleted_at.is_(None)))
        .where(Device.deleted_at.is_(None), DeviceType.code == "SECTOR")
    )

    cpe_link = DeviceHierarchyLink.__table__.alias("group_cpe_link")
    cpe_devices = (
        select(
            Device.id.label("device_id"),
            City.network_id.label("network_id"),
            Location.city_id.label("city_id"),
            Sector.location_id.label("location_id"),
            Sector.id.label("sector_id"),
            Sector.role.label("sector_role"),
        )
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .join(
            cpe_link,
            and_(
                cpe_link.c.child_device_id == Device.id,
                cpe_link.c.relationship_type == "SECTOR_CPE",
                cpe_link.c.deleted_at.is_(None),
            ),
        )
        .join(
            Sector,
            and_(
                Sector.sector_device_id == cpe_link.c.parent_device_id,
                Sector.deleted_at.is_(None),
            ),
        )
        .join(
            Location,
            and_(Location.id == Sector.location_id, Location.deleted_at.is_(None)),
        )
        .join(City, and_(City.id == Location.city_id, City.deleted_at.is_(None)))
        .where(Device.deleted_at.is_(None), DeviceType.code == "CPE")
    )

    ap_link = DeviceHierarchyLink.__table__.alias("group_ap_link")
    ap_sector_link = DeviceHierarchyLink.__table__.alias("group_ap_sector_link")
    ap_devices = (
        select(
            Device.id.label("device_id"),
            City.network_id.label("network_id"),
            Location.city_id.label("city_id"),
            Sector.location_id.label("location_id"),
            Sector.id.label("sector_id"),
            Sector.role.label("sector_role"),
        )
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .join(
            ap_link,
            and_(
                ap_link.c.child_device_id == Device.id,
                ap_link.c.relationship_type == "CPE_ACCESS_POINT",
                ap_link.c.deleted_at.is_(None),
            ),
        )
        .join(
            ap_sector_link,
            and_(
                ap_sector_link.c.child_device_id == ap_link.c.parent_device_id,
                ap_sector_link.c.relationship_type == "SECTOR_CPE",
                ap_sector_link.c.deleted_at.is_(None),
            ),
        )
        .join(
            Sector,
            and_(
                Sector.sector_device_id == ap_sector_link.c.parent_device_id,
                Sector.deleted_at.is_(None),
            ),
        )
        .join(
            Location,
            and_(Location.id == Sector.location_id, Location.deleted_at.is_(None)),
        )
        .join(City, and_(City.id == Location.city_id, City.deleted_at.is_(None)))
        .where(Device.deleted_at.is_(None), DeviceType.code == "ACCESS_POINT")
    )

    return union_all(
        independent, sector_devices, cpe_devices, ap_devices
    ).subquery("effective_group_context")


def direct_group_device_select(group: DeviceGroup):
    """Build a one-column SQL select for a group's direct device population."""
    if getattr(group, "membership_mode", "MANUAL") == "MANUAL":
        return (
            select(Device.id.label("device_id"))
            .join(
                DeviceGroupMembership,
                and_(
                    DeviceGroupMembership.device_id == Device.id,
                    DeviceGroupMembership.deleted_at.is_(None),
                ),
            )
            .where(
                DeviceGroupMembership.group_id == group.id,
                Device.deleted_at.is_(None),
            )
        )

    stmt = (
        select(Device.id.label("device_id"))
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .where(Device.deleted_at.is_(None))
    )
    if group.device_scope != "ANY":
        stmt = stmt.where(DeviceType.code == group.device_scope)

    if group.scope_type != "GLOBAL" or group.sector_role is not None:
        context = effective_group_context_subquery()
        stmt = stmt.join(context, context.c.device_id == Device.id)
        if group.scope_type == "NETWORK":
            stmt = stmt.where(context.c.network_id == group.network_id)
        elif group.scope_type == "CITY":
            stmt = stmt.where(context.c.city_id == group.city_id)
        elif group.scope_type == "LOCATION":
            stmt = stmt.where(context.c.location_id == group.location_id)
        elif group.scope_type == "SECTOR":
            stmt = stmt.where(context.c.sector_id == group.sector_id)
        if group.sector_role is not None:
            stmt = stmt.where(context.c.sector_role == group.sector_role)
    return stmt


async def effective_group_population_subquery(db: AsyncSession, group_id: UUID):
    """Return a SQL subquery for effective device membership without materializing device ids."""
    group_ids = {group_id, *(await descendant_group_ids(db, group_id))}
    groups = list((await db.scalars(
        select(DeviceGroup).where(
            DeviceGroup.id.in_(group_ids),
            DeviceGroup.deleted_at.is_(None),
        )
    )).all())
    if not groups:
        return select(Device.id.label("device_id")).where(literal(False)).subquery("effective_group_devices")
    populations = [direct_group_device_select(group) for group in groups]
    return (
        union_all(*populations).subquery("effective_group_devices")
        if len(populations) > 1
        else populations[0].subquery("effective_group_devices")
    )


async def effective_group_population_context_subquery(db: AsyncSession, group_id: UUID):
    """Return effective device geography restricted to a group's effective population."""
    population = await effective_group_population_subquery(db, group_id)
    context = effective_group_context_subquery()
    return (
        select(
            context.c.device_id, context.c.network_id, context.c.city_id,
            context.c.location_id, context.c.sector_id, context.c.sector_role,
        )
        .select_from(context)
        .join(population, population.c.device_id == context.c.device_id)
        .distinct()
        .subquery("effective_group_population_context")
    )


async def effective_group_device_ids(db: AsyncSession, group_id: UUID) -> set[UUID]:
    """Return unique effective devices for manual or dynamic nested groups.

    This is the shared group-population contract used by Devices, Topology,
    and other existing views. Dynamic groups are evaluated at query time; no
    synthetic DeviceGroupMembership rows are created.
    """
    group_ids = {group_id, *(await descendant_group_ids(db, group_id))}
    groups = list((await db.scalars(
        select(DeviceGroup).where(
            DeviceGroup.id.in_(group_ids),
            DeviceGroup.deleted_at.is_(None),
        )
    )).all())
    if not groups:
        return set()

    populations = [direct_group_device_select(group) for group in groups]
    population = (
        union_all(*populations).subquery("effective_group_devices")
        if len(populations) > 1
        else populations[0].subquery("effective_group_devices")
    )
    return set((await db.scalars(
        select(population.c.device_id).distinct()
    )).all())
