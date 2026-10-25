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

from .group_common import get_group

def _group_scope_rank(scope: str) -> int:
    return {"GLOBAL": 0, "NETWORK": 1, "CITY": 2, "LOCATION": 3, "SECTOR": 4}[scope]


async def _group_context_lineage(db: AsyncSession, group: DeviceGroup) -> dict[str, UUID | None]:
    """Resolve a group's organizational context to a comparable lineage."""
    lineage = {"NETWORK": None, "CITY": None, "LOCATION": None, "SECTOR": None}
    if group.scope_type == "GLOBAL":
        return lineage
    if group.scope_type == "NETWORK":
        lineage["NETWORK"] = group.network_id
        return lineage
    if group.scope_type == "CITY":
        city = await db.scalar(select(City).where(City.id == group.city_id, City.deleted_at.is_(None)))
        if city is None: raise ValueError("GROUP_CONTEXT_INVALID")
        lineage.update(NETWORK=city.network_id, CITY=city.id)
        return lineage
    if group.scope_type == "LOCATION":
        location = await db.scalar(select(Location).where(Location.id == group.location_id, Location.deleted_at.is_(None)))
        if location is None: raise ValueError("GROUP_CONTEXT_INVALID")
        city = await db.scalar(select(City).where(City.id == location.city_id, City.deleted_at.is_(None)))
        if city is None: raise ValueError("GROUP_CONTEXT_INVALID")
        lineage.update(NETWORK=city.network_id, CITY=city.id, LOCATION=location.id)
        return lineage
    sector = await db.scalar(select(Sector).where(Sector.id == group.sector_id, Sector.deleted_at.is_(None)))
    if sector is None: raise ValueError("GROUP_CONTEXT_INVALID")
    location = await db.scalar(select(Location).where(Location.id == sector.location_id, Location.deleted_at.is_(None)))
    if location is None: raise ValueError("GROUP_CONTEXT_INVALID")
    city = await db.scalar(select(City).where(City.id == location.city_id, City.deleted_at.is_(None)))
    if city is None: raise ValueError("GROUP_CONTEXT_INVALID")
    lineage.update(NETWORK=city.network_id, CITY=city.id, LOCATION=location.id, SECTOR=sector.id)
    return lineage


async def validate_group_nesting(db: AsyncSession, parent: DeviceGroup, child: DeviceGroup) -> None:
    if getattr(parent, "group_kind", "CUSTOM") == "SYSTEM" or getattr(child, "group_kind", "CUSTOM") == "SYSTEM":
        raise ValueError("GROUP_SYSTEM_NESTING_NOT_ALLOWED")
    if parent.id == child.id:
        raise ValueError("GROUP_NESTING_SELF")
    if parent.device_scope != "ANY" and parent.device_scope != child.device_scope:
        raise ValueError("GROUP_NESTING_DEVICE_SCOPE_MISMATCH")
    if parent.sector_role is not None and parent.sector_role != child.sector_role:
        raise ValueError("GROUP_NESTING_SECTOR_ROLE_MISMATCH")
    if _group_scope_rank(child.scope_type) < _group_scope_rank(parent.scope_type):
        raise ValueError("GROUP_NESTING_SCOPE_TOO_BROAD")
    parent_lineage = await _group_context_lineage(db, parent)
    child_lineage = await _group_context_lineage(db, child)
    if parent.scope_type != "GLOBAL":
        key = parent.scope_type
        if parent_lineage[key] != child_lineage[key]:
            raise ValueError("GROUP_NESTING_CONTEXT_MISMATCH")

    # Cycle check: child must not already be an ancestor of parent.
    cursor = parent.id
    seen: set[UUID] = set()
    while cursor not in seen:
        seen.add(cursor)
        link = await db.scalar(select(DeviceGroupNesting).where(
            DeviceGroupNesting.child_group_id == cursor,
            DeviceGroupNesting.deleted_at.is_(None),
        ))
        if link is None:
            break
        if link.parent_group_id == child.id:
            raise ValueError("GROUP_NESTING_CYCLE")
        cursor = link.parent_group_id


async def add_child_group(db: AsyncSession, parent_group_id: UUID, child_group_id: UUID) -> DeviceGroupNesting:
    groups = await lock_active_rows(db, DeviceGroup, (parent_group_id, child_group_id))
    parent, child = groups.get(parent_group_id), groups.get(child_group_id)
    if parent is None or child is None:
        raise ValueError("GROUP_NOT_FOUND")
    existing = await db.scalar(select(DeviceGroupNesting).where(
        DeviceGroupNesting.child_group_id == child_group_id,
        DeviceGroupNesting.deleted_at.is_(None),
    ))
    if existing is not None:
        raise ValueError("GROUP_CHILD_ALREADY_HAS_PARENT")
    await validate_group_nesting(db, parent, child)
    link = DeviceGroupNesting(parent_group_id=parent_group_id, child_group_id=child_group_id)
    db.add(link); await db.flush()
    await record_audit(db, action="GROUP_CHILD_ADDED", entity_type="DeviceGroupNesting", entity_id=link.id,
        description="Child group added to organizational group.", entity_display_snapshot=display_snapshot(link), after_summary=business_summary(link))
    return link


async def remove_child_group(db: AsyncSession, parent_group_id: UUID, child_group_id: UUID) -> None:
    link = await db.scalar(select(DeviceGroupNesting).where(
        DeviceGroupNesting.parent_group_id == parent_group_id,
        DeviceGroupNesting.child_group_id == child_group_id,
        DeviceGroupNesting.deleted_at.is_(None),
    ).with_for_update())
    if link is None:
        raise ValueError("GROUP_NESTING_NOT_FOUND")
    before = business_summary(link)
    await record_audit(db, action="GROUP_CHILD_REMOVED", entity_type="DeviceGroupNesting", entity_id=link.id,
        description="Child group removed from organizational group.", entity_display_snapshot=display_snapshot(link), before_summary=before)
    await db.delete(link)


async def replace_child_groups(db: AsyncSession, parent_group_id: UUID, child_group_ids: list[UUID]) -> None:
    """Replace a custom group's direct children as one validated unit of work.

    The caller owns the surrounding transaction. All requested additions are
    validated before any existing relationship is removed, so an invalid
    candidate cannot leave the parent with a partially-updated child set.
    """
    desired = list(dict.fromkeys(child_group_ids))
    if parent_group_id in desired:
        raise ValueError("GROUP_NESTING_SELF")

    groups = await lock_active_rows(db, DeviceGroup, (parent_group_id, *desired))
    parent = groups.get(parent_group_id)
    if parent is None:
        raise ValueError("GROUP_NOT_FOUND")
    if getattr(parent, "group_kind", "CUSTOM") == "SYSTEM":
        raise ValueError("GROUP_SYSTEM_NESTING_NOT_ALLOWED")
    missing = [child_id for child_id in desired if child_id not in groups]
    if missing:
        raise ValueError("GROUP_NOT_FOUND")

    current_links = list((await db.scalars(
        select(DeviceGroupNesting)
        .where(
            DeviceGroupNesting.parent_group_id == parent_group_id,
            DeviceGroupNesting.deleted_at.is_(None),
        )
        .with_for_update()
    )).all())
    current_ids = {link.child_group_id for link in current_links}

    if desired:
        other_parent_rows = (await db.execute(
            select(DeviceGroupNesting.child_group_id, DeviceGroupNesting.parent_group_id).where(
                DeviceGroupNesting.child_group_id.in_(desired),
                DeviceGroupNesting.deleted_at.is_(None),
            )
        )).all()
        for child_id, existing_parent_id in other_parent_rows:
            if existing_parent_id != parent_group_id:
                raise ValueError("GROUP_CHILD_ALREADY_HAS_PARENT")

    for child_id in desired:
        await validate_group_nesting(db, parent, groups[child_id])

    for child_id in current_ids - set(desired):
        await remove_child_group(db, parent_group_id, child_id)
    for child_id in set(desired) - current_ids:
        await add_child_group(db, parent_group_id, child_id)


async def descendant_group_ids(db: AsyncSession, group_id: UUID) -> set[UUID]:
    result: set[UUID] = set()
    frontier = {group_id}
    while frontier:
        rows = (await db.execute(select(DeviceGroupNesting.child_group_id).where(
            DeviceGroupNesting.parent_group_id.in_(frontier), DeviceGroupNesting.deleted_at.is_(None)
        ))).scalars().all()
        nxt = set(rows) - result
        result.update(nxt); frontier = nxt
    return result

