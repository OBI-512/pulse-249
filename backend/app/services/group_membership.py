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

from .group_common import GroupMembershipConflict, get_group, get_device, group_context_key

async def find_conflicting_membership(
    db: AsyncSession,
    device_id: UUID,
    destination_group: DeviceGroup,
) -> DeviceGroup | None:
    """
    Find an existing membership that conflicts with the destination group.

    Membership rules:

    1. A device may belong to multiple organizational groups.
    2. A device may belong to groups at different organizational scopes.
    3. For a scoped context, a device may belong to only one group in
       that exact scope + context.
    4. GLOBAL groups are not subject to scoped exclusivity.
    5. The physical placement of the device is irrelevant here.
    """

    destination_scope, destination_context = group_context_key(
        destination_group
    )

    if destination_scope == DeviceGroupScope.GLOBAL.value:
        return None

    result = await db.execute(
        select(DeviceGroup)
        .join(
            DeviceGroupMembership,
            DeviceGroupMembership.group_id == DeviceGroup.id,
        )
        .where(
            DeviceGroupMembership.device_id == device_id,
            DeviceGroup.scope_type == destination_scope,
        )
    )

    existing_groups = result.scalars().all()

    for existing_group in existing_groups:
        existing_scope, existing_context = group_context_key(
            existing_group
        )

        if (
            existing_scope == destination_scope
            and existing_context == destination_context
            and existing_group.id != destination_group.id
        ):
            return existing_group

    return None


async def validate_membership(
    db: AsyncSession,
    device_id: UUID,
    group_id: UUID,
) -> tuple[Device, DeviceGroup]:
    """
    Validate that the device and destination group exist and that the
    membership is semantically valid.

    Membership does not alter physical placement or hierarchy. Scoped groups
    do, however, validate the device's effective organizational context. For
    CPE/AP this context is derived from DeviceHierarchyLink, never from the
    compatibility placement projection.
    """

    devices = await lock_active_rows(db, Device, (device_id,))
    device = devices.get(device_id)

    if device is None:
        raise ValueError(
            "DEVICE_NOT_FOUND"
        )

    groups = await lock_active_rows(db, DeviceGroup, (group_id,))
    group = groups.get(group_id)

    if group is None:
        raise ValueError(
            "GROUP_NOT_FOUND"
        )

    if getattr(group, "group_kind", "CUSTOM") == "SYSTEM" or getattr(group, "membership_mode", "MANUAL") != "MANUAL":
        raise ValueError("GROUP_MEMBERSHIP_NOT_MANUAL")

    type_code = await db.scalar(select(DeviceType.code).where(DeviceType.id == device.device_type_id))
    if group.device_scope != "ANY" and group.device_scope != type_code:
        raise ValueError("GROUP_DEVICE_TYPE_MISMATCH")
    # A global, unrestricted group deliberately remains usable for devices that
    # have no physical placement.  Scoped groups and sector-role groups require
    # an effective hierarchy; CPE/AP obtain it through their authoritative
    # parent links rather than copied placement columns.
    hierarchy = None
    if group.scope_type != "GLOBAL" or group.sector_role is not None:
        try:
            hierarchy = await resolve_effective_hierarchy(db, device)
        except HierarchyValidationError as exc:
            raise ValueError("GROUP_HIERARCHY_INVALID") from exc

    if group.scope_type == "NETWORK" and hierarchy.network_id != group.network_id:
        raise ValueError("GROUP_NETWORK_SCOPE_MISMATCH")
    if group.scope_type == "CITY" and hierarchy.city_id != group.city_id:
        raise ValueError("GROUP_CITY_SCOPE_MISMATCH")
    if group.scope_type == "LOCATION" and hierarchy.location_id != group.location_id:
        raise ValueError("GROUP_LOCATION_SCOPE_MISMATCH")
    if group.scope_type == "SECTOR" and hierarchy.sector_id != group.sector_id:
        raise ValueError("GROUP_SECTOR_SCOPE_MISMATCH")
    if group.sector_role is not None:
        if type_code != "SECTOR" or hierarchy.sector_id is None:
            raise ValueError("GROUP_SECTOR_ROLE_MISMATCH")
        sector = await db.scalar(select(Sector).where(Sector.id == hierarchy.sector_id))
        if sector is None or sector.role != group.sector_role:
            raise ValueError("GROUP_SECTOR_ROLE_MISMATCH")

    return device, group


async def get_existing_membership(
    db: AsyncSession,
    device_id: UUID,
    group_id: UUID,
    *,
    for_update: bool = False,
) -> DeviceGroupMembership | None:
    statement = select(DeviceGroupMembership).where(
            DeviceGroupMembership.device_id == device_id,
            DeviceGroupMembership.group_id == group_id,
        )
    if for_update:
        statement = (
            statement.with_for_update()
            .execution_options(populate_existing=True)
        )
    result = await db.execute(statement)

    return result.scalar_one_or_none()


async def _lock_membership_state(
    db: AsyncSession,
    device_ids: list[UUID] | tuple[UUID, ...],
    *,
    extra_group_ids: list[UUID] | tuple[UUID, ...] = (),
) -> tuple[
    dict[UUID, Device],
    dict[UUID, DeviceGroup],
    list[DeviceGroupMembership],
]:
    """Lock active membership context as Device -> Groups -> memberships.

    Group recycle uses Group -> memberships.  Taking all group locks in UUID
    order before any membership row prevents detach/move/reconcile from hard
    deleting a bundle item after another transaction has tombstoned it.
    """

    devices = await lock_active_rows(db, Device, device_ids)
    if not devices:
        return {}, {}, []
    probes = (
        await db.execute(
            select(
                DeviceGroupMembership.id,
                DeviceGroupMembership.device_id,
                DeviceGroupMembership.group_id,
            )
            .where(DeviceGroupMembership.device_id.in_(devices))
            .order_by(DeviceGroupMembership.id)
        )
    ).all()
    group_ids = {row.group_id for row in probes} | set(extra_group_ids)
    groups = await lock_active_rows(db, DeviceGroup, group_ids)
    memberships_by_id = await lock_active_rows(
        db,
        DeviceGroupMembership,
        [row.id for row in probes],
    )
    memberships = [
        membership
        for row in probes
        if (membership := memberships_by_id.get(row.id)) is not None
        and membership.device_id == row.device_id
        and membership.group_id == row.group_id
        and membership.group_id in groups
    ]
    return devices, groups, memberships


async def add_membership(
    db: AsyncSession,
    device_id: UUID,
    group_id: UUID,
) -> DeviceGroupMembership:
    """
    Add an organizational membership.

    This operation only changes DeviceGroupMembership.

    It does NOT change:
        - DevicePlacement
        - DeviceRelationship
        - CustomerService
        - Device classification
        - Device identity
    """

    _, group = await validate_membership(
        db,
        device_id,
        group_id,
    )

    existing = await get_existing_membership(
        db,
        device_id,
        group_id,
    )

    if existing is not None:
        raise ValueError(
            "MEMBERSHIP_EXISTS"
        )

    conflicting_group = await find_conflicting_membership(
        db,
        device_id,
        group,
    )

    if conflicting_group is not None:
        raise GroupMembershipConflict(
            conflicting_group
        )

    membership = DeviceGroupMembership(
        device_id=device_id,
        group_id=group_id,
    )

    db.add(membership)
    await db.flush()
    await record_audit(
        db,
        action="GROUP_MEMBERSHIP_ADDED",
        entity_type="DeviceGroupMembership",
        entity_id=membership.id,
        description="Device added to a group.",
        entity_display_snapshot=display_snapshot(membership),
        after_summary=business_summary(membership),
    )

    return membership


async def move_membership(
    db: AsyncSession,
    device_id: UUID,
    destination_group_id: UUID,
) -> DeviceGroupMembership:
    """
    Move a device into a destination organizational group.

    The move replaces an existing membership only when that membership
    occupies the same organizational scope + exact organizational context.

    Memberships in other scopes/contexts are preserved.

    This operation changes ONLY DeviceGroupMembership.

    It does NOT modify:
        - DevicePlacement
        - DeviceRelationship
        - CustomerService
        - Device
        - DeviceCandidate
    """

    devices, groups, source_memberships = await _lock_membership_state(
        db,
        (device_id,),
        extra_group_ids=(destination_group_id,),
    )
    if device_id not in devices:
        raise ValueError("DEVICE_NOT_FOUND")
    destination_group = groups.get(destination_group_id)
    if destination_group is None:
        raise ValueError("GROUP_NOT_FOUND")

    # Reuse the domain validator after the complete lock set is held; its
    # repeated Device/Group selects refresh but cannot acquire locks out of
    # order now.
    await validate_membership(db, device_id, destination_group_id)

    if any(
        membership.group_id == destination_group_id
        for membership in source_memberships
    ):
        raise ValueError(
            "MEMBERSHIP_EXISTS"
        )

    destination_scope, destination_context = group_context_key(
        destination_group
    )

    memberships_to_remove: list[DeviceGroupMembership] = []

    for membership in source_memberships:
        existing_group = groups[membership.group_id]
        existing_scope, existing_context = group_context_key(
            existing_group
        )

        if (
            existing_scope == destination_scope
            and existing_context == destination_context
        ):
            memberships_to_remove.append(
                membership
            )

    for membership in memberships_to_remove:
        await record_audit(
            db,
            action="GROUP_MEMBERSHIP_REMOVED",
            entity_type="DeviceGroupMembership",
            entity_id=membership.id,
            description="Group membership removed while moving the device to another group.",
            entity_display_snapshot=display_snapshot(membership),
            metadata={"reason": "GROUP_MOVE"},
            before_summary=business_summary(membership),
        )
        await db.delete(membership)

    new_membership = DeviceGroupMembership(
        device_id=device_id,
        group_id=destination_group_id,
    )

    db.add(new_membership)
    await db.flush()
    await record_audit(
        db,
        action="GROUP_MEMBERSHIP_ADDED",
        entity_type="DeviceGroupMembership",
        entity_id=new_membership.id,
        description="Device moved into a destination group.",
        entity_display_snapshot=display_snapshot(new_membership),
        metadata={
            "reason": "GROUP_MOVE",
            "removed_membership_ids": [
                str(membership.id) for membership in memberships_to_remove
            ],
        },
        after_summary=business_summary(new_membership),
    )

    return new_membership


async def remove_membership(
    db: AsyncSession,
    device_id: UUID,
    group_id: UUID,
) -> DeviceGroupMembership:
    """
    Remove an organizational membership.

    This operation only removes DeviceGroupMembership.
    """

    # Keep the same device -> group -> membership lock order as add/move and
    # recycle/restore validation. If either parent has already been recycled,
    # the operational membership is no longer detachable through this route.
    devices, groups, memberships = await _lock_membership_state(
        db,
        (device_id,),
        extra_group_ids=(group_id,),
    )
    if device_id not in devices or group_id not in groups:
        raise ValueError("MEMBERSHIP_NOT_FOUND")

    membership = next(
        (
            row
            for row in memberships
            if row.device_id == device_id and row.group_id == group_id
        ),
        None,
    )

    if membership is None:
        raise ValueError(
            "MEMBERSHIP_NOT_FOUND"
        )

    await record_audit(
        db,
        action="GROUP_MEMBERSHIP_REMOVED",
        entity_type="DeviceGroupMembership",
        entity_id=membership.id,
        description="Device removed from a group.",
        entity_display_snapshot=display_snapshot(membership),
        metadata={"reason": "EXPLICIT_REMOVAL"},
        before_summary=business_summary(membership),
    )
    await db.delete(membership)

    return membership


async def reconcile_physical_move_memberships(
    db: AsyncSession,
    device_ids: list[UUID],
) -> int:
    """Remove scoped memberships invalidated by an authoritative physical move.

    Physical hierarchy remains authoritative over organizational grouping.  A
    move therefore never fails merely because a device still belongs to a
    location-, city-, network-, or sector-scoped group in its old context.
    GLOBAL memberships are deliberately preserved.
    """

    if not device_ids:
        return 0

    _, groups, memberships = await _lock_membership_state(db, tuple(device_ids))

    removed = 0
    for membership in memberships:
        group = groups[membership.group_id]
        if group.scope_type == DeviceGroupScope.GLOBAL.value:
            continue
        try:
            await validate_membership(db, membership.device_id, group.id)
        except ValueError:
            await record_audit(
                db,
                action="GROUP_MEMBERSHIP_RECONCILED",
                entity_type="DeviceGroupMembership",
                entity_id=membership.id,
                description="Invalid scoped membership removed after a physical movement.",
                entity_display_snapshot=display_snapshot(membership),
                metadata={"reason": "PHYSICAL_MOVEMENT"},
                before_summary=business_summary(membership),
            )
            await db.delete(membership)
            removed += 1

    return removed

