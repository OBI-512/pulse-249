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


class GroupMembershipConflict(Exception):
    """Raised when a device already has a group in the same context."""

    def __init__(
        self,
        existing_group: DeviceGroup,
    ) -> None:
        self.existing_group = existing_group
        super().__init__(
            "The device already belongs to a group in this organizational context."
        )


async def get_group(
    db: AsyncSession,
    group_id: UUID,
) -> DeviceGroup | None:
    result = await db.execute(
        select(DeviceGroup).where(
            DeviceGroup.id == group_id,
        )
    )

    return result.scalar_one_or_none()


async def get_device(
    db: AsyncSession,
    device_id: UUID,
) -> Device | None:
    result = await db.execute(
        select(Device).where(
            Device.id == device_id,
        )
    )

    return result.scalar_one_or_none()


def group_context_key(
    group: DeviceGroup,
) -> tuple[str, UUID | None]:
    """
    Return the organizational context represented by a group.

    GLOBAL groups deliberately have no context key because legacy/global
    grouping does not participate in the scoped membership exclusivity rule.

    For scoped groups the key is:

        (scope_type, context_id)

    Examples:

        ("NETWORK", network_id)
        ("CITY", city_id)
        ("LOCATION", location_id)
        ("SECTOR", sector_id)
    """

    scope = DeviceGroupScope(group.scope_type)

    if scope == DeviceGroupScope.GLOBAL:
        return (scope.value, None)

    if scope == DeviceGroupScope.NETWORK:
        return (scope.value, group.network_id)

    if scope == DeviceGroupScope.CITY:
        return (scope.value, group.city_id)

    if scope == DeviceGroupScope.LOCATION:
        return (scope.value, group.location_id)

    if scope == DeviceGroupScope.SECTOR:
        return (scope.value, group.sector_id)

    raise ValueError(
        f"Unsupported device group scope: {group.scope_type}"
    )


