"""Dependency-aware recoverable deletion, restore, and purge services.

The ledger is action metadata; recoverable typed rows remain the source of
truth. Public functions stage changes and flush, but never commit.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import (
    City,
    Customer,
    CustomerService,
    Device,
    DeviceCandidate,
    DeviceGroup,
    DeviceGroupMembership,
    DeviceGroupNesting,
    DeviceHierarchyLink,
    DeviceIP,
    DeviceInterface,
    DevicePlacement,
    DeviceRelationship,
    DeviceType,
    Location,
    Network,
    RecycleBinBatch,
    RecycleBinItem,
    Sector,
)
from .audit import record_audit
from .settings_registry import get_typed_setting
from .customer_services import CustomerServiceValidationError, _validate_service_references
from .groups import GroupMembershipConflict, find_conflicting_membership, validate_group_nesting, validate_membership
from .hierarchy import HierarchyValidationError, resolve_effective_hierarchy, synchronize_derived_placement
from .placements import PlacementValidationError, validate_placement_hierarchy
from .recycle_policies import (
    ITEM_MODELS,
    ROOT_MODELS,
    PurgeSummary,
    RecyclePreview,
    RecyclePreviewItem,
    normalize_entity_type,
    preview_item,
    safe_display_snapshot,
)

RECYCLED = "RECYCLED"
RESTORED = "RESTORED"
PURGE_FAILED = "PURGE_FAILED"
DEFAULT_RETENTION_DAYS = 30
PURGE_CANDIDATE_DEPENDENCY = "RECYCLE_PURGE_DEVICE_CANDIDATE_DEPENDENCY"
_AUDIT_ACTION_PREFIXES = {
    # The recycle ledger intentionally uses the explicit internal entity type
    # DEVICE_GROUP.  Audit consumers use the established public GROUP action
    # family, so do not leak that implementation detail into event names.
    "DEVICE_GROUP": "GROUP",
}


class RecycleBinError(ValueError):
    """Stable domain failure consumed by the recycle HTTP boundary."""

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = 409,
        conflicts: list[dict[str, Any]] | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.status_code = status_code
        self.conflicts = conflicts or []
        super().__init__(message)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _recycle_audit_action(entity_type: str, lifecycle: str) -> str:
    """Return the stable public audit action for a recycle lifecycle event."""

    return f"{_AUDIT_ACTION_PREFIXES.get(entity_type, entity_type)}_{lifecycle}"


def _blocker(code: str, entity_type: str, entity_id: UUID, message: str) -> dict[str, Any]:
    return {
        "code": code,
        "entity_type": entity_type,
        "entity_id": str(entity_id),
        "message": message,
    }


async def _rows(
    db: AsyncSession,
    model,
    *conditions,
    include_recycled: bool = False,
    for_update: bool = False,
) -> list[Any]:
    statement = select(model).where(*conditions)
    if include_recycled:
        statement = statement.execution_options(include_recycled=True)
    if for_update:
        statement = (
            statement.order_by(model.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    return list((await db.scalars(statement)).all())


async def _one(
    db: AsyncSession,
    model,
    object_id: UUID,
    *,
    include_recycled: bool = False,
    for_update: bool = False,
) -> Any | None:
    statement = select(model).where(model.id == object_id)
    if include_recycled:
        statement = statement.execution_options(include_recycled=True)
    if for_update:
        statement = statement.with_for_update().execution_options(populate_existing=True)
    return await db.scalar(statement)


async def _active_root(
    db: AsyncSession,
    entity_type: str,
    entity_id: UUID,
    *,
    for_update: bool,
) -> Any:
    model = ROOT_MODELS[entity_type]
    row = await _one(db, model, entity_id, for_update=for_update)
    if row is not None:
        return row
    hidden = await _one(db, model, entity_id, include_recycled=True)
    if hidden is not None and hidden.deleted_at is not None:
        raise RecycleBinError("ENTITY_ALREADY_RECYCLED", "The entity is already recycled.")
    raise RecycleBinError(
        "RESOURCE_NOT_FOUND",
        f"{entity_type.replace('_', ' ').title()} not found.",
        status_code=404,
    )


async def _type_code(db: AsyncSession, device: Device) -> str | None:
    return await db.scalar(select(DeviceType.code).where(DeviceType.id == device.device_type_id))


def _dedupe(items: Iterable[RecyclePreviewItem]) -> list[RecyclePreviewItem]:
    found: dict[tuple[str, UUID], RecyclePreviewItem] = {}
    for item in items:
        key = (item.entity_type, item.entity_id)
        if key not in found or item.restore_order < found[key].restore_order:
            found[key] = item
    return sorted(found.values(), key=lambda item: (item.restore_order, item.entity_type, str(item.entity_id)))


async def _scoped_group_blockers(
    db: AsyncSession,
    field,
    entity_id: UUID,
    *,
    for_update: bool,
) -> list[dict[str, Any]]:
    groups = await _rows(db, DeviceGroup, field == entity_id, for_update=for_update)
    return [
        _blocker(
            "ENTITY_HAS_DEVICE_GROUP_DEPENDENCIES",
            "DEVICE_GROUP",
            group.id,
            "A scoped device group still depends on this entity.",
        )
        for group in groups
    ]


async def _hidden_dependency_blockers(
    db: AsyncSession,
    model,
    entity_type: str,
    condition,
    *,
    for_update: bool,
) -> list[dict[str, Any]]:
    """Protect a dependent row already owned by another recycle batch."""

    hidden = await _rows(
        db,
        model,
        condition,
        model.deleted_at.is_not(None),
        include_recycled=True,
        for_update=for_update,
    )
    return [
        _blocker(
            "ENTITY_HAS_OTHER_RECYCLE_BATCH_DEPENDENCIES",
            entity_type,
            row.id,
            "A dependent row belongs to another recycle batch.",
        )
        for row in hidden
    ]


