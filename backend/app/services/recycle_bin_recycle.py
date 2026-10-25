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

from .recycle_bin_common import (
    RECYCLED, RecycleBinError, _active_root, _blocker, _dedupe, _now, _one,
    _recycle_audit_action,
)
from .recycle_bin_preview import _build_preview
from ..security.recycle_scope import add_required_grants_snapshot, cross_scope_recycle_conflicts

async def _retention_days(db: AsyncSession) -> int:
    return int((await get_typed_setting(db, "recycle_bin.retention_days"))["value"])


_ROOT_ORDER = {
    "NETWORK": 10,
    "CITY": 10,
    "LOCATION": 10,
    "SECTOR": 10,
    "DEVICE": 20,
    "CUSTOMER": 10,
    "CUSTOMER_SERVICE": 30,
    "DEVICE_GROUP": 20,
    "DEVICE_RELATIONSHIP": 60,
    "DEVICE_IP": 40,
    "DEVICE_INTERFACE": 40,
}


async def recycle_entity(
    db: AsyncSession,
    *,
    entity_type: str,
    entity_id: UUID,
    actor_user_id: UUID | None,
    reason: str | None = None,
    confirmed: bool = False,
    now: datetime | None = None,
) -> RecycleBinBatch:
    """Tombstone one validated root and every explicit bundle item."""

    try:
        entity_type = normalize_entity_type(entity_type)
    except ValueError as exc:
        raise RecycleBinError(
            "UNSUPPORTED_RECYCLE_ENTITY_TYPE",
            "The requested entity type is not recoverable.",
            status_code=422,
        ) from exc
    timestamp = now or _now()
    root = await _active_root(db, entity_type, entity_id, for_update=True)
    preview = await _build_preview(db, entity_type, root, for_update=True)
    if preview.blockers:
        error_code = "RECYCLE_DEPENDENCIES_PRESENT"
        error_message = "Protected dependencies prevent recycle."
        if entity_type == "DEVICE":
            priority = {
                "DEVICE_HAS_CUSTOMER_SERVICE_DEPENDENCIES": 0,
                "DEVICE_HAS_HIERARCHY_DEPENDENCIES": 1,
                "SECTOR_DEVICE_IS_BOUND": 2,
                "DEVICE_NOT_DECOMMISSIONED": 3,
            }
            primary = min(
                preview.blockers,
                key=lambda blocker: priority.get(blocker["code"], 100),
            )
            error_code = primary["code"]
            error_message = primary["message"]
        raise RecycleBinError(
            error_code,
            error_message,
            conflicts=preview.blockers,
        )
    if preview.requires_confirmation and not confirmed:
        raise RecycleBinError(
            "RECYCLE_CONFIRMATION_REQUIRED",
            "This coherent domain bundle requires explicit confirmation.",
        )

    order = _ROOT_ORDER[entity_type]
    root_item = RecyclePreviewItem(
        entity_type=entity_type,
        entity_id=root.id,
        item_role="ROOT",
        display_snapshot=preview.display_snapshot,
        restore_order=order,
        # A bound Sector owns a Device FK. Permanent purge removes the
        # logical Sector after components but before its Device, so business
        # semantics never rely on ON DELETE SET NULL.
        purge_order=75 if entity_type == "SECTOR" else 100 - order,
    )
    all_items = _dedupe([root_item, *preview.bundled_items])
    typed_rows: list[tuple[RecyclePreviewItem, Any]] = []
    for item in all_items:
        row = await _one(db, ITEM_MODELS[item.entity_type], item.entity_id, for_update=True)
        if row is None:
            raise RecycleBinError(
                "RECYCLE_DEPENDENCY_CHANGED",
                "A dependency changed during recycle validation.",
                conflicts=[
                    _blocker("RECYCLE_DEPENDENCY_CHANGED", item.entity_type, item.entity_id, "Row is no longer active.")
                ],
            )
        typed_rows.append((item, row))

    scope_conflicts, required_grants = await cross_scope_recycle_conflicts(
        db, actor_user_id=actor_user_id, typed_rows=typed_rows
    )
    if scope_conflicts:
        raise RecycleBinError(
            "RECYCLE_SCOPE_CROSS_BOUNDARY",
            "The recycle bundle crosses the actor's resource scope.",
            status_code=403,
            conflicts=scope_conflicts,
        )

    batch = RecycleBinBatch(
        id=uuid.uuid4(),
        root_entity_type=entity_type,
        root_entity_id=root.id,
        root_display_snapshot=add_required_grants_snapshot(preview.display_snapshot, required_grants),
        status=RECYCLED,
        deleted_at=timestamp,
        deleted_by_user_id=actor_user_id,
        deletion_reason=reason,
        purge_after=timestamp + timedelta(days=await _retention_days(db)),
    )
    try:
        async with db.begin_nested():
            db.add(batch)
            # There is intentionally no ORM relationship from typed business
            # rows to the action ledger. Materialize the batch first so FK
            # ordering cannot place tombstone UPDATEs ahead of its INSERT.
            await db.flush()
            for item, row in typed_rows:
                row.deleted_at = timestamp
                row.deletion_batch_id = batch.id
                db.add(
                    RecycleBinItem(
                        batch_id=batch.id,
                        entity_type=item.entity_type,
                        entity_id=item.entity_id,
                        item_role=item.item_role,
                        display_snapshot=item.display_snapshot,
                        restore_order=item.restore_order,
                        purge_order=item.purge_order,
                    )
                )
            await record_audit(
                db,
                action=_recycle_audit_action(entity_type, "RECYCLED"),
                entity_type=entity_type,
                entity_id=root.id,
                description="Entity moved to the recycle bin.",
                metadata={
                    "batch_id": str(batch.id),
                    "item_count": len(all_items),
                    "purge_after": batch.purge_after.isoformat(),
                },
                actor_user_id=actor_user_id,
            )
            await db.flush()
    except IntegrityError as exc:
        raise RecycleBinError(
            "RECYCLE_STATE_CONFLICT",
            "A concurrent change prevented recycle.",
        ) from exc
    return batch


