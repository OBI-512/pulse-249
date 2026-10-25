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
    PURGE_FAILED, PURGE_CANDIDATE_DEPENDENCY, RECYCLED, RESTORED, RecycleBinError,
    _blocker, _now, _one, _recycle_audit_action, _rows,
)
from .recycle_bin_restore import get_recycle_batch

def _scheduled_ids(items: list[RecycleBinItem]) -> dict[str, set[UUID]]:
    result: dict[str, set[UUID]] = {}
    for item in items:
        result.setdefault(item.entity_type, set()).add(item.entity_id)
    return result


async def _candidate_purge_conflicts(
    db: AsyncSession,
    scheduled: dict[str, set[UUID]],
) -> list[dict[str, Any]]:
    """Detach retained DeviceCandidate live references to rows being purged.

    DeviceCandidate history is intentionally retained. Its nullable foreign
    keys must not block an otherwise-authorized recycle-bin purge. Historical
    metadata remains unchanged.
    """

    conditions = []

    device_ids = scheduled.get("DEVICE", set())
    if device_ids:
        ordered_device_ids = sorted(device_ids, key=str)
        conditions.extend(
            (
                DeviceCandidate.duplicate_device_id.in_(ordered_device_ids),
                DeviceCandidate.relationship_target_device_id.in_(ordered_device_ids),
            )
        )

    reference_columns = {
        "NETWORK": DeviceCandidate.network_id,
        "CITY": DeviceCandidate.city_id,
        "LOCATION": DeviceCandidate.location_id,
        "SECTOR": DeviceCandidate.sector_id,
        "CUSTOMER": DeviceCandidate.customer_id,
    }

    for entity_type, column in reference_columns.items():
        entity_ids = scheduled.get(entity_type, set())
        if entity_ids:
            conditions.append(column.in_(sorted(entity_ids, key=str)))

    if not conditions:
        return []

    candidates = list(
        (
            await db.scalars(
                select(DeviceCandidate)
                .where(or_(*conditions))
                .order_by(DeviceCandidate.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).all()
    )

    for candidate in candidates:
        if candidate.duplicate_device_id in device_ids:
            candidate.duplicate_device_id = None

        if candidate.relationship_target_device_id in device_ids:
            candidate.relationship_target_device_id = None

        for entity_type, field in (
            ("NETWORK", "network_id"),
            ("CITY", "city_id"),
            ("LOCATION", "location_id"),
            ("SECTOR", "sector_id"),
            ("CUSTOMER", "customer_id"),
        ):
            value = getattr(candidate, field)
            if value is not None and value in scheduled.get(entity_type, set()):
                setattr(candidate, field, None)

    # DeviceCandidate metadata is retained as historical information.
    # Only live foreign-key relationships are detached.
    return []

async def _retire_cross_batch_group_relationships(
    db: AsyncSession,
    *,
    batch_id: UUID,
    group_id: UUID,
    scheduled: dict[str, set[UUID]],
) -> int:
    """Retire recycled cross-batch group links before a group is purged.

    Group membership and nesting rows are recoverable relationship history, not
    owned entities.  If one of those rows was already recycled by another
    batch, permanently purging this group would otherwise either be blocked or
    let PostgreSQL CASCADE-delete the typed row while leaving a stale recycle
    ledger item behind.  Remove only fully tombstoned rows whose owning batch
    and ledger item are still valid.  Active or inconsistent rows are left in
    place so the normal purge-conflict scan fails closed.
    """

    relationship_specs = (
        (
            "DEVICE_GROUP_MEMBERSHIP",
            DeviceGroupMembership,
            DeviceGroupMembership.group_id == group_id,
        ),
        (
            "DEVICE_GROUP_NESTING",
            DeviceGroupNesting,
            or_(
                DeviceGroupNesting.parent_group_id == group_id,
                DeviceGroupNesting.child_group_id == group_id,
            ),
        ),
    )
    retired = 0
    for entity_type, model, condition in relationship_specs:
        included = scheduled.get(entity_type, set())
        rows = await _rows(
            db,
            model,
            condition,
            include_recycled=True,
            for_update=True,
        )
        for row in rows:
            if row.id in included:
                continue
            owner_batch_id = row.deletion_batch_id
            if (
                row.deleted_at is None
                or owner_batch_id is None
                or owner_batch_id == batch_id
            ):
                # Active/same-batch-but-unscheduled rows indicate an integrity
                # problem and must still be caught by _purge_conflicts().
                continue

            owner_batch = await db.scalar(
                select(RecycleBinBatch)
                .where(RecycleBinBatch.id == owner_batch_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if owner_batch is None or owner_batch.status not in {RECYCLED, PURGE_FAILED}:
                continue

            ledger_item = await db.scalar(
                select(RecycleBinItem)
                .where(
                    RecycleBinItem.batch_id == owner_batch_id,
                    RecycleBinItem.entity_type == entity_type,
                    RecycleBinItem.entity_id == row.id,
                )
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if ledger_item is None:
                continue

            # The endpoint group is being destroyed permanently.  A future
            # restore of the other batch must therefore restore without this
            # now-impossible relationship.  Retiring both the typed row and
            # its ledger entry keeps that later restore deterministic.
            await db.delete(ledger_item)
            await db.delete(row)
            retired += 1

    if retired:
        await db.flush()
    return retired


async def _purge_conflicts(
    db: AsyncSession,
    items: list[RecycleBinItem],
) -> list[dict[str, Any]]:
    """Detect every row a database cascade/SET NULL would mutate implicitly."""

    scheduled = _scheduled_ids(items)
    conflicts = await _candidate_purge_conflicts(db, scheduled)

    async def protect(model, entity_type: str, condition) -> None:
        included = scheduled.get(entity_type, set())
        for row in await _rows(
            db,
            model,
            condition,
            include_recycled=True,
            for_update=True,
        ):
            if row.id not in included:
                conflicts.append(
                    _blocker(
                        "PURGE_DEPENDENCY_OUTSIDE_BATCH",
                        entity_type,
                        row.id,
                        "Permanent purge would mutate a dependency outside this batch.",
                    )
                )

    for item in items:
        if item.entity_type == "NETWORK":
            await protect(City, "CITY", City.network_id == item.entity_id)
            await protect(DevicePlacement, "DEVICE_PLACEMENT", DevicePlacement.network_id == item.entity_id)
            await protect(DeviceGroup, "DEVICE_GROUP", DeviceGroup.network_id == item.entity_id)
        elif item.entity_type == "CITY":
            await protect(Location, "LOCATION", Location.city_id == item.entity_id)
            await protect(DevicePlacement, "DEVICE_PLACEMENT", DevicePlacement.city_id == item.entity_id)
            await protect(DeviceGroup, "DEVICE_GROUP", DeviceGroup.city_id == item.entity_id)
        elif item.entity_type == "LOCATION":
            await protect(Sector, "SECTOR", Sector.location_id == item.entity_id)
            await protect(DevicePlacement, "DEVICE_PLACEMENT", DevicePlacement.location_id == item.entity_id)
            await protect(DeviceGroup, "DEVICE_GROUP", DeviceGroup.location_id == item.entity_id)
        elif item.entity_type == "SECTOR":
            await protect(CustomerService, "CUSTOMER_SERVICE", CustomerService.sector_id == item.entity_id)
            await protect(DevicePlacement, "DEVICE_PLACEMENT", DevicePlacement.sector_id == item.entity_id)
            await protect(DeviceGroup, "DEVICE_GROUP", DeviceGroup.sector_id == item.entity_id)
        elif item.entity_type == "DEVICE":
            await protect(Sector, "SECTOR", Sector.sector_device_id == item.entity_id)
            await protect(
                CustomerService,
                "CUSTOMER_SERVICE",
                or_(
                    CustomerService.cpe_device_id == item.entity_id,
                    CustomerService.access_point_device_id == item.entity_id,
                    CustomerService.router_device_id == item.entity_id,
                ),
            )
            await protect(DeviceIP, "DEVICE_IP", DeviceIP.device_id == item.entity_id)
            await protect(DeviceInterface, "DEVICE_INTERFACE", DeviceInterface.device_id == item.entity_id)
            await protect(DevicePlacement, "DEVICE_PLACEMENT", DevicePlacement.device_id == item.entity_id)
            await protect(
                DeviceHierarchyLink,
                "DEVICE_HIERARCHY_LINK",
                or_(
                    DeviceHierarchyLink.parent_device_id == item.entity_id,
                    DeviceHierarchyLink.child_device_id == item.entity_id,
                ),
            )
            await protect(
                DeviceRelationship,
                "DEVICE_RELATIONSHIP",
                or_(
                    DeviceRelationship.source_device_id == item.entity_id,
                    DeviceRelationship.target_device_id == item.entity_id,
                ),
            )
            await protect(
                DeviceGroupMembership,
                "DEVICE_GROUP_MEMBERSHIP",
                DeviceGroupMembership.device_id == item.entity_id,
            )
        elif item.entity_type == "CUSTOMER":
            await protect(CustomerService, "CUSTOMER_SERVICE", CustomerService.customer_id == item.entity_id)
        elif item.entity_type == "DEVICE_GROUP":
            await protect(
                DeviceGroupMembership,
                "DEVICE_GROUP_MEMBERSHIP",
                DeviceGroupMembership.group_id == item.entity_id,
            )
            await protect(
                DeviceGroupNesting,
                "DEVICE_GROUP_NESTING",
                or_(
                    DeviceGroupNesting.parent_group_id == item.entity_id,
                    DeviceGroupNesting.child_group_id == item.entity_id,
                ),
            )

    return list(
        {
            (value["code"], value["entity_type"], value["entity_id"]): value
            for value in conflicts
        }.values()
    )


async def purge_recycle_batch(
    db: AsyncSession,
    *,
    batch_id: UUID,
    actor_user_id: UUID | None,
    now: datetime | None = None,
    enforce_retention: bool = True,
) -> None:
    """Permanently remove a batch in explicit reverse dependency order."""

    timestamp = now or _now()
    batch, items = await get_recycle_batch(db, batch_id=batch_id, for_update=True)
    if batch.status == RESTORED:
        raise RecycleBinError("RECYCLE_BATCH_ALREADY_RESTORED", "A restored batch cannot be purged.")
    if batch.status not in {RECYCLED, PURGE_FAILED}:
        raise RecycleBinError("RECYCLE_BATCH_STATE_INVALID", "The batch cannot be purged.")
    if enforce_retention and timestamp < batch.purge_after:
        raise RecycleBinError(
            "RECYCLE_RETENTION_NOT_EXPIRED",
            "The recycle retention period has not expired.",
        )

    def purge_tier(item: RecycleBinItem) -> int:
        # Apply the corrected order dynamically for batches created before
        # this invariant was introduced as well as writing 75 on new ledgers.
        if (
            batch.root_entity_type == "SECTOR"
            and item.entity_type == "SECTOR"
            and item.item_role == "ROOT"
        ):
            return 75
        return item.purge_order

    typed: list[tuple[RecycleBinItem, Any]] = []
    for item in sorted(items, key=lambda value: (purge_tier(value), value.entity_type, str(value.entity_id))):
        model = ITEM_MODELS.get(item.entity_type)
        if model is None:
            raise RecycleBinError("RECYCLE_ITEM_TYPE_UNSUPPORTED", "The batch contains an unsupported item type.")
        row = await _one(
            db,
            model,
            item.entity_id,
            include_recycled=True,
            for_update=True,
        )
        if row is None:
            raise RecycleBinError(
                "RECYCLE_ITEM_MISSING",
                "A typed row required for deterministic purge is missing.",
            )
        if row.deletion_batch_id != batch.id or row.deleted_at is None:
            raise RecycleBinError(
                "RECYCLE_ITEM_BATCH_MISMATCH",
                "A typed row no longer belongs to this batch.",
            )
        typed.append((item, row))

    # Lock every typed row before scanning candidate/dependency tables. A
    # concurrent FK insert/update must either commit before these locks (and
    # therefore be observed below), or wait until this transaction completes
    # and fail after the typed parent has been purged. Reuse `typed` for the
    # delete phase so no second lock window is introduced.
    if batch.root_entity_type == "DEVICE_GROUP":
        group_row = next(
            (row for item, row in typed if item.entity_type == "DEVICE_GROUP" and item.item_role == "ROOT"),
            None,
        )
        if group_row is not None and getattr(group_row, "group_kind", "CUSTOM") == "CUSTOM":
            await _retire_cross_batch_group_relationships(
                db,
                batch_id=batch.id,
                group_id=batch.root_entity_id,
                scheduled=_scheduled_ids(items),
            )

    conflicts = await _purge_conflicts(db, items)
    if conflicts:
        candidate_history_conflict = any(
            conflict["code"] == PURGE_CANDIDATE_DEPENDENCY for conflict in conflicts
        )
        raise RecycleBinError(
            PURGE_CANDIDATE_DEPENDENCY
            if candidate_history_conflict
            else "RECYCLE_PURGE_DEPENDENCY_CONFLICT",
            "Permanent purge is blocked by retained DeviceCandidate history."
            if candidate_history_conflict
            else "Permanent purge would affect dependencies outside this batch.",
            conflicts=conflicts,
        )

    root_type = batch.root_entity_type
    root_id = batch.root_entity_id
    display_snapshot = batch.root_display_snapshot
    try:
        current_tier: int | None = None
        for item, row in typed:
            item_tier = purge_tier(item)
            if current_tier is not None and item_tier != current_tier:
                # ORM mappings intentionally have no cascade relationships;
                # an explicit flush per ledger tier is what guarantees the
                # requested reverse business-dependency order in PostgreSQL.
                await db.flush()
            current_tier = item_tier
            await db.delete(row)
        await db.flush()
        for item in items:
            await db.delete(item)
        await db.flush()
        await db.delete(batch)
        await record_audit(
            db,
            action=_recycle_audit_action(root_type, "PURGED"),
            entity_type=root_type,
            entity_id=root_id,
            description="Recycle-bin batch permanently purged.",
            metadata={
                "batch_id": str(batch_id),
                "display_snapshot": display_snapshot,
            },
            actor_user_id=actor_user_id,
        )
        await db.flush()
    except IntegrityError as exc:
        raise RecycleBinError(
            "RECYCLE_PURGE_DEPENDENCY_CONFLICT",
            "A concurrent dependency prevented permanent purge.",
        ) from exc


async def purge_due_batches(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    limit: int = 100,
) -> PurgeSummary:
    """Purge due batches independently and retain safe failure diagnostics."""

    timestamp = now or _now()
    due = list(
        (
            await db.scalars(
                select(RecycleBinBatch)
                .where(
                    RecycleBinBatch.status.in_([RECYCLED, PURGE_FAILED]),
                    RecycleBinBatch.purge_after <= timestamp,
                )
                .order_by(RecycleBinBatch.purge_after, RecycleBinBatch.id)
                .limit(max(1, min(limit, 1000)))
                .with_for_update(skip_locked=True)
                .execution_options(populate_existing=True)
            )
        ).all()
    )
    purged_ids: list[UUID] = []
    failed = 0
    for due_batch in due:
        try:
            async with db.begin_nested():
                await purge_recycle_batch(
                    db,
                    batch_id=due_batch.id,
                    actor_user_id=None,
                    now=timestamp,
                    enforce_retention=True,
                )
            purged_ids.append(due_batch.id)
        except Exception as exc:  # one corrupt/dependent batch must not abort the run
            failed += 1
            batch = await db.scalar(
                select(RecycleBinBatch)
                .where(RecycleBinBatch.id == due_batch.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if batch is not None:
                batch.status = PURGE_FAILED
                batch.last_attempt_at = timestamp
                batch.last_error_code = getattr(exc, "code", "RECYCLE_PURGE_FAILED")
                batch.last_error_message = (
                    exc.message
                    if isinstance(exc, RecycleBinError)
                    else "Scheduled purge failed safely; see the stable error code."
                )
                await record_audit(
                    db,
                    action="RECYCLE_PURGE_FAILED",
                    entity_type=batch.root_entity_type,
                    entity_id=batch.root_entity_id,
                    description="Scheduled recycle-bin purge failed safely.",
                    metadata={"batch_id": str(batch.id), "error_code": batch.last_error_code},
                    result="FAILURE",
                )
                await db.flush()

    return PurgeSummary(
        considered=len(due),
        purged=len(purged_ids),
        failed=failed,
        batch_ids=purged_ids,
    )
