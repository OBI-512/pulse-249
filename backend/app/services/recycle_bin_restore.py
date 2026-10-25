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
    RECYCLED, RESTORED, PURGE_FAILED, RecycleBinError, _blocker, _now, _one, _recycle_audit_action,
)

async def get_recycle_batch(
    db: AsyncSession,
    *,
    batch_id: UUID,
    for_update: bool = False,
) -> tuple[RecycleBinBatch, list[RecycleBinItem]]:
    statement = select(RecycleBinBatch).where(RecycleBinBatch.id == batch_id)
    if for_update:
        statement = statement.with_for_update().execution_options(populate_existing=True)
    batch = await db.scalar(statement)
    if batch is None:
        raise RecycleBinError(
            "RECYCLE_BATCH_NOT_FOUND",
            "Recycle-bin batch not found.",
            status_code=404,
        )
    statement = (
        select(RecycleBinItem)
        .where(RecycleBinItem.batch_id == batch.id)
        .order_by(RecycleBinItem.restore_order, RecycleBinItem.created_at, RecycleBinItem.id)
    )
    if for_update:
        statement = statement.with_for_update().execution_options(populate_existing=True)
    return batch, list((await db.scalars(statement)).all())


async def _active_exists(
    db: AsyncSession,
    model,
    entity_type: str,
    object_id: UUID,
    restoring: set[tuple[str, UUID]],
) -> bool:
    if (entity_type, object_id) in restoring:
        return True
    return (
        await db.scalar(
            select(model.id)
            .where(model.id == object_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        is not None
    )


async def _context_row(
    db: AsyncSession,
    model,
    entity_type: str,
    object_id: UUID,
    typed: dict[tuple[str, UUID], Any],
) -> Any | None:
    return typed.get((entity_type, object_id)) or await _one(
        db, model, object_id, for_update=True
    )


async def _checked_type(db: AsyncSession, device: Device) -> str:
    device_type = await db.scalar(select(DeviceType).where(DeviceType.id == device.device_type_id))
    if device_type is None or not device_type.is_active:
        raise RecycleBinError(
            "RECYCLE_RESTORE_DEVICE_TYPE_INVALID",
            "The device type is missing or inactive.",
            conflicts=[
                _blocker(
                    "DEVICE_TYPE_INACTIVE_OR_MISSING",
                    "DEVICE",
                    device.id,
                    "A restored device requires an active controlled device type.",
                )
            ],
        )
    return device_type.code


async def _active_conflict(db: AsyncSession, model, object_id: UUID, *conditions) -> Any | None:
    return await db.scalar(
        select(model)
        .where(model.id != object_id, *conditions)
        .order_by(model.id)
        .limit(1)
        .with_for_update()
        .execution_options(populate_existing=True)
    )


async def _link_for_child(
    db: AsyncSession,
    child_id: UUID,
    relationship_type: str,
    typed: dict[tuple[str, UUID], Any],
) -> DeviceHierarchyLink | None:
    active = await db.scalar(
        select(DeviceHierarchyLink)
        .where(
            DeviceHierarchyLink.child_device_id == child_id,
            DeviceHierarchyLink.relationship_type == relationship_type,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if active is not None:
        return active
    return next(
        (
            row
            for (kind, _), row in typed.items()
            if kind == "DEVICE_HIERARCHY_LINK"
            and row.child_device_id == child_id
            and row.relationship_type == relationship_type
        ),
        None,
    )


async def _sector_for_device(
    db: AsyncSession,
    device_id: UUID,
    typed: dict[tuple[str, UUID], Any],
) -> Sector | None:
    active = await db.scalar(
        select(Sector)
        .where(Sector.sector_device_id == device_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if active is not None:
        return active
    return next(
        (
            row
            for (kind, _), row in typed.items()
            if kind == "SECTOR" and row.sector_device_id == device_id
        ),
        None,
    )


async def _effective_sector(
    db: AsyncSession,
    device: Device,
    typed: dict[tuple[str, UUID], Any],
) -> Sector | None:
    type_code = await _checked_type(db, device)
    if type_code == "SECTOR":
        return await _sector_for_device(db, device.id, typed)
    if type_code == "CPE":
        link = await _link_for_child(db, device.id, "SECTOR_CPE", typed)
        if link is None:
            return None
        parent = await _context_row(db, Device, "DEVICE", link.parent_device_id, typed)
        if parent is None or await _checked_type(db, parent) != "SECTOR":
            return None
        return await _sector_for_device(db, parent.id, typed)
    if type_code == "ACCESS_POINT":
        link = await _link_for_child(db, device.id, "CPE_ACCESS_POINT", typed)
        if link is None:
            return None
        parent = await _context_row(db, Device, "DEVICE", link.parent_device_id, typed)
        if parent is None or await _checked_type(db, parent) != "CPE":
            return None
        return await _effective_sector(db, parent, typed)
    return None


async def _require_active(
    db: AsyncSession,
    model,
    entity_type: str,
    object_id: UUID,
    restoring: set[tuple[str, UUID]],
) -> None:
    if not await _active_exists(db, model, entity_type, object_id, restoring):
        raise RecycleBinError(
            "RECYCLE_RESTORE_PARENT_MISSING",
            "A required parent is missing or recycled.",
            conflicts=[
                _blocker(
                    f"{entity_type}_NOT_ACTIVE",
                    entity_type,
                    object_id,
                    "Required parent is not active.",
                )
            ],
        )


async def _validate_restore_item(
    db: AsyncSession,
    entity_type: str,
    row: Any,
    *,
    restoring: set[tuple[str, UUID]],
    typed: dict[tuple[str, UUID], Any],
) -> None:
    """Prevalidate an item without clearing any tombstone."""

    if entity_type == "NETWORK":
        if await _active_conflict(db, Network, row.id, Network.code == row.code):
            raise RecycleBinError("RECYCLE_RESTORE_IDENTITY_CONFLICT", "Network code is already in use.")
        return

    if entity_type == "CITY":
        await _require_active(db, Network, "NETWORK", row.network_id, restoring)
        if await _active_conflict(db, City, row.id, City.network_id == row.network_id, City.code == row.code):
            raise RecycleBinError("RECYCLE_RESTORE_IDENTITY_CONFLICT", "City code is already in use.")
        return

    if entity_type == "LOCATION":
        await _require_active(db, City, "CITY", row.city_id, restoring)
        if await _active_conflict(db, Location, row.id, Location.city_id == row.city_id, Location.code == row.code):
            raise RecycleBinError("RECYCLE_RESTORE_IDENTITY_CONFLICT", "Location code is already in use.")
        return

    if entity_type == "SECTOR":
        await _require_active(db, Location, "LOCATION", row.location_id, restoring)
        if await _active_conflict(db, Sector, row.id, Sector.location_id == row.location_id, Sector.code == row.code):
            raise RecycleBinError("RECYCLE_RESTORE_IDENTITY_CONFLICT", "Sector code is already in use.")
        if row.sector_device_id is not None:
            device = await _context_row(db, Device, "DEVICE", row.sector_device_id, typed)
            if device is None or await _checked_type(db, device) != "SECTOR":
                raise RecycleBinError(
                    "RECYCLE_RESTORE_SECTOR_DEVICE_INVALID",
                    "The bound SECTOR device is missing or invalid.",
                )
        return

    if entity_type == "DEVICE":
        type_code = await _checked_type(db, row)
        management_ip = await db.scalar(
            select(DeviceIP.id).where(
                DeviceIP.device_id == row.id,
                DeviceIP.is_management.is_(True),
            )
        )
        restoring_management_ip = any(
            kind == "DEVICE_IP"
            and candidate.device_id == row.id
            and candidate.is_management
            for (kind, _), candidate in typed.items()
        )
        if management_ip is None and not restoring_management_ip:
            raise RecycleBinError(
                "RECYCLE_RESTORE_MANAGEMENT_IP_REQUIRED",
                "A restored device requires an available management IP.",
            )
        if type_code == "SECTOR":
            if await _sector_for_device(db, row.id, typed) is None:
                raise RecycleBinError(
                    "RECYCLE_RESTORE_HIERARCHY_CONFLICT",
                    "A SECTOR device must remain bound to a logical Sector.",
                )
        elif type_code in {"CPE", "ACCESS_POINT"}:
            expected = "SECTOR_CPE" if type_code == "CPE" else "CPE_ACCESS_POINT"
            link = await _link_for_child(db, row.id, expected, typed)
            sector = await _effective_sector(db, row, typed)
            if link is None or sector is None:
                raise RecycleBinError(
                    "RECYCLE_RESTORE_HIERARCHY_CONFLICT",
                    "The authoritative parent hierarchy is no longer available.",
                )
            if sector.role == "BACKHAUL":
                raise RecycleBinError(
                    "RECYCLE_RESTORE_BACKHAUL_CONFLICT",
                    "Customer equipment cannot be restored into a BACKHAUL Sector.",
                )
        else:
            placement = next(
                (
                    candidate
                    for (kind, _), candidate in typed.items()
                    if kind == "DEVICE_PLACEMENT" and candidate.device_id == row.id
                ),
                None,
            ) or await db.scalar(select(DevicePlacement).where(DevicePlacement.device_id == row.id))
            if placement is None:
                raise RecycleBinError(
                    "RECYCLE_RESTORE_PLACEMENT_MISSING",
                    "Independently placed equipment requires a placement.",
                )
        return

    if entity_type == "CUSTOMER":
        if await _active_conflict(db, Customer, row.id, Customer.customer_code == row.customer_code):
            raise RecycleBinError("RECYCLE_RESTORE_IDENTITY_CONFLICT", "Customer code is already in use.")
        return

    if entity_type == "CUSTOMER_SERVICE":
        for model, kind, object_id in (
            (Customer, "CUSTOMER", row.customer_id),
            (Sector, "SECTOR", row.sector_id),
            (Device, "DEVICE", row.cpe_device_id),
            (Device, "DEVICE", row.access_point_device_id),
        ):
            await _require_active(db, model, kind, object_id, restoring)
        if row.router_device_id is not None:
            await _require_active(db, Device, "DEVICE", row.router_device_id, restoring)
        for condition, label in (
            (CustomerService.customer_id == row.customer_id, "customer"),
            (CustomerService.service_code == row.service_code, "service code"),
            (CustomerService.cpe_device_id == row.cpe_device_id, "CPE"),
            (CustomerService.access_point_device_id == row.access_point_device_id, "access point"),
        ):
            if await _active_conflict(db, CustomerService, row.id, condition):
                raise RecycleBinError(
                    "RECYCLE_RESTORE_CUSTOMER_SERVICE_CONFLICT",
                    f"The CustomerService {label} is already in use.",
                )
        cpe = await _context_row(db, Device, "DEVICE", row.cpe_device_id, typed)
        ap = await _context_row(db, Device, "DEVICE", row.access_point_device_id, typed)
        cpe_sector = await _effective_sector(db, cpe, typed) if cpe else None
        ap_sector = await _effective_sector(db, ap, typed) if ap else None
        ap_link = await _link_for_child(db, row.access_point_device_id, "CPE_ACCESS_POINT", typed)
        if (
            cpe_sector is None
            or ap_sector is None
            or cpe_sector.id != row.sector_id
            or ap_sector.id != row.sector_id
            or ap_link is None
            or ap_link.parent_device_id != row.cpe_device_id
            or cpe_sector.role == "BACKHAUL"
        ):
            raise RecycleBinError(
                "RECYCLE_RESTORE_CUSTOMER_SERVICE_CONFLICT",
                "The CustomerService hierarchy is no longer valid.",
            )
        return

    if entity_type == "DEVICE_GROUP":
        if await _active_conflict(db, DeviceGroup, row.id, DeviceGroup.name == row.name):
            raise RecycleBinError("RECYCLE_RESTORE_IDENTITY_CONFLICT", "Group name is already in use.")
        if await _active_conflict(db, DeviceGroup, row.id, DeviceGroup.code == row.code):
            raise RecycleBinError("RECYCLE_RESTORE_IDENTITY_CONFLICT", "Group code is already in use.")
        scope_parents = {
            "NETWORK": (Network, "NETWORK", row.network_id),
            "CITY": (City, "CITY", row.city_id),
            "LOCATION": (Location, "LOCATION", row.location_id),
            "SECTOR": (Sector, "SECTOR", row.sector_id),
        }
        if row.scope_type in scope_parents:
            model, kind, object_id = scope_parents[row.scope_type]
            if object_id is None:
                raise RecycleBinError("RECYCLE_RESTORE_GROUP_SCOPE_INVALID", "Group scope parent is missing.")
            await _require_active(db, model, kind, object_id, restoring)
        return

    if entity_type == "DEVICE_GROUP_NESTING":
        await _require_active(db, DeviceGroup, "DEVICE_GROUP", row.parent_group_id, restoring)
        await _require_active(db, DeviceGroup, "DEVICE_GROUP", row.child_group_id, restoring)
        if row.parent_group_id == row.child_group_id:
            raise RecycleBinError("RECYCLE_RESTORE_GROUP_NESTING_CONFLICT", "A group cannot contain itself.")
        existing_parent = await db.scalar(
            select(DeviceGroupNesting).where(
                DeviceGroupNesting.id != row.id,
                DeviceGroupNesting.child_group_id == row.child_group_id,
                DeviceGroupNesting.deleted_at.is_(None),
            )
        )
        if existing_parent is not None:
            raise RecycleBinError(
                "RECYCLE_RESTORE_GROUP_NESTING_CONFLICT",
                "The child group already has an active parent group.",
            )
        return

    if entity_type == "DEVICE_RELATIONSHIP":
        if row.direction not in {"DIRECTED", "UNDIRECTED"} or row.source_device_id == row.target_device_id:
            raise RecycleBinError(
                "RECYCLE_RESTORE_RELATIONSHIP_CONFLICT",
                "Relationship direction or endpoints are invalid.",
            )
        await _require_active(db, Device, "DEVICE", row.source_device_id, restoring)
        await _require_active(db, Device, "DEVICE", row.target_device_id, restoring)
        reverse_or_exact = await db.scalar(
            select(DeviceRelationship).where(
                DeviceRelationship.id != row.id,
                DeviceRelationship.relationship_type == row.relationship_type,
                or_(
                    and_(
                        DeviceRelationship.source_device_id == row.source_device_id,
                        DeviceRelationship.target_device_id == row.target_device_id,
                    ),
                    and_(
                        DeviceRelationship.source_device_id == row.target_device_id,
                        DeviceRelationship.target_device_id == row.source_device_id,
                    ),
                ),
            )
        )
        if reverse_or_exact is not None:
            raise RecycleBinError(
                "RECYCLE_RESTORE_RELATIONSHIP_CONFLICT",
                "An exact or reverse relationship already exists.",
            )
        return

    if entity_type == "DEVICE_IP":
        await _require_active(db, Device, "DEVICE", row.device_id, restoring)
        if await _active_conflict(db, DeviceIP, row.id, DeviceIP.ip_address == row.ip_address):
            raise RecycleBinError(
                "RECYCLE_RESTORE_IP_ADDRESS_CONFLICT",
                "The IP address has been reused.",
            )
        return

    if entity_type == "DEVICE_INTERFACE":
        await _require_active(db, Device, "DEVICE", row.device_id, restoring)
        return

    if entity_type == "DEVICE_PLACEMENT":
        await _require_active(db, Device, "DEVICE", row.device_id, restoring)
        device = await _context_row(db, Device, "DEVICE", row.device_id, typed)
        if device is not None and await _checked_type(db, device) not in {"CPE", "ACCESS_POINT"}:
            await _require_active(db, Network, "NETWORK", row.network_id, restoring)
            await _require_active(db, City, "CITY", row.city_id, restoring)
            await _require_active(db, Location, "LOCATION", row.location_id, restoring)
            if row.sector_id is not None:
                await _require_active(db, Sector, "SECTOR", row.sector_id, restoring)
        return

    if entity_type == "DEVICE_HIERARCHY_LINK":
        parent = await _context_row(db, Device, "DEVICE", row.parent_device_id, typed)
        child = await _context_row(db, Device, "DEVICE", row.child_device_id, typed)
        if parent is None or child is None:
            raise RecycleBinError("RECYCLE_RESTORE_PARENT_MISSING", "A hierarchy endpoint is missing.")
        parent_type = await _checked_type(db, parent)
        child_type = await _checked_type(db, child)
        valid = (
            row.relationship_type == "SECTOR_CPE" and parent_type == "SECTOR" and child_type == "CPE"
        ) or (
            row.relationship_type == "CPE_ACCESS_POINT"
            and parent_type == "CPE"
            and child_type == "ACCESS_POINT"
        )
        if not valid:
            raise RecycleBinError(
                "RECYCLE_RESTORE_HIERARCHY_CONFLICT",
                "Hierarchy endpoint types no longer match.",
            )
        if await _active_conflict(
            db, DeviceHierarchyLink, row.id, DeviceHierarchyLink.child_device_id == row.child_device_id
        ):
            raise RecycleBinError(
                "RECYCLE_RESTORE_HIERARCHY_CONFLICT",
                "The hierarchy child already has an active parent.",
            )
        if row.relationship_type == "CPE_ACCESS_POINT" and await _active_conflict(
            db,
            DeviceHierarchyLink,
            row.id,
            DeviceHierarchyLink.parent_device_id == row.parent_device_id,
            DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
        ):
            raise RecycleBinError(
                "RECYCLE_RESTORE_AP_SLOT_CONFLICT",
                "The CPE already has an active access point.",
            )
        if row.relationship_type == "SECTOR_CPE":
            sector = await _sector_for_device(db, parent.id, typed)
            if sector is None or sector.role == "BACKHAUL":
                raise RecycleBinError(
                    "RECYCLE_RESTORE_BACKHAUL_CONFLICT",
                    "The CPE parent Sector is missing or BACKHAUL.",
                )
        return

    if entity_type == "DEVICE_GROUP_MEMBERSHIP":
        await _require_active(db, Device, "DEVICE", row.device_id, restoring)
        await _require_active(db, DeviceGroup, "DEVICE_GROUP", row.group_id, restoring)


async def _post_restore_validate(
    db: AsyncSession,
    typed: dict[tuple[str, UUID], Any],
) -> None:
    """Re-run authoritative services after rows become visible in the savepoint."""

    for (entity_type, _), row in typed.items():
        if entity_type == "DEVICE":
            type_code = await _checked_type(db, row)
            if type_code in {"CPE", "ACCESS_POINT"}:
                hierarchy = await resolve_effective_hierarchy(db, row)
                await synchronize_derived_placement(
                    db,
                    device_id=row.id,
                    hierarchy=hierarchy,
                    derived_from="SECTOR_CPE" if type_code == "CPE" else "CPE_ACCESS_POINT",
                )
            elif type_code == "SECTOR":
                await resolve_effective_hierarchy(db, row)
        elif entity_type == "CUSTOMER_SERVICE":
            await _validate_service_references(
                db,
                customer_id=row.customer_id,
                sector_id=row.sector_id,
                cpe_device_id=row.cpe_device_id,
                access_point_device_id=row.access_point_device_id,
                router_device_id=row.router_device_id,
            )
        elif entity_type == "DEVICE_GROUP_MEMBERSHIP":
            _, group = await validate_membership(db, row.device_id, row.group_id)
            conflicting_group = await find_conflicting_membership(
                db,
                row.device_id,
                group,
            )
            if conflicting_group is not None:
                raise GroupMembershipConflict(conflicting_group)
        elif entity_type == "DEVICE_GROUP_NESTING":
            parent = await db.scalar(
                select(DeviceGroup).where(
                    DeviceGroup.id == row.parent_group_id,
                    DeviceGroup.deleted_at.is_(None),
                )
            )
            child = await db.scalar(
                select(DeviceGroup).where(
                    DeviceGroup.id == row.child_group_id,
                    DeviceGroup.deleted_at.is_(None),
                )
            )
            if parent is None or child is None:
                raise RecycleBinError(
                    "RECYCLE_RESTORE_GROUP_NESTING_CONFLICT",
                    "Both nested groups must be active after restore.",
                )
            siblings = await db.scalar(
                select(DeviceGroupNesting).where(
                    DeviceGroupNesting.id != row.id,
                    DeviceGroupNesting.child_group_id == row.child_group_id,
                    DeviceGroupNesting.deleted_at.is_(None),
                )
            )
            if siblings is not None:
                raise RecycleBinError(
                    "RECYCLE_RESTORE_GROUP_NESTING_CONFLICT",
                    "The child group already has another active parent group.",
                )
            try:
                await validate_group_nesting(db, parent, child)
            except ValueError as exc:
                raise RecycleBinError(
                    "RECYCLE_RESTORE_GROUP_NESTING_CONFLICT",
                    "The restored group nesting is no longer valid.",
                ) from exc
        elif entity_type == "DEVICE_PLACEMENT":
            device = await db.scalar(select(Device).where(Device.id == row.device_id))
            if device is not None and await _checked_type(db, device) not in {"CPE", "ACCESS_POINT"}:
                await validate_placement_hierarchy(
                    db,
                    network_id=row.network_id,
                    city_id=row.city_id,
                    location_id=row.location_id,
                    sector_id=row.sector_id,
                )


async def _lock_restore_context(
    db: AsyncSession,
    typed: dict[tuple[str, UUID], Any],
) -> None:
    """Lock all external restore parents/endpoints in a stable order.

    Batch rows are hidden, so no normal mutation can target them. External
    parents are different: a concurrent parent recycle or Sector role change
    could otherwise pass between prevalidation and the final flush. We gather
    the complete reference set first and acquire locks by model and UUID.
    """

    refs: dict[Any, set[UUID]] = {
        Customer: set(),
        Network: set(),
        City: set(),
        Location: set(),
        Sector: set(),
        DeviceType: set(),
        Device: set(),
        DeviceGroup: set(),
    }
    for (entity_type, _), row in typed.items():
        if entity_type == "CITY":
            refs[Network].add(row.network_id)
        elif entity_type == "LOCATION":
            refs[City].add(row.city_id)
        elif entity_type == "SECTOR":
            refs[Location].add(row.location_id)
            if row.sector_device_id is not None:
                refs[Device].add(row.sector_device_id)
        elif entity_type == "DEVICE":
            refs[DeviceType].add(row.device_type_id)
        elif entity_type == "CUSTOMER_SERVICE":
            refs[Customer].add(row.customer_id)
            refs[Sector].add(row.sector_id)
            refs[Device].update({row.cpe_device_id, row.access_point_device_id})
            if row.router_device_id is not None:
                refs[Device].add(row.router_device_id)
        elif entity_type == "DEVICE_GROUP":
            scope_ref = {
                "NETWORK": (Network, row.network_id),
                "CITY": (City, row.city_id),
                "LOCATION": (Location, row.location_id),
                "SECTOR": (Sector, row.sector_id),
            }.get(row.scope_type)
            if scope_ref is not None and scope_ref[1] is not None:
                refs[scope_ref[0]].add(scope_ref[1])
        elif entity_type == "DEVICE_RELATIONSHIP":
            refs[Device].update({row.source_device_id, row.target_device_id})
        elif entity_type in {"DEVICE_IP", "DEVICE_INTERFACE"}:
            refs[Device].add(row.device_id)
        elif entity_type == "DEVICE_PLACEMENT":
            refs[Device].add(row.device_id)
            refs[Network].add(row.network_id)
            refs[City].add(row.city_id)
            refs[Location].add(row.location_id)
            if row.sector_id is not None:
                refs[Sector].add(row.sector_id)
        elif entity_type == "DEVICE_HIERARCHY_LINK":
            refs[Device].update({row.parent_device_id, row.child_device_id})
        elif entity_type == "DEVICE_GROUP_MEMBERSHIP":
            refs[Device].add(row.device_id)
            refs[DeviceGroup].add(row.group_id)
        elif entity_type == "DEVICE_GROUP_NESTING":
            refs[DeviceGroup].update({row.parent_group_id, row.child_group_id})

    async def lock_ids(model, ids: set[UUID]) -> list[Any]:
        if not ids:
            return []
        return list(
            (
                await db.scalars(
                    select(model)
                    .where(model.id.in_(ids))
                    .order_by(model.id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
            ).all()
        )

    # This prefix mirrors CustomerService validation: customer, geography /
    # Sector, then device endpoints. Independent model families do not share
    # locks and are ordered here so multiple restores make the same choice.
    await lock_ids(Customer, refs[Customer])
    await lock_ids(Network, refs[Network])
    await lock_ids(City, refs[City])
    await lock_ids(Location, refs[Location])
    await lock_ids(Sector, refs[Sector])
    await lock_ids(DeviceType, refs[DeviceType])

    # Expand the physical hierarchy closure. Three levels cover
    # AP -> CPE -> SECTOR device and any incident child slot that can conflict.
    device_closure = set(refs[Device])
    for _ in range(3):
        if not device_closure:
            break
        links = list(
            (
                await db.scalars(
                    select(DeviceHierarchyLink)
                    .where(
                        or_(
                            DeviceHierarchyLink.parent_device_id.in_(device_closure),
                            DeviceHierarchyLink.child_device_id.in_(device_closure),
                        )
                    )
                    .order_by(DeviceHierarchyLink.id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
            ).all()
        )
        expanded = device_closure | {
            endpoint
            for link in links
            for endpoint in (link.parent_device_id, link.child_device_id)
        }
        if expanded == device_closure:
            break
        device_closure = expanded

    devices = await lock_ids(Device, device_closure)
    refs[DeviceType].update(device.device_type_id for device in devices)
    await lock_ids(DeviceType, refs[DeviceType])

    bound_sectors = []
    if device_closure:
        bound_sectors = list(
            (
                await db.scalars(
                    select(Sector)
                    .where(Sector.sector_device_id.in_(device_closure))
                    .order_by(Sector.id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
            ).all()
        )
    # Lock the geography branch that gives the authoritative hierarchy its
    # current meaning. Active children already prevent parent recycle, but
    # retaining these locks also stabilizes restore-time group validation.
    locations = await lock_ids(
        Location,
        refs[Location] | {sector.location_id for sector in bound_sectors},
    )
    cities = await lock_ids(City, refs[City] | {location.city_id for location in locations})
    await lock_ids(Network, refs[Network] | {city.network_id for city in cities})
    await lock_ids(DeviceGroup, refs[DeviceGroup])


async def restore_recycle_batch(
    db: AsyncSession,
    *,
    batch_id: UUID,
    actor_user_id: UUID | None,
    now: datetime | None = None,
) -> RecycleBinBatch:
    """Lock and restore the complete batch, or restore nothing."""

    batch, items = await get_recycle_batch(db, batch_id=batch_id, for_update=True)
    if batch.status == RESTORED:
        raise RecycleBinError("RECYCLE_BATCH_ALREADY_RESTORED", "The batch is already restored.")
    if batch.status not in {RECYCLED, PURGE_FAILED}:
        raise RecycleBinError("RECYCLE_BATCH_STATE_INVALID", "The batch cannot be restored.")
    if not items:
        raise RecycleBinError("RECYCLE_BATCH_EMPTY", "The batch contains no restorable items.")

    typed: dict[tuple[str, UUID], Any] = {}
    for item in items:
        model = ITEM_MODELS.get(item.entity_type)
        if model is None:
            raise RecycleBinError("RECYCLE_ITEM_TYPE_UNSUPPORTED", "The batch contains an unsupported item type.")
        row = await _one(
            db,
            model,
            item.entity_id,
            include_recycled=True,
            for_update=False,
        )
        if row is None:
            raise RecycleBinError(
                "RECYCLE_ITEM_MISSING",
                "A typed row required by the batch is missing.",
                conflicts=[_blocker("RECYCLE_ITEM_MISSING", item.entity_type, item.entity_id, "Typed row is missing.")],
            )
        if row.deleted_at is None or row.deletion_batch_id != batch.id:
            raise RecycleBinError(
                "RECYCLE_ITEM_BATCH_MISMATCH",
                "A typed row no longer belongs to this batch.",
            )
        typed[(item.entity_type, item.entity_id)] = row

    await _lock_restore_context(db, typed)
    # External parents are locked before hidden bundle rows. This matches
    # delete-preview lock order and avoids group/geography cross-batch cycles.
    for item in sorted(items, key=lambda value: (value.restore_order, value.entity_type, str(value.entity_id))):
        row = await _one(
            db,
            ITEM_MODELS[item.entity_type],
            item.entity_id,
            include_recycled=True,
            for_update=True,
        )
        if row is None or row.deleted_at is None or row.deletion_batch_id != batch.id:
            raise RecycleBinError(
                "RECYCLE_ITEM_BATCH_MISMATCH",
                "A typed row changed while the restore context was being locked.",
                conflicts=[
                    _blocker(
                        "RECYCLE_ITEM_BATCH_MISMATCH",
                        item.entity_type,
                        item.entity_id,
                        "The typed row is missing or belongs to another batch.",
                    )
                ],
            )
        typed[(item.entity_type, item.entity_id)] = row

    restoring = set(typed)
    for item in sorted(items, key=lambda value: value.restore_order):
        try:
            await _validate_restore_item(
                db,
                item.entity_type,
                typed[(item.entity_type, item.entity_id)],
                restoring=restoring,
                typed=typed,
            )
        except RecycleBinError as exc:
            if not exc.conflicts:
                exc.conflicts = [
                    _blocker(exc.code, item.entity_type, item.entity_id, exc.message)
                ]
            raise

    timestamp = now or _now()
    try:
        async with db.begin_nested():
            for item in sorted(items, key=lambda value: value.restore_order):
                row = typed[(item.entity_type, item.entity_id)]
                row.deleted_at = None
                row.deletion_batch_id = None
            await db.flush()
            await _post_restore_validate(db, typed)
            batch.status = RESTORED
            batch.restored_at = timestamp
            batch.restored_by_user_id = actor_user_id
            batch.last_attempt_at = timestamp
            batch.last_error_code = None
            batch.last_error_message = None
            await record_audit(
                db,
                action=_recycle_audit_action(batch.root_entity_type, "RESTORED"),
                entity_type=batch.root_entity_type,
                entity_id=batch.root_entity_id,
                description="Recycle-bin batch restored atomically.",
                metadata={"batch_id": str(batch.id), "item_count": len(items)},
                actor_user_id=actor_user_id,
            )
            await db.flush()
    except RecycleBinError:
        raise
    except IntegrityError as exc:
        raise RecycleBinError(
            "RECYCLE_RESTORE_CONFLICT",
            "A unique identity or concurrent dependency prevents restore.",
            conflicts=[
                _blocker(
                    "RECYCLE_RESTORE_CONFLICT",
                    batch.root_entity_type,
                    batch.root_entity_id,
                    "A database uniqueness or dependency rule rejected the batch.",
                )
            ],
        ) from exc
    except (
        CustomerServiceValidationError,
        GroupMembershipConflict,
        HierarchyValidationError,
        PlacementValidationError,
        ValueError,
    ) as exc:
        code = getattr(exc, "code", "RECYCLE_RESTORE_VALIDATION_FAILED")
        message = getattr(exc, "message", str(exc))
        raise RecycleBinError(
            "RECYCLE_RESTORE_VALIDATION_FAILED",
            "The batch no longer satisfies current domain rules.",
            conflicts=[_blocker(code, batch.root_entity_type, batch.root_entity_id, message)],
        ) from exc
    return batch
