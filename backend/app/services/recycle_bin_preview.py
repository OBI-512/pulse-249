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
    RecycleBinError, _active_root, _blocker, _dedupe, _hidden_dependency_blockers,
    _one, _rows, _scoped_group_blockers, _type_code,
)

async def _device_parts(
    db: AsyncSession,
    device: Device,
    *,
    for_update: bool,
    allowed_sector_id: UUID | None = None,
    include_device: bool = False,
) -> tuple[list[RecyclePreviewItem], list[dict[str, Any]]]:
    items: list[RecyclePreviewItem] = []
    blockers: list[dict[str, Any]] = []

    device_type_code = await _type_code(db, device)
    if device_type_code is None:
        blockers.append(_blocker("DEVICE_TYPE_NOT_FOUND", "DEVICE", device.id, "Device type is missing."))

    for sector in await _rows(
        db, Sector, Sector.sector_device_id == device.id, for_update=for_update
    ):
        if sector.id != allowed_sector_id:
            blockers.append(
                _blocker(
                    "SECTOR_DEVICE_IS_BOUND",
                    "SECTOR",
                    sector.id,
                    "A bound SECTOR device must be recycled through its logical Sector.",
                )
            )

    children = await _rows(
        db,
        DeviceHierarchyLink,
        DeviceHierarchyLink.parent_device_id == device.id,
        for_update=for_update,
    )
    blockers.extend(
        _blocker(
            "DEVICE_HAS_HIERARCHY_DEPENDENCIES",
            "DEVICE_HIERARCHY_LINK",
            link.id,
            "An authoritative hierarchy child is still attached.",
        )
        for link in children
    )

    services = await _rows(
        db,
        CustomerService,
        or_(
            CustomerService.cpe_device_id == device.id,
            CustomerService.access_point_device_id == device.id,
            CustomerService.router_device_id == device.id,
        ),
        for_update=for_update,
    )
    if device_type_code == "ACCESS_POINT" and services:
        # Phase 23 operator workflow: an ACCESS_POINT owns the customer-facing
        # end of one CustomerService. Recycle the service and its customer in
        # the same recoverable batch instead of forcing three separate recycle
        # operations. CPE hierarchy protection remains unchanged.
        items.extend(
            preview_item(
                "CUSTOMER_SERVICE",
                service,
                item_role="BUNDLE",
                restore_order=30,
            )
            for service in services
        )
        customer_ids = {service.customer_id for service in services}
        customers = (
            await _rows(
                db,
                Customer,
                Customer.id.in_(customer_ids),
                for_update=for_update,
            )
            if customer_ids
            else []
        )
        customer_by_id = {customer.id: customer for customer in customers}
        for service in services:
            customer = customer_by_id.get(service.customer_id)
            if customer is None:
                blockers.append(
                    _blocker(
                        "CUSTOMER_SERVICE_CUSTOMER_NOT_ACTIVE",
                        "CUSTOMER",
                        service.customer_id,
                        "The customer referenced by this service is not active.",
                    )
                )
                continue
            items.append(
                preview_item(
                    "CUSTOMER",
                    customer,
                    item_role="BUNDLE",
                    restore_order=10,
                )
            )
    else:
        blockers.extend(
            _blocker(
                "DEVICE_HAS_CUSTOMER_SERVICE_DEPENDENCIES",
                "CUSTOMER_SERVICE",
                service.id,
                "A customer service still references this device.",
            )
            for service in services
        )

    # Hidden dependants from another batch cannot be allowed to disappear via
    # this device's database cascades during a later permanent purge.
    incident_specs = (
        ("DEVICE_IP", DeviceIP, DeviceIP.device_id == device.id),
        ("DEVICE_INTERFACE", DeviceInterface, DeviceInterface.device_id == device.id),
        ("DEVICE_PLACEMENT", DevicePlacement, DevicePlacement.device_id == device.id),
        (
            "DEVICE_HIERARCHY_LINK",
            DeviceHierarchyLink,
            or_(DeviceHierarchyLink.parent_device_id == device.id, DeviceHierarchyLink.child_device_id == device.id),
        ),
        (
            "DEVICE_RELATIONSHIP",
            DeviceRelationship,
            or_(DeviceRelationship.source_device_id == device.id, DeviceRelationship.target_device_id == device.id),
        ),
        ("DEVICE_GROUP_MEMBERSHIP", DeviceGroupMembership, DeviceGroupMembership.device_id == device.id),
    )
    for entity_type, model, condition in incident_specs:
        hidden = await _rows(
            db,
            model,
            condition,
            model.deleted_at.is_not(None),
            include_recycled=True,
            for_update=for_update,
        )
        blockers.extend(
            _blocker(
                "ENTITY_HAS_OTHER_RECYCLE_BATCH_DEPENDENCIES",
                entity_type,
                dependent.id,
                "A dependent row belongs to another recycle batch.",
            )
            for dependent in hidden
        )
    hidden_services = await _rows(
        db,
        CustomerService,
        or_(
            CustomerService.cpe_device_id == device.id,
            CustomerService.access_point_device_id == device.id,
            CustomerService.router_device_id == device.id,
        ),
        CustomerService.deleted_at.is_not(None),
        include_recycled=True,
        for_update=for_update,
    )
    blockers.extend(
        _blocker(
            "ENTITY_HAS_OTHER_RECYCLE_BATCH_DEPENDENCIES",
            "CUSTOMER_SERVICE",
            service.id,
            "A customer-service dependency belongs to another recycle batch.",
        )
        for service in hidden_services
    )

    if include_device:
        items.append(preview_item("DEVICE", device, item_role="BUNDLE", restore_order=20))
    component_specs = (
        ("DEVICE_IP", DeviceIP, DeviceIP.device_id == device.id, 40),
        ("DEVICE_INTERFACE", DeviceInterface, DeviceInterface.device_id == device.id, 40),
        ("DEVICE_PLACEMENT", DevicePlacement, DevicePlacement.device_id == device.id, 45),
        ("DEVICE_HIERARCHY_LINK", DeviceHierarchyLink, DeviceHierarchyLink.child_device_id == device.id, 50),
        (
            "DEVICE_RELATIONSHIP",
            DeviceRelationship,
            or_(DeviceRelationship.source_device_id == device.id, DeviceRelationship.target_device_id == device.id),
            60,
        ),
        ("DEVICE_GROUP_MEMBERSHIP", DeviceGroupMembership, DeviceGroupMembership.device_id == device.id, 70),
    )
    for entity_type, model, condition, restore_order in component_specs:
        items.extend(
            preview_item(entity_type, row, item_role="BUNDLE", restore_order=restore_order)
            for row in await _rows(db, model, condition, for_update=for_update)
        )
    return _dedupe(items), blockers


async def _build_preview(
    db: AsyncSession,
    entity_type: str,
    root: Any,
    *,
    for_update: bool,
) -> RecyclePreview:
    items: list[RecyclePreviewItem] = []
    blockers: list[dict[str, Any]] = []
    requires_confirmation = False

    if entity_type == "NETWORK":
        blockers.extend(
            _blocker("NETWORK_HAS_CITIES", "CITY", row.id, "The network still contains an active city.")
            for row in await _rows(db, City, City.network_id == root.id, for_update=for_update)
        )
        blockers.extend(
            _blocker("NETWORK_HAS_PLACED_DEVICES", "DEVICE_PLACEMENT", row.id, "A placement depends on the network.")
            for row in await _rows(db, DevicePlacement, DevicePlacement.network_id == root.id, for_update=for_update)
        )
        blockers.extend(await _scoped_group_blockers(db, DeviceGroup.network_id, root.id, for_update=for_update))
        blockers.extend(
            await _hidden_dependency_blockers(
                db, City, "CITY", City.network_id == root.id, for_update=for_update
            )
        )
        blockers.extend(
            await _hidden_dependency_blockers(
                db,
                DevicePlacement,
                "DEVICE_PLACEMENT",
                DevicePlacement.network_id == root.id,
                for_update=for_update,
            )
        )
        blockers.extend(
            await _hidden_dependency_blockers(
                db, DeviceGroup, "DEVICE_GROUP", DeviceGroup.network_id == root.id, for_update=for_update
            )
        )
    elif entity_type == "CITY":
        blockers.extend(
            _blocker("CITY_HAS_LOCATIONS", "LOCATION", row.id, "The city still contains an active location.")
            for row in await _rows(db, Location, Location.city_id == root.id, for_update=for_update)
        )
        blockers.extend(
            _blocker("CITY_HAS_PLACED_DEVICES", "DEVICE_PLACEMENT", row.id, "A placement depends on the city.")
            for row in await _rows(db, DevicePlacement, DevicePlacement.city_id == root.id, for_update=for_update)
        )
        blockers.extend(await _scoped_group_blockers(db, DeviceGroup.city_id, root.id, for_update=for_update))
        blockers.extend(
            await _hidden_dependency_blockers(
                db, Location, "LOCATION", Location.city_id == root.id, for_update=for_update
            )
        )
        blockers.extend(
            await _hidden_dependency_blockers(
                db,
                DevicePlacement,
                "DEVICE_PLACEMENT",
                DevicePlacement.city_id == root.id,
                for_update=for_update,
            )
        )
        blockers.extend(
            await _hidden_dependency_blockers(
                db, DeviceGroup, "DEVICE_GROUP", DeviceGroup.city_id == root.id, for_update=for_update
            )
        )
    elif entity_type == "LOCATION":
        blockers.extend(
            _blocker("LOCATION_HAS_SECTORS", "SECTOR", row.id, "The location still contains an active Sector.")
            for row in await _rows(db, Sector, Sector.location_id == root.id, for_update=for_update)
        )
        for placement in await _rows(
            db, DevicePlacement, DevicePlacement.location_id == root.id, for_update=for_update
        ):
            device = await _one(db, Device, placement.device_id)
            if device is None or await _type_code(db, device) not in {"CPE", "ACCESS_POINT", "SECTOR"}:
                blockers.append(
                    _blocker(
                        "LOCATION_HAS_PLACED_DEVICES",
                        "DEVICE_PLACEMENT",
                        placement.id,
                        "Independently placed equipment depends on the location.",
                    )
                )
        blockers.extend(await _scoped_group_blockers(db, DeviceGroup.location_id, root.id, for_update=for_update))
        blockers.extend(
            await _hidden_dependency_blockers(
                db, Sector, "SECTOR", Sector.location_id == root.id, for_update=for_update
            )
        )
        blockers.extend(
            await _hidden_dependency_blockers(
                db,
                DevicePlacement,
                "DEVICE_PLACEMENT",
                DevicePlacement.location_id == root.id,
                for_update=for_update,
            )
        )
        blockers.extend(
            await _hidden_dependency_blockers(
                db, DeviceGroup, "DEVICE_GROUP", DeviceGroup.location_id == root.id, for_update=for_update
            )
        )
    elif entity_type == "SECTOR":
        blockers.extend(
            _blocker(
                "SECTOR_HAS_CUSTOMER_SERVICE_DEPENDENCIES",
                "CUSTOMER_SERVICE",
                row.id,
                "A CustomerService still depends on the Sector.",
            )
            for row in await _rows(db, CustomerService, CustomerService.sector_id == root.id, for_update=for_update)
        )
        if root.sector_device_id is not None:
            blockers.extend(
                _blocker(
                    "SECTOR_HAS_CPE_DEPENDENCIES",
                    "DEVICE_HIERARCHY_LINK",
                    row.id,
                    "An attached CPE still depends on the Sector.",
                )
                for row in await _rows(
                    db,
                    DeviceHierarchyLink,
                    DeviceHierarchyLink.parent_device_id == root.sector_device_id,
                    DeviceHierarchyLink.relationship_type == "SECTOR_CPE",
                    for_update=for_update,
                )
            )
        blockers.extend(
            _blocker(
                "SECTOR_HAS_PLACED_DEVICE_DEPENDENCIES",
                "DEVICE_PLACEMENT",
                row.id,
                "An independently managed placement still depends on the Sector.",
            )
            for row in await _rows(db, DevicePlacement, DevicePlacement.sector_id == root.id, for_update=for_update)
            if row.device_id != root.sector_device_id
        )
        blockers.extend(await _scoped_group_blockers(db, DeviceGroup.sector_id, root.id, for_update=for_update))
        blockers.extend(
            await _hidden_dependency_blockers(
                db,
                CustomerService,
                "CUSTOMER_SERVICE",
                CustomerService.sector_id == root.id,
                for_update=for_update,
            )
        )
        blockers.extend(
            await _hidden_dependency_blockers(
                db,
                DevicePlacement,
                "DEVICE_PLACEMENT",
                DevicePlacement.sector_id == root.id,
                for_update=for_update,
            )
        )
        blockers.extend(
            await _hidden_dependency_blockers(
                db, DeviceGroup, "DEVICE_GROUP", DeviceGroup.sector_id == root.id, for_update=for_update
            )
        )
        if root.sector_device_id is not None:
            blockers.extend(
                await _hidden_dependency_blockers(
                    db,
                    DeviceHierarchyLink,
                    "DEVICE_HIERARCHY_LINK",
                    DeviceHierarchyLink.parent_device_id == root.sector_device_id,
                    for_update=for_update,
                )
            )
        if root.sector_device_id is not None:
            sector_device = await _one(db, Device, root.sector_device_id, for_update=for_update)
            if sector_device is None:
                blockers.append(
                    _blocker(
                        "SECTOR_DEVICE_NOT_ACTIVE",
                        "DEVICE",
                        root.sector_device_id,
                        "The bound SECTOR device is missing or already recycled.",
                    )
                )
            else:
                if await _type_code(db, sector_device) != "SECTOR":
                    blockers.append(
                        _blocker("SECTOR_DEVICE_TYPE_INVALID", "DEVICE", sector_device.id, "Bound device type is invalid.")
                    )
                component_items, component_blockers = await _device_parts(
                    db,
                    sector_device,
                    for_update=for_update,
                    allowed_sector_id=root.id,
                    include_device=True,
                )
                items.extend(component_items)
                blockers.extend(component_blockers)
                requires_confirmation = True
    elif entity_type == "DEVICE":
        if root.lifecycle_state != "DECOMMISSIONED":
            blockers.append(
                _blocker(
                    "DEVICE_NOT_DECOMMISSIONED",
                    "DEVICE",
                    root.id,
                    "A device must be decommissioned before it can be recycled.",
                )
            )
        component_items, component_blockers = await _device_parts(db, root, for_update=for_update)
        items.extend(component_items)
        blockers.extend(component_blockers)
        if any(item.entity_type in {"CUSTOMER", "CUSTOMER_SERVICE"} for item in component_items):
            requires_confirmation = True
    elif entity_type == "CUSTOMER":
        services = await _rows(
            db,
            CustomerService,
            CustomerService.customer_id == root.id,
            for_update=for_update,
        )
        items.extend(
            preview_item(
                "CUSTOMER_SERVICE",
                service,
                item_role="BUNDLE",
                restore_order=30,
            )
            for service in services
        )
        if services:
            requires_confirmation = True
        blockers.extend(
            await _hidden_dependency_blockers(
                db,
                CustomerService,
                "CUSTOMER_SERVICE",
                CustomerService.customer_id == root.id,
                for_update=for_update,
            )
        )
    elif entity_type == "DEVICE_GROUP":
        if getattr(root, "group_kind", "CUSTOM") == "SYSTEM":
            blockers.append(
                _blocker(
                    "SYSTEM_GROUP_IMMUTABLE",
                    "DEVICE_GROUP",
                    root.id,
                    "Built-in system groups cannot be recycled or deleted.",
                )
            )
        items.extend(
            preview_item("DEVICE_GROUP_MEMBERSHIP", row, item_role="BUNDLE", restore_order=70)
            for row in await _rows(
                db,
                DeviceGroupMembership,
                DeviceGroupMembership.group_id == root.id,
                for_update=for_update,
            )
        )
        # A group owns no device. Historical membership rows that were already
        # tombstoned by another recycle batch must not prevent the group itself
        # from being recycled. They remain attached to their original batch so
        # restore history stays intact; cross-batch purge protection is enforced
        # separately by _purge_conflicts().
        nesting_condition = or_(
            DeviceGroupNesting.parent_group_id == root.id,
            DeviceGroupNesting.child_group_id == root.id,
        )
        items.extend(
            preview_item("DEVICE_GROUP_NESTING", row, item_role="BUNDLE", restore_order=70)
            for row in await _rows(
                db,
                DeviceGroupNesting,
                nesting_condition,
                for_update=for_update,
            )
        )
        # The same rule applies to historical parent/child links already owned
        # by another recycle batch. Active links are bundled above; hidden links
        # stay with the batch that tombstoned them and do not block recycling
        # this custom group. Parent/child groups themselves are never cascaded.
    elif entity_type == "DEVICE_RELATIONSHIP":
        if await _one(db, Device, root.source_device_id) is None or await _one(db, Device, root.target_device_id) is None:
            blockers.append(
                _blocker(
                    "RELATIONSHIP_ENDPOINT_NOT_ACTIVE",
                    entity_type,
                    root.id,
                    "Both relationship endpoints must be active.",
                )
            )
    elif entity_type in {"DEVICE_IP", "DEVICE_INTERFACE"}:
        if await _one(db, Device, root.device_id) is None:
            blockers.append(
                _blocker("DEVICE_PARENT_NOT_ACTIVE", "DEVICE", root.device_id, "The parent device is not active.")
            )
        if entity_type == "DEVICE_IP":
            device_ips = await _rows(
                db, DeviceIP, DeviceIP.device_id == root.device_id, for_update=for_update
            )
            if root.is_management and sum(1 for row in device_ips if row.is_management) <= 1:
                blockers.append(
                    _blocker(
                        "LAST_MANAGEMENT_IP_PROTECTED", "DEVICE", root.device_id,
                        "A device must retain at least one management IP.",
                    )
                )
            if root.is_primary:
                blockers.append(
                    _blocker(
                        "PRIMARY_IP_PROTECTED", "DEVICE_IP", root.id,
                        "Promote another management IP before recycling the primary IP.",
                    )
                )

    return RecyclePreview(
        entity_type=entity_type,
        entity_id=root.id,
        display_snapshot=safe_display_snapshot(entity_type, root),
        bundled_items=_dedupe(items),
        blockers=blockers,
        requires_confirmation=requires_confirmation,
    )


async def preview_recycle(
    db: AsyncSession,
    *,
    entity_type: str,
    entity_id: UUID,
) -> RecyclePreview:
    try:
        entity_type = normalize_entity_type(entity_type)
    except ValueError as exc:
        raise RecycleBinError(
            "UNSUPPORTED_RECYCLE_ENTITY_TYPE",
            "The requested entity type is not recoverable.",
            status_code=422,
        ) from exc
    root = await _active_root(db, entity_type, entity_id, for_update=False)
    return await _build_preview(db, entity_type, root, for_update=False)
