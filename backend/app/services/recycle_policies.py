"""Explicit model catalog and safe display metadata for recycle operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from ..models import (
    City,
    Customer,
    CustomerService,
    Device,
    DeviceGroup,
    DeviceGroupMembership,
    DeviceGroupNesting,
    DeviceHierarchyLink,
    DeviceIP,
    DeviceInterface,
    DevicePlacement,
    DeviceRelationship,
    Location,
    Network,
    Sector,
)


ROOT_MODELS = {
    "NETWORK": Network,
    "CITY": City,
    "LOCATION": Location,
    "SECTOR": Sector,
    "DEVICE": Device,
    "CUSTOMER": Customer,
    "CUSTOMER_SERVICE": CustomerService,
    "DEVICE_GROUP": DeviceGroup,
    "DEVICE_RELATIONSHIP": DeviceRelationship,
    "DEVICE_IP": DeviceIP,
    "DEVICE_INTERFACE": DeviceInterface,
}

ITEM_MODELS = {
    **ROOT_MODELS,
    "DEVICE_PLACEMENT": DevicePlacement,
    "DEVICE_HIERARCHY_LINK": DeviceHierarchyLink,
    "DEVICE_GROUP_MEMBERSHIP": DeviceGroupMembership,
    "DEVICE_GROUP_NESTING": DeviceGroupNesting,
}

ENTITY_ALIASES = {
    "CUSTOMERSERVICE": "CUSTOMER_SERVICE",
    "SERVICE": "CUSTOMER_SERVICE",
    "GROUP": "DEVICE_GROUP",
    "RELATIONSHIP": "DEVICE_RELATIONSHIP",
    "IP": "DEVICE_IP",
    "INTERFACE": "DEVICE_INTERFACE",
}


@dataclass(frozen=True)
class RecyclePreviewItem:
    entity_type: str
    entity_id: UUID
    item_role: str
    display_snapshot: dict[str, Any]
    restore_order: int
    purge_order: int


@dataclass(frozen=True)
class RecyclePreview:
    entity_type: str
    entity_id: UUID
    display_snapshot: dict[str, Any]
    bundled_items: list[RecyclePreviewItem]
    blockers: list[dict[str, Any]]
    requires_confirmation: bool


@dataclass(frozen=True)
class PurgeSummary:
    considered: int
    purged: int
    failed: int
    batch_ids: list[UUID]


def normalize_entity_type(entity_type: str) -> str:
    normalized = entity_type.strip().upper().replace("-", "_").replace(" ", "_")
    normalized = ENTITY_ALIASES.get(normalized, normalized)
    if normalized not in ROOT_MODELS:
        raise ValueError("UNSUPPORTED_RECYCLE_ENTITY_TYPE")
    return normalized


def safe_display_snapshot(entity_type: str, row: Any) -> dict[str, Any]:
    """Return allow-listed, immutable display data with no credentials/metadata."""

    snapshot: dict[str, Any] = {"id": str(row.id), "entity_type": entity_type}
    if entity_type in {"NETWORK", "CITY", "LOCATION", "SECTOR"}:
        snapshot.update(label=row.name, code=row.code)
    elif entity_type == "DEVICE":
        snapshot.update(
            label=row.display_name,
            hostname=row.hostname,
            device_type_id=str(row.device_type_id),
            lifecycle_state=row.lifecycle_state,
        )
    elif entity_type == "CUSTOMER":
        snapshot.update(label=row.name, code=row.customer_code)
    elif entity_type == "CUSTOMER_SERVICE":
        snapshot.update(label=row.service_code, status=row.status)
    elif entity_type == "DEVICE_GROUP":
        snapshot.update(label=row.name, code=row.code, scope_type=row.scope_type)
    elif entity_type == "DEVICE_RELATIONSHIP":
        snapshot.update(
            label=row.relationship_type,
            source_device_id=str(row.source_device_id),
            target_device_id=str(row.target_device_id),
            direction=row.direction,
        )
    elif entity_type == "DEVICE_IP":
        snapshot.update(
            label=row.ip_address,
            device_id=str(row.device_id),
            is_management=row.is_management,
            is_primary=row.is_primary,
        )
    elif entity_type == "DEVICE_INTERFACE":
        snapshot.update(
            label=row.interface_name,
            device_id=str(row.device_id),
            interface_index=row.interface_index,
        )
    elif entity_type == "DEVICE_PLACEMENT":
        snapshot.update(label="Device placement", device_id=str(row.device_id))
    elif entity_type == "DEVICE_HIERARCHY_LINK":
        snapshot.update(
            label=row.relationship_type,
            parent_device_id=str(row.parent_device_id),
            child_device_id=str(row.child_device_id),
        )
    elif entity_type == "DEVICE_GROUP_MEMBERSHIP":
        snapshot.update(
            label="Group membership",
            device_id=str(row.device_id),
            group_id=str(row.group_id),
        )
    elif entity_type == "DEVICE_GROUP_NESTING":
        snapshot.update(label="Nested group", parent_group_id=str(row.parent_group_id), child_group_id=str(row.child_group_id))
    return snapshot


def preview_item(
    entity_type: str,
    row: Any,
    *,
    item_role: str,
    restore_order: int,
) -> RecyclePreviewItem:
    return RecyclePreviewItem(
        entity_type=entity_type,
        entity_id=row.id,
        item_role=item_role,
        display_snapshot=safe_display_snapshot(entity_type, row),
        restore_order=restore_order,
        purge_order=100 - restore_order,
    )

