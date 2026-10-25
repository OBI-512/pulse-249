"""Allowlisted audit summaries for mutable business-domain records.

These helpers deliberately omit free-form metadata, descriptions, device
credential references, and every authentication/session field.  The audit
service applies recursive redaction as defense in depth, but domain callers
should never submit a secret-bearing field in the first place.
"""

from __future__ import annotations

from enum import Enum
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
    DeviceIP,
    DeviceInterface,
    DevicePlacement,
    DeviceRelationship,
    Location,
    Network,
    Sector,
)


def _value(value: Any) -> Any:
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    return value


def _fields(row: Any, *names: str) -> dict[str, Any]:
    return {name: _value(getattr(row, name, None)) for name in names}


def business_summary(row: Any) -> dict[str, Any]:
    """Return a small, non-secret state summary for a supported domain row."""

    if isinstance(row, Network):
        return _fields(row, "name", "code", "status")
    if isinstance(row, City):
        return _fields(row, "network_id", "name", "code", "status", "service_vlan_id")
    if isinstance(row, Location):
        return _fields(row, "city_id", "name", "code", "status")
    if isinstance(row, Sector):
        return _fields(
            row,
            "location_id",
            "name",
            "code",
            "sequence_number",
            "status",
            "role",
            "customer_vlan_start",
            "customer_vlan_end",
            "sector_device_id",
        )
    if isinstance(row, Device):
        return _fields(
            row,
            "device_type_id",
            "display_name",
            "hostname",
            "vendor",
            "model",
            "lifecycle_state",
            "operational_state",
            "management_protocol",
        )
    if isinstance(row, DeviceIP):
        return _fields(
            row,
            "device_id",
            "ip_address",
            "address_family",
            "is_management",
            "is_primary",
            "source",
        )
    if isinstance(row, DeviceInterface):
        return _fields(
            row,
            "device_id",
            "interface_name",
            "interface_index",
            "mac_address",
            "operational_status",
            "administrative_status",
        )
    if isinstance(row, Customer):
        return _fields(row, "customer_code", "name", "status")
    if isinstance(row, CustomerService):
        return _fields(
            row,
            "customer_id",
            "sector_id",
            "service_code",
            "status",
            "cpe_device_id",
            "access_point_device_id",
            "router_device_id",
            "customer_vlan_id",
        )
    if isinstance(row, DeviceGroup):
        return _fields(
            row,
            "name",
            "code",
            "scope_type",
            "network_id",
            "city_id",
            "location_id",
            "sector_id",
            "device_scope",
            "sector_role",
        )
    if isinstance(row, DeviceGroupMembership):
        return _fields(row, "device_id", "group_id")
    if isinstance(row, DeviceGroupNesting):
        return _fields(row, "parent_group_id", "child_group_id")
    if isinstance(row, DevicePlacement):
        return _fields(
            row,
            "device_id",
            "network_id",
            "city_id",
            "location_id",
            "sector_id",
        )
    if isinstance(row, DeviceRelationship):
        return _fields(
            row,
            "source_device_id",
            "target_device_id",
            "relationship_type",
            "direction",
        )
    raise TypeError(f"Unsupported audit summary type: {type(row).__name__}")


def display_snapshot(row: Any) -> dict[str, Any]:
    """Return immutable labels suitable for list/detail audit presentation."""

    if isinstance(row, Device):
        return _fields(row, "display_name", "hostname")
    if isinstance(row, Customer):
        return _fields(row, "customer_code", "name")
    if isinstance(row, CustomerService):
        return _fields(row, "service_code", "customer_id")
    if isinstance(row, DeviceIP):
        return _fields(row, "ip_address", "device_id")
    if isinstance(row, DeviceInterface):
        return _fields(row, "interface_name", "device_id")
    if isinstance(row, DeviceGroup):
        return _fields(row, "name", "code")
    if isinstance(row, DeviceGroupMembership):
        return _fields(row, "device_id", "group_id")
    if isinstance(row, DeviceGroupNesting):
        return _fields(row, "parent_group_id", "child_group_id")
    if isinstance(row, DevicePlacement):
        return _fields(row, "device_id", "location_id")
    if isinstance(row, DeviceRelationship):
        return _fields(
            row,
            "relationship_type",
            "source_device_id",
            "target_device_id",
        )
    if isinstance(row, (Network, City, Location, Sector)):
        return _fields(row, "name", "code")
    raise TypeError(f"Unsupported audit display type: {type(row).__name__}")


def changed_summary(
    before: dict[str, Any],
    after: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """Return only changed allowlisted values and their stable field names."""

    changed = sorted(
        key
        for key in before.keys() | after.keys()
        if before.get(key) != after.get(key)
    )
    return (
        {key: before.get(key) for key in changed},
        {key: after.get(key) for key in changed},
        changed,
    )
