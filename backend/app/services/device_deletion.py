"""Dependency-safe hard deletion for decommissioned devices.

Hard deletion remains a temporary operation until recycle semantics exist, but
it must never use database cascades as the business decision for the
authoritative customer hierarchy.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import CustomerService, Device, DeviceHierarchyLink, Sector
from .audit import record_audit


class DeviceDeletionError(ValueError):
    """A device cannot be hard-deleted in its current domain state."""

    def __init__(self, code: str, message: str, status_code: int = 409):
        self.code = code
        self.message = message
        self.status_code = status_code
        super().__init__(message)


async def delete_device_with_domain_guards(
    db: AsyncSession,
    *,
    device_id: UUID,
) -> None:
    """Validate and stage one dependency-safe device deletion.

    The target device row is locked before dependency inspection. PostgreSQL
    foreign-key checks on concurrent hierarchy, sector-binding, or
    customer-service creation must consequently wait for this transaction,
    preventing a dependency from appearing between validation and deletion.

    This service deliberately does not commit. The caller owns the transaction
    boundary so the audit record and deletion succeed or roll back together.
    """

    device = await db.scalar(
        select(Device)
        .where(Device.id == device_id)
        .with_for_update()
    )
    if device is None:
        raise DeviceDeletionError(
            "RESOURCE_NOT_FOUND",
            "Device not found.",
            status_code=404,
        )

    if device.lifecycle_state != "DECOMMISSIONED":
        raise DeviceDeletionError(
            "DEVICE_NOT_DECOMMISSIONED",
            "Device must be decommissioned before permanent deletion.",
        )

    # CustomerService is retained domain data even when its status is no
    # longer ACTIVE. Protecting every reference avoids replacing a stable
    # domain conflict with a late FK error and prevents historical services
    # from losing their physical endpoints.
    service_dependency = await db.scalar(
        select(CustomerService.id)
        .where(
            or_(
                CustomerService.cpe_device_id == device.id,
                CustomerService.access_point_device_id == device.id,
            )
        )
        .limit(1)
        .with_for_update()
    )
    if service_dependency is not None:
        raise DeviceDeletionError(
            "DEVICE_HAS_CUSTOMER_SERVICE_DEPENDENCIES",
            "Device cannot be deleted while it is referenced by a customer service.",
        )

    # Only outgoing authoritative hierarchy links leave another device behind.
    # An incoming link belongs to the device being removed and is safe to
    # disappear with that same child.
    child_dependency = await db.scalar(
        select(DeviceHierarchyLink.id)
        .where(DeviceHierarchyLink.parent_device_id == device.id)
        .limit(1)
        .with_for_update()
    )
    if child_dependency is not None:
        raise DeviceDeletionError(
            "DEVICE_HAS_HIERARCHY_DEPENDENCIES",
            "Device cannot be deleted while authoritative hierarchy children are attached.",
        )

    sector_binding = await db.scalar(
        select(Sector.id)
        .where(Sector.sector_device_id == device.id)
        .limit(1)
        .with_for_update()
    )
    if sector_binding is not None:
        raise DeviceDeletionError(
            "SECTOR_DEVICE_IS_BOUND",
            "Device cannot be deleted while it is bound to a sector.",
        )

    await record_audit(
        db,
        action="DEVICE_DELETED",
        entity_type="Device",
        entity_id=device.id,
        description="Decommissioned device permanently deleted through the device-management API.",
        metadata={"display_name": device.display_name},
    )
    await db.delete(device)
    await db.flush()
