from ipaddress import ip_address
import logging
from uuid import UUID
import time

import httpx

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, case, func, select, or_
from sqlalchemy.orm import aliased
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ..recycle_support import recycle_from_delete_endpoint
from ...security.authorization import authorize_request, user_has_permission
from ...security.resource_scope import scope_for_actor
from ...security.scope_queries import require_device
from ...models import (
    CustomerService,
    Device,
    DeviceHierarchyLink,
    DeviceIP,
    DeviceInterface,
    DeviceType,
    DevicePlacement,
    Network,
    City,
    Location,
    Sector,
)
from ...schemas.device import (
    DeviceCreate,
    DeviceIPCreate,
    DeviceIPRead,
    DeviceIPUpdate,
    DeviceInterfaceCreate,
    DeviceInterfaceRead,
    DeviceInterfaceUpdate,
    DeviceRead,
    DeviceInventoryRead,
    DeviceManagementRead,
    DeviceAccessibilityResponse,
    DeviceStatusUpdate,
    DeviceTypeRead,
    DeviceUpdate,
)
from ...services.audit import record_audit, record_failure_audit
from ...core.audit_context import get_audit_context
from ...core.exceptions import APIError
from ...security.permissions import Permission as PermissionCode
from ...services.audit_summaries import business_summary, changed_summary, display_snapshot
from ...services.crud import get_active_for_update_or_404, get_or_404
from ...services.device_registration import register_domain_device
from ...services.device_ips import apply_ip_flags, ensure_ip_recycle_permitted
from ...services.hierarchy import HierarchyValidationError, resolve_effective_hierarchy
from ...services.movement import (
    MovementValidationError,
    move_cpe_to_sector,
    reassign_access_point,
    rebind_sector_device,
)
from ...services.placements import PlacementValidationError, update_device_placement
from ...schemas.device import LIFECYCLE_STATES
from ...services.groups import effective_group_device_ids
from ...schemas.pagination import PageResult


router = APIRouter()

@router.get(
    "/{device_id}/interfaces",
    response_model=list[DeviceInterfaceRead],
)
async def list_device_interfaces(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await require_device(db, await scope_for_actor(db, actor), device_id)
    result = await db.execute(
        select(DeviceInterface)
        .where(DeviceInterface.device_id == device_id)
        .order_by(DeviceInterface.interface_index, DeviceInterface.interface_name)
    )
    return result.scalars().all()


@router.post(
    "/{device_id}/interfaces",
    response_model=DeviceInterfaceRead,
    status_code=status.HTTP_201_CREATED,
)
async def add_device_interface(
    device_id: UUID,
    payload: DeviceInterfaceCreate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await require_device(db, await scope_for_actor(db, actor), device_id, for_update=True)

    data = payload.model_dump()
    data["metadata_"] = data.pop("metadata")
    obj = DeviceInterface(device_id=device_id, **data)
    db.add(obj)
    await db.flush()
    await record_audit(
        db,
        action="DEVICE_INTERFACE_CHANGED",
        entity_type="DeviceInterface",
        entity_id=obj.id,
        description="Device interface added.",
        entity_display_snapshot=display_snapshot(obj),
        metadata={"operation": "ADDED"},
        after_summary=business_summary(obj),
    )
    await db.commit()
    await db.refresh(obj)
    return obj


@router.patch(
    "/{device_id}/interfaces/{interface_id}",
    response_model=DeviceInterfaceRead,
)
async def update_device_interface(
    device_id: UUID,
    interface_id: UUID,
    payload: DeviceInterfaceUpdate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await require_device(db, await scope_for_actor(db, actor), device_id, for_update=True)

    result = await db.execute(
        select(DeviceInterface)
        .where(
            DeviceInterface.id == interface_id,
            DeviceInterface.device_id == device_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    obj = result.scalar_one_or_none()

    if obj is None:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=404,
            detail={
                "code": "INTERFACE_NOT_FOUND",
                "message": "Device interface not found.",
            },
        )

    before = business_summary(obj)
    data = payload.model_dump(exclude_unset=True)
    metadata_requested = "metadata" in data
    if "metadata" in data:
        obj.metadata_ = data.pop("metadata")

    for key, value in data.items():
        old_value = getattr(obj, key)
        if old_value != value:
            setattr(obj, key, value)

    after = business_summary(obj)
    before_changes, after_changes, changed_fields = changed_summary(before, after)
    if changed_fields or metadata_requested:
        await record_audit(
            db,
            action="DEVICE_INTERFACE_CHANGED",
            entity_type="DeviceInterface",
            entity_id=obj.id,
            description="Device interface updated.",
            entity_display_snapshot=display_snapshot(obj),
            metadata={
                "operation": "UPDATED",
                "changed_fields": [
                    *changed_fields,
                    *(["metadata"] if metadata_requested else []),
                ],
            },
            before_summary=before_changes,
            after_summary=after_changes,
        )

    await db.commit()
    await db.refresh(obj)
    return obj


@router.delete(
    "/{device_id}/interfaces/{interface_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_device_interface(
    device_id: UUID,
    interface_id: UUID,
    reason: str | None = None,
    confirmed: bool = False,
    actor=Depends(authorize_request),
    db: AsyncSession = Depends(get_db),
):
    await require_device(db, await scope_for_actor(db, actor), device_id, for_update=True)

    result = await db.execute(
        select(DeviceInterface)
        .where(
            DeviceInterface.id == interface_id,
            DeviceInterface.device_id == device_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    obj = result.scalar_one_or_none()

    if obj is None:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=404,
            detail={
                "code": "INTERFACE_NOT_FOUND",
                "message": "Device interface not found.",
            },
        )

    await recycle_from_delete_endpoint(
        db,
        entity_type="DEVICE_INTERFACE",
        entity_id=interface_id,
        actor=actor,
        reason=reason,
        confirmed=confirmed,
    )
    return None
