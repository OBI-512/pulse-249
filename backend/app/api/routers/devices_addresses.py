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
from ...services.web_tls_endpoint_invalidation import (
    current_management_ip_snapshot,
    invalidate_web_tls_trust_if_management_endpoint_changed,
)
from ...schemas.device import LIFECYCLE_STATES
from ...services.groups import effective_group_device_ids
from ...schemas.pagination import PageResult


router = APIRouter()

@router.get("/{device_id}/ips", response_model=list[DeviceIPRead])
async def list_device_ips(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await require_device(db, await scope_for_actor(db, actor), device_id)
    result = await db.execute(
        select(DeviceIP)
        .where(DeviceIP.device_id == device_id)
        .order_by(DeviceIP.is_management.desc(), DeviceIP.is_primary.desc())
    )
    return result.scalars().all()


@router.post(
    "/{device_id}/ips",
    response_model=DeviceIPRead,
    status_code=status.HTTP_201_CREATED,
)
async def add_device_ip(
    device_id: UUID,
    payload: DeviceIPCreate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await require_device(db, await scope_for_actor(db, actor), device_id, for_update=True)
    before_management_ip = await current_management_ip_snapshot(db, device_id)

    parsed = ip_address(payload.ip_address)
    family = payload.address_family or parsed.version

    if family != parsed.version:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=422,
            detail={
                "code": "ADDRESS_FAMILY_MISMATCH",
                "message": "address_family does not match ip_address.",
            },
        )

    # Primary is the device's canonical IP and therefore must also be a management IP.
    if payload.is_primary and not payload.is_management:
        raise HTTPException(status_code=422, detail={"code": "PRIMARY_IP_MUST_BE_MANAGEMENT", "message": "A primary IP must also be a management IP."})

    obj = DeviceIP(
        device_id=device_id,
        ip_address=payload.ip_address,
        address_family=family,
        is_management=payload.is_management,
        # Promote through the shared service after the row exists.  Starting
        # it as non-primary avoids a transient partial-unique-index conflict
        # with the device's current primary address.
        is_primary=False,
        source=payload.source,
    )
    db.add(obj)

    try:
        if payload.is_primary:
            await db.flush()
            await apply_ip_flags(
                db, device_id=device_id, target=obj,
                is_management=True, is_primary=True,
            )
        await db.flush()
        await invalidate_web_tls_trust_if_management_endpoint_changed(
            db,
            device_id=device_id,
            before_management_ip=before_management_ip,
            actor_user_id=getattr(actor, "id", None),
        )
        await record_audit(
            db,
            action="DEVICE_IP_ADDED",
            entity_type="DeviceIP",
            entity_id=obj.id,
            description="Device IP address added.",
            entity_display_snapshot=display_snapshot(obj),
            after_summary=business_summary(obj),
        )
        await db.commit()
    except IntegrityError:
        await db.rollback()
        from fastapi import HTTPException
        raise HTTPException(
            status_code=409,
            detail={
                "code": "IP_ALREADY_REGISTERED",
                "message": "This IP address is already registered.",
            },
        )

    await db.refresh(obj)
    return obj


@router.patch("/{device_id}/ips/{ip_id}", response_model=DeviceIPRead)
async def update_device_ip(
    device_id: UUID,
    ip_id: UUID,
    payload: DeviceIPUpdate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await require_device(db, await scope_for_actor(db, actor), device_id, for_update=True)
    result = await db.execute(
        select(DeviceIP)
        .where(
            DeviceIP.id == ip_id,
            DeviceIP.device_id == device_id,
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
                "code": "IP_NOT_FOUND",
                "message": "Device IP not found.",
            },
        )

    before_management_ip = await current_management_ip_snapshot(db, device_id)
    before = business_summary(obj)
    data = payload.model_dump(exclude_unset=True)

    if "is_primary" in data or "is_management" in data:
        await apply_ip_flags(
            db,
            device_id=device_id,
            target=obj,
            is_management=data.pop("is_management", None),
            is_primary=data.pop("is_primary", None),
        )

    for key, value in data.items():
        old_value = getattr(obj, key)
        if old_value != value:
            setattr(obj, key, value)

    await db.flush()
    await invalidate_web_tls_trust_if_management_endpoint_changed(
        db,
        device_id=device_id,
        before_management_ip=before_management_ip,
        actor_user_id=getattr(actor, "id", None),
    )

    after = business_summary(obj)
    before_changes, after_changes, changed_fields = changed_summary(before, after)
    if changed_fields:
        await record_audit(
            db,
            action="DEVICE_IP_UPDATED",
            entity_type="DeviceIP",
            entity_id=obj.id,
            description="Device IP address updated.",
            entity_display_snapshot=display_snapshot(obj),
            metadata={"changed_fields": changed_fields},
            before_summary=before_changes,
            after_summary=after_changes,
        )

    await db.commit()
    await db.refresh(obj)
    return obj


@router.delete("/{device_id}/ips/{ip_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device_ip(
    device_id: UUID,
    ip_id: UUID,
    reason: str | None = None,
    confirmed: bool = False,
    actor=Depends(authorize_request),
    db: AsyncSession = Depends(get_db),
):
    await require_device(db, await scope_for_actor(db, actor), device_id, for_update=True)

    result = await db.execute(
        select(DeviceIP)
        .where(
            DeviceIP.id == ip_id,
            DeviceIP.device_id == device_id,
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
                "code": "IP_NOT_FOUND",
                "message": "Device IP not found.",
            },
        )

    before_management_ip = await current_management_ip_snapshot(db, device_id)
    await ensure_ip_recycle_permitted(db, obj)

    async def invalidate_endpoint_trust() -> None:
        await invalidate_web_tls_trust_if_management_endpoint_changed(
            db,
            device_id=device_id,
            before_management_ip=before_management_ip,
            actor_user_id=getattr(actor, "id", None),
        )

    await recycle_from_delete_endpoint(
        db,
        entity_type="DEVICE_IP",
        entity_id=ip_id,
        actor=actor,
        reason=reason,
        confirmed=confirmed,
        before_commit=invalidate_endpoint_trust,
    )
    return None
