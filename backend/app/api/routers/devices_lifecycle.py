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
from ...security.scope_queries import require_device, require_location, require_sector
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
    DeviceRemoteAccessProfile,
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
from ...services.remote_access import apply_remote_access_update
from ...web_management import effective_web_port, web_management_url
from ...core.audit_context import get_audit_context
from ...core.exceptions import APIError
from ...security.permissions import Permission as PermissionCode
from ...services.audit_summaries import business_summary, changed_summary, display_snapshot
from ...services.crud import get_active_for_update_or_404, get_or_404
from ...services.device_registration import register_domain_device
from ...availability.service import synchronize_lifecycle_state, set_manual_degraded_override
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
logger = logging.getLogger(__name__)

async def _require_actor_permission_for_change(db: AsyncSession, permission_code: str) -> None:
    """Require an additional permission for a request-scoped domain change.

    Route authorization still requires device.update first. This secondary check
    protects physical movement/placement changes submitted through the generic
    device PATCH endpoint. Direct service-level test calls have no bound actor
    and therefore continue to exercise domain behavior without HTTP RBAC state.
    """
    actor_user_id = get_audit_context().actor_user_id
    if actor_user_id is None:
        return
    if not await user_has_permission(db, user_id=actor_user_id, permission_code=permission_code):
        raise APIError(
            403,
            "PERMISSION_DENIED",
            f"Permission '{permission_code}' is required.",
        )

@router.post("", response_model=DeviceRead, status_code=status.HTTP_201_CREATED)
async def create_device(
    payload: DeviceCreate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    if payload.lifecycle_state == "DECOMMISSIONED":
        raise HTTPException(status_code=422, detail={"code": "INVALID_INITIAL_LIFECYCLE_STATE", "message": "A newly created device cannot start as DECOMMISSIONED."})

    data = payload.model_dump()
    # Operational UP/DOWN/UNKNOWN is availability-authoritative. New devices
    # always begin UNKNOWN until the availability engine produces evidence.
    data["operational_state"] = "UNKNOWN"
    management_ip = data.pop("management_ip")
    location_id = data.pop("location_id", None)
    sector_id = data.pop("sector_id", None)
    parent_device_id = data.pop("parent_device_id", None)
    data.pop("sector_role", None)
    metadata = data.pop("metadata")
    scope = await scope_for_actor(db, actor)
    # Creation is authorized against destination geography, not merely a parent
    # device that might be visible through GROUP scope.
    if sector_id is not None:
        await require_sector(db, scope, sector_id)
    if location_id is not None:
        await require_location(db, scope, location_id)
    if parent_device_id is not None:
        parent = await require_device(db, scope, parent_device_id)
        try:
            parent_hierarchy = await resolve_effective_hierarchy(db, parent)
        except HierarchyValidationError as exc:
            raise HTTPException(422, detail={"code": exc.code, "message": exc.message}) from exc
        if parent_hierarchy.sector_id is not None:
            await require_sector(db, scope, parent_hierarchy.sector_id)
        else:
            await require_location(db, scope, parent_hierarchy.location_id)
    registration = await register_domain_device(
        db,
        management_ip=management_ip,
        location_id=location_id,
        sector_id=sector_id,
        parent_device_id=parent_device_id,
        metadata=metadata,
        ip_source="MANUAL",
        **data,
    )
    obj = registration.device
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        existing_ip = await db.scalar(
            select(DeviceIP).where(
                DeviceIP.ip_address == str(ip_address(management_ip))
            )
        )
        if existing_ip is not None:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "IP_ALREADY_REGISTERED",
                    "message": "This management IP address is already registered.",
                },
            )
        raise
    await db.refresh(obj)
    return obj


@router.post("/{device_id}/test-accessibility", response_model=DeviceAccessibilityResponse)
async def test_device_accessibility(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    device = await require_device(db, await scope_for_actor(db, actor), device_id)
    device_audit_id = device.id
    device_display = display_snapshot(device)
    management_protocol = device.management_protocol or "HTTP"
    result = await db.execute(
        select(DeviceIP)
        .where(DeviceIP.device_id == device_audit_id)
        .order_by(DeviceIP.is_management.desc(), DeviceIP.is_primary.desc(), DeviceIP.id)
        .limit(1)
    )
    ip_record = result.scalar_one_or_none()
    management_ip = ip_record.ip_address if ip_record is not None else None
    web_profile = await db.scalar(
        select(DeviceRemoteAccessProfile).where(DeviceRemoteAccessProfile.device_id == device_audit_id)
    )
    logger.info("device_access_attempt", extra={"event": "DEVICE_ACCESS_ATTEMPT", "entity_id": device_audit_id})
    await record_audit(
        db,
        action="DEVICE_ACCESS_ATTEMPT",
        entity_type="Device",
        entity_id=device_audit_id,
        description="Device management accessibility test started.",
        entity_display_snapshot=device_display,
        result="ATTEMPT",
        metadata={"management_protocol": management_protocol},
    )
    # ATTEMPT must survive every outcome, and no database transaction should be
    # held open while waiting for the remote management endpoint.
    await db.commit()

    if management_ip is None:
        response_payload = DeviceAccessibilityResponse(
            device_id=device_audit_id,
            reachable=False,
            url="",
            message="No management IP is assigned to this device.",
        )
        logger.warning("device_access_failure_no_management_ip", extra={"event": "DEVICE_ACCESS_FAILURE", "entity_id": device_audit_id, "error_code": "MANAGEMENT_IP_NOT_FOUND"})
        await record_audit(
            db,
            action="DEVICE_ACCESS_FAILURE",
            entity_type="Device",
            entity_id=device_audit_id,
            description="Device accessibility test failed because no management IP is assigned.",
            entity_display_snapshot=device_display,
            result="FAILURE",
            metadata={"error_code": "MANAGEMENT_IP_NOT_FOUND"},
        )
        await db.commit()
        return response_payload

    # The device management transport (SNMP/SSH/etc.) is not necessarily the
    # same protocol as its web GUI. A configured Web-GUI profile is authoritative;
    # otherwise preserve the historical HTTPS-first, HTTP-second behavior.
    if web_profile is not None and web_profile.web_enabled:
        configured_scheme = web_profile.web_scheme.lower()
        configured_port = effective_web_port(web_profile.web_scheme, web_profile.web_port)
        targets = [(configured_scheme, configured_port)]
    else:
        targets = [("https", 443), ("http", 80)]
    attempts: list[dict[str, object]] = []
    for scheme, port in targets:
        url = web_management_url(scheme, management_ip, port)
        started = time.perf_counter()
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=3.0, verify=False) as client:
                response = await client.get(url)
            elapsed = int((time.perf_counter() - started) * 1000)
            response_payload = DeviceAccessibilityResponse(
                device_id=device_audit_id,
                reachable=True,
                url=url,
                status_code=response.status_code,
                response_time_ms=elapsed,
                message=f"Management endpoint resolved to {scheme.upper()} and responded with HTTP {response.status_code}.",
            )
            logger.info("device_access_success", extra={"event": "DEVICE_ACCESS_SUCCESS", "entity_id": device_audit_id})
            await record_audit(
                db,
                action="DEVICE_ACCESS_SUCCESS",
                entity_type="Device",
                entity_id=device_audit_id,
                description="Device management endpoint responded.",
                entity_display_snapshot=device_display,
                metadata={
                    "status_code": response.status_code,
                    "response_time_ms": elapsed,
                    "management_ip": management_ip,
                    "resolved_scheme": scheme,
                    "resolved_port": port,
                    "resolution_order": [web_management_url(item_scheme, management_ip, item_port) for item_scheme, item_port in targets],
                },
            )
            await db.commit()
            return response_payload
        except httpx.HTTPError as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            attempts.append({"scheme": scheme, "port": port, "url": url, "error_type": exc.__class__.__name__, "response_time_ms": elapsed})
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            # Preserve the historical audit invariant for unexpected failures,
            # but never persist exception text because it may contain secrets.
            logger.warning(
                "device_access_failure_unexpected",
                extra={
                    "event": "DEVICE_ACCESS_FAILURE",
                    "entity_id": device_audit_id,
                    "error_code": "UNEXPECTED_ACCESS_TEST_ERROR",
                    "error_type": exc.__class__.__name__,
                },
            )
            await record_audit(
                db,
                action="DEVICE_ACCESS_FAILURE",
                entity_type="Device",
                entity_id=device_audit_id,
                description="Device management accessibility test failed unexpectedly.",
                entity_display_snapshot=device_display,
                result="FAILURE",
                metadata={
                    "error_type": exc.__class__.__name__,
                    "management_ip": management_ip,
                    "attempted_scheme": scheme,
                    "attempted_port": port,
                    "response_time_ms": elapsed,
                },
            )
            await db.commit()
            raise

    response_payload = DeviceAccessibilityResponse(
        device_id=device_audit_id,
        reachable=False,
        url=web_management_url(targets[0][0], management_ip, targets[0][1]),
        response_time_ms=max((int(item["response_time_ms"]) for item in attempts), default=0),
        message="Management endpoint was not reachable on the configured HTTP/HTTPS target(s).",
    )
    logger.warning("device_access_failure", extra={"event": "DEVICE_ACCESS_FAILURE", "entity_id": device_audit_id, "error_code": "HTTPS_HTTP_UNREACHABLE"})
    await record_audit(
        db,
        action="DEVICE_ACCESS_FAILURE",
        entity_type="Device",
        entity_id=device_audit_id,
        description="Device management endpoint was not reachable on the configured HTTP/HTTPS target(s).",
        entity_display_snapshot=device_display,
        result="FAILURE",
        metadata={
            "error_type": "HTTPS_HTTP_UNREACHABLE",
            "management_ip": management_ip,
            "attempts": attempts,
        },
    )
    await db.commit()
    return response_payload


@router.get("/{device_id}", response_model=DeviceRead)
async def get_device(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    return await require_device(db, await scope_for_actor(db, actor), device_id)


@router.patch("/{device_id}", response_model=DeviceRead)
async def update_device(
    device_id: UUID,
    payload: DeviceUpdate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    obj = await require_device(db, scope, device_id, for_update=True)
    if obj.deleted_at is not None:
        raise HTTPException(404, detail={"code":"DEVICE_NOT_FOUND","message":"Device not found."})
    before = business_summary(obj)
    data = payload.model_dump(exclude_unset=True)
    remote_access_data = data.pop("remote_access", None)
    requested_operational_state = data.pop("operational_state", None)
    requested_degraded_override = data.pop("manual_degraded_override", None)
    if remote_access_data is not None:
        ssh_remote_fields = {
            "ssh_enabled", "ssh_port", "ssh_compatibility_profile", "ssh_username_reference",
            "ssh_password_reference", "ssh_private_key_reference", "ssh_host_key_fingerprint",
            "clear_password_reference", "clear_private_key_reference",
        }
        web_remote_fields = {
            "web_enabled", "web_scheme", "web_port", "web_tls_mode", "web_tls_compat_profile", "web_tls_ca_reference",
            "web_tls_pinned_certificate_reference", "clear_web_tls_ca_reference",
            "clear_web_tls_pinned_certificate_reference",
        }
        requested_remote_fields = set(remote_access_data)
        if requested_remote_fields & ssh_remote_fields:
            await _require_actor_permission_for_change(db, PermissionCode.DEVICE_REMOTE_ACCESS_SSH)
        if requested_remote_fields & web_remote_fields:
            await _require_actor_permission_for_change(db, PermissionCode.DEVICE_REMOTE_ACCESS_WEB)

    assignment = {
        key: data.pop(key)
        for key in ("location_id", "sector_id", "parent_device_id")
        if key in data
    }

    requested_type_id = data.get("device_type_id", obj.device_type_id)
    device_type = await get_or_404(db, DeviceType, requested_type_id)
    if not device_type.is_active:
        raise HTTPException(
            status_code=409,
            detail={"code": "DEVICE_TYPE_INACTIVE", "message": "The selected device type is inactive."},
        )

    if requested_type_id != obj.device_type_id:
        sector_binding = await db.scalar(select(Sector.id).where(Sector.sector_device_id == obj.id))
        hierarchy_link = await db.scalar(
            select(DeviceHierarchyLink.id).where(
                (DeviceHierarchyLink.child_device_id == obj.id)
                | (DeviceHierarchyLink.parent_device_id == obj.id)
            )
        )
        placement_reference = await db.scalar(
            select(DevicePlacement.id).where(DevicePlacement.device_id == obj.id)
        )
        service_reference = await db.scalar(
            select(CustomerService.id).where(
                (CustomerService.cpe_device_id == obj.id)
                | (CustomerService.access_point_device_id == obj.id)
                | (CustomerService.router_device_id == obj.id)
            )
        )
        if any(value is not None for value in (sector_binding, hierarchy_link, placement_reference, service_reference)):
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "DEVICE_TYPE_CHANGE_RELATIONSHIP_PROTECTED",
                    "message": "Device type cannot change after the device has physical placement, hierarchy, or customer-service relationships.",
                },
            )

    requested_lifecycle = data.get("lifecycle_state")
    if requested_lifecycle is not None and requested_lifecycle != obj.lifecycle_state:
        allowed = {
            "REGISTERED": {"ACTIVE", "MAINTENANCE", "DECOMMISSIONED"},
            "ACTIVE": {"MAINTENANCE", "DECOMMISSIONED"},
            "MAINTENANCE": {"ACTIVE", "DECOMMISSIONED"},
            "DECOMMISSIONED": set(),
        }
        if requested_lifecycle not in allowed.get(obj.lifecycle_state, set()):
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "INVALID_LIFECYCLE_TRANSITION",
                    "message": f"Cannot transition device lifecycle from {obj.lifecycle_state} to {requested_lifecycle}.",
                },
            )

    if obj.lifecycle_state == "DECOMMISSIONED" and (data or assignment or remote_access_data is not None):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "DEVICE_DECOMMISSIONED",
                "message": "Reactivate the device before changing its configuration or physical hierarchy.",
            },
        )

    type_code = device_type.code
    try:
        if assignment:
            location_id = assignment.get("location_id")
            sector_id = assignment.get("sector_id")
            parent_device_id = assignment.get("parent_device_id")

            if type_code == "SECTOR":
                if sector_id is None:
                    raise HTTPException(422, detail={"code": "SECTOR_ID_REQUIRED", "message": "A SECTOR device must be bound to a logical sector."})
                if location_id is not None or parent_device_id is not None:
                    raise HTTPException(422, detail={"code": "INVALID_SECTOR_ASSIGNMENT", "message": "A physical SECTOR device is assigned through its logical sector, not through a device parent or direct location."})
                current_sector_id = await db.scalar(select(Sector.id).where(Sector.sector_device_id == obj.id, Sector.deleted_at.is_(None)))
                if current_sector_id != sector_id:
                    await require_sector(db, scope, sector_id)
                    await _require_actor_permission_for_change(db, PermissionCode.PHYSICAL_MOVEMENT_SECTOR)
                    await rebind_sector_device(db, sector_device_id=obj.id, destination_sector_id=sector_id)

            elif type_code == "CPE":
                if parent_device_id is None:
                    raise HTTPException(422, detail={"code": "PARENT_DEVICE_REQUIRED", "message": "CPE requires a physical customer-access SECTOR parent."})
                if location_id is not None or sector_id is not None:
                    raise HTTPException(422, detail={"code": "HIERARCHY_INPUT_FORBIDDEN", "message": "CPE geography is derived from its physical SECTOR parent."})
                current_parent_id = await db.scalar(
                    select(DeviceHierarchyLink.parent_device_id).where(
                        DeviceHierarchyLink.child_device_id == obj.id,
                        DeviceHierarchyLink.relationship_type == "SECTOR_CPE",
                        DeviceHierarchyLink.deleted_at.is_(None),
                    )
                )
                if current_parent_id != parent_device_id:
                    destination_parent = await require_device(db, scope, parent_device_id)
                    destination_hierarchy = await resolve_effective_hierarchy(db, destination_parent)
                    if destination_hierarchy.sector_id is None:
                        raise HTTPException(422, detail={"code":"DESTINATION_SCOPE_INVALID","message":"CPE destination must resolve to a logical sector."})
                    await require_sector(db, scope, destination_hierarchy.sector_id)
                    await _require_actor_permission_for_change(db, PermissionCode.PHYSICAL_MOVEMENT_CPE)
                    await move_cpe_to_sector(db, cpe_device_id=obj.id, destination_sector_device_id=parent_device_id)

            elif type_code == "ACCESS_POINT":
                if parent_device_id is None:
                    raise HTTPException(422, detail={"code": "PARENT_DEVICE_REQUIRED", "message": "ACCESS_POINT requires an eligible CPE parent."})
                if location_id is not None or sector_id is not None:
                    raise HTTPException(422, detail={"code": "HIERARCHY_INPUT_FORBIDDEN", "message": "Access-point geography is derived from its CPE parent."})
                current_parent_id = await db.scalar(
                    select(DeviceHierarchyLink.parent_device_id).where(
                        DeviceHierarchyLink.child_device_id == obj.id,
                        DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
                        DeviceHierarchyLink.deleted_at.is_(None),
                    )
                )
                if current_parent_id != parent_device_id:
                    destination_parent = await require_device(db, scope, parent_device_id)
                    destination_hierarchy = await resolve_effective_hierarchy(db, destination_parent)
                    if destination_hierarchy.sector_id is None:
                        raise HTTPException(422, detail={"code":"DESTINATION_SCOPE_INVALID","message":"Access-point destination must resolve to a logical sector."})
                    await require_sector(db, scope, destination_hierarchy.sector_id)
                    await _require_actor_permission_for_change(db, PermissionCode.PHYSICAL_MOVEMENT_ACCESS_POINT)
                    await reassign_access_point(db, access_point_device_id=obj.id, destination_cpe_device_id=parent_device_id)

            else:
                if location_id is None:
                    raise HTTPException(422, detail={"code": "LOCATION_REQUIRED", "message": f"{type_code} requires an active location."})
                if sector_id is not None or parent_device_id is not None:
                    raise HTTPException(422, detail={"code": "INVALID_LOCATION_ASSIGNMENT", "message": f"{type_code} is independently placed and cannot use a sector or device parent."})
                await require_location(db, scope, location_id)
                location_row = (
                    await db.execute(
                        select(Location, City, Network)
                        .join(City, City.id == Location.city_id)
                        .join(Network, Network.id == City.network_id)
                        .where(
                            Location.id == location_id,
                            Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None),
                            Location.status == "ACTIVE", City.status == "ACTIVE", Network.status == "ACTIVE",
                        )
                    )
                ).first()
                if location_row is None:
                    raise HTTPException(422, detail={"code": "LOCATION_NOT_AVAILABLE", "message": "The selected location is not active or no longer exists."})
                location, city, network = location_row
                current_location_id = await db.scalar(
                    select(DevicePlacement.location_id).where(DevicePlacement.device_id == obj.id)
                )
                if current_location_id != location.id:
                    await _require_actor_permission_for_change(db, PermissionCode.PLACEMENT_UPDATE)
                    await update_device_placement(
                        db,
                        obj.id,
                        {
                            "network_id": network.id,
                            "city_id": city.id,
                            "location_id": location.id,
                            "sector_id": None,
                        },
                    )
    except MovementValidationError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.message}) from exc
    except PlacementValidationError as exc:
        raise HTTPException(status_code=422, detail={"code": exc.code, "message": exc.message}) from exc

    changed_outside_summary = False
    if "metadata" in data:
        old_metadata = obj.metadata_
        obj.metadata_ = data.pop("metadata")
        if old_metadata != obj.metadata_:
            changed_outside_summary = True

    for key, value in data.items():
        old_value = getattr(obj, key)
        if old_value != value:
            setattr(obj, key, value)
            if key not in before:
                changed_outside_summary = True

    remote_access_changed = False
    if remote_access_data is not None:
        before_profile = await db.scalar(
            select(DeviceRemoteAccessProfile).where(DeviceRemoteAccessProfile.device_id == obj.id)
        )
        before_remote = None
        if before_profile is not None:
            before_remote = (
                before_profile.ssh_enabled,
                before_profile.ssh_port,
                before_profile.ssh_username_reference,
                before_profile.ssh_password_reference,
                before_profile.ssh_private_key_reference,
                before_profile.ssh_host_key_fingerprint,
                before_profile.web_enabled,
                before_profile.web_scheme,
                before_profile.web_port,
                before_profile.web_tls_mode,
                before_profile.web_tls_compat_profile,
                before_profile.web_tls_ca_reference,
                before_profile.web_tls_pinned_certificate_reference,
            )
        from ...schemas.remote_access import DeviceRemoteAccessUpdate
        profile = await apply_remote_access_update(
            db,
            device_id=obj.id,
            payload=DeviceRemoteAccessUpdate.model_validate(remote_access_data),
        )
        after_remote = (
            profile.ssh_enabled,
            profile.ssh_port,
            profile.ssh_username_reference,
            profile.ssh_password_reference,
            profile.ssh_private_key_reference,
            profile.ssh_host_key_fingerprint,
            profile.web_enabled,
            profile.web_scheme,
            profile.web_port,
            profile.web_tls_mode,
            profile.web_tls_compat_profile,
            profile.web_tls_ca_reference,
            profile.web_tls_pinned_certificate_reference,
        )
        remote_access_changed = before_remote != after_remote

    if requested_lifecycle is not None:
        await synchronize_lifecycle_state(db, obj)

    operational_override_changed = False
    if requested_degraded_override is not None or requested_operational_state is not None:
        degraded = (
            bool(requested_degraded_override)
            if requested_degraded_override is not None
            else requested_operational_state == "DEGRADED"
        )
        operational_override_changed = await set_manual_degraded_override(
            db, device=obj, enabled=degraded, source="DEVICE_UPDATE"
        )

    after = business_summary(obj)
    before_changes, after_changes, changed_fields = changed_summary(before, after)

    if changed_fields or changed_outside_summary or remote_access_changed or operational_override_changed:
        await record_audit(
            db,
            action="DEVICE_UPDATED",
            entity_type="Device",
            entity_id=obj.id,
            description="Device updated through the device-management API.",
            entity_display_snapshot=display_snapshot(obj),
            metadata={
                "changed_fields": changed_fields,
                "protected_or_metadata_fields_changed": changed_outside_summary,
                "domain_assignment_updated": bool(assignment),
                "remote_access_profile_changed": remote_access_changed,
                "manual_degraded_override_changed": operational_override_changed,
            },
            before_summary=before_changes,
            after_summary=after_changes,
        )

    await db.commit()
    await db.refresh(obj)
    return obj


@router.patch("/{device_id}/status", response_model=DeviceRead)
async def update_device_status(
    device_id: UUID,
    payload: DeviceStatusUpdate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    obj = await require_device(db, await scope_for_actor(db, actor), device_id, for_update=True)
    if obj.deleted_at is not None: raise HTTPException(404, detail={"code":"DEVICE_NOT_FOUND","message":"Device not found."})
    before = business_summary(obj)
    if obj.lifecycle_state == "DECOMMISSIONED":
        raise HTTPException(status_code=409, detail={"code": "DEVICE_DECOMMISSIONED", "message": "A decommissioned device cannot change status."})

    if payload.lifecycle_state is not None and payload.lifecycle_state != obj.lifecycle_state:
        allowed = {
            "REGISTERED": {"ACTIVE", "MAINTENANCE", "DECOMMISSIONED"},
            "ACTIVE": {"MAINTENANCE", "DECOMMISSIONED"},
            "MAINTENANCE": {"ACTIVE", "DECOMMISSIONED"},
        }
        if payload.lifecycle_state not in allowed.get(obj.lifecycle_state, set()):
            raise HTTPException(status_code=409, detail={"code": "INVALID_LIFECYCLE_TRANSITION", "message": f"Cannot transition device lifecycle from {obj.lifecycle_state} to {payload.lifecycle_state}."})
        obj.lifecycle_state = payload.lifecycle_state

    if payload.lifecycle_state is not None:
        await synchronize_lifecycle_state(db, obj)

    if payload.manual_degraded_override is not None or payload.operational_state is not None:
        degraded = (
            bool(payload.manual_degraded_override)
            if payload.manual_degraded_override is not None
            else payload.operational_state == "DEGRADED"
        )
        await set_manual_degraded_override(
            db, device=obj, enabled=degraded, source="DEVICE_STATUS_API"
        )

    after = business_summary(obj)
    before_changes, after_changes, changed_fields = changed_summary(before, after)
    if changed_fields:
        await record_audit(
            db,
            action="DEVICE_STATUS_CHANGED",
            entity_type="Device",
            entity_id=obj.id,
            description="Device operational/lifecycle status changed.",
            entity_display_snapshot=display_snapshot(obj),
            metadata={"changed_fields": changed_fields},
            before_summary=before_changes,
            after_summary=after_changes,
        )
    await db.commit()
    await db.refresh(obj)
    return obj


@router.post("/{device_id}/decommission", response_model=DeviceRead)
async def decommission_device(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    obj = await require_device(db, await scope_for_actor(db, actor), device_id, for_update=True)
    if obj.deleted_at is not None: raise HTTPException(404, detail={"code":"DEVICE_NOT_FOUND","message":"Device not found."})
    before = business_summary(obj)

    if obj.lifecycle_state == "DECOMMISSIONED":
        raise HTTPException(
            status_code=409,
            detail={"code": "DEVICE_ALREADY_DECOMMISSIONED", "message": "Device is already decommissioned."},
        )

    obj.lifecycle_state = "DECOMMISSIONED"
    obj.operational_state = "UNKNOWN"
    await synchronize_lifecycle_state(db, obj)
    after = business_summary(obj)
    before_changes, after_changes, changed_fields = changed_summary(before, after)
    await record_audit(
        db,
        action="DEVICE_DECOMMISSIONED",
        entity_type="Device",
        entity_id=obj.id,
        description="Device decommissioned through the device-management API.",
        entity_display_snapshot=display_snapshot(obj),
        metadata={"changed_fields": changed_fields},
        before_summary=before_changes,
        after_summary=after_changes,
    )
    await db.commit()
    await db.refresh(obj)
    return obj


@router.post("/{device_id}/reactivate", response_model=DeviceRead)
async def reactivate_device(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    obj = await require_device(db, await scope_for_actor(db, actor), device_id, for_update=True)
    if obj.deleted_at is not None: raise HTTPException(404, detail={"code":"DEVICE_NOT_FOUND","message":"Device not found."})
    if obj.lifecycle_state != "DECOMMISSIONED":
        raise HTTPException(
            status_code=409,
            detail={"code": "DEVICE_NOT_DECOMMISSIONED", "message": "Only a decommissioned device can be reactivated."},
        )

    type_code = await db.scalar(select(DeviceType.code).where(DeviceType.id == obj.device_type_id))
    if type_code is None:
        raise HTTPException(422, detail={"code": "DEVICE_TYPE_NOT_FOUND", "message": "The device has no valid controlled type."})

    if type_code == "SECTOR":
        valid = await db.scalar(
            select(Sector.id)
            .join(Location, Location.id == Sector.location_id)
            .join(City, City.id == Location.city_id)
            .join(Network, Network.id == City.network_id)
            .where(
                Sector.sector_device_id == obj.id,
                Sector.deleted_at.is_(None), Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None),
                Sector.status == "ACTIVE", Location.status == "ACTIVE", City.status == "ACTIVE", Network.status == "ACTIVE",
            )
        )
        if valid is None:
            raise HTTPException(409, detail={"code": "REACTIVATION_HIERARCHY_INVALID", "message": "The SECTOR device must be bound to an active logical sector before it can be reactivated."})
    elif type_code == "CPE":
        valid = await db.scalar(
            select(DeviceHierarchyLink.id)
            .join(Device, Device.id == DeviceHierarchyLink.parent_device_id)
            .join(Sector, Sector.sector_device_id == Device.id)
            .join(Location, Location.id == Sector.location_id)
            .join(City, City.id == Location.city_id)
            .join(Network, Network.id == City.network_id)
            .where(
                DeviceHierarchyLink.child_device_id == obj.id,
                DeviceHierarchyLink.relationship_type == "SECTOR_CPE",
                DeviceHierarchyLink.deleted_at.is_(None), Device.deleted_at.is_(None),
                Device.lifecycle_state != "DECOMMISSIONED",
                Sector.role == "CUSTOMER_ACCESS", Sector.deleted_at.is_(None), Sector.status == "ACTIVE",
                Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None),
                Location.status == "ACTIVE", City.status == "ACTIVE", Network.status == "ACTIVE",
            )
        )
        if valid is None:
            raise HTTPException(409, detail={"code": "REACTIVATION_HIERARCHY_INVALID", "message": "Assign the CPE to an active customer-access SECTOR device before reactivation."})
    elif type_code == "ACCESS_POINT":
        cpe_id = await db.scalar(
            select(DeviceHierarchyLink.parent_device_id).where(
                DeviceHierarchyLink.child_device_id == obj.id,
                DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT",
                DeviceHierarchyLink.deleted_at.is_(None),
            )
        )
        if cpe_id is None:
            raise HTTPException(409, detail={"code": "REACTIVATION_HIERARCHY_INVALID", "message": "Assign the access point to an eligible CPE before reactivation."})
        PhysicalSectorForReactivation = aliased(Device)
        valid = await db.scalar(
            select(DeviceHierarchyLink.id)
            .join(Device, Device.id == DeviceHierarchyLink.child_device_id)
            .join(PhysicalSectorForReactivation, PhysicalSectorForReactivation.id == DeviceHierarchyLink.parent_device_id)
            .join(Sector, Sector.sector_device_id == PhysicalSectorForReactivation.id)
            .join(Location, Location.id == Sector.location_id)
            .join(City, City.id == Location.city_id)
            .join(Network, Network.id == City.network_id)
            .where(
                DeviceHierarchyLink.child_device_id == cpe_id,
                DeviceHierarchyLink.relationship_type == "SECTOR_CPE",
                DeviceHierarchyLink.deleted_at.is_(None), Device.deleted_at.is_(None), PhysicalSectorForReactivation.deleted_at.is_(None),
                Device.lifecycle_state != "DECOMMISSIONED", PhysicalSectorForReactivation.lifecycle_state != "DECOMMISSIONED",
                Sector.role == "CUSTOMER_ACCESS", Sector.deleted_at.is_(None), Sector.status == "ACTIVE",
                Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None),
                Location.status == "ACTIVE", City.status == "ACTIVE", Network.status == "ACTIVE",
            )
        )
        if valid is None:
            raise HTTPException(409, detail={"code": "REACTIVATION_HIERARCHY_INVALID", "message": "The access point parent hierarchy is not currently eligible for reactivation."})
    else:
        valid = await db.scalar(
            select(DevicePlacement.id)
            .join(Location, Location.id == DevicePlacement.location_id)
            .join(City, City.id == DevicePlacement.city_id)
            .join(Network, Network.id == DevicePlacement.network_id)
            .where(
                DevicePlacement.device_id == obj.id,
                Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None),
                Location.status == "ACTIVE", City.status == "ACTIVE", Network.status == "ACTIVE",
            )
        )
        if valid is None:
            raise HTTPException(409, detail={"code": "REACTIVATION_HIERARCHY_INVALID", "message": "Assign the device to an active location before reactivation."})

    before = business_summary(obj)
    obj.lifecycle_state = "ACTIVE"
    obj.operational_state = "UNKNOWN"
    await synchronize_lifecycle_state(db, obj)
    after = business_summary(obj)
    before_changes, after_changes, changed_fields = changed_summary(before, after)
    await record_audit(
        db,
        action="DEVICE_REACTIVATED",
        entity_type="Device",
        entity_id=obj.id,
        description="Decommissioned device reactivated after hierarchy validation.",
        entity_display_snapshot=display_snapshot(obj),
        metadata={"changed_fields": changed_fields},
        before_summary=before_changes,
        after_summary=after_changes,
    )
    await db.commit()
    await db.refresh(obj)
    return obj


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(
    device_id: UUID,
    reason: str | None = None,
    confirmed: bool = False,
    actor=Depends(authorize_request),
    db: AsyncSession = Depends(get_db),
):
    await require_device(db, await scope_for_actor(db, actor), device_id)
    await recycle_from_delete_endpoint(
        db,
        entity_type="DEVICE",
        entity_id=device_id,
        actor=actor,
        reason=reason,
        confirmed=confirmed,
    )
    return None
