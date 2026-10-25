from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...core.exceptions import APIError
from ...models import AccessTemplate, AccessTemplateAssignment, AccessTemplateTestResult
from ...schemas.access_templates import (
    AccessTemplateAssignmentCreate,
    AccessTemplateAssignmentRead,
    AccessTemplateCreate,
    AccessTemplateRead,
    AccessTemplateTestRead,
    AccessTemplateTestRequest,
    AccessTemplateUpdate,
    EffectiveAccessRead,
)
from ...schemas.remote_access import SSHHostKeyActionResponse
from ...security.authorization import require_permission
from ...security.resource_scope import scope_for_actor
from ...security.scope_queries import (
    require_city,
    require_device,
    require_group,
    require_location,
    require_network,
    require_sector,
)
from ...services.access_template_secret_hygiene import (
    calculate_secret_key_transition,
    prune_template_secret_keys,
)
from ...services.access_template_testing import test_access_template_connection
from ...services.access_templates import (
    apply_secret_inputs,
    assignment_scope_id,
    resolve_effective_access,
    secret_provider_map,
    validate_template_definition,
)
from ...services.audit import record_audit
from ...services.ssh_host_trust import (
    SSHHostKeyCandidate,
    discover_device_ssh_host_key,
    trust_device_ssh_host_key,
)


router = APIRouter(prefix="/access-templates", tags=["Access Templates"])

READ_PERMISSION = "access_template.read"
MANAGE_PERMISSION = "access_template.manage"
TEST_PERMISSION = "access_template.test"
SUPPORTED_PROTOCOLS = {"SNMP", "SSH", "TELNET", "WEB"}


async def _read_template(db: AsyncSession, row: AccessTemplate) -> AccessTemplateRead:
    return AccessTemplateRead(
        id=row.id,
        name=row.name,
        description=row.description,
        protocol=row.protocol,
        protocol_variant=row.protocol_variant,
        visibility=row.visibility,
        owner_user_id=row.owner_user_id,
        is_active=row.is_active,
        settings=dict(row.settings_json or {}),
        secret_providers=await secret_provider_map(db, row.id),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _read_assignment(row: AccessTemplateAssignment) -> AccessTemplateAssignmentRead:
    return AccessTemplateAssignmentRead(
        id=row.id,
        template_id=row.template_id,
        scope_type=row.scope_type,
        scope_id=assignment_scope_id(row),
        priority=row.priority,
        enabled=row.enabled,
        created_by_user_id=row.created_by_user_id,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _read_test_result(row: AccessTemplateTestResult) -> AccessTemplateTestRead:
    return AccessTemplateTestRead(
        id=row.id,
        template_id=row.template_id,
        device_id=row.device_id,
        status=row.status,
        failure_code=row.failure_code,
        sanitized_message=row.sanitized_message,
        latency_ms=row.latency_ms,
        tested_at=row.tested_at,
        tested_by_user_id=row.tested_by_user_id,
    )


def _host_key_action(candidate: SSHHostKeyCandidate) -> SSHHostKeyActionResponse:
    return SSHHostKeyActionResponse(
        action="DISCOVER_HOST_KEY",
        device_id=candidate.device_id,
        template_id=candidate.template_id,
        template_name=candidate.template_name,
        fingerprint=candidate.fingerprint,
        key_type=candidate.key_type,
        port=candidate.port,
        compatibility_profile=candidate.compatibility_profile,
        pinned_fingerprint=candidate.pinned_fingerprint,
        trust_state=candidate.trust_state,
    )


async def _visible_template(db: AsyncSession, template_id: UUID, actor_id: UUID) -> AccessTemplate:
    row = await db.scalar(
        select(AccessTemplate).where(
            AccessTemplate.id == template_id,
            AccessTemplate.deleted_at.is_(None),
            (AccessTemplate.owner_user_id == actor_id) | (AccessTemplate.visibility == "SHARED"),
        )
    )
    if row is None:
        raise APIError(404, "ACCESS_TEMPLATE_NOT_FOUND", "Access template not found.")
    return row


async def _owned_template(db: AsyncSession, template_id: UUID, actor_id: UUID, *, for_update: bool = False) -> AccessTemplate:
    stmt = select(AccessTemplate).where(
        AccessTemplate.id == template_id,
        AccessTemplate.owner_user_id == actor_id,
        AccessTemplate.deleted_at.is_(None),
    )
    if for_update:
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    row = await db.scalar(stmt)
    if row is None:
        raise APIError(404, "ACCESS_TEMPLATE_NOT_FOUND", "Owned access template not found.")
    return row


async def _owned_deleted_template(
    db: AsyncSession,
    template_id: UUID,
    actor_id: UUID,
    *,
    for_update: bool = False,
) -> AccessTemplate:
    stmt = (
        select(AccessTemplate)
        .where(
            AccessTemplate.id == template_id,
            AccessTemplate.owner_user_id == actor_id,
            AccessTemplate.deleted_at.is_not(None),
        )
        .execution_options(include_recycled=True)
    )
    if for_update:
        stmt = stmt.with_for_update().execution_options(include_recycled=True, populate_existing=True)
    row = await db.scalar(stmt)
    if row is None:
        raise APIError(404, "ACCESS_TEMPLATE_NOT_FOUND", "Deleted owned access template not found.")
    return row


async def _require_assignment_scope(db: AsyncSession, actor, scope_type: str, scope_id: UUID) -> None:
    scope = await scope_for_actor(db, actor)
    if scope_type == "DEVICE":
        await require_device(db, scope, scope_id)
    elif scope_type == "DEVICE_GROUP":
        await require_group(db, scope, scope_id)
    elif scope_type == "LOGICAL_SECTOR":
        await require_sector(db, scope, scope_id)
    elif scope_type == "LOCATION":
        await require_location(db, scope, scope_id)
    elif scope_type == "NETWORK":
        await require_network(db, scope, scope_id)
    elif scope_type == "CITY":
        await require_city(db, scope, scope_id)
    else:
        raise APIError(422, "ACCESS_TEMPLATE_SCOPE_INVALID", "Unsupported assignment scope.")


@router.get("", response_model=list[AccessTemplateRead], dependencies=[Depends(require_permission(READ_PERMISSION))])
async def list_access_templates(
    protocol: str | None = Query(default=None, max_length=20),
    include_inactive: bool = False,
    search: str | None = Query(default=None, max_length=200),
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(READ_PERMISSION)),
):
    filters = [
        AccessTemplate.deleted_at.is_(None),
        (AccessTemplate.owner_user_id == actor.id) | (AccessTemplate.visibility == "SHARED"),
    ]
    if protocol:
        normalized = protocol.strip().upper()
        if normalized not in SUPPORTED_PROTOCOLS:
            raise APIError(422, "ACCESS_TEMPLATE_PROTOCOL_INVALID", "Protocol must be SNMP, SSH, TELNET, or WEB.")
        filters.append(AccessTemplate.protocol == normalized)
    if not include_inactive:
        filters.append(AccessTemplate.is_active.is_(True))
    if search and search.strip():
        term = f"%{search.strip()}%"
        filters.append(
            or_(
                AccessTemplate.name.ilike(term),
                AccessTemplate.description.ilike(term),
                AccessTemplate.protocol_variant.ilike(term),
            )
        )
    rows = list((await db.scalars(select(AccessTemplate).where(*filters).order_by(AccessTemplate.protocol, AccessTemplate.name))).all())
    return [await _read_template(db, row) for row in rows]


@router.get("/deleted", response_model=list[AccessTemplateRead])
async def list_deleted_access_templates(
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(READ_PERMISSION)),
):
    statement = (
        select(AccessTemplate)
        .where(
            AccessTemplate.owner_user_id == actor.id,
            AccessTemplate.deleted_at.is_not(None),
        )
        .order_by(AccessTemplate.protocol, AccessTemplate.name)
        .execution_options(include_recycled=True)
    )
    rows = list((await db.scalars(statement)).all())
    return [await _read_template(db, row) for row in rows]


@router.post("", response_model=AccessTemplateRead, status_code=201)
async def create_access_template(
    payload: AccessTemplateCreate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(MANAGE_PERMISSION)),
):
    secret_keys, _stale = calculate_secret_key_transition(
        protocol=payload.protocol,
        protocol_variant=payload.protocol_variant,
        existing_keys=set(),
        changes=payload.secrets,
    )
    protocol, variant, cleaned_settings = validate_template_definition(
        protocol=payload.protocol,
        protocol_variant=payload.protocol_variant,
        template_settings=payload.settings,
        secret_keys=secret_keys,
        is_active=payload.is_active,
    )
    row = AccessTemplate(
        name=payload.name,
        description=payload.description,
        protocol=protocol,
        protocol_variant=variant,
        visibility=payload.visibility,
        owner_user_id=actor.id,
        is_active=payload.is_active,
        settings_json=cleaned_settings,
    )
    db.add(row)
    await db.flush()
    await apply_secret_inputs(db, row, payload.secrets)
    await record_audit(
        db,
        action="ACCESS_TEMPLATE_CREATE",
        entity_type="ACCESS_TEMPLATE",
        entity_id=row.id,
        actor_user_id=actor.id,
        entity_display_snapshot={"name": row.name, "protocol": row.protocol},
        after_summary={"visibility": row.visibility, "is_active": row.is_active, "secret_keys": sorted(secret_keys)},
    )
    await db.commit()
    await db.refresh(row)
    return await _read_template(db, row)


@router.get("/{template_id}", response_model=AccessTemplateRead)
async def get_access_template(
    template_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(READ_PERMISSION)),
):
    return await _read_template(db, await _visible_template(db, template_id, actor.id))


@router.patch("/{template_id}", response_model=AccessTemplateRead)
async def update_access_template(
    template_id: UUID,
    payload: AccessTemplateUpdate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(MANAGE_PERMISSION)),
):
    row = await _owned_template(db, template_id, actor.id, for_update=True)
    was_active = row.is_active
    existing_keys = set((await secret_provider_map(db, row.id)).keys())
    changes = payload.secrets or {}
    requested_variant = payload.protocol_variant if payload.protocol_variant is not None else row.protocol_variant
    resulting_keys, stale_keys = calculate_secret_key_transition(
        protocol=row.protocol,
        protocol_variant=requested_variant,
        existing_keys=existing_keys,
        changes=changes,
    )
    next_active = payload.is_active if payload.is_active is not None else row.is_active
    _protocol, variant, cleaned_settings = validate_template_definition(
        protocol=row.protocol,
        protocol_variant=requested_variant,
        template_settings=payload.settings if payload.settings is not None else dict(row.settings_json or {}),
        secret_keys=resulting_keys,
        is_active=next_active,
    )
    if payload.name is not None:
        row.name = payload.name.strip()
    if payload.description is not None:
        row.description = payload.description
    if payload.visibility is not None:
        row.visibility = payload.visibility
    row.protocol_variant = variant
    row.is_active = next_active
    row.settings_json = cleaned_settings
    row.updated_at = datetime.now(timezone.utc)
    if payload.secrets is not None:
        await apply_secret_inputs(db, row, payload.secrets)
    await prune_template_secret_keys(db, template_id=row.id, secret_keys=stale_keys)
    if was_active and not next_active:
        await db.execute(
            update(AccessTemplateAssignment)
            .where(AccessTemplateAssignment.template_id == row.id)
            .values(enabled=False)
        )
    await record_audit(
        db,
        action="ACCESS_TEMPLATE_UPDATE",
        entity_type="ACCESS_TEMPLATE",
        entity_id=row.id,
        actor_user_id=actor.id,
        entity_display_snapshot={"name": row.name, "protocol": row.protocol},
        after_summary={
            "visibility": row.visibility,
            "is_active": row.is_active,
            "secret_keys": sorted(resulting_keys),
            "assignments_disabled": bool(was_active and not next_active),
        },
    )
    await db.commit()
    await db.refresh(row)
    return await _read_template(db, row)


@router.delete("/{template_id}", status_code=204)
async def delete_access_template(
    template_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(MANAGE_PERMISSION)),
):
    row = await _owned_template(db, template_id, actor.id, for_update=True)
    row.is_active = False
    row.deleted_at = datetime.now(timezone.utc)
    await db.execute(
        update(AccessTemplateAssignment)
        .where(AccessTemplateAssignment.template_id == row.id)
        .values(enabled=False)
    )
    await record_audit(
        db,
        action="ACCESS_TEMPLATE_DELETE",
        entity_type="ACCESS_TEMPLATE",
        entity_id=row.id,
        actor_user_id=actor.id,
        entity_display_snapshot={"name": row.name, "protocol": row.protocol},
    )
    await db.commit()
    return None


@router.post("/{template_id}/restore", response_model=AccessTemplateRead)
async def restore_access_template(
    template_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(MANAGE_PERMISSION)),
):
    row = await _owned_deleted_template(db, template_id, actor.id, for_update=True)
    conflict = await db.scalar(
        select(AccessTemplate.id).where(
            AccessTemplate.id != row.id,
            AccessTemplate.owner_user_id == actor.id,
            AccessTemplate.name == row.name,
            AccessTemplate.protocol == row.protocol,
            AccessTemplate.deleted_at.is_(None),
        )
    )
    if conflict is not None:
        raise APIError(
            409,
            "ACCESS_TEMPLATE_RESTORE_IDENTITY_CONFLICT",
            "Another active Access Template now uses this owner/name/protocol identity.",
        )

    row.deleted_at = None
    row.is_active = False
    row.updated_at = datetime.now(timezone.utc)
    await db.execute(
        update(AccessTemplateAssignment)
        .where(AccessTemplateAssignment.template_id == row.id)
        .values(enabled=False)
    )
    await record_audit(
        db,
        action="ACCESS_TEMPLATE_RESTORE",
        entity_type="ACCESS_TEMPLATE",
        entity_id=row.id,
        actor_user_id=actor.id,
        entity_display_snapshot={"name": row.name, "protocol": row.protocol},
        before_summary={"deleted": True, "is_active": False},
        after_summary={"deleted": False, "is_active": False, "assignments_enabled": False},
    )
    await db.commit()
    await db.refresh(row)
    return await _read_template(db, row)


@router.get("/{template_id}/assignments", response_model=list[AccessTemplateAssignmentRead])
async def list_access_template_assignments(
    template_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(READ_PERMISSION)),
):
    await _visible_template(db, template_id, actor.id)
    rows = list((await db.scalars(
        select(AccessTemplateAssignment)
        .where(AccessTemplateAssignment.template_id == template_id)
        .order_by(AccessTemplateAssignment.scope_type, AccessTemplateAssignment.priority.desc())
    )).all())
    allowed = []
    for row in rows:
        try:
            await _require_assignment_scope(db, actor, row.scope_type, assignment_scope_id(row))
        except APIError:
            continue
        allowed.append(_read_assignment(row))
    return allowed


@router.post("/{template_id}/assignments", response_model=AccessTemplateAssignmentRead, status_code=201)
async def create_access_template_assignment(
    template_id: UUID,
    payload: AccessTemplateAssignmentCreate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(MANAGE_PERMISSION)),
):
    template = await _visible_template(db, template_id, actor.id)
    if not template.is_active:
        raise APIError(409, "ACCESS_TEMPLATE_INACTIVE", "Inactive access templates cannot receive new assignments.")
    await _require_assignment_scope(db, actor, payload.scope_type, payload.scope_id)
    target_field = {
        "DEVICE": "device_id",
        "DEVICE_GROUP": "group_id",
        "LOGICAL_SECTOR": "sector_id",
        "LOCATION": "location_id",
        "NETWORK": "network_id",
        "CITY": "city_id",
    }[payload.scope_type]
    duplicate = await db.scalar(
        select(AccessTemplateAssignment.id).where(
            AccessTemplateAssignment.template_id == template.id,
            AccessTemplateAssignment.scope_type == payload.scope_type,
            getattr(AccessTemplateAssignment, target_field) == payload.scope_id,
            AccessTemplateAssignment.priority == payload.priority,
        )
    )
    if duplicate is not None:
        raise APIError(409, "ACCESS_TEMPLATE_ASSIGNMENT_EXISTS", "This template assignment already exists.")
    kwargs = {target_field: payload.scope_id}
    row = AccessTemplateAssignment(
        template_id=template.id,
        scope_type=payload.scope_type,
        priority=payload.priority,
        enabled=payload.enabled,
        created_by_user_id=actor.id,
        **kwargs,
    )
    db.add(row)
    await db.flush()
    await record_audit(
        db,
        action="ACCESS_TEMPLATE_ASSIGN",
        entity_type="ACCESS_TEMPLATE_ASSIGNMENT",
        entity_id=row.id,
        actor_user_id=actor.id,
        metadata={"template_id": str(template.id), "scope_type": row.scope_type, "scope_id": str(payload.scope_id), "priority": row.priority},
    )
    await db.commit()
    await db.refresh(row)
    return _read_assignment(row)


@router.delete("/{template_id}/assignments/{assignment_id}", status_code=204)
async def delete_access_template_assignment(
    template_id: UUID,
    assignment_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(MANAGE_PERMISSION)),
):
    template = await _visible_template(db, template_id, actor.id)
    row = await db.scalar(
        select(AccessTemplateAssignment).where(
            AccessTemplateAssignment.id == assignment_id,
            AccessTemplateAssignment.template_id == template.id,
        ).with_for_update()
    )
    if row is None:
        raise APIError(404, "ACCESS_TEMPLATE_ASSIGNMENT_NOT_FOUND", "Access template assignment not found.")
    await _require_assignment_scope(db, actor, row.scope_type, assignment_scope_id(row))
    if template.owner_user_id != actor.id and row.created_by_user_id != actor.id:
        raise APIError(403, "ACCESS_TEMPLATE_ASSIGNMENT_NOT_OWNED", "Only the template owner or assignment creator can remove this assignment.")
    await db.delete(row)
    await record_audit(
        db,
        action="ACCESS_TEMPLATE_UNASSIGN",
        entity_type="ACCESS_TEMPLATE_ASSIGNMENT",
        entity_id=row.id,
        actor_user_id=actor.id,
        metadata={"template_id": str(template.id), "scope_type": row.scope_type},
    )
    await db.commit()
    return None


@router.post(
    "/{template_id}/test",
    response_model=AccessTemplateTestRead | SSHHostKeyActionResponse,
)
async def test_access_template(
    template_id: UUID,
    payload: AccessTemplateTestRequest,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(TEST_PERMISSION)),
):
    template = await _visible_template(db, template_id, actor.id)
    scope = await scope_for_actor(db, actor)
    await require_device(db, scope, payload.device_id)

    protocol = template.protocol.strip().upper()
    if protocol == "SSH":
        if payload.trust_host_key:
            assert payload.expected_fingerprint is not None
            await trust_device_ssh_host_key(
                db,
                device_id=payload.device_id,
                actor_user_id=actor.id,
                expected_fingerprint=payload.expected_fingerprint,
                replace_existing=payload.replace_existing,
                template=template,
                enable_remote_access=False,
            )
        else:
            candidate = await discover_device_ssh_host_key(
                db,
                device_id=payload.device_id,
                template=template,
            )
            if candidate.trust_state != "MATCH":
                return _host_key_action(candidate)
    elif payload.trust_host_key or payload.expected_fingerprint or payload.replace_existing:
        raise APIError(422, "ACCESS_TEMPLATE_PROTOCOL_INVALID", "SSH host-key confirmation is valid only for SSH Access Templates.")

    result = await test_access_template_connection(
        db,
        template=template,
        device_id=payload.device_id,
        tested_by_user_id=actor.id,
    )
    await record_audit(
        db,
        action="ACCESS_TEMPLATE_TEST",
        entity_type="ACCESS_TEMPLATE_TEST_RESULT",
        entity_id=result.id,
        actor_user_id=actor.id,
        metadata={
            "template_id": str(template.id),
            "device_id": str(payload.device_id),
            "protocol": template.protocol,
            "status": result.status,
            "failure_code": result.failure_code,
            "latency_ms": result.latency_ms,
        },
    )
    await db.commit()
    await db.refresh(result)
    return _read_test_result(result)


@router.get("/effective/{device_id}/{protocol}", response_model=EffectiveAccessRead)
async def get_effective_access_template(
    device_id: UUID,
    protocol: str,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(READ_PERMISSION)),
):
    normalized = protocol.strip().upper()
    if normalized not in SUPPORTED_PROTOCOLS:
        raise APIError(422, "ACCESS_TEMPLATE_PROTOCOL_INVALID", "Protocol must be SNMP, SSH, TELNET, or WEB.")
    scope = await scope_for_actor(db, actor)
    await require_device(db, scope, device_id)
    resolved = await resolve_effective_access(db, device_id=device_id, protocol=normalized)
    if resolved.status != "RESOLVED":
        return EffectiveAccessRead(device_id=device_id, protocol=normalized, status=resolved.status)
    return EffectiveAccessRead(
        device_id=device_id,
        protocol=normalized,
        status="RESOLVED",
        template_id=resolved.template.id,
        template_name=resolved.template.name,
        assignment_id=resolved.assignment.id,
        scope_type=resolved.assignment.scope_type,
        priority=resolved.assignment.priority,
    )
