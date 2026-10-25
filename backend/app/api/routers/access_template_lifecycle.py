from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...core.exceptions import APIError
from ...models import AccessTemplate
from ...schemas.access_template_lifecycle import (
    AccessTemplateCloneRead,
    AccessTemplateCloneRequest,
    AccessTemplateFamilyCreate,
    AccessTemplateRevisionCreate,
    AccessTemplateRevisionRead,
    AccessTemplateRevisionTestRead,
    AccessTemplateRevisionUpdate,
)
from ...schemas.access_templates import AccessTemplateTestRequest
from ...schemas.remote_access import SSHHostKeyActionResponse
from ...security.authorization import require_permission
from ...security.resource_scope import scope_for_actor
from ...security.scope_queries import require_device
from ...services.access_template_lifecycle import (
    activate_revision,
    approve_revision,
    clone_template_family,
    create_template_family,
    create_revision,
    get_revision,
    list_revisions,
    revision_secret_provider_map,
    runtime_template_for_revision,
    test_revision_connection,
    update_revision,
)
from ...services.ssh_host_trust import (
    SSHHostKeyCandidate,
    discover_device_ssh_host_key,
    trust_device_ssh_host_key,
)
from ...services.template_packages import sanitized_portable_metadata


router = APIRouter(prefix="/access-templates", tags=["Access Template Lifecycle"])

READ_PERMISSION = "access_template.read"
MANAGE_PERMISSION = "access_template.manage"
TEST_PERMISSION = "access_template.test"


async def _visible_template(
    db: AsyncSession,
    template_id: UUID,
    actor_id: UUID,
) -> AccessTemplate:
    row = await db.scalar(
        select(AccessTemplate).where(
            AccessTemplate.id == template_id,
            AccessTemplate.deleted_at.is_(None),
            (AccessTemplate.owner_user_id == actor_id)
            | (AccessTemplate.visibility == "SHARED"),
        )
    )
    if row is None:
        raise APIError(404, "ACCESS_TEMPLATE_NOT_FOUND", "Access Template not found.")
    return row


async def _owned_template(
    db: AsyncSession,
    template_id: UUID,
    actor_id: UUID,
) -> AccessTemplate:
    row = await db.scalar(
        select(AccessTemplate).where(
            AccessTemplate.id == template_id,
            AccessTemplate.owner_user_id == actor_id,
            AccessTemplate.deleted_at.is_(None),
        )
    )
    if row is None:
        raise APIError(404, "ACCESS_TEMPLATE_NOT_FOUND", "Owned Access Template not found.")
    return row


async def _read_revision(
    db: AsyncSession,
    row,
) -> AccessTemplateRevisionRead:
    return AccessTemplateRevisionRead(
        id=row.id,
        template_id=row.template_id,
        revision_number=row.revision_number,
        lifecycle_status=row.lifecycle_status,
        protocol_variant=row.protocol_variant,
        settings=dict(row.settings_json or {}),
        source_revision_id=row.source_revision_id,
        change_note=row.change_note,
        definition_sha256=row.definition_sha256,
        legacy_backfill=row.legacy_backfill,
        secret_providers=await revision_secret_provider_map(db, row.id),
        tested_at=row.tested_at,
        tested_by_user_id=row.tested_by_user_id,
        approved_at=row.approved_at,
        approved_by_user_id=row.approved_by_user_id,
        activated_at=row.activated_at,
        activated_by_user_id=row.activated_by_user_id,
        retired_at=row.retired_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
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


@router.post(
    "/families",
    response_model=AccessTemplateCloneRead,
    status_code=201,
)
async def create_access_template_family(
    payload: AccessTemplateFamilyCreate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(MANAGE_PERMISSION)),
):
    try:
        family, revision = await create_template_family(
            db,
            name=payload.name,
            description=payload.description,
            protocol=payload.protocol,
            protocol_variant=payload.protocol_variant,
            visibility=payload.visibility,
            settings=payload.settings,
            secrets=payload.secrets,
            change_note=payload.change_note,
            actor_user_id=actor.id,
        )
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    await db.refresh(family)
    await db.refresh(revision)
    return AccessTemplateCloneRead(
        template_id=family.id,
        revision=await _read_revision(db, revision),
    )


@router.get(
    "/{template_id}/revisions",
    response_model=list[AccessTemplateRevisionRead],
)
async def list_access_template_revisions(
    template_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(READ_PERMISSION)),
):
    await _visible_template(db, template_id, actor.id)
    rows = await list_revisions(db, template_id=template_id)
    return [await _read_revision(db, row) for row in rows]


@router.post(
    "/{template_id}/revisions",
    response_model=AccessTemplateRevisionRead,
    status_code=201,
)
async def create_access_template_revision(
    template_id: UUID,
    payload: AccessTemplateRevisionCreate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(MANAGE_PERMISSION)),
):
    template = await _owned_template(db, template_id, actor.id)
    revision = await create_revision(
        db,
        template=template,
        source_revision_id=payload.source_revision_id,
        change_note=payload.change_note,
        actor_user_id=actor.id,
    )
    await db.commit()
    await db.refresh(revision)
    return await _read_revision(db, revision)


@router.patch(
    "/{template_id}/revisions/{revision_id}",
    response_model=AccessTemplateRevisionRead,
)
async def update_access_template_revision(
    template_id: UUID,
    revision_id: UUID,
    payload: AccessTemplateRevisionUpdate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(MANAGE_PERMISSION)),
):
    template = await _owned_template(db, template_id, actor.id)
    revision = await update_revision(
        db,
        template=template,
        revision_id=revision_id,
        payload=payload,
        actor_user_id=actor.id,
    )
    await db.commit()
    await db.refresh(revision)
    return await _read_revision(db, revision)


@router.post(
    "/{template_id}/revisions/{revision_id}/test",
    response_model=AccessTemplateRevisionTestRead | SSHHostKeyActionResponse,
)
async def test_access_template_revision(
    template_id: UUID,
    revision_id: UUID,
    payload: AccessTemplateTestRequest,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(TEST_PERMISSION)),
):
    template = await _visible_template(db, template_id, actor.id)
    revision = await get_revision(
        db,
        template_id=template_id,
        revision_id=revision_id,
    )
    scope = await scope_for_actor(db, actor)
    await require_device(db, scope, payload.device_id)

    runtime_template = runtime_template_for_revision(template, revision)
    if template.protocol.strip().upper() == "SSH":
        if payload.trust_host_key:
            assert payload.expected_fingerprint is not None
            await trust_device_ssh_host_key(
                db,
                device_id=payload.device_id,
                actor_user_id=actor.id,
                expected_fingerprint=payload.expected_fingerprint,
                replace_existing=payload.replace_existing,
                template=runtime_template,
                enable_remote_access=False,
            )
        else:
            candidate = await discover_device_ssh_host_key(
                db,
                device_id=payload.device_id,
                template=runtime_template,
            )
            if candidate.trust_state != "MATCH":
                return _host_key_action(candidate)
    elif payload.trust_host_key or payload.expected_fingerprint or payload.replace_existing:
        raise APIError(
            422,
            "ACCESS_TEMPLATE_PROTOCOL_INVALID",
            "SSH host-key confirmation is valid only for SSH Access Templates.",
        )

    result = await test_revision_connection(
        db,
        template=template,
        revision=revision,
        device_id=payload.device_id,
        tested_by_user_id=actor.id,
    )
    await db.commit()
    await db.refresh(result)
    return AccessTemplateRevisionTestRead(
        id=result.id,
        template_id=result.template_id,
        revision_id=result.revision_id,
        device_id=result.device_id,
        status=result.status,
        failure_code=result.failure_code,
        sanitized_message=result.sanitized_message,
        latency_ms=result.latency_ms,
        tested_at=result.tested_at,
        tested_by_user_id=result.tested_by_user_id,
    )


@router.post(
    "/{template_id}/revisions/{revision_id}/approve",
    response_model=AccessTemplateRevisionRead,
)
async def approve_access_template_revision(
    template_id: UUID,
    revision_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(MANAGE_PERMISSION)),
):
    template = await _owned_template(db, template_id, actor.id)
    revision = await approve_revision(
        db,
        template=template,
        revision_id=revision_id,
        actor_user_id=actor.id,
    )
    await db.commit()
    await db.refresh(revision)
    return await _read_revision(db, revision)


@router.post(
    "/{template_id}/revisions/{revision_id}/activate",
    response_model=AccessTemplateRevisionRead,
)
async def activate_access_template_revision(
    template_id: UUID,
    revision_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(MANAGE_PERMISSION)),
):
    template = await _owned_template(db, template_id, actor.id)
    revision = await activate_revision(
        db,
        template=template,
        revision_id=revision_id,
        actor_user_id=actor.id,
    )
    await db.commit()
    await db.refresh(revision)
    return await _read_revision(db, revision)


@router.post(
    "/{template_id}/clone",
    response_model=AccessTemplateCloneRead,
    status_code=201,
)
async def clone_access_template_family(
    template_id: UUID,
    payload: AccessTemplateCloneRequest,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(MANAGE_PERMISSION)),
):
    source = await _visible_template(db, template_id, actor.id)
    family, revision = await clone_template_family(
        db,
        source_template=source,
        source_revision_id=payload.source_revision_id,
        name=payload.name,
        description=payload.description,
        visibility=payload.visibility,
        change_note=payload.change_note,
        actor_user_id=actor.id,
    )
    # Preserve only sanitized portable provenance/compatibility metadata. The
    # cloned family is still a fresh inactive DRAFT and credentials remain absent.
    family.metadata_ = sanitized_portable_metadata(source.metadata_)
    await db.commit()
    await db.refresh(family)
    await db.refresh(revision)
    return AccessTemplateCloneRead(
        template_id=family.id,
        revision=await _read_revision(db, revision),
    )
