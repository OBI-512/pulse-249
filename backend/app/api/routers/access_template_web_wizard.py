from __future__ import annotations

import ipaddress
from datetime import timezone
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, SecretStr, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...core.exceptions import APIError
from ...models import (
    AccessTemplate,
    AccessTemplateAssignment,
    AccessTemplateRevision,
    AccessTemplateTestResult,
    AuthSession,
    Device,
    DeviceIP,
    DeviceRemoteAccessProfile,
    RemoteAccessSession,
)
from ...schemas.access_templates import (
    AccessTemplateRead,
    AccessTemplateSecretInput,
    AccessTemplateTestRead,
    WebTemplateDiscoveryRead,
)
from ...schemas.remote_access import DeviceRemoteAccessUpdate, WebRemoteAccessLaunchResponse
from ...security.authentication import extract_bearer_token
from ...security.authorization import require_permission
from ...security.resource_scope import scope_for_actor
from ...security.scope_queries import require_device
from ...security.sessions import hash_session_token
from ...services.access_template_lifecycle import (
    activate_revision,
    approve_revision,
    create_template_family,
    list_revisions,
    resolved_revision_secrets,
    revision_definition_sha256,
    runtime_template_for_revision,
    test_revision_connection,
)
from ...services.access_template_runtime import build_web_runtime_access
from ...services.access_templates import (
    secret_provider_map,
)
from ...services.audit import record_audit
from ...services.manual_web_template_discovery import verify_manual_web_template
from ...services.remote_access import (
    apply_remote_access_update,
    issue_web_session,
    profile_web_port,
    web_profile_is_ready,
)
from ...services.web_template_discovery import WebTemplateDiscoveryError, discover_web_template


router = APIRouter(prefix="/access-templates/web-wizard", tags=["Access Templates"])
MANAGE_PERMISSION = "access_template.manage"
TEST_PERMISSION = "access_template.test"


class WebTemplateWizardStartRequest(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=4000)
    visibility: Literal["PRIVATE", "SHARED"] = "PRIVATE"
    management_ip: str = Field(min_length=3, max_length=64)
    credential_mode: Literal["USERNAME_PASSWORD", "PASSWORD_ONLY"] = "USERNAME_PASSWORD"
    username: SecretStr | None = None
    password: SecretStr
    timeout_seconds: int = Field(default=10, ge=1, le=30)
    apply_reference_transport: bool = True
    discovery_mode: Literal["AUTO", "MANUAL"] = "AUTO"
    manual_scheme: Literal["HTTP", "HTTPS"] = "HTTPS"
    manual_port: int = Field(default=443, ge=1, le=65535)
    manual_auth_mode: Literal["FORM_POST", "HTTP_BASIC", "HTTP_DIGEST"] = "FORM_POST"
    manual_login_page_path: str = Field(default="/", max_length=512)
    manual_login_submit_path: str = Field(default="/", max_length=512)
    manual_username_field: str = Field(default="username", max_length=80)
    manual_password_field: str = Field(default="password", max_length=80)
    manual_capture_hidden_fields: bool = True
    manual_success_path_prefix: str | None = Field(default=None, max_length=512)
    manual_success_text: str | None = Field(default=None, max_length=500)
    manual_failure_text: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def validate_credentials(self):
        if self.credential_mode == "USERNAME_PASSWORD" and (
            self.username is None or not self.username.get_secret_value()
        ):
            raise ValueError("Username is required for username + password devices.")
        if self.discovery_mode == "MANUAL" and self.manual_auth_mode in {"HTTP_BASIC", "HTTP_DIGEST"} and self.credential_mode != "USERNAME_PASSWORD":
            raise ValueError("HTTP Basic and Digest manual fallback require username + password credentials.")
        return self


class WebTemplateWizardStartRead(BaseModel):
    template: AccessTemplateRead
    discovery: WebTemplateDiscoveryRead


class WebTemplateWizardDeviceRequest(BaseModel):
    device_id: UUID


class WebTemplateWizardConfirmRequest(BaseModel):
    device_id: UUID
    preview_session_id: UUID
    assign_reference_device: bool = False


async def _auth_session_for_request(request: Request, db: AsyncSession) -> AuthSession | None:
    token = extract_bearer_token(request)
    if not token:
        return None
    return await db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_session_token(token)))


async def _template_read(db: AsyncSession, row: AccessTemplate) -> AccessTemplateRead:
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


async def _owned_web_template(
    db: AsyncSession,
    template_id: UUID,
    actor_id: UUID,
    *,
    require_inactive_draft: bool = False,
) -> AccessTemplate:
    template = await db.scalar(
        select(AccessTemplate).where(
            AccessTemplate.id == template_id,
            AccessTemplate.owner_user_id == actor_id,
            AccessTemplate.deleted_at.is_(None),
        )
    )
    if template is None:
        raise APIError(404, "ACCESS_TEMPLATE_NOT_FOUND", "Owned Access Template not found.")
    if template.protocol != "WEB":
        raise APIError(422, "WEB_WIZARD_PROTOCOL_REQUIRED", "Secure Web wizard actions require a WEB Access Template.")
    if require_inactive_draft:
        enabled_assignment = await db.scalar(
            select(AccessTemplateAssignment.id)
            .where(
                AccessTemplateAssignment.template_id == template.id,
                AccessTemplateAssignment.enabled.is_(True),
            )
            .limit(1)
        )
        if template.is_active or enabled_assignment is not None:
            raise APIError(
                409,
                "WEB_WIZARD_DRAFT_REQUIRED",
                "Secure Web wizard test, preview, and confirmation require an inactive unassigned draft.",
            )
    return template


async def _wizard_lifecycle_revision(
    db: AsyncSession,
    template_id: UUID,
    actor_id: UUID,
) -> tuple[AccessTemplate, AccessTemplateRevision]:
    template = await _owned_web_template(
        db,
        template_id,
        actor_id,
        require_inactive_draft=True,
    )
    revisions = [
        row
        for row in await list_revisions(db, template_id=template.id)
        if row.lifecycle_status != "RETIRED"
    ]
    if not revisions:
        raise APIError(
            409,
            "WEB_WIZARD_REVISION_REQUIRED",
            "Secure Web wizard actions require a lifecycle revision.",
        )
    if len(revisions) != 1:
        raise APIError(
            409,
            "WEB_WIZARD_REVISION_AMBIGUOUS",
            "Secure Web wizard revision selection is ambiguous. Resolve the revision history before continuing.",
        )
    revision = revisions[0]
    if revision.lifecycle_status not in {"DRAFT", "TESTED", "APPROVED"}:
        raise APIError(
            409,
            "WEB_WIZARD_REVISION_STATE_INVALID",
            "Secure Web wizard actions require a draft, tested, or approved lifecycle revision.",
        )
    return template, revision


async def _reference_device_for_ip(db: AsyncSession, actor, management_ip: str) -> tuple[Device, str]:
    try:
        normalized_ip = str(ipaddress.ip_address(management_ip.strip()))
    except ValueError as exc:
        raise APIError(422, "WEB_WIZARD_REFERENCE_IP_INVALID", "Enter a valid reference-device management IP address.") from exc

    rows = list(
        (
            await db.execute(
                select(Device)
                .join(DeviceIP, DeviceIP.device_id == Device.id)
                .where(
                    Device.deleted_at.is_(None),
                    DeviceIP.deleted_at.is_(None),
                    DeviceIP.is_management.is_(True),
                    DeviceIP.ip_address == normalized_ip,
                )
            )
        ).scalars().all()
    )
    unique = {row.id: row for row in rows}
    if not unique:
        raise APIError(
            404,
            "WEB_WIZARD_REFERENCE_DEVICE_NOT_FOUND",
            "The reference IP must belong to a registered FTTW device management address before discovery can run.",
        )
    if len(unique) > 1:
        raise APIError(
            409,
            "WEB_WIZARD_REFERENCE_IP_AMBIGUOUS",
            "More than one active device uses this management IP. Resolve the inventory conflict before discovery.",
        )
    device = next(iter(unique.values()))
    await require_device(db, await scope_for_actor(db, actor), device.id)
    if device.lifecycle_state == "DECOMMISSIONED":
        raise APIError(409, "DEVICE_DECOMMISSIONED", "A decommissioned device cannot be used as the Secure Web reference device.")
    return device, normalized_ip


async def _apply_discovered_transport(
    db: AsyncSession,
    *,
    device_id: UUID,
    scheme: str,
    port: int,
) -> bool:
    profile = await db.scalar(
        select(DeviceRemoteAccessProfile).where(DeviceRemoteAccessProfile.device_id == device_id)
    )
    if (
        profile is not None
        and web_profile_is_ready(profile)
        and profile.web_scheme == scheme
        and profile_web_port(profile) == port
    ):
        return True

    payload = DeviceRemoteAccessUpdate(
        web_enabled=True,
        web_scheme=scheme,
        web_port=port,
        web_tls_mode="SYSTEM",
        web_tls_compat_profile="MODERN",
    )
    await apply_remote_access_update(db, device_id=device_id, payload=payload)
    return True


async def _require_successful_test(
    db: AsyncSession,
    *,
    template: AccessTemplate,
    revision: AccessTemplateRevision,
    device_id: UUID,
) -> AccessTemplateTestResult:
    if revision.lifecycle_status not in {"TESTED", "APPROVED"}:
        raise APIError(
            409,
            "WEB_WIZARD_CONNECTION_TEST_REQUIRED",
            "Run and pass the current draft revision connection test before continuing.",
        )
    fingerprint = await revision_definition_sha256(
        db,
        template=template,
        revision=revision,
    )
    if not revision.definition_sha256 or revision.definition_sha256 != fingerprint:
        raise APIError(
            409,
            "WEB_WIZARD_CONNECTION_TEST_STALE",
            "The Secure Web wizard revision changed after testing and must be tested again.",
        )
    result = await db.scalar(
        select(AccessTemplateTestResult)
        .where(
            AccessTemplateTestResult.template_id == template.id,
            AccessTemplateTestResult.revision_id == revision.id,
            AccessTemplateTestResult.device_id == device_id,
        )
        .order_by(
            AccessTemplateTestResult.tested_at.desc(),
            AccessTemplateTestResult.id.desc(),
        )
        .limit(1)
    )
    if result is None or result.status != "SUCCESS":
        raise APIError(
            409,
            "WEB_WIZARD_CONNECTION_TEST_REQUIRED",
            "Run and pass the current draft revision connection test before continuing.",
        )
    return result


def _test_read(row: AccessTemplateTestResult) -> AccessTemplateTestRead:
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


@router.post("/start", response_model=WebTemplateWizardStartRead, status_code=201)
async def start_web_template_wizard(
    payload: WebTemplateWizardStartRequest,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(MANAGE_PERMISSION)),
):
    device, management_ip = await _reference_device_for_ip(db, actor, payload.management_ip)
    username = payload.username.get_secret_value() if payload.username is not None else None
    password = payload.password.get_secret_value()

    try:
        if payload.discovery_mode == "MANUAL":
            discovered = await verify_manual_web_template(
                db,
                device_id=device.id,
                management_ip=management_ip,
                scheme=payload.manual_scheme,
                port=payload.manual_port,
                auth_mode=payload.manual_auth_mode,
                credential_mode=payload.credential_mode,
                username=username,
                password=password,
                timeout_seconds=payload.timeout_seconds,
                login_page_path=payload.manual_login_page_path,
                login_submit_path=payload.manual_login_submit_path,
                username_field=payload.manual_username_field,
                password_field=payload.manual_password_field,
                capture_hidden_fields=payload.manual_capture_hidden_fields,
                success_path_prefix=payload.manual_success_path_prefix,
                success_text=payload.manual_success_text,
                failure_text=payload.manual_failure_text,
            )
        else:
            discovered = await discover_web_template(
                db,
                device_id=device.id,
                management_ip=management_ip,
                credential_mode=payload.credential_mode,
                username=username,
                password=password,
                timeout_seconds=payload.timeout_seconds,
            )
    except WebTemplateDiscoveryError as exc:
        raise APIError(422, exc.code, exc.message) from exc

    secret_inputs: dict[str, AccessTemplateSecretInput] = {
        "password": AccessTemplateSecretInput(provider="ENCRYPTED_DATABASE", value=password),
    }
    if discovered.credential_mode == "USERNAME_PASSWORD":
        secret_inputs["username"] = AccessTemplateSecretInput(
            provider="ENCRYPTED_DATABASE",
            value=username,
        )

    try:
        transport_applied = False
        if payload.apply_reference_transport:
            transport_applied = await _apply_discovered_transport(
                db,
                device_id=device.id,
                scheme=discovered.scheme,
                port=discovered.port,
            )
        template, revision = await create_template_family(
            db,
            name=payload.name,
            description=payload.description,
            protocol="WEB",
            protocol_variant=discovered.auth_mode,
            visibility=payload.visibility,
            settings=discovered.settings,
            secrets=secret_inputs,
            change_note="Created by Secure Web Access Template Wizard.",
            actor_user_id=actor.id,
        )
        await record_audit(
            db,
            action="ACCESS_TEMPLATE_WEB_WIZARD_DRAFT_CREATED",
            entity_type="ACCESS_TEMPLATE",
            entity_id=template.id,
            actor_user_id=actor.id,
            entity_display_snapshot={"name": template.name, "protocol": "WEB"},
            metadata={
                "reference_device_id": str(device.id),
                "revision_id": str(revision.id),
                "revision_number": revision.revision_number,
                "lifecycle_status": revision.lifecycle_status,
                "scheme": discovered.scheme,
                "port": discovered.port,
                "auth_mode": discovered.auth_mode,
                "credential_mode": discovered.credential_mode,
                "discovery_mode": payload.discovery_mode,
                "reference_transport_applied": transport_applied,
                "credentials_logged": False,
            },
        )
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    await db.refresh(template)

    discovery_read = WebTemplateDiscoveryRead(
        device_id=device.id,
        device_name=device.display_name,
        vendor=getattr(device, "vendor", None),
        model=getattr(device, "model", None),
        management_ip=management_ip,
        scheme=discovered.scheme,
        port=discovered.port,
        auth_mode=discovered.auth_mode,
        credential_mode=discovered.credential_mode,
        settings=discovered.settings,
        landing_path=discovered.landing_path,
        form_encoding=discovered.form_encoding,
        username_field=discovered.username_field,
        password_field=discovered.password_field,
        confidence=discovered.confidence,
        reference_transport_applied=transport_applied,
    )
    return WebTemplateWizardStartRead(
        template=await _template_read(db, template),
        discovery=discovery_read,
    )


@router.post("/{template_id}/test", response_model=AccessTemplateTestRead)
async def test_web_template_draft(
    template_id: UUID,
    payload: WebTemplateWizardDeviceRequest,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(TEST_PERMISSION)),
):
    template, revision = await _wizard_lifecycle_revision(db, template_id, actor.id)
    device = await require_device(db, await scope_for_actor(db, actor), payload.device_id)
    if device.lifecycle_state == "DECOMMISSIONED":
        raise APIError(409, "DEVICE_DECOMMISSIONED", "A decommissioned device cannot be used for Secure Web testing.")
    management_ip = await db.scalar(
        select(DeviceIP.ip_address)
        .where(
            DeviceIP.device_id == device.id,
            DeviceIP.deleted_at.is_(None),
            DeviceIP.is_management.is_(True),
        )
        .order_by(DeviceIP.is_primary.desc(), DeviceIP.created_at.asc())
        .limit(1)
    )
    if not management_ip:
        raise APIError(409, "DEVICE_MANAGEMENT_IP_REQUIRED", "The reference device has no active management IP.")

    row = await test_revision_connection(
        db,
        template=template,
        revision=revision,
        device_id=device.id,
        tested_by_user_id=actor.id,
    )
    await record_audit(
        db,
        action="ACCESS_TEMPLATE_WEB_WIZARD_TEST",
        entity_type="ACCESS_TEMPLATE",
        entity_id=template.id,
        actor_user_id=actor.id,
        metadata={
            "reference_device_id": str(device.id),
            "revision_id": str(revision.id),
            "revision_number": revision.revision_number,
            "status": row.status,
            "failure_code": row.failure_code,
            "credentials_logged": False,
        },
    )
    await db.commit()
    await db.refresh(row)
    return _test_read(row)


@router.post("/{template_id}/preview", response_model=WebRemoteAccessLaunchResponse)
async def preview_web_template(
    template_id: UUID,
    payload: WebTemplateWizardDeviceRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(TEST_PERMISSION)),
):
    template, revision = await _wizard_lifecycle_revision(db, template_id, actor.id)
    device = await require_device(db, await scope_for_actor(db, actor), payload.device_id)
    if device.lifecycle_state == "DECOMMISSIONED":
        raise APIError(409, "DEVICE_DECOMMISSIONED", "A decommissioned device cannot be used for Secure GUI preview.")
    await _require_successful_test(
        db,
        template=template,
        revision=revision,
        device_id=device.id,
    )

    runtime_template = runtime_template_for_revision(template, revision)
    auth_mode = (revision.protocol_variant or "FORM_POST").strip().upper()
    secrets = {} if auth_mode == "NONE" else await resolved_revision_secrets(
        db,
        template_id=template.id,
        revision_id=revision.id,
    )
    build_web_runtime_access(runtime_template, secrets)

    auth_session = await _auth_session_for_request(request, db)
    ticket, session = await issue_web_session(
        db,
        device_id=device.id,
        actor_user_id=actor.id,
        auth_session_id=auth_session.id if auth_session else None,
        source_ip=request.client.host if request.client else None,
        access_template_id=template.id,
    )
    await db.commit()
    return WebRemoteAccessLaunchResponse(
        session_id=session.id,
        ticket=ticket,
        expires_at=session.expires_at.astimezone(timezone.utc),
    )


@router.post("/{template_id}/confirm", response_model=AccessTemplateRead)
async def confirm_web_template(
    template_id: UUID,
    payload: WebTemplateWizardConfirmRequest,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission(MANAGE_PERMISSION)),
):
    template, revision = await _wizard_lifecycle_revision(db, template_id, actor.id)
    device = await require_device(db, await scope_for_actor(db, actor), payload.device_id)
    successful_test = await _require_successful_test(
        db,
        template=template,
        revision=revision,
        device_id=device.id,
    )

    preview = await db.scalar(
        select(RemoteAccessSession).where(
            RemoteAccessSession.id == payload.preview_session_id,
            RemoteAccessSession.device_id == device.id,
            RemoteAccessSession.actor_user_id == actor.id,
            RemoteAccessSession.mode == "WEB",
            RemoteAccessSession.access_template_id == template.id,
        )
    )
    if (
        preview is None
        or preview.activated_at is None
        or preview.status == "FAILED"
        or preview.error_message
        or preview.activated_at < successful_test.tested_at
    ):
        raise APIError(
            409,
            "WEB_WIZARD_PREVIEW_CONFIRMATION_REQUIRED",
            "Open a successful authenticated Secure GUI preview after the current draft test before confirming this template.",
        )

    if revision.lifecycle_status == "TESTED":
        revision = await approve_revision(
            db,
            template=template,
            revision_id=revision.id,
            actor_user_id=actor.id,
        )
    elif revision.lifecycle_status != "APPROVED":
        raise APIError(
            409,
            "WEB_WIZARD_REVISION_NOT_TESTED",
            "Secure Web wizard confirmation requires a tested or approved lifecycle revision.",
        )
    revision = await activate_revision(
        db,
        template=template,
        revision_id=revision.id,
        actor_user_id=actor.id,
    )
    if payload.assign_reference_device:
        existing = await db.scalar(
            select(AccessTemplateAssignment).where(
                AccessTemplateAssignment.template_id == template.id,
                AccessTemplateAssignment.scope_type == "DEVICE",
                AccessTemplateAssignment.device_id == device.id,
            )
        )
        if existing is None:
            db.add(
                AccessTemplateAssignment(
                    template_id=template.id,
                    scope_type="DEVICE",
                    device_id=device.id,
                    priority=0,
                    enabled=True,
                    created_by_user_id=actor.id,
                )
            )
        else:
            existing.enabled = True

    await record_audit(
        db,
        action="ACCESS_TEMPLATE_WEB_WIZARD_CONFIRMED",
        entity_type="ACCESS_TEMPLATE",
        entity_id=template.id,
        actor_user_id=actor.id,
        entity_display_snapshot={"name": template.name, "protocol": "WEB"},
        metadata={
            "reference_device_id": str(device.id),
            "revision_id": str(revision.id),
            "revision_number": revision.revision_number,
            "lifecycle_status": revision.lifecycle_status,
            "preview_session_id": str(preview.id),
            "assigned_to_reference_device": payload.assign_reference_device,
        },
    )
    await db.commit()
    await db.refresh(template)
    return await _template_read(db, template)
