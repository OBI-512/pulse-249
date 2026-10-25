from __future__ import annotations

from datetime import timezone
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...core.exceptions import APIError
from ...models import AuthSession, DeviceRemoteAccessProfile, RemoteAccessSession
from ...schemas.remote_access import (
    DeviceAccessCapabilitiesRead,
    DeviceAccessCapabilityRead,
    DeviceRemoteAccessRead,
    DeviceWebRemoteAccessRead,
    RemoteAccessLaunchResponse,
    RemoteAccessRevokeResponse,
    SSHHostKeyActionResponse,
    SSHSessionActionRequest,
    WebRemoteAccessLaunchResponse,
    WebTLSCertificateInspectionRead,
    WebTLSInspectRequest,
    WebTLSReplaceRequest,
    WebTLSTrustRead,
    WebTLSTrustRequest,
)
from ...security.authentication import extract_bearer_token
from ...security.authorization import authorize_request, user_has_permission
from ...security.resource_scope import scope_for_actor
from ...security.scope_queries import require_device
from ...security.sessions import hash_session_token
from ...settings import settings
from ...services.access_template_runtime import access_template_ready
from ...services.access_templates import resolve_effective_access
from ...services.remote_access import (
    get_management_ip,
    issue_ssh_session,
    issue_telnet_session,
    issue_web_session,
    profile_is_ready,
    profile_read,
    revoke_remote_session,
    web_profile_internal_trust_fingerprint,
    web_profile_is_ready_async,
    web_profile_read,
)
from ...services.ssh_host_trust import (
    SSHHostKeyCandidate,
    discover_device_ssh_host_key,
    trust_device_ssh_host_key,
)
from ...services.web_tls_trust import (
    inspect_device_web_tls,
    replace_device_web_tls_certificate,
    trust_device_web_tls_certificate,
)


router = APIRouter()


async def _auth_session_for_request(request: Request, db: AsyncSession) -> AuthSession | None:
    token = extract_bearer_token(request)
    if not token:
        return None
    return await db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_session_token(token)))


async def _eligible_device(device_id: UUID, db: AsyncSession, actor):
    device = await require_device(db, await scope_for_actor(db, actor), device_id)
    if device.lifecycle_state == "DECOMMISSIONED":
        raise APIError(409, "DEVICE_DECOMMISSIONED", "Remote access is unavailable for a decommissioned device.")
    return device


def _host_key_response(action: str, candidate: SSHHostKeyCandidate) -> SSHHostKeyActionResponse:
    return SSHHostKeyActionResponse(
        action=action,
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


def _tls_trust_response(row) -> WebTLSTrustRead:
    return WebTLSTrustRead(
        trust_id=row.id,
        device_id=row.device_id,
        management_ip=row.management_ip_snapshot,
        port=row.port,
        compatibility_profile=row.compatibility_profile,
        certificate_sha256=row.certificate_sha256,
        subject=row.subject,
        issuer=row.issuer,
        serial_number=row.serial_number,
        not_valid_before=row.not_valid_before,
        not_valid_after=row.not_valid_after,
        san_dns=list(row.san_dns or []),
        san_ip=list(row.san_ip or []),
        status=row.status,
        trusted_at=row.trusted_at,
        supersedes_trust_id=row.supersedes_trust_id,
    )


async def _template_capability_readiness(
    db: AsyncSession,
    *,
    device_id: UUID,
    protocol: str,
) -> tuple[bool | None, str | None]:
    try:
        return await access_template_ready(db, device_id=device_id, protocol=protocol), None
    except APIError as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        return False, str(detail.get("code") or "ACCESS_TEMPLATE_UNAVAILABLE")


def _capability(
    *,
    available: bool = False,
    ready: bool = False,
    reason_code: str | None = None,
) -> DeviceAccessCapabilityRead:
    return DeviceAccessCapabilityRead(
        available=available,
        ready=ready,
        reason_code=reason_code,
    )


@router.get(
    "/{device_id}/access-capabilities",
    response_model=DeviceAccessCapabilitiesRead,
)
async def get_device_access_capabilities(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    device = await require_device(db, await scope_for_actor(db, actor), device_id)
    profile = await db.scalar(
        select(DeviceRemoteAccessProfile).where(DeviceRemoteAccessProfile.device_id == device_id)
    )

    can_web = await user_has_permission(
        db, user_id=actor.id, permission_code="device.remote_access.web"
    )
    can_ssh = await user_has_permission(
        db, user_id=actor.id, permission_code="device.remote_access.ssh"
    )
    can_telnet = await user_has_permission(
        db, user_id=actor.id, permission_code="device.remote_access.telnet"
    )

    secure_web = _capability(reason_code="PERMISSION_DENIED")
    ssh = _capability(reason_code="PERMISSION_DENIED")
    telnet = _capability(reason_code="PERMISSION_DENIED")

    common_reason = None
    if not settings.remote_access_enabled:
        common_reason = "REMOTE_ACCESS_DISABLED"
    elif device.lifecycle_state == "DECOMMISSIONED":
        common_reason = "DEVICE_DECOMMISSIONED"
    elif not await get_management_ip(db, device_id):
        common_reason = "DEVICE_MANAGEMENT_IP_REQUIRED"

    if can_web:
        if common_reason:
            secure_web = _capability(reason_code=common_reason)
        else:
            template_ready, template_error = await _template_capability_readiness(
                db, device_id=device_id, protocol="WEB"
            )
            if template_error:
                secure_web = _capability(reason_code=template_error)
            elif template_ready is None:
                secure_web = _capability(reason_code="WEB_ACCESS_TEMPLATE_REQUIRED")
            elif template_ready is not True:
                secure_web = _capability(reason_code="WEB_ACCESS_TEMPLATE_INCOMPLETE")
            elif not await web_profile_is_ready_async(db, profile):
                secure_web = _capability(
                    available=bool(profile is not None and profile.web_enabled),
                    reason_code="WEB_TLS_TRUST_NOT_READY",
                )
            else:
                secure_web = _capability(available=True, ready=True)

    if can_ssh:
        if common_reason:
            ssh = _capability(reason_code=common_reason)
        else:
            template_ready, template_error = await _template_capability_readiness(
                db, device_id=device_id, protocol="SSH"
            )
            if template_error:
                ssh = _capability(reason_code=template_error)
            elif template_ready is None:
                legacy_ready = profile_is_ready(profile)
                legacy_enabled = bool(profile is not None and profile.ssh_enabled)
                ssh = _capability(
                    available=legacy_enabled,
                    ready=legacy_ready,
                    reason_code=(
                        None
                        if legacy_ready
                        else "SSH_LEGACY_NOT_READY"
                        if legacy_enabled
                        else "SSH_NOT_CONFIGURED"
                    ),
                )
            elif template_ready is not True:
                template_enabled = bool(profile is not None and profile.ssh_enabled)
                ssh = _capability(
                    available=template_enabled,
                    ready=False,
                    reason_code="SSH_ACCESS_TEMPLATE_INCOMPLETE",
                )
            else:
                trusted = bool(
                    profile is not None
                    and profile.ssh_enabled
                    and profile.ssh_host_key_fingerprint
                )
                ssh = _capability(
                    available=True,
                    ready=trusted,
                    reason_code=None if trusted else "SSH_HOST_KEY_TRUST_REQUIRED",
                )

    if can_telnet:
        if common_reason:
            telnet = _capability(reason_code=common_reason)
        elif not settings.telnet_access_enabled:
            telnet = _capability(reason_code="TELNET_ACCESS_DISABLED")
        else:
            template_ready, template_error = await _template_capability_readiness(
                db, device_id=device_id, protocol="TELNET"
            )
            if template_error:
                telnet = _capability(reason_code=template_error)
            elif template_ready is None:
                telnet = _capability(reason_code="TELNET_ACCESS_TEMPLATE_REQUIRED")
            elif template_ready is not True:
                telnet = _capability(reason_code="TELNET_ACCESS_TEMPLATE_INCOMPLETE")
            else:
                telnet = _capability(available=True, ready=True)

    return DeviceAccessCapabilitiesRead(
        device_id=device_id,
        secure_web=secure_web,
        ssh=ssh,
        telnet=telnet,
    )


@router.get("/{device_id}/remote-access", response_model=DeviceRemoteAccessRead)
async def get_remote_access_status(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await require_device(db, await scope_for_actor(db, actor), device_id)
    profile = await db.scalar(select(DeviceRemoteAccessProfile).where(DeviceRemoteAccessProfile.device_id == device_id))
    status = profile_read(profile, device_id)
    template_ready = await access_template_ready(db, device_id=device_id, protocol="SSH")
    if template_ready is not None:
        status.ready = bool(
            template_ready
            and profile is not None
            and profile.ssh_enabled
            and profile.ssh_host_key_fingerprint
        )
    return status


@router.get("/{device_id}/remote-access/web", response_model=DeviceWebRemoteAccessRead)
async def get_web_remote_access_status(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await require_device(db, await scope_for_actor(db, actor), device_id)
    profile = await db.scalar(select(DeviceRemoteAccessProfile).where(DeviceRemoteAccessProfile.device_id == device_id))
    status = web_profile_read(profile, device_id)
    status.internal_tls_trust_fingerprint = await web_profile_internal_trust_fingerprint(db, profile)
    template_ready = await access_template_ready(db, device_id=device_id, protocol="WEB")
    status.ready = bool(await web_profile_is_ready_async(db, profile) and template_ready is True)
    return status


@router.post(
    "/{device_id}/remote-access/web/tls/inspect",
    response_model=WebTLSCertificateInspectionRead,
)
async def inspect_web_tls_certificate(
    device_id: UUID,
    payload: WebTLSInspectRequest,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await _eligible_device(device_id, db, actor)
    device, observation, current, relation = await inspect_device_web_tls(
        db,
        device_id=device_id,
        actor_user_id=actor.id,
        port=payload.port,
        compatibility_profile=payload.compatibility_profile,
    )
    await db.commit()
    return WebTLSCertificateInspectionRead(
        device_id=device.id,
        device_name=device.display_name,
        management_ip=observation.management_ip,
        port=observation.port,
        compatibility_profile=observation.compatibility_profile,
        certificate_sha256=observation.certificate_sha256,
        subject=observation.subject,
        issuer=observation.issuer,
        serial_number=observation.serial_number,
        not_valid_before=observation.not_valid_before,
        not_valid_after=observation.not_valid_after,
        san_dns=list(observation.san_dns),
        san_ip=list(observation.san_ip),
        self_signed=observation.self_signed,
        validity_state=observation.validity_state,
        current_trusted_certificate_sha256=current.certificate_sha256 if current is not None else None,
        trust_relation=relation,
        credentials_sent=False,
        application_data_sent=False,
        observed_at=observation.observed_at,
    )


@router.post(
    "/{device_id}/remote-access/web/tls/trust",
    response_model=WebTLSTrustRead,
)
async def trust_web_tls_certificate(
    device_id: UUID,
    payload: WebTLSTrustRequest,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await _eligible_device(device_id, db, actor)
    trust = await trust_device_web_tls_certificate(
        db,
        device_id=device_id,
        actor_user_id=actor.id,
        expected_certificate_sha256=payload.expected_certificate_sha256,
        port=payload.port,
        compatibility_profile=payload.compatibility_profile,
    )
    await db.commit()
    await db.refresh(trust)
    return _tls_trust_response(trust)


@router.post(
    "/{device_id}/remote-access/web/tls/replace",
    response_model=WebTLSTrustRead,
)
async def replace_web_tls_certificate(
    device_id: UUID,
    payload: WebTLSReplaceRequest,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await _eligible_device(device_id, db, actor)
    trust = await replace_device_web_tls_certificate(
        db,
        device_id=device_id,
        actor_user_id=actor.id,
        current_certificate_sha256=payload.current_certificate_sha256,
        expected_new_certificate_sha256=payload.expected_new_certificate_sha256,
        acknowledge_certificate_change=payload.acknowledge_certificate_change,
        port=payload.port,
        compatibility_profile=payload.compatibility_profile,
    )
    await db.commit()
    await db.refresh(trust)
    return _tls_trust_response(trust)


@router.post(
    "/{device_id}/remote-access/ssh-sessions",
    response_model=RemoteAccessLaunchResponse | SSHHostKeyActionResponse,
)
async def create_ssh_session(
    device_id: UUID,
    request: Request,
    payload: SSHSessionActionRequest | None = None,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await _eligible_device(device_id, db, actor)
    action = payload.action if payload is not None else "LAUNCH"

    if action == "DISCOVER_HOST_KEY":
        candidate = await discover_device_ssh_host_key(db, device_id=device_id)
        return _host_key_response("DISCOVER_HOST_KEY", candidate)

    if action == "TRUST_HOST_KEY":
        assert payload is not None and payload.expected_fingerprint is not None
        candidate = await trust_device_ssh_host_key(
            db,
            device_id=device_id,
            actor_user_id=actor.id,
            expected_fingerprint=payload.expected_fingerprint,
            replace_existing=payload.replace_existing,
        )
        await db.commit()
        return _host_key_response("TRUST_HOST_KEY", candidate)

    auth_session = await _auth_session_for_request(request, db)
    ticket, session = await issue_ssh_session(
        db,
        device_id=device_id,
        actor_user_id=actor.id,
        auth_session_id=auth_session.id if auth_session else None,
        source_ip=request.client.host if request.client else None,
    )
    await db.commit()
    return RemoteAccessLaunchResponse(
        session_id=session.id,
        ticket=ticket,
        expires_at=session.expires_at.astimezone(timezone.utc),
        websocket_path="/ws/ssh",
    )


@router.post("/{device_id}/remote-access/telnet-sessions", response_model=RemoteAccessLaunchResponse)
async def create_telnet_session(
    device_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await _eligible_device(device_id, db, actor)
    auth_session = await _auth_session_for_request(request, db)
    ticket, session = await issue_telnet_session(
        db,
        device_id=device_id,
        actor_user_id=actor.id,
        auth_session_id=auth_session.id if auth_session else None,
        source_ip=request.client.host if request.client else None,
    )
    await db.commit()
    return RemoteAccessLaunchResponse(
        session_id=session.id,
        ticket=ticket,
        expires_at=session.expires_at.astimezone(timezone.utc),
        websocket_path="/ws/telnet",
    )


@router.post("/{device_id}/remote-access/web-sessions", response_model=WebRemoteAccessLaunchResponse)
async def create_web_session(
    device_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await _eligible_device(device_id, db, actor)
    template_ready = await access_template_ready(db, device_id=device_id, protocol="WEB")
    effective = await resolve_effective_access(db, device_id=device_id, protocol="WEB")
    if template_ready is not True or effective.status != "RESOLVED" or effective.template is None:
        raise APIError(
            409,
            "REMOTE_ACCESS_WEB_NOT_CONFIGURED",
            "Secure Web-GUI requires a complete effective WEB Access Template in addition to the device Web transport/TLS profile.",
        )
    auth_session = await _auth_session_for_request(request, db)
    ticket, session = await issue_web_session(
        db,
        device_id=device_id,
        actor_user_id=actor.id,
        auth_session_id=auth_session.id if auth_session else None,
        source_ip=request.client.host if request.client else None,
        access_template_id=effective.template.id,
    )
    await db.commit()
    return WebRemoteAccessLaunchResponse(
        session_id=session.id, ticket=ticket, expires_at=session.expires_at.astimezone(timezone.utc)
    )


async def _revoke_owned_session(
    *, device_id: UUID, session_id: UUID, expected_mode: str, db: AsyncSession, actor
) -> RemoteAccessSession:
    await require_device(db, await scope_for_actor(db, actor), device_id)
    session = await db.scalar(
        select(RemoteAccessSession)
        .where(RemoteAccessSession.id == session_id, RemoteAccessSession.device_id == device_id)
        .with_for_update()
    )
    if session is None or session.mode != expected_mode:
        raise APIError(404, "REMOTE_ACCESS_SESSION_NOT_FOUND", "Remote-access session not found.")
    if session.actor_user_id != actor.id:
        raise APIError(403, "REMOTE_ACCESS_SESSION_OWNER_REQUIRED", "Only the session owner may revoke this remote-access session.")
    await revoke_remote_session(db, session=session, actor_user_id=actor.id, reason="USER_REQUEST")
    await db.commit()
    return session


@router.delete("/{device_id}/remote-access/sessions/{session_id}", response_model=RemoteAccessRevokeResponse)
async def revoke_ssh_session(
    device_id: UUID,
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    session = await _revoke_owned_session(
        device_id=device_id, session_id=session_id, expected_mode="SSH", db=db, actor=actor
    )
    return RemoteAccessRevokeResponse(session_id=session.id, status=session.status)


@router.delete("/{device_id}/remote-access/telnet-sessions/{session_id}", response_model=RemoteAccessRevokeResponse)
async def revoke_telnet_session(
    device_id: UUID,
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    session = await _revoke_owned_session(
        device_id=device_id, session_id=session_id, expected_mode="TELNET", db=db, actor=actor
    )
    return RemoteAccessRevokeResponse(session_id=session.id, status=session.status)


@router.delete("/{device_id}/remote-access/web-sessions/{session_id}", response_model=RemoteAccessRevokeResponse)
async def revoke_web_session(
    device_id: UUID,
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    session = await _revoke_owned_session(
        device_id=device_id, session_id=session_id, expected_mode="WEB", db=db, actor=actor
    )
    return RemoteAccessRevokeResponse(session_id=session.id, status=session.status)
