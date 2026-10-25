from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import (
    AuthSession,
    DeviceIP,
    DeviceRemoteAccessProfile,
    RemoteAccessSession,
)
from ..services.access_template_runtime import access_template_ready
from ..services.audit import record_audit
from ..core.exceptions import APIError
from ..settings import settings
from ..web_management import effective_web_port
from .web_tls_trust import linked_internal_web_tls_trust, revoke_linked_internal_web_tls_trust


TICKET_BYTES = 32


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_remote_ticket(ticket: str) -> str:
    if not ticket:
        raise ValueError("Remote-access ticket must not be empty.")
    return hashlib.sha256(ticket.encode("utf-8")).hexdigest()


def profile_is_ready(profile: DeviceRemoteAccessProfile | None) -> bool:
    """Return legacy env-reference SSH readiness. Kept for existing callers."""
    return bool(
        profile is not None
        and profile.ssh_enabled
        and profile.ssh_username_reference
        and profile.ssh_host_key_fingerprint
        and (profile.ssh_password_reference or profile.ssh_private_key_reference)
    )


def web_profile_is_ready(profile: DeviceRemoteAccessProfile | None) -> bool:
    """Return structural WEB readiness without database trust validation."""
    if profile is None or not profile.web_enabled:
        return False
    if profile.web_scheme == "HTTP":
        return profile.web_tls_compat_profile == "MODERN"
    if profile.web_scheme != "HTTPS":
        return False
    if profile.web_tls_compat_profile == "LEGACY_WEAK_CERT_KEY" and profile.web_tls_mode != "PINNED_CERT":
        return False
    if profile.web_tls_compat_profile not in {"MODERN", "LEGACY_WEAK_CERT_KEY"}:
        return False
    if profile.web_tls_mode == "SYSTEM":
        return True
    if profile.web_tls_mode == "PRIVATE_CA":
        return bool(profile.web_tls_ca_reference)
    if profile.web_tls_mode == "PINNED_CERT":
        return bool(profile.web_tls_trust_id or profile.web_tls_pinned_certificate_reference)
    return False


async def web_profile_is_ready_async(
    db: AsyncSession,
    profile: DeviceRemoteAccessProfile | None,
) -> bool:
    if not web_profile_is_ready(profile):
        return False
    assert profile is not None
    if profile.web_tls_mode != "PINNED_CERT" or profile.web_tls_trust_id is None:
        return True
    try:
        port = profile_web_port(profile)
    except ValueError:
        return False
    trust = await linked_internal_web_tls_trust(db, profile, port=port)
    return trust is not None


async def web_profile_internal_trust_fingerprint(
    db: AsyncSession,
    profile: DeviceRemoteAccessProfile | None,
) -> str | None:
    if profile is None or profile.web_tls_trust_id is None:
        return None
    try:
        port = profile_web_port(profile)
    except ValueError:
        return None
    trust = await linked_internal_web_tls_trust(db, profile, port=port, require_valid_now=False)
    return trust.certificate_sha256 if trust is not None else None


def profile_web_port(profile: DeviceRemoteAccessProfile) -> int:
    return effective_web_port(profile.web_scheme, profile.web_port)


def profile_read(profile: DeviceRemoteAccessProfile | None, device_id: UUID):
    from ..schemas.remote_access import DeviceRemoteAccessRead

    if profile is None:
        return DeviceRemoteAccessRead(
            device_id=device_id,
            ssh_enabled=False,
            ssh_port=22,
            ssh_compatibility_profile="MODERN",
            ssh_host_key_fingerprint=None,
            username_reference_configured=False,
            password_reference_configured=False,
            private_key_reference_configured=False,
            ready=False,
        )
    return DeviceRemoteAccessRead(
        device_id=device_id,
        ssh_enabled=profile.ssh_enabled,
        ssh_port=profile.ssh_port,
        ssh_compatibility_profile=profile.ssh_compatibility_profile,
        ssh_host_key_fingerprint=profile.ssh_host_key_fingerprint,
        username_reference_configured=bool(profile.ssh_username_reference),
        password_reference_configured=bool(profile.ssh_password_reference),
        private_key_reference_configured=bool(profile.ssh_private_key_reference),
        ready=profile_is_ready(profile),
    )


def web_profile_read(profile: DeviceRemoteAccessProfile | None, device_id: UUID):
    from ..schemas.remote_access import DeviceWebRemoteAccessRead

    if profile is None:
        return DeviceWebRemoteAccessRead(
            device_id=device_id,
            web_enabled=False,
            web_scheme="HTTPS",
            web_port=None,
            effective_web_port=443,
            web_tls_mode="SYSTEM",
            web_tls_compat_profile="MODERN",
            tls_ca_reference_configured=False,
            tls_pinned_certificate_reference_configured=False,
            internal_tls_trust_configured=False,
            internal_tls_trust_fingerprint=None,
            ready=False,
        )
    return DeviceWebRemoteAccessRead(
        device_id=device_id,
        web_enabled=profile.web_enabled,
        web_scheme=profile.web_scheme,
        web_port=profile.web_port,
        effective_web_port=profile_web_port(profile),
        web_tls_mode=profile.web_tls_mode,
        web_tls_compat_profile=profile.web_tls_compat_profile,
        tls_ca_reference_configured=bool(profile.web_tls_ca_reference),
        tls_pinned_certificate_reference_configured=bool(profile.web_tls_pinned_certificate_reference),
        internal_tls_trust_configured=bool(profile.web_tls_trust_id),
        internal_tls_trust_fingerprint=None,
        ready=web_profile_is_ready(profile),
    )


async def apply_remote_access_update(
    db: AsyncSession,
    *,
    device_id: UUID,
    payload,
) -> DeviceRemoteAccessProfile:
    profile = await db.scalar(
        select(DeviceRemoteAccessProfile)
        .where(DeviceRemoteAccessProfile.device_id == device_id)
        .with_for_update()
    )
    if profile is None:
        profile = DeviceRemoteAccessProfile(device_id=device_id)
        db.add(profile)
        await db.flush()

    data = payload.model_dump(exclude_unset=True)
    clear_password = bool(data.pop("clear_password_reference", False))
    clear_key = bool(data.pop("clear_private_key_reference", False))
    clear_web_ca = bool(data.pop("clear_web_tls_ca_reference", False))
    clear_web_pin = bool(data.pop("clear_web_tls_pinned_certificate_reference", False))

    if profile.web_tls_trust_id is not None:
        old_port = profile_web_port(profile)
        new_scheme = data.get("web_scheme", profile.web_scheme)
        new_port_value = data.get("web_port", profile.web_port)
        new_mode = data.get("web_tls_mode", profile.web_tls_mode)
        new_compat = data.get("web_tls_compat_profile", profile.web_tls_compat_profile)
        try:
            new_effective_port = effective_web_port(new_scheme, new_port_value)
        except ValueError:
            new_effective_port = -1
        if (
            new_scheme != "HTTPS"
            or new_mode != "PINNED_CERT"
            or new_effective_port != old_port
            or new_compat != profile.web_tls_compat_profile
        ):
            await revoke_linked_internal_web_tls_trust(
                db,
                profile,
                reason="Device Web transport/TLS endpoint changed",
            )

    if clear_password:
        profile.ssh_password_reference = None
    if clear_key:
        profile.ssh_private_key_reference = None
    if clear_web_ca:
        profile.web_tls_ca_reference = None
    if clear_web_pin:
        profile.web_tls_pinned_certificate_reference = None

    for field in (
        "ssh_enabled",
        "ssh_port",
        "ssh_compatibility_profile",
        "ssh_username_reference",
        "ssh_password_reference",
        "ssh_private_key_reference",
        "ssh_host_key_fingerprint",
        "web_enabled",
        "web_scheme",
        "web_port",
        "web_tls_mode",
        "web_tls_compat_profile",
        "web_tls_ca_reference",
        "web_tls_pinned_certificate_reference",
    ):
        if field in data:
            setattr(profile, field, data[field])

    if profile.ssh_enabled and (
        profile.ssh_username_reference
        or profile.ssh_password_reference
        or profile.ssh_private_key_reference
    ):
        if not profile.ssh_username_reference:
            raise APIError(422, "REMOTE_ACCESS_USERNAME_REQUIRED", "SSH username credential reference is required.")
        if not profile.ssh_host_key_fingerprint:
            raise APIError(422, "REMOTE_ACCESS_HOST_KEY_REQUIRED", "Pinned SSH host-key fingerprint is required.")
        if not (profile.ssh_password_reference or profile.ssh_private_key_reference):
            raise APIError(422, "REMOTE_ACCESS_CREDENTIAL_REQUIRED", "SSH password or private-key credential reference is required.")

    if profile.web_enabled:
        try:
            profile_web_port(profile)
        except ValueError as exc:
            raise APIError(422, "REMOTE_ACCESS_WEB_PORT_INVALID", str(exc)) from exc
        if profile.web_scheme == "HTTP":
            if profile.web_tls_mode != "SYSTEM":
                raise APIError(422, "REMOTE_ACCESS_WEB_HTTP_TLS_MODE_INVALID", "HTTP Web-GUI profiles must use SYSTEM as the inactive TLS mode.")
            if profile.web_tls_compat_profile != "MODERN":
                raise APIError(422, "REMOTE_ACCESS_WEB_HTTP_TLS_COMPAT_INVALID", "HTTP Web-GUI profiles cannot use an HTTPS TLS compatibility profile.")
        elif profile.web_scheme == "HTTPS":
            if profile.web_tls_compat_profile == "LEGACY_WEAK_CERT_KEY" and profile.web_tls_mode != "PINNED_CERT":
                raise APIError(422, "REMOTE_ACCESS_WEB_LEGACY_TLS_PIN_REQUIRED", "Legacy weak-certificate compatibility requires exact pinned-certificate trust.")
            if profile.web_tls_compat_profile not in {"MODERN", "LEGACY_WEAK_CERT_KEY"}:
                raise APIError(422, "REMOTE_ACCESS_WEB_TLS_COMPAT_INVALID", "Unsupported Web-GUI TLS compatibility profile.")
            if profile.web_tls_mode == "PRIVATE_CA" and not profile.web_tls_ca_reference:
                raise APIError(422, "REMOTE_ACCESS_WEB_CA_REQUIRED", "A gateway-side private-CA env:// reference is required.")
            if (
                profile.web_tls_mode == "PINNED_CERT"
                and not profile.web_tls_trust_id
                and not profile.web_tls_pinned_certificate_reference
            ):
                raise APIError(
                    422,
                    "REMOTE_ACCESS_WEB_PIN_REQUIRED",
                    "An internal trusted certificate or legacy gateway-side pinned-certificate reference is required.",
                )
        else:
            raise APIError(422, "REMOTE_ACCESS_WEB_SCHEME_INVALID", "Web-GUI scheme must be HTTP or HTTPS.")
    return profile


async def get_management_ip(db: AsyncSession, device_id: UUID) -> str | None:
    return await db.scalar(
        select(DeviceIP.ip_address)
        .where(
            DeviceIP.device_id == device_id,
            DeviceIP.deleted_at.is_(None),
            DeviceIP.is_management.is_(True),
        )
        .order_by(DeviceIP.is_primary.desc(), DeviceIP.created_at.asc())
        .limit(1)
    )


async def _issue_session(
    db: AsyncSession,
    *,
    device_id: UUID,
    actor_user_id: UUID,
    auth_session_id: UUID | None,
    source_ip: str | None,
    mode: str,
    access_template_id: UUID | None = None,
) -> tuple[str, RemoteAccessSession]:
    now = utcnow()
    ticket = secrets.token_urlsafe(TICKET_BYTES)
    session = RemoteAccessSession(
        device_id=device_id,
        actor_user_id=actor_user_id,
        auth_session_id=auth_session_id,
        access_template_id=access_template_id,
        mode=mode,
        status="ISSUED",
        ticket_hash=hash_remote_ticket(ticket),
        issued_at=now,
        expires_at=now + timedelta(seconds=max(10, settings.remote_access_ticket_ttl_seconds)),
        source_ip=(source_ip or "")[:64] or None,
    )
    db.add(session)
    await db.flush()
    return ticket, session


async def issue_ssh_session(
    db: AsyncSession,
    *,
    device_id: UUID,
    actor_user_id: UUID,
    auth_session_id: UUID | None,
    source_ip: str | None,
) -> tuple[str, RemoteAccessSession]:
    if not settings.remote_access_enabled:
        raise APIError(503, "REMOTE_ACCESS_DISABLED", "Remote access is disabled on this FTTW installation.")

    profile = await db.scalar(select(DeviceRemoteAccessProfile).where(DeviceRemoteAccessProfile.device_id == device_id))
    template_ready = await access_template_ready(db, device_id=device_id, protocol="SSH")
    if template_ready is None:
        ready = profile_is_ready(profile)
    else:
        ready = bool(
            template_ready
            and profile is not None
            and profile.ssh_enabled
            and profile.ssh_host_key_fingerprint
        )
    if not ready:
        raise APIError(409, "REMOTE_ACCESS_NOT_CONFIGURED", "SSH remote access is not fully configured for this device.")
    if not await get_management_ip(db, device_id):
        raise APIError(409, "DEVICE_MANAGEMENT_IP_REQUIRED", "The device has no active management IP address.")

    ticket, session = await _issue_session(
        db, device_id=device_id, actor_user_id=actor_user_id, auth_session_id=auth_session_id,
        source_ip=source_ip, mode="SSH",
    )
    await record_audit(
        db,
        action="REMOTE_ACCESS_SSH_ISSUED",
        entity_type="Device",
        entity_id=device_id,
        actor_user_id=actor_user_id,
        description="One-time Web SSH launch ticket issued.",
        metadata={
            "remote_access_session_id": str(session.id),
            "mode": "SSH",
            "credential_source": "ACCESS_TEMPLATE" if template_ready is not None else "REMOTE_ACCESS_PROFILE",
            "ticket_ttl_seconds": settings.remote_access_ticket_ttl_seconds,
        },
    )
    return ticket, session


async def issue_telnet_session(
    db: AsyncSession,
    *,
    device_id: UUID,
    actor_user_id: UUID,
    auth_session_id: UUID | None,
    source_ip: str | None,
) -> tuple[str, RemoteAccessSession]:
    if not settings.remote_access_enabled:
        raise APIError(503, "REMOTE_ACCESS_DISABLED", "Remote access is disabled on this FTTW installation.")
    if not settings.telnet_access_enabled:
        raise APIError(
            503,
            "TELNET_ACCESS_DISABLED",
            "Legacy Telnet access is disabled on this FTTW installation.",
        )
    template_ready = await access_template_ready(db, device_id=device_id, protocol="TELNET")
    if template_ready is not True:
        raise APIError(
            409,
            "TELNET_ACCESS_NOT_CONFIGURED",
            "A complete effective Telnet Access Template is required for this device.",
        )
    if not await get_management_ip(db, device_id):
        raise APIError(409, "DEVICE_MANAGEMENT_IP_REQUIRED", "The device has no active management IP address.")

    ticket, session = await _issue_session(
        db, device_id=device_id, actor_user_id=actor_user_id, auth_session_id=auth_session_id,
        source_ip=source_ip, mode="TELNET",
    )
    await record_audit(
        db,
        action="REMOTE_ACCESS_TELNET_ISSUED",
        entity_type="Device",
        entity_id=device_id,
        actor_user_id=actor_user_id,
        description="One-time legacy Telnet terminal launch ticket issued.",
        metadata={
            "remote_access_session_id": str(session.id),
            "mode": "TELNET",
            "credential_source": "ACCESS_TEMPLATE",
            "insecure_transport": True,
            "ticket_ttl_seconds": settings.remote_access_ticket_ttl_seconds,
        },
    )
    return ticket, session


async def issue_web_session(
    db: AsyncSession,
    *,
    device_id: UUID,
    actor_user_id: UUID,
    auth_session_id: UUID | None,
    source_ip: str | None,
    access_template_id: UUID | None = None,
) -> tuple[str, RemoteAccessSession]:
    if not settings.remote_access_enabled:
        raise APIError(503, "REMOTE_ACCESS_DISABLED", "Remote access is disabled on this FTTW installation.")
    profile = await db.scalar(select(DeviceRemoteAccessProfile).where(DeviceRemoteAccessProfile.device_id == device_id))
    if not await web_profile_is_ready_async(db, profile):
        raise APIError(409, "REMOTE_ACCESS_WEB_NOT_CONFIGURED", "Native Web-GUI proxy access is not fully configured for this device.")
    if profile is None:
        raise APIError(409, "REMOTE_ACCESS_WEB_NOT_CONFIGURED", "Native Web-GUI proxy access is not fully configured for this device.")
    try:
        profile_web_port(profile)
    except ValueError as exc:
        raise APIError(409, "REMOTE_ACCESS_WEB_PORT_INVALID", str(exc)) from exc
    if not await get_management_ip(db, device_id):
        raise APIError(409, "DEVICE_MANAGEMENT_IP_REQUIRED", "The device has no active management IP address.")

    ticket, session = await _issue_session(
        db,
        device_id=device_id,
        actor_user_id=actor_user_id,
        auth_session_id=auth_session_id,
        source_ip=source_ip,
        mode="WEB",
        access_template_id=access_template_id,
    )
    await record_audit(
        db,
        action="REMOTE_ACCESS_WEB_ISSUED",
        entity_type="Device",
        entity_id=device_id,
        actor_user_id=actor_user_id,
        description="One-time native Web-GUI proxy launch ticket issued.",
        metadata={
            "remote_access_session_id": str(session.id),
            "mode": "WEB",
            "access_template_id": str(access_template_id) if access_template_id else None,
            "ticket_ttl_seconds": settings.remote_access_ticket_ttl_seconds,
        },
    )
    return ticket, session


async def revoke_remote_session(
    db: AsyncSession,
    *,
    session: RemoteAccessSession,
    actor_user_id: UUID | None,
    reason: str,
) -> None:
    if session.status in {"CLOSED", "REVOKED", "FAILED"}:
        return
    now = utcnow()
    session.status = "REVOKED"
    session.revoked_at = now
    session.ended_at = session.ended_at or now
    session.revoked_reason = reason[:80]
    await record_audit(
        db,
        action="REMOTE_ACCESS_SESSION_REVOKED",
        entity_type="Device",
        entity_id=session.device_id,
        actor_user_id=actor_user_id,
        description="Remote-access session revoked.",
        metadata={
            "remote_access_session_id": str(session.id),
            "reason": reason[:80],
            "mode": session.mode,
        },
    )


async def revoke_for_auth_session(
    db: AsyncSession,
    *,
    auth_session_id: UUID | None,
    reason: str,
) -> int:
    if auth_session_id is None:
        return 0
    now = utcnow()
    result = await db.execute(
        update(RemoteAccessSession)
        .where(
            RemoteAccessSession.auth_session_id == auth_session_id,
            RemoteAccessSession.status.in_(("ISSUED", "ACTIVE")),
        )
        .values(
            status="REVOKED",
            revoked_at=now,
            ended_at=now,
            revoked_reason=reason[:80],
        )
    )
    return int(result.rowcount or 0)
