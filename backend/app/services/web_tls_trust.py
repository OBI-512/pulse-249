from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import APIError
from ..models import Device, DeviceIP, DeviceRemoteAccessProfile, DeviceWebTLSTrust
from .audit import record_audit


WEB_TLS_COMPATIBILITY_PROFILES = {"MODERN", "LEGACY_WEAK_CERT_KEY"}
WEB_TLS_INSPECT_TIMEOUT_SECONDS = 8


@dataclass(frozen=True)
class WebTLSCertificateObservation:
    management_ip: str
    port: int
    compatibility_profile: str
    certificate_sha256: str
    certificate_der: bytes
    subject: str
    issuer: str
    serial_number: str
    not_valid_before: datetime
    not_valid_after: datetime
    san_dns: tuple[str, ...]
    san_ip: tuple[str, ...]
    self_signed: bool
    validity_state: str
    observed_at: datetime


def _normalize_compatibility_profile(value: str) -> str:
    normalized = str(value or "MODERN").strip().upper()
    if normalized not in WEB_TLS_COMPATIBILITY_PROFILES:
        raise APIError(
            422,
            "WEB_TLS_COMPATIBILITY_PROFILE_INVALID",
            "Unsupported Web-GUI TLS compatibility profile.",
        )
    return normalized


def _normalize_port(value: int) -> int:
    port = int(value)
    if port < 1 or port > 65535:
        raise APIError(422, "WEB_TLS_PORT_INVALID", "HTTPS management port must be between 1 and 65535.")
    return port


def _normalize_expected_fingerprint(value: str) -> str:
    normalized = str(value or "").strip().lower().replace(":", "")
    if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise APIError(
            422,
            "WEB_TLS_CERTIFICATE_FINGERPRINT_INVALID",
            "Expected certificate fingerprint must be a 64-character SHA-256 hex value.",
        )
    return normalized


def _validate_management_ip(value: str) -> str:
    try:
        parsed = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise APIError(409, "DEVICE_MANAGEMENT_IP_INVALID", "The registered management IP is invalid.") from exc
    if parsed.is_unspecified or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_reserved:
        raise APIError(409, "DEVICE_MANAGEMENT_IP_FORBIDDEN", "The registered management IP is not eligible for remote access.")
    return str(parsed)


def _inspection_context(compatibility_profile: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if compatibility_profile == "LEGACY_WEAK_CERT_KEY":
        context.set_ciphers("DEFAULT:@SECLEVEL=1")
    return context


def build_internal_pin_ssl_context(certificate_der: bytes, compatibility_profile: str) -> ssl.SSLContext:
    compatibility = _normalize_compatibility_profile(compatibility_profile)
    if not certificate_der:
        raise APIError(409, "WEB_TLS_INTERNAL_TRUST_INVALID", "The internally trusted certificate is unavailable.")
    try:
        pem = ssl.DER_cert_to_PEM_cert(bytes(certificate_der))
    except (TypeError, ValueError) as exc:
        raise APIError(409, "WEB_TLS_INTERNAL_TRUST_INVALID", "The internally trusted certificate is invalid.") from exc
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if compatibility == "LEGACY_WEAK_CERT_KEY":
        context.set_ciphers("DEFAULT:@SECLEVEL=1")
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False
    try:
        context.load_verify_locations(cadata=pem)
    except ssl.SSLError as exc:
        raise APIError(409, "WEB_TLS_INTERNAL_TRUST_INVALID", "The internally trusted certificate could not be loaded.") from exc
    if hasattr(ssl, "VERIFY_X509_PARTIAL_CHAIN"):
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return context


def _certificate_validity_state(not_before: datetime, not_after: datetime, now: datetime) -> str:
    if now < not_before:
        return "NOT_YET_VALID"
    if now > not_after:
        return "EXPIRED"
    return "VALID"


def _certificate_is_self_signed(certificate: x509.Certificate) -> bool:
    try:
        certificate.verify_directly_issued_by(certificate)
        return True
    except Exception:
        return False


def _parse_certificate(
    *,
    management_ip: str,
    port: int,
    compatibility_profile: str,
    certificate_der: bytes,
) -> WebTLSCertificateObservation:
    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
    except ValueError as exc:
        raise APIError(502, "WEB_TLS_CERTIFICATE_INVALID", "The HTTPS endpoint returned an invalid X.509 certificate.") from exc

    try:
        san = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        san_dns = tuple(sorted(set(san.get_values_for_type(x509.DNSName))))
        san_ip = tuple(sorted({str(value) for value in san.get_values_for_type(x509.IPAddress)}))
    except x509.ExtensionNotFound:
        san_dns = ()
        san_ip = ()

    now = datetime.now(timezone.utc)
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    return WebTLSCertificateObservation(
        management_ip=management_ip,
        port=port,
        compatibility_profile=compatibility_profile,
        certificate_sha256=hashlib.sha256(certificate_der).hexdigest(),
        certificate_der=bytes(certificate_der),
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        serial_number=format(certificate.serial_number, "x"),
        not_valid_before=not_before,
        not_valid_after=not_after,
        san_dns=san_dns,
        san_ip=san_ip,
        self_signed=_certificate_is_self_signed(certificate),
        validity_state=_certificate_validity_state(not_before, not_after, now),
        observed_at=now,
    )


async def observe_web_tls_certificate(
    management_ip: str,
    *,
    port: int = 443,
    compatibility_profile: str = "MODERN",
    timeout_seconds: int = WEB_TLS_INSPECT_TIMEOUT_SECONDS,
) -> WebTLSCertificateObservation:
    """Perform a credential-free TLS handshake and capture only the peer leaf certificate.

    No HTTP request, cookie, Access Template, credential resolver, or application
    payload is used. The socket is closed immediately after the TLS handshake.
    """

    host = _validate_management_ip(management_ip)
    target_port = _normalize_port(port)
    compatibility = _normalize_compatibility_profile(compatibility_profile)
    context = _inspection_context(compatibility)
    writer = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=host,
                port=target_port,
                ssl=context,
                server_hostname=None,
                ssl_handshake_timeout=max(1, min(int(timeout_seconds), 15)),
            ),
            timeout=max(1, min(int(timeout_seconds), 15)),
        )
        ssl_object = writer.get_extra_info("ssl_object")
        certificate_der = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
        if not certificate_der:
            raise APIError(502, "WEB_TLS_CERTIFICATE_MISSING", "The HTTPS endpoint did not present a server certificate.")
        return _parse_certificate(
            management_ip=host,
            port=target_port,
            compatibility_profile=compatibility,
            certificate_der=certificate_der,
        )
    except asyncio.TimeoutError as exc:
        raise APIError(504, "WEB_TLS_INSPECTION_TIMEOUT", "The HTTPS certificate inspection timed out.") from exc
    except ssl.SSLError as exc:
        raise APIError(502, "WEB_TLS_HANDSHAKE_FAILED", "The HTTPS TLS handshake could not be completed.") from exc
    except OSError as exc:
        raise APIError(502, "WEB_TLS_ENDPOINT_UNREACHABLE", "The registered HTTPS management endpoint is unreachable.") from exc
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def verify_tls_handshake(
    management_ip: str,
    *,
    port: int,
    ssl_context: ssl.SSLContext,
    timeout_seconds: int = WEB_TLS_INSPECT_TIMEOUT_SECONDS,
) -> None:
    """Verify TLS transport without sending any application bytes."""

    host = _validate_management_ip(management_ip)
    target_port = _normalize_port(port)
    writer = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=host,
                port=target_port,
                ssl=ssl_context,
                server_hostname=None,
                ssl_handshake_timeout=max(1, min(int(timeout_seconds), 15)),
            ),
            timeout=max(1, min(int(timeout_seconds), 15)),
        )
    except asyncio.TimeoutError as exc:
        raise APIError(504, "WEB_TLS_VERIFICATION_TIMEOUT", "The HTTPS TLS verification timed out.") from exc
    except ssl.SSLCertVerificationError as exc:
        raise APIError(409, "WEB_TLS_CERTIFICATE_MISMATCH", "The device certificate does not match the configured TLS trust.") from exc
    except ssl.SSLError as exc:
        raise APIError(502, "WEB_TLS_HANDSHAKE_FAILED", "The HTTPS TLS handshake could not be completed.") from exc
    except OSError as exc:
        raise APIError(502, "WEB_TLS_ENDPOINT_UNREACHABLE", "The registered HTTPS management endpoint is unreachable.") from exc
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def _registered_management_ip(db: AsyncSession, device_id: UUID) -> str:
    value = await db.scalar(
        select(DeviceIP.ip_address)
        .where(
            DeviceIP.device_id == device_id,
            DeviceIP.deleted_at.is_(None),
            DeviceIP.is_management.is_(True),
        )
        .order_by(DeviceIP.is_primary.desc(), DeviceIP.created_at.asc())
        .limit(1)
    )
    if not value:
        raise APIError(409, "DEVICE_MANAGEMENT_IP_REQUIRED", "The device has no active management IP address.")
    return _validate_management_ip(value)


async def active_web_tls_trust(db: AsyncSession, device_id: UUID, *, for_update: bool = False) -> DeviceWebTLSTrust | None:
    statement = select(DeviceWebTLSTrust).where(
        DeviceWebTLSTrust.device_id == device_id,
        DeviceWebTLSTrust.status == "ACTIVE",
    )
    if for_update:
        statement = statement.with_for_update()
    return await db.scalar(statement)


async def linked_internal_web_tls_trust(
    db: AsyncSession,
    profile: DeviceRemoteAccessProfile,
    *,
    management_ip: str | None = None,
    port: int | None = None,
    require_valid_now: bool = True,
) -> DeviceWebTLSTrust | None:
    if profile.web_tls_trust_id is None:
        return None
    trust = await db.get(DeviceWebTLSTrust, profile.web_tls_trust_id)
    if trust is None or trust.device_id != profile.device_id or trust.status != "ACTIVE":
        return None
    expected_ip = management_ip or await _registered_management_ip(db, profile.device_id)
    expected_port = int(port if port is not None else (profile.web_port or 443))
    if trust.management_ip_snapshot != expected_ip or trust.port != expected_port:
        return None
    if trust.compatibility_profile != profile.web_tls_compat_profile:
        return None
    if require_valid_now:
        now = datetime.now(timezone.utc)
        if now < trust.not_valid_before or now > trust.not_valid_after:
            return None
    return trust


async def inspect_device_web_tls(
    db: AsyncSession,
    *,
    device_id: UUID,
    actor_user_id: UUID,
    port: int = 443,
    compatibility_profile: str = "MODERN",
) -> tuple[Device, WebTLSCertificateObservation, DeviceWebTLSTrust | None, str]:
    device = await db.get(Device, device_id)
    if device is None or device.deleted_at is not None:
        raise APIError(404, "DEVICE_NOT_FOUND", "Device not found.")
    management_ip = await _registered_management_ip(db, device_id)
    observation = await observe_web_tls_certificate(
        management_ip,
        port=port,
        compatibility_profile=compatibility_profile,
    )
    current = await active_web_tls_trust(db, device_id)
    if current is None:
        relation = "UNTRUSTED"
    elif current.certificate_sha256 == observation.certificate_sha256 and current.management_ip_snapshot == observation.management_ip and current.port == observation.port:
        relation = "MATCH"
    else:
        relation = "MISMATCH"
    await record_audit(
        db,
        action="REMOTE_ACCESS_WEB_TLS_CERTIFICATE_INSPECTED",
        entity_type="Device",
        entity_id=device_id,
        actor_user_id=actor_user_id,
        description="Credential-free HTTPS server certificate inspection completed.",
        metadata={
            "management_ip": observation.management_ip,
            "port": observation.port,
            "compatibility_profile": observation.compatibility_profile,
            "certificate_sha256": observation.certificate_sha256,
            "subject": observation.subject[:500],
            "issuer": observation.issuer[:500],
            "not_valid_before": observation.not_valid_before.isoformat(),
            "not_valid_after": observation.not_valid_after.isoformat(),
            "trust_relation": relation,
            "credentials_sent": False,
            "application_data_sent": False,
        },
    )
    return device, observation, current, relation


def _advisory_lock_key(device_id: UUID) -> int:
    digest = hashlib.sha256(f"TP3:WEB_TLS_TRUST:{device_id}".encode("utf-8")).digest()
    value = int.from_bytes(digest[:8], byteorder="big", signed=False)
    return value - (1 << 64) if value >= (1 << 63) else value


async def _lock_device_trust(db: AsyncSession, device_id: UUID) -> None:
    await db.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": _advisory_lock_key(device_id)})


def _require_currently_valid(observation: WebTLSCertificateObservation) -> None:
    if observation.validity_state != "VALID":
        raise APIError(
            409,
            "WEB_TLS_CERTIFICATE_NOT_CURRENTLY_VALID",
            f"The observed HTTPS certificate is {observation.validity_state.lower().replace('_', ' ')}.",
        )


def _new_trust_from_observation(
    *,
    device_id: UUID,
    actor_user_id: UUID,
    observation: WebTLSCertificateObservation,
    supersedes_trust_id: UUID | None = None,
) -> DeviceWebTLSTrust:
    return DeviceWebTLSTrust(
        device_id=device_id,
        management_ip_snapshot=observation.management_ip,
        port=observation.port,
        compatibility_profile=observation.compatibility_profile,
        certificate_sha256=observation.certificate_sha256,
        certificate_der=observation.certificate_der,
        subject=observation.subject,
        issuer=observation.issuer,
        serial_number=observation.serial_number,
        not_valid_before=observation.not_valid_before,
        not_valid_after=observation.not_valid_after,
        san_dns=list(observation.san_dns),
        san_ip=list(observation.san_ip),
        status="ACTIVE",
        trusted_at=observation.observed_at,
        trusted_by_user_id=actor_user_id,
        supersedes_trust_id=supersedes_trust_id,
    )


async def _profile_for_update(db: AsyncSession, device_id: UUID) -> DeviceRemoteAccessProfile:
    profile = await db.scalar(
        select(DeviceRemoteAccessProfile)
        .where(DeviceRemoteAccessProfile.device_id == device_id)
        .with_for_update()
    )
    if profile is None:
        profile = DeviceRemoteAccessProfile(device_id=device_id)
        db.add(profile)
        await db.flush()
    return profile


def _apply_internal_trust_to_profile(
    profile: DeviceRemoteAccessProfile,
    trust: DeviceWebTLSTrust,
    *,
    port: int,
    compatibility_profile: str,
) -> None:
    profile.web_enabled = True
    profile.web_scheme = "HTTPS"
    profile.web_port = port
    profile.web_tls_mode = "PINNED_CERT"
    profile.web_tls_compat_profile = compatibility_profile
    profile.web_tls_trust_id = trust.id
    profile.web_tls_pinned_certificate_reference = None


async def trust_device_web_tls_certificate(
    db: AsyncSession,
    *,
    device_id: UUID,
    actor_user_id: UUID,
    expected_certificate_sha256: str,
    port: int = 443,
    compatibility_profile: str = "MODERN",
) -> DeviceWebTLSTrust:
    expected = _normalize_expected_fingerprint(expected_certificate_sha256)
    target_port = _normalize_port(port)
    compatibility = _normalize_compatibility_profile(compatibility_profile)
    await _lock_device_trust(db, device_id)
    management_ip = await _registered_management_ip(db, device_id)
    profile = await _profile_for_update(db, device_id)
    observation = await observe_web_tls_certificate(
        management_ip,
        port=target_port,
        compatibility_profile=compatibility,
    )
    if await _registered_management_ip(db, device_id) != management_ip:
        raise APIError(409, "WEB_TLS_ENDPOINT_CHANGED_DURING_TRUST", "The registered management endpoint changed during certificate confirmation.")
    if observation.certificate_sha256 != expected:
        raise APIError(
            409,
            "WEB_TLS_CERTIFICATE_CHANGED_DURING_TRUST",
            "The observed HTTPS certificate changed after inspection; inspect it again before trusting.",
        )
    _require_currently_valid(observation)

    current = await active_web_tls_trust(db, device_id, for_update=True)
    if current is not None:
        same = (
            current.certificate_sha256 == observation.certificate_sha256
            and current.management_ip_snapshot == observation.management_ip
            and current.port == observation.port
            and current.compatibility_profile == observation.compatibility_profile
        )
        if not same:
            raise APIError(
                409,
                "WEB_TLS_CERTIFICATE_REPLACEMENT_REQUIRED",
                "A different certificate is already trusted for this device; use the explicit replacement action.",
            )
        _apply_internal_trust_to_profile(
            profile,
            current,
            port=target_port,
            compatibility_profile=compatibility,
        )
        return current

    trust = _new_trust_from_observation(
        device_id=device_id,
        actor_user_id=actor_user_id,
        observation=observation,
    )
    db.add(trust)
    await db.flush()
    _apply_internal_trust_to_profile(
        profile,
        trust,
        port=target_port,
        compatibility_profile=compatibility,
    )
    await record_audit(
        db,
        action="REMOTE_ACCESS_WEB_TLS_CERTIFICATE_TRUSTED",
        entity_type="Device",
        entity_id=device_id,
        actor_user_id=actor_user_id,
        description="Device-specific HTTPS server certificate trust was explicitly enrolled.",
        metadata={
            "management_ip": observation.management_ip,
            "port": target_port,
            "compatibility_profile": compatibility,
            "certificate_sha256": observation.certificate_sha256,
            "subject": observation.subject[:500],
            "issuer": observation.issuer[:500],
            "credentials_sent": False,
            "application_data_sent": False,
        },
    )
    return trust


async def replace_device_web_tls_certificate(
    db: AsyncSession,
    *,
    device_id: UUID,
    actor_user_id: UUID,
    current_certificate_sha256: str,
    expected_new_certificate_sha256: str,
    acknowledge_certificate_change: bool,
    port: int = 443,
    compatibility_profile: str = "MODERN",
) -> DeviceWebTLSTrust:
    if acknowledge_certificate_change is not True:
        raise APIError(422, "WEB_TLS_CERTIFICATE_CHANGE_ACK_REQUIRED", "Explicit certificate-change acknowledgement is required.")
    current_expected = _normalize_expected_fingerprint(current_certificate_sha256)
    new_expected = _normalize_expected_fingerprint(expected_new_certificate_sha256)
    if new_expected == current_expected:
        raise APIError(409, "WEB_TLS_CERTIFICATE_REPLACEMENT_NOT_REQUIRED", "The replacement fingerprint is identical to the current trust.")
    target_port = _normalize_port(port)
    compatibility = _normalize_compatibility_profile(compatibility_profile)

    await _lock_device_trust(db, device_id)
    management_ip = await _registered_management_ip(db, device_id)
    profile = await _profile_for_update(db, device_id)
    current = await active_web_tls_trust(db, device_id, for_update=True)
    if current is None or current.certificate_sha256 != current_expected:
        raise APIError(409, "WEB_TLS_CURRENT_TRUST_STALE", "The currently trusted certificate no longer matches this replacement confirmation.")

    observation = await observe_web_tls_certificate(
        management_ip,
        port=target_port,
        compatibility_profile=compatibility,
    )
    if await _registered_management_ip(db, device_id) != management_ip:
        raise APIError(409, "WEB_TLS_ENDPOINT_CHANGED_DURING_TRUST", "The registered management endpoint changed during certificate replacement.")
    if observation.certificate_sha256 != new_expected:
        raise APIError(
            409,
            "WEB_TLS_CERTIFICATE_CHANGED_DURING_TRUST",
            "The observed HTTPS certificate does not match the explicitly confirmed replacement fingerprint.",
        )
    _require_currently_valid(observation)

    now = datetime.now(timezone.utc)
    current.status = "SUPERSEDED"
    current.retired_at = now
    current.retired_by_user_id = actor_user_id
    current.retired_reason = "Explicit HTTPS certificate replacement"
    replacement = _new_trust_from_observation(
        device_id=device_id,
        actor_user_id=actor_user_id,
        observation=observation,
        supersedes_trust_id=current.id,
    )
    db.add(replacement)
    await db.flush()
    _apply_internal_trust_to_profile(
        profile,
        replacement,
        port=target_port,
        compatibility_profile=compatibility,
    )
    await record_audit(
        db,
        action="REMOTE_ACCESS_WEB_TLS_CERTIFICATE_REPLACED",
        entity_type="Device",
        entity_id=device_id,
        actor_user_id=actor_user_id,
        description="Device-specific HTTPS server certificate trust was explicitly replaced.",
        metadata={
            "management_ip": observation.management_ip,
            "port": target_port,
            "compatibility_profile": compatibility,
            "previous_certificate_sha256": current.certificate_sha256,
            "certificate_sha256": replacement.certificate_sha256,
            "credentials_sent": False,
            "application_data_sent": False,
        },
    )
    return replacement


async def revoke_linked_internal_web_tls_trust(
    db: AsyncSession,
    profile: DeviceRemoteAccessProfile,
    *,
    reason: str,
    actor_user_id: UUID | None = None,
) -> None:
    if profile.web_tls_trust_id is None:
        return
    trust = await db.get(DeviceWebTLSTrust, profile.web_tls_trust_id)
    profile.web_tls_trust_id = None
    if trust is not None and trust.device_id == profile.device_id and trust.status == "ACTIVE":
        trust.status = "REVOKED"
        trust.retired_at = datetime.now(timezone.utc)
        trust.retired_by_user_id = actor_user_id
        trust.retired_reason = str(reason)[:500]


async def record_web_tls_runtime_mismatch(
    db: AsyncSession,
    *,
    device_id: UUID,
    actor_user_id: UUID | None,
    management_ip: str,
    port: int,
    configured_fingerprint: str | None,
) -> None:
    await record_audit(
        db,
        action="REMOTE_ACCESS_WEB_TLS_CERTIFICATE_MISMATCH",
        entity_type="Device",
        entity_id=device_id,
        actor_user_id=actor_user_id,
        description="Device HTTPS identity failed the configured pinned-certificate verification.",
        metadata={
            "management_ip": management_ip,
            "port": port,
            "configured_certificate_sha256": configured_fingerprint,
            "credentials_sent": False,
            "application_data_sent": False,
        },
    )
