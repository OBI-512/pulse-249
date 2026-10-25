from __future__ import annotations

import asyncio
import hashlib
import hmac
import ssl
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import APIError
from ..models import DeviceRemoteAccessProfile
from ..remote_gateway.secrets import RemoteAccessSecretError, resolve_secret_reference
from .web_tls_trust import (
    build_internal_pin_ssl_context,
    linked_internal_web_tls_trust,
    record_web_tls_runtime_mismatch,
)


WEB_TLS_RUNTIME_TIMEOUT_SECONDS = 10


def _normalize_pem(value: str) -> str:
    normalized = str(value or "").strip().replace("\\n", "\n")
    if "-----BEGIN " not in normalized or "-----END " not in normalized:
        raise APIError(409, "REMOTE_ACCESS_TLS_MATERIAL_INVALID", "Configured TLS trust material is invalid.")
    return normalized + ("\n" if not normalized.endswith("\n") else "")


def _exact_pin_context_from_pem(pem: str, compatibility_profile: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if compatibility_profile == "LEGACY_WEAK_CERT_KEY":
        context.set_ciphers("DEFAULT:@SECLEVEL=1")
    elif compatibility_profile != "MODERN":
        raise APIError(409, "REMOTE_ACCESS_WEB_TLS_COMPAT_INVALID", "Unsupported Web-GUI TLS compatibility profile.")
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False
    try:
        context.load_verify_locations(cadata=pem)
    except ssl.SSLError as exc:
        raise APIError(409, "REMOTE_ACCESS_TLS_MATERIAL_INVALID", "Configured TLS trust material is invalid.") from exc
    if hasattr(ssl, "VERIFY_X509_PARTIAL_CHAIN"):
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return context


def _private_ca_context(pem: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    try:
        context.load_verify_locations(cadata=pem)
    except ssl.SSLError as exc:
        raise APIError(409, "REMOTE_ACCESS_TLS_MATERIAL_INVALID", "Configured private-CA trust material is invalid.") from exc
    return context


async def _credential_free_verify(
    host: str,
    port: int,
    context: ssl.SSLContext,
    *,
    timeout_seconds: int,
) -> bytes:
    writer = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=host,
                port=port,
                ssl=context,
                server_hostname=host if context.check_hostname else None,
                ssl_handshake_timeout=max(1, min(int(timeout_seconds), 30)),
            ),
            timeout=max(1, min(int(timeout_seconds), 30)),
        )
        ssl_object = writer.get_extra_info("ssl_object")
        certificate_der = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
        if not certificate_der:
            raise APIError(
                502,
                "WEB_TLS_CERTIFICATE_MISSING",
                "The HTTPS endpoint did not present a server certificate.",
            )
        return bytes(certificate_der)
    except asyncio.TimeoutError as exc:
        raise APIError(504, "WEB_TLS_VERIFICATION_TIMEOUT", "The HTTPS TLS verification timed out.") from exc
    except ssl.SSLCertVerificationError as exc:
        raise APIError(409, "WEB_TLS_CERTIFICATE_MISMATCH", "The device certificate does not match the configured TLS trust.") from exc
    except ssl.SSLError as exc:
        raise APIError(502, "WEB_TLS_HANDSHAKE_FAILED", "The HTTPS TLS handshake could not be completed.") from exc
    except OSError as exc:
        raise APIError(502, "WEB_TLS_ENDPOINT_UNREACHABLE", "The HTTPS management endpoint is unreachable.") from exc
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def resolve_verified_web_ssl_context(
    db: AsyncSession,
    *,
    profile: DeviceRemoteAccessProfile,
    management_ip: str,
    port: int,
    actor_user_id: UUID | None = None,
    timeout_seconds: int = WEB_TLS_RUNTIME_TIMEOUT_SECONDS,
) -> ssl.SSLContext | bool:
    """Resolve WEB TLS trust and verify it before any device credentials are resolved.

    Internal public-certificate trust is authoritative whenever web_tls_trust_id
    is present. A failed internal pin never falls back to SYSTEM, PRIVATE_CA, or
    the legacy external pin reference. Internal pins additionally compare the
    peer leaf DER SHA-256 exactly after the credential-free TLS handshake.
    """

    if profile.web_scheme == "HTTP":
        if profile.web_tls_compat_profile != "MODERN":
            raise APIError(409, "REMOTE_ACCESS_WEB_HTTP_TLS_COMPAT_INVALID", "HTTP Web-GUI cannot use an HTTPS TLS compatibility profile.")
        return False
    if profile.web_scheme != "HTTPS":
        raise APIError(409, "REMOTE_ACCESS_WEB_SCHEME_INVALID", "Web-GUI scheme must be HTTP or HTTPS.")

    configured_fingerprint: str | None = None
    if profile.web_tls_mode == "SYSTEM":
        context = ssl.create_default_context()
    elif profile.web_tls_mode == "PRIVATE_CA":
        try:
            pem = _normalize_pem(resolve_secret_reference(profile.web_tls_ca_reference))
        except RemoteAccessSecretError as exc:
            raise APIError(409, "REMOTE_ACCESS_WEB_CA_REQUIRED", "Configured private-CA trust is unavailable.") from exc
        context = _private_ca_context(pem)
    elif profile.web_tls_mode == "PINNED_CERT":
        if profile.web_tls_trust_id is not None:
            trust = await linked_internal_web_tls_trust(
                db,
                profile,
                management_ip=management_ip,
                port=port,
            )
            if trust is None:
                raise APIError(
                    409,
                    "WEB_TLS_INTERNAL_TRUST_NOT_READY",
                    "The internally trusted certificate is stale, expired, or no longer matches the registered management endpoint.",
                )
            configured_fingerprint = trust.certificate_sha256
            context = build_internal_pin_ssl_context(
                trust.certificate_der,
                profile.web_tls_compat_profile,
            )
        else:
            try:
                pem = _normalize_pem(resolve_secret_reference(profile.web_tls_pinned_certificate_reference))
            except RemoteAccessSecretError as exc:
                raise APIError(409, "REMOTE_ACCESS_WEB_PIN_REQUIRED", "Configured pinned-certificate trust is unavailable.") from exc
            context = _exact_pin_context_from_pem(pem, profile.web_tls_compat_profile)
    else:
        raise APIError(409, "REMOTE_ACCESS_WEB_TLS_MODE_INVALID", "Unsupported Web-GUI TLS trust mode.")

    try:
        presented_der = await _credential_free_verify(
            management_ip,
            port,
            context,
            timeout_seconds=timeout_seconds,
        )
        if profile.web_tls_trust_id is not None and configured_fingerprint is not None:
            presented_fingerprint = hashlib.sha256(presented_der).hexdigest()
            if not hmac.compare_digest(presented_fingerprint, configured_fingerprint.lower()):
                raise APIError(
                    409,
                    "WEB_TLS_CERTIFICATE_MISMATCH",
                    "The device certificate does not match the internally pinned certificate fingerprint.",
                )
    except APIError as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        code = str(detail.get("code") or "")
        if profile.web_tls_trust_id is not None and code == "WEB_TLS_CERTIFICATE_MISMATCH":
            await record_web_tls_runtime_mismatch(
                db,
                device_id=profile.device_id,
                actor_user_id=actor_user_id,
                management_ip=management_ip,
                port=port,
                configured_fingerprint=configured_fingerprint,
            )
        raise
    return context
