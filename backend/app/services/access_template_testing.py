from __future__ import annotations

import asyncio
import errno
import ssl
import time
from dataclasses import dataclass
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import APIError
from ..discovery.adapters.snmp import _run_snmpget
from ..discovery.models import DiscoveryContext
from ..models import (
    AccessTemplate,
    AccessTemplateTestResult,
    DeviceRemoteAccessProfile,
)
from ..remote_gateway.ssh_transport import (
    SSH_HOST_KEY_LINE_METADATA_KEY,
    SSHTransportError,
    start_ssh,
)
from ..remote_gateway.telnet_transport import TelnetTransportError, start_telnet
from ..remote_gateway.web_auth import (
    WebAuthenticationError,
    authenticate_web_client,
    httpx_auth_for_web,
)
from ..remote_gateway.web_proxy import validate_management_target
from ..settings import settings
from .access_template_runtime import build_web_runtime_access
from .access_templates import (
    AccessTemplateSecretError,
    build_snmp_runtime_credential,
    resolved_secrets,
)
from .remote_access import get_management_ip, profile_web_port, web_profile_is_ready_async
from .web_tls_runtime import resolve_verified_web_ssl_context


@dataclass(frozen=True)
class ProbeOutcome:
    success: bool
    failure_code: str | None = None
    sanitized_message: str | None = None


@dataclass(frozen=True)
class VerifiedWebTransport:
    profile: DeviceRemoteAccessProfile
    target_host: str
    port: int
    ssl_context: ssl.SSLContext | bool


class AccessTemplateProbeFailure(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(code)


async def _tcp_preflight(host: str, port: int, timeout_seconds: int) -> None:
    writer = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=host, port=int(port)),
            timeout=max(1, min(int(timeout_seconds), 30)),
        )
    except asyncio.TimeoutError as exc:
        raise AccessTemplateProbeFailure(
            "TIMEOUT",
            "The device did not accept the management connection before the timeout.",
        ) from exc
    except OSError as exc:
        if exc.errno in {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN}:
            raise AccessTemplateProbeFailure(
                "NETWORK_UNREACHABLE",
                "The device management network is unreachable from the FTTW service.",
            ) from exc
        raise AccessTemplateProbeFailure(
            "PORT_UNREACHABLE",
            "The configured management port is unreachable.",
        ) from exc
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


def _ssh_material(template: AccessTemplate, secrets: dict[str, str]):
    username = secrets.get("username")
    password = secrets.get("password")
    private_key = secrets.get("private_key")
    if not username or not (password or private_key):
        raise AccessTemplateProbeFailure(
            "AUTHENTICATION_FAILED",
            "The SSH Access Template does not contain complete authentication material.",
        )
    template_settings = dict(template.settings_json or {})
    compatibility = str(template_settings.get("compatibility_profile", "MODERN")).strip().upper()
    if compatibility not in {"MODERN", "LEGACY_SSH_RSA_DH1_CBC"}:
        raise AccessTemplateProbeFailure(
            "PROTOCOL_NOT_SUPPORTED",
            "The configured SSH compatibility profile is not supported.",
        )
    if private_key and secrets.get("private_key_passphrase"):
        raise AccessTemplateProbeFailure(
            "PROTOCOL_NOT_SUPPORTED",
            "Encrypted SSH private-key passphrases are not supported by the current transport.",
        )
    return (
        username,
        password,
        private_key,
        int(template_settings.get("port", 22)),
        int(template_settings.get("timeout_seconds", 10)),
        compatibility,
    )


async def _probe_ssh(
    db: AsyncSession,
    *,
    template: AccessTemplate,
    device_id: UUID,
    management_ip: str,
    secrets: dict[str, str],
) -> ProbeOutcome:
    username, password, private_key, port, timeout_seconds, compatibility = _ssh_material(
        template, secrets
    )
    profile = await db.scalar(
        select(DeviceRemoteAccessProfile).where(DeviceRemoteAccessProfile.device_id == device_id)
    )
    fingerprint = profile.ssh_host_key_fingerprint if profile is not None else None
    if not fingerprint:
        raise AccessTemplateProbeFailure(
            "SSH_HOST_KEY_REQUIRED",
            "A device-specific SHA256 SSH host-key fingerprint must be pinned before testing this template.",
        )
    metadata = dict(getattr(profile, "metadata_", None) or {}) if profile is not None else {}
    trusted_host_key_line = metadata.get(SSH_HOST_KEY_LINE_METADATA_KEY)
    if not isinstance(trusted_host_key_line, str):
        trusted_host_key_line = None

    await _tcp_preflight(management_ip, port, timeout_seconds)
    process = None
    try:
        process = await start_ssh(
            host=management_ip,
            port=port,
            username=username,
            password=password,
            private_key=private_key,
            expected_fingerprint=fingerprint,
            compatibility_profile=compatibility,
            authentication_timeout_seconds=timeout_seconds,
            trusted_host_key_line=trusted_host_key_line,
        )
        return ProbeOutcome(True, sanitized_message="SSH authentication and host-key verification succeeded.")
    except SSHTransportError as exc:
        code = str(exc)
        if code == "SSH_HOST_KEY_MISMATCH":
            raise AccessTemplateProbeFailure(
                "SSH_HOST_KEY_MISMATCH",
                "The device SSH host key does not match the pinned fingerprint.",
            ) from exc
        if code == "SSH_HOST_KEY_SCAN_FAILED":
            raise AccessTemplateProbeFailure(
                "TIMEOUT",
                "The SSH host key could not be retrieved within the bounded probe.",
            ) from exc
        if code == "SSH_AUTHENTICATION_FAILED":
            raise AccessTemplateProbeFailure(
                "AUTHENTICATION_FAILED",
                "The device rejected the configured SSH credentials.",
            ) from exc
        if code == "SSH_AUTHENTICATION_TIMEOUT":
            raise AccessTemplateProbeFailure(
                "TIMEOUT",
                "SSH authentication did not complete before the configured timeout.",
            ) from exc
        if code == "SSH_INTERACTIVE_SESSION_FAILED":
            raise AccessTemplateProbeFailure(
                "PROTOCOL_NOT_SUPPORTED",
                "SSH authentication succeeded, but the device did not enter an interactive session.",
            ) from exc
        raise AccessTemplateProbeFailure(
            "PROTOCOL_NOT_SUPPORTED",
            "The SSH transport could not establish a compatible session.",
        ) from exc
    except OSError as exc:
        raise AccessTemplateProbeFailure(
            "PORT_UNREACHABLE",
            "The SSH client could not start or connect to the configured endpoint.",
        ) from exc
    finally:
        if process is not None:
            process.close()


async def _probe_telnet(
    *,
    template: AccessTemplate,
    management_ip: str,
    secrets: dict[str, str],
) -> ProbeOutcome:
    if not settings.telnet_access_enabled:
        raise AccessTemplateProbeFailure(
            "PROTOCOL_NOT_SUPPORTED",
            "Legacy Telnet is disabled by installation policy.",
        )
    username = secrets.get("username")
    password = secrets.get("password")
    if not username or not password:
        raise AccessTemplateProbeFailure(
            "TELNET_LOGIN_FAILED",
            "The Telnet Access Template does not contain complete login credentials.",
        )
    template_settings = dict(template.settings_json or {})
    port = int(template_settings.get("port", 23))
    timeout_seconds = int(template_settings.get("timeout_seconds", 10))
    await _tcp_preflight(management_ip, port, timeout_seconds)

    connection = None
    try:
        connection = await start_telnet(
            host=management_ip,
            port=port,
            username=username,
            password=password,
            timeout_seconds=timeout_seconds,
        )
        return ProbeOutcome(
            True,
            sanitized_message="Legacy Telnet login succeeded. Transport is plaintext and insecure.",
        )
    except TelnetTransportError as exc:
        code = str(exc)
        if code == "TELNET_LOGIN_FAILED":
            raise AccessTemplateProbeFailure(
                "TELNET_LOGIN_FAILED",
                "The device rejected the Telnet credentials.",
            ) from exc
        if code in {"TELNET_LOGIN_PROMPT_TIMEOUT", "TELNET_CONNECTION_CLOSED"}:
            raise AccessTemplateProbeFailure(
                "TIMEOUT",
                "The Telnet login sequence did not complete before the bounded timeout.",
            ) from exc
        raise AccessTemplateProbeFailure(
            "PROTOCOL_NOT_SUPPORTED",
            "The endpoint did not complete the supported Telnet login sequence.",
        ) from exc
    finally:
        if connection is not None:
            await connection.close()


def _tls_probe_failure(exc: APIError) -> AccessTemplateProbeFailure:
    detail = exc.detail if isinstance(exc.detail, dict) else {}
    code = str(detail.get("code") or "WEB_TLS_VERIFICATION_FAILED")
    messages = {
        "WEB_TLS_CERTIFICATE_MISMATCH": "The device HTTPS certificate does not match the configured trust.",
        "WEB_TLS_INTERNAL_TRUST_NOT_READY": "The internally trusted HTTPS certificate is stale, expired, or no longer matches the registered management endpoint.",
        "WEB_TLS_VERIFICATION_TIMEOUT": "The device HTTPS TLS verification timed out.",
        "WEB_TLS_ENDPOINT_UNREACHABLE": "The registered HTTPS management endpoint is unreachable.",
        "WEB_TLS_HANDSHAKE_FAILED": "The device HTTPS TLS handshake could not be completed.",
        "REMOTE_ACCESS_WEB_CA_REQUIRED": "The configured private-CA trust is unavailable.",
        "REMOTE_ACCESS_WEB_PIN_REQUIRED": "The configured pinned-certificate trust is unavailable.",
    }
    return AccessTemplateProbeFailure(
        code,
        messages.get(code, "The device Secure Web-GUI transport or TLS trust configuration is incomplete."),
    )


async def _prepare_web_transport(
    db: AsyncSession,
    *,
    device_id: UUID,
    management_ip: str,
    timeout_seconds: int,
    actor_user_id: UUID | None,
) -> VerifiedWebTransport:
    """Verify the WEB transport before any Access Template credential resolution."""

    profile = await db.scalar(
        select(DeviceRemoteAccessProfile).where(DeviceRemoteAccessProfile.device_id == device_id)
    )
    if profile is None or not await web_profile_is_ready_async(db, profile):
        raise AccessTemplateProbeFailure(
            "WEB_TLS_TRUST_NOT_READY",
            "Configure and verify the device Secure Web-GUI HTTP/HTTPS transport and TLS trust before testing WEB credentials.",
        )
    try:
        target_host = validate_management_target(management_ip)
        port = profile_web_port(profile)
        ssl_context = await resolve_verified_web_ssl_context(
            db,
            profile=profile,
            management_ip=target_host,
            port=port,
            actor_user_id=actor_user_id,
            timeout_seconds=timeout_seconds,
        )
    except APIError as exc:
        raise _tls_probe_failure(exc) from exc
    except ValueError as exc:
        raise AccessTemplateProbeFailure(
            "WEB_TRANSPORT_NOT_CONFIGURED",
            "The registered Secure Web-GUI management target is invalid.",
        ) from exc
    return VerifiedWebTransport(
        profile=profile,
        target_host=target_host,
        port=port,
        ssl_context=ssl_context,
    )


async def _probe_web(
    *,
    template: AccessTemplate,
    secrets: dict[str, str],
    transport: VerifiedWebTransport,
) -> ProbeOutcome:
    runtime = build_web_runtime_access(template, secrets)
    profile = transport.profile
    scheme = profile.web_scheme.lower()
    default = (scheme == "http" and transport.port == 80) or (
        scheme == "https" and transport.port == 443
    )
    host_text = f"[{transport.target_host}]" if ":" in transport.target_host else transport.target_host
    origin = f"{scheme}://{host_text}{'' if default else ':' + str(transport.port)}"
    timeout = httpx.Timeout(max(1, runtime.timeout_seconds), connect=max(1, runtime.timeout_seconds))
    try:
        async with httpx.AsyncClient(
            base_url=origin,
            verify=transport.ssl_context,
            auth=httpx_auth_for_web(runtime),
            follow_redirects=False,
            timeout=timeout,
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
        ) as client:
            if runtime.auth_mode == "NONE":
                response = await client.get("/", follow_redirects=False)
                if response.status_code in {401, 403}:
                    raise WebAuthenticationError("WEB_AUTHENTICATION_REQUIRED")
                if response.status_code >= 500:
                    raise WebAuthenticationError("WEB_AUTH_UPSTREAM_FAILURE")
                return ProbeOutcome(
                    True,
                    sanitized_message="The Secure Web-GUI endpoint is reachable; this template does not perform device authentication.",
                )
            await authenticate_web_client(client, runtime)
            return ProbeOutcome(
                True,
                sanitized_message="Secure Web-GUI TLS verification and server-side authentication succeeded; device credentials remained gateway-side.",
            )
    except WebAuthenticationError as exc:
        code = str(exc)
        messages = {
            "WEB_AUTHENTICATION_FAILED": "The device rejected the configured Web-GUI credentials.",
            "WEB_AUTHENTICATION_REQUIRED": "The device requires authentication but this WEB template is configured for NONE.",
            "WEB_AUTHENTICATION_UNCONFIRMED": "The login request completed, but FTTW could not positively confirm an authenticated device session.",
            "WEB_AUTH_EXTERNAL_REDIRECT_BLOCKED": "The device login attempted to redirect outside the registered management target and was blocked.",
            "WEB_AUTH_REDIRECT_LIMIT": "The device login exceeded the bounded redirect limit.",
            "WEB_AUTH_LOGIN_REQUEST_REJECTED": "The device rejected the Web-GUI login request.",
            "WEB_AUTH_UPSTREAM_FAILURE": "The device Web-GUI returned a server-side failure during authentication.",
            "WEB_AUTH_CONNECT_FAILED": "FTTW could not complete the Web-GUI authentication exchange.",
        }
        raise AccessTemplateProbeFailure(
            code if code in messages else "WEB_AUTHENTICATION_FAILED",
            messages.get(code, "The Secure Web-GUI authentication exchange failed."),
        ) from exc
    except (httpx.HTTPError, OSError) as exc:
        raise AccessTemplateProbeFailure(
            "WEB_CONNECT_FAILED",
            "FTTW could not reach the configured Secure Web-GUI endpoint after TLS verification.",
        ) from exc


async def _probe_snmp(
    *,
    template: AccessTemplate,
    management_ip: str,
    secrets: dict[str, str],
) -> ProbeOutcome:
    credential = build_snmp_runtime_credential(template, secrets)
    template_settings = dict(template.settings_json or {})
    context = DiscoveryContext(
        ip_address=management_ip,
        timeout_seconds=float(template_settings.get("timeout_seconds", 10)),
        snmp_port=int(template_settings.get("port", 161)),
        snmp_retries=int(template_settings.get("retries", 1)),
        snmp_version=credential.get("version", "2c"),
        snmp_community=credential.get("community"),
        snmp_v3_username=credential.get("username"),
        snmp_v3_security_level=credential.get("security_level", "noAuthNoPriv"),
        snmp_v3_context_name=credential.get("context_name"),
        snmp_v3_auth_protocol=credential.get("auth_protocol"),
        snmp_v3_auth_password=credential.get("auth_password"),
        snmp_v3_priv_protocol=credential.get("priv_protocol"),
        snmp_v3_priv_password=credential.get("priv_password"),
    )
    try:
        _sys_name, _elapsed_ms, _version = await asyncio.to_thread(_run_snmpget, context)
        return ProbeOutcome(True, sanitized_message="SNMP authentication and scalar query succeeded.")
    except TimeoutError as exc:
        raise AccessTemplateProbeFailure(
            "TIMEOUT",
            "The SNMP agent did not return a response before the bounded timeout.",
        ) from exc
    except PermissionError as exc:
        variant = (template.protocol_variant or "V2C").strip().upper()
        code = "AUTHENTICATION_FAILED" if variant == "V3" else "SNMP_COMMUNITY_REJECTED"
        message = (
            "SNMPv3 authentication was rejected by the device."
            if variant == "V3"
            else "The SNMP community was rejected by the device."
        )
        raise AccessTemplateProbeFailure(code, message) from exc
    except RuntimeError as exc:
        code = str(exc)
        if code == "SNMP_CLIENT_NOT_INSTALLED":
            raise AccessTemplateProbeFailure(
                "PROTOCOL_NOT_SUPPORTED",
                "The SNMP client utility is not installed in this service image.",
            ) from exc
        raise AccessTemplateProbeFailure(
            "SNMP_PROBE_FAILED",
            "The SNMP endpoint returned an unusable response.",
        ) from exc


async def test_access_template_connection(
    db: AsyncSession,
    *,
    template: AccessTemplate,
    device_id: UUID,
    tested_by_user_id: UUID | None,
) -> AccessTemplateTestResult:
    """Test one explicitly selected template against one device.

    WEB is special: the registered transport/TLS trust is verified with no
    application bytes before Access Template secrets are resolved. Other
    protocols preserve their established probe behavior.
    """

    management_ip = await get_management_ip(db, device_id)
    started = time.perf_counter()
    outcome: ProbeOutcome
    if not management_ip:
        outcome = ProbeOutcome(
            False,
            "NETWORK_UNREACHABLE",
            "The device has no active management IP address.",
        )
    elif not template.is_active:
        outcome = ProbeOutcome(
            False,
            "PROTOCOL_NOT_SUPPORTED",
            "Inactive Access Templates cannot be connection-tested.",
        )
    else:
        try:
            protocol = template.protocol.strip().upper()
            if protocol == "WEB":
                timeout_seconds = int(dict(template.settings_json or {}).get("timeout_seconds", 10))
                transport = await _prepare_web_transport(
                    db,
                    device_id=device_id,
                    management_ip=management_ip,
                    timeout_seconds=timeout_seconds,
                    actor_user_id=tested_by_user_id,
                )
                secrets = await resolved_secrets(db, template.id)
                outcome = await _probe_web(
                    template=template,
                    secrets=secrets,
                    transport=transport,
                )
            else:
                secrets = await resolved_secrets(db, template.id)
                if protocol == "SSH":
                    outcome = await _probe_ssh(
                        db,
                        template=template,
                        device_id=device_id,
                        management_ip=management_ip,
                        secrets=secrets,
                    )
                elif protocol == "TELNET":
                    outcome = await _probe_telnet(
                        template=template,
                        management_ip=management_ip,
                        secrets=secrets,
                    )
                elif protocol == "SNMP":
                    outcome = await _probe_snmp(
                        template=template,
                        management_ip=management_ip,
                        secrets=secrets,
                    )
                else:
                    outcome = ProbeOutcome(
                        False,
                        "PROTOCOL_NOT_SUPPORTED",
                        "This Access Template protocol is not supported by the tester.",
                    )
        except AccessTemplateProbeFailure as exc:
            outcome = ProbeOutcome(False, exc.code, exc.message)
        except AccessTemplateSecretError as exc:
            code = str(exc)
            safe_code = code if code in {
                "ACCESS_TEMPLATE_MASTER_KEY_NOT_AVAILABLE",
                "ACCESS_TEMPLATE_MASTER_KEY_INVALID",
                "ACCESS_TEMPLATE_SECRET_DECRYPT_FAILED",
                "ACCESS_TEMPLATE_ENV_SECRET_NOT_AVAILABLE",
                "AUTHENTICATION_FAILED",
                "SNMP_COMMUNITY_REJECTED",
                "SNMP_VERSION_MISMATCH",
                "PROTOCOL_NOT_SUPPORTED",
                "WEB_AUTH_MODE_UNSUPPORTED",
                "WEB_AUTHENTICATION_FAILED",
            } else "AUTHENTICATION_FAILED"
            outcome = ProbeOutcome(
                False,
                safe_code,
                "The Access Template credentials could not be resolved or validated.",
            )
        except (ValueError, TypeError):
            outcome = ProbeOutcome(
                False,
                "PROTOCOL_NOT_SUPPORTED",
                "The Access Template connection settings are invalid for this protocol.",
            )

    latency_ms = max(0, int(round((time.perf_counter() - started) * 1000)))
    row = AccessTemplateTestResult(
        template_id=template.id,
        device_id=device_id,
        status="SUCCESS" if outcome.success else "FAILED",
        failure_code=None if outcome.success else outcome.failure_code,
        sanitized_message=outcome.sanitized_message,
        latency_ms=latency_ms,
        tested_by_user_id=tested_by_user_id,
    )
    db.add(row)
    await db.flush()
    return row
