from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import APIError
from ..models import AccessTemplate
from .access_templates import (
    AccessTemplateSecretError,
    resolve_effective_access,
    resolved_secrets,
    secret_provider_map,
)


@dataclass(frozen=True)
class SSHRuntimeAccess:
    username: str = field(repr=False)
    password: str | None = field(default=None, repr=False)
    private_key: str | None = field(default=None, repr=False)
    private_key_passphrase: str | None = field(default=None, repr=False)
    port: int = 22
    timeout_seconds: int = 10
    compatibility_profile: str = "MODERN"


@dataclass(frozen=True)
class TelnetRuntimeAccess:
    username: str = field(repr=False)
    password: str = field(repr=False)
    port: int = 23
    timeout_seconds: int = 10


@dataclass(frozen=True)
class WebRuntimeAccess:
    auth_mode: str
    credential_mode: str = "USERNAME_PASSWORD"
    username: str | None = field(default=None, repr=False)
    password: str | None = field(default=None, repr=False)
    timeout_seconds: int = 10
    login_page_path: str = "/"
    login_submit_path: str = "/"
    username_field: str = "username"
    password_field: str = "password"
    success_path_prefix: str | None = None
    success_text: str | None = None
    failure_text: str | None = None
    capture_hidden_fields: bool = True


def build_web_runtime_access(template: AccessTemplate, secrets: dict[str, str]) -> WebRuntimeAccess:
    settings = dict(template.settings_json or {})
    auth_mode = (template.protocol_variant or "FORM_POST").strip().upper()
    if auth_mode not in {"NONE", "HTTP_BASIC", "HTTP_DIGEST", "FORM_POST"}:
        raise AccessTemplateSecretError("WEB_AUTH_MODE_UNSUPPORTED")

    credential_mode = str(settings.get("credential_mode", "USERNAME_PASSWORD")).strip().upper()
    if auth_mode != "FORM_POST":
        credential_mode = "USERNAME_PASSWORD"
    if credential_mode not in {"USERNAME_PASSWORD", "PASSWORD_ONLY"}:
        raise AccessTemplateSecretError("WEB_CREDENTIAL_MODE_UNSUPPORTED")

    username = secrets.get("username")
    password = secrets.get("password")
    if auth_mode in {"HTTP_BASIC", "HTTP_DIGEST"} and (not username or not password):
        raise AccessTemplateSecretError("WEB_AUTHENTICATION_FAILED")
    if auth_mode == "FORM_POST":
        if not password:
            raise AccessTemplateSecretError("WEB_AUTHENTICATION_FAILED")
        if credential_mode == "USERNAME_PASSWORD" and not username:
            raise AccessTemplateSecretError("WEB_AUTHENTICATION_FAILED")

    return WebRuntimeAccess(
        auth_mode=auth_mode,
        credential_mode=credential_mode,
        username=username,
        password=password,
        timeout_seconds=int(settings.get("timeout_seconds", 10)),
        login_page_path=str(settings.get("login_page_path", "/")),
        login_submit_path=str(settings.get("login_submit_path", settings.get("login_page_path", "/"))),
        username_field=str(settings.get("username_field", "username")),
        password_field=str(settings.get("password_field", "password")),
        success_path_prefix=(str(settings["success_path_prefix"]) if settings.get("success_path_prefix") else None),
        success_text=(str(settings["success_text"]) if settings.get("success_text") else None),
        failure_text=(str(settings["failure_text"]) if settings.get("failure_text") else None),
        capture_hidden_fields=bool(settings.get("capture_hidden_fields", True)),
    )


async def access_template_ready(
    db: AsyncSession,
    *,
    device_id: UUID,
    protocol: str,
) -> bool | None:
    """Check effective-template readiness without resolving secret values.

    ``None`` means there is no effective template and callers may use their
    pre-0038 compatibility path. Conflicts fail closed.
    """

    normalized = protocol.strip().upper()
    effective = await resolve_effective_access(db, device_id=device_id, protocol=normalized)
    if effective.status == "NONE":
        return None
    if effective.status == "CONFLICT":
        raise APIError(
            409,
            "CONFIGURATION_CONFLICT",
            f"Multiple equally-preferred {normalized} Access Templates match this device.",
        )
    if effective.template is None:
        raise APIError(409, "ACCESS_TEMPLATE_RESOLUTION_FAILED", "Access Template resolution failed.")

    keys = set(await secret_provider_map(db, effective.template.id))
    if normalized == "SSH":
        return "username" in keys and bool({"password", "private_key"} & keys)
    if normalized == "TELNET":
        return {"username", "password"}.issubset(keys)
    if normalized == "SNMP":
        variant = (effective.template.protocol_variant or "V2C").upper()
        if variant in {"V1", "V2C"}:
            return "community" in keys
        return "security_name" in keys
    if normalized == "WEB":
        auth_mode = (effective.template.protocol_variant or "FORM_POST").upper()
        if auth_mode == "NONE":
            return True
        if auth_mode == "FORM_POST":
            credential_mode = str((effective.template.settings_json or {}).get("credential_mode", "USERNAME_PASSWORD")).strip().upper()
            if credential_mode == "PASSWORD_ONLY":
                return "password" in keys
        return {"username", "password"}.issubset(keys)
    raise APIError(422, "PROTOCOL_NOT_SUPPORTED", "Unsupported Access Template protocol.")


async def resolve_ssh_runtime_access(
    db: AsyncSession,
    *,
    device_id: UUID,
) -> SSHRuntimeAccess | None:
    effective = await resolve_effective_access(db, device_id=device_id, protocol="SSH")
    if effective.status == "NONE":
        return None
    if effective.status == "CONFLICT":
        raise AccessTemplateSecretError("CONFIGURATION_CONFLICT")
    if effective.template is None:
        raise AccessTemplateSecretError("ACCESS_TEMPLATE_RESOLUTION_FAILED")

    template = effective.template
    secrets = await resolved_secrets(db, template.id)
    username = secrets.get("username")
    password = secrets.get("password")
    private_key = secrets.get("private_key")
    if not username or not (password or private_key):
        raise AccessTemplateSecretError("AUTHENTICATION_FAILED")
    settings = dict(template.settings_json or {})
    compatibility = str(settings.get("compatibility_profile", "MODERN")).strip().upper()
    if compatibility not in {"MODERN", "LEGACY_SSH_RSA_DH1_CBC"}:
        raise AccessTemplateSecretError("SSH_COMPATIBILITY_PROFILE_UNSUPPORTED")
    return SSHRuntimeAccess(
        username=username,
        password=password,
        private_key=private_key,
        private_key_passphrase=secrets.get("private_key_passphrase"),
        port=int(settings.get("port", 22)),
        timeout_seconds=int(settings.get("timeout_seconds", 10)),
        compatibility_profile=compatibility,
    )


async def resolve_telnet_runtime_access(
    db: AsyncSession,
    *,
    device_id: UUID,
) -> TelnetRuntimeAccess | None:
    effective = await resolve_effective_access(db, device_id=device_id, protocol="TELNET")
    if effective.status == "NONE":
        return None
    if effective.status == "CONFLICT":
        raise AccessTemplateSecretError("CONFIGURATION_CONFLICT")
    if effective.template is None:
        raise AccessTemplateSecretError("ACCESS_TEMPLATE_RESOLUTION_FAILED")

    template = effective.template
    secrets = await resolved_secrets(db, template.id)
    username = secrets.get("username")
    password = secrets.get("password")
    if not username or not password:
        raise AccessTemplateSecretError("TELNET_LOGIN_FAILED")
    settings = dict(template.settings_json or {})
    return TelnetRuntimeAccess(
        username=username,
        password=password,
        port=int(settings.get("port", 23)),
        timeout_seconds=int(settings.get("timeout_seconds", 10)),
    )


async def resolve_web_runtime_access(
    db: AsyncSession,
    *,
    device_id: UUID,
) -> WebRuntimeAccess | None:
    effective = await resolve_effective_access(db, device_id=device_id, protocol="WEB")
    if effective.status == "NONE":
        return None
    if effective.status == "CONFLICT":
        raise AccessTemplateSecretError("CONFIGURATION_CONFLICT")
    if effective.template is None:
        raise AccessTemplateSecretError("ACCESS_TEMPLATE_RESOLUTION_FAILED")

    template = effective.template
    auth_mode = (template.protocol_variant or "FORM_POST").strip().upper()
    secrets = {} if auth_mode == "NONE" else await resolved_secrets(db, template.id)
    return build_web_runtime_access(template, secrets)
