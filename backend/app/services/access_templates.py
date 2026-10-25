from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import APIError
from ..models import (
    AccessTemplate,
    AccessTemplateAssignment,
    AccessTemplateSecret,
    Device,
)
from ..remote_gateway.secrets import RemoteAccessSecretError, resolve_secret_reference
from ..services.group_effective import effective_group_device_ids, effective_group_context_subquery
from ..settings import settings


_SCOPE_RANK = {
    "CITY": 1,
    "NETWORK": 2,
    "LOCATION": 3,
    "LOGICAL_SECTOR": 4,
    "DEVICE_GROUP": 5,
    "DEVICE": 6,
}

_ALLOWED_SECRET_KEYS = {
    "SSH": {"username", "password", "private_key", "private_key_passphrase"},
    "TELNET": {"username", "password"},
    "SNMP": {"community", "security_name", "auth_secret", "privacy_secret"},
    "WEB": {"username", "password"},
}
_SNMP_AUTH_PROTOCOLS = {"MD5", "SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"}
_SNMP_PRIVACY_PROTOCOLS = {"DES", "AES"}
_SNMP_SECURITY_LEVELS = {
    "noauthnopriv": "noAuthNoPriv",
    "authnopriv": "authNoPriv",
    "authpriv": "authPriv",
}
_WEB_AUTH_MODES = {"NONE", "HTTP_BASIC", "HTTP_DIGEST", "FORM_POST"}
_WEB_CREDENTIAL_MODES = {"USERNAME_PASSWORD", "PASSWORD_ONLY"}
_WEB_FIELD_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")


class AccessTemplateSecretError(ValueError):
    pass


@dataclass(frozen=True)
class EffectiveAccess:
    status: str
    template: AccessTemplate | None = None
    assignment: AccessTemplateAssignment | None = None


@dataclass(frozen=True)
class SNMPRuntimeAccess:
    """Resolved in-process SNMP runtime material.

    The credential mapping is deliberately excluded from repr so accidental
    diagnostic logging of this object cannot disclose secret material.
    """

    credential: dict[str, str] = field(repr=False)
    port: int = 161
    timeout_seconds: int = 10
    retries: int = 1


def _master_key() -> bytes:
    try:
        value = resolve_secret_reference(settings.access_template_key_reference)
    except RemoteAccessSecretError as exc:
        raise AccessTemplateSecretError("ACCESS_TEMPLATE_MASTER_KEY_NOT_AVAILABLE") from exc
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise AccessTemplateSecretError("ACCESS_TEMPLATE_MASTER_KEY_INVALID") from exc
    if len(raw) != 32:
        raise AccessTemplateSecretError("ACCESS_TEMPLATE_MASTER_KEY_INVALID")
    return raw


def encrypt_secret(*, template_id: UUID, secret_key: str, plaintext: str) -> str:
    nonce = os.urandom(12)
    aad = f"fttw-access-template:v1:{template_id}:{secret_key}".encode("utf-8")
    ciphertext = AESGCM(_master_key()).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return "v1:" + base64.b64encode(nonce).decode("ascii") + ":" + base64.b64encode(ciphertext).decode("ascii")


def decrypt_secret(*, template_id: UUID, secret_key: str, payload: str) -> str:
    try:
        version, nonce_b64, ciphertext_b64 = payload.split(":", 2)
        if version != "v1":
            raise ValueError
        nonce = base64.b64decode(nonce_b64, validate=True)
        ciphertext = base64.b64decode(ciphertext_b64, validate=True)
        aad = f"fttw-access-template:v1:{template_id}:{secret_key}".encode("utf-8")
        plaintext = AESGCM(_master_key()).decrypt(nonce, ciphertext, aad)
        return plaintext.decode("utf-8")
    except AccessTemplateSecretError:
        raise
    except Exception as exc:
        raise AccessTemplateSecretError("ACCESS_TEMPLATE_SECRET_DECRYPT_FAILED") from exc


def _normalize_snmp_security_level(value: Any) -> str:
    normalized = str(value or "noAuthNoPriv").strip().lower()
    result = _SNMP_SECURITY_LEVELS.get(normalized)
    if result is None:
        raise APIError(
            422,
            "ACCESS_TEMPLATE_SNMP_SECURITY_LEVEL_INVALID",
            "SNMPv3 security_level must be noAuthNoPriv, authNoPriv, or authPriv.",
        )
    return result


def _contains_secret_setting_key(
    value: Any,
    *,
    allowed_keys: frozenset[str] = frozenset(),
) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).lower()
            if lowered not in allowed_keys and any(
                marker in lowered
                for marker in ("password", "secret", "community", "private_key")
            ):
                return True
            if _contains_secret_setting_key(child):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_secret_setting_key(child) for child in value)
    return False


def _web_path(value: Any, *, field_name: str, default: str | None = None) -> str | None:
    raw = str(value if value is not None else default or "").strip()
    if not raw:
        return None
    if len(raw) > 512 or not raw.startswith("/") or raw.startswith("//"):
        raise APIError(
            422,
            "ACCESS_TEMPLATE_WEB_PATH_INVALID",
            f"{field_name} must be a target-relative path beginning with /.",
        )
    parsed = urlsplit(raw)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise APIError(
            422,
            "ACCESS_TEMPLATE_WEB_PATH_INVALID",
            f"{field_name} must not contain a scheme, host, or fragment.",
        )
    return raw


def validate_template_definition(
    *,
    protocol: str,
    protocol_variant: str | None,
    template_settings: dict[str, Any],
    secret_keys: set[str],
    is_active: bool,
) -> tuple[str, str | None, dict[str, Any]]:
    normalized_protocol = protocol.strip().upper()
    if normalized_protocol not in {"SNMP", "SSH", "TELNET", "WEB"}:
        raise APIError(422, "ACCESS_TEMPLATE_PROTOCOL_INVALID", "Protocol must be SNMP, SSH, TELNET, or WEB.")

    variant = protocol_variant.strip().upper() if protocol_variant and protocol_variant.strip() else None
    cleaned = dict(template_settings or {})
    allowed_setting_keys = frozenset({"password_field"}) if normalized_protocol == "WEB" else frozenset()
    if _contains_secret_setting_key(cleaned, allowed_keys=allowed_setting_keys):
        raise APIError(
            422,
            "ACCESS_TEMPLATE_SECRET_IN_SETTINGS",
            "Secret values must be supplied through template secrets, not settings.",
        )

    unknown = secret_keys - _ALLOWED_SECRET_KEYS[normalized_protocol]
    if unknown:
        raise APIError(
            422,
            "ACCESS_TEMPLATE_SECRET_KEY_INVALID",
            f"Unsupported secret key for {normalized_protocol}.",
        )

    if normalized_protocol != "WEB":
        default_ports = {"SSH": 22, "TELNET": 23, "SNMP": 161}
        port = int(cleaned.get("port", default_ports[normalized_protocol]))
        if port < 1 or port > 65535:
            raise APIError(422, "ACCESS_TEMPLATE_PORT_INVALID", "Port must be between 1 and 65535.")
        cleaned["port"] = port
    else:
        cleaned.pop("port", None)

    timeout = int(cleaned.get("timeout_seconds", 10))
    if timeout < 1 or timeout > 300:
        raise APIError(
            422,
            "ACCESS_TEMPLATE_TIMEOUT_INVALID",
            "timeout_seconds must be between 1 and 300.",
        )
    cleaned["timeout_seconds"] = timeout

    if normalized_protocol == "SNMP":
        variant = variant or "V2C"
        if variant not in {"V1", "V2C", "V3"}:
            raise APIError(
                422,
                "ACCESS_TEMPLATE_SNMP_VARIANT_INVALID",
                "SNMP variant must be V1, V2C, or V3.",
            )
        retries = int(cleaned.get("retries", 1))
        if retries < 0 or retries > 10:
            raise APIError(
                422,
                "ACCESS_TEMPLATE_RETRIES_INVALID",
                "SNMP retries must be between 0 and 10.",
            )
        cleaned["retries"] = retries
        access_mode = str(cleaned.get("access_mode", "RO")).strip().upper()
        if access_mode not in {"RO", "RW"}:
            raise APIError(
                422,
                "ACCESS_TEMPLATE_SNMP_ACCESS_MODE_INVALID",
                "SNMP access_mode must be RO or RW.",
            )
        cleaned["access_mode"] = access_mode

        if variant in {"V1", "V2C"}:
            if is_active and "community" not in secret_keys:
                raise APIError(
                    422,
                    "ACCESS_TEMPLATE_INCOMPLETE",
                    "Active SNMP v1/v2c templates require a community secret.",
                )
        else:
            level = _normalize_snmp_security_level(cleaned.get("security_level"))
            cleaned["security_level"] = level
            context_name = str(cleaned.get("context_name", "")).strip()
            if len(context_name) > 255:
                raise APIError(
                    422,
                    "ACCESS_TEMPLATE_SNMP_CONTEXT_INVALID",
                    "SNMPv3 context_name must not exceed 255 characters.",
                )
            if context_name:
                cleaned["context_name"] = context_name
            else:
                cleaned.pop("context_name", None)

            auth_protocol = str(cleaned.get("auth_protocol", "SHA")).strip().upper()
            if level in {"authNoPriv", "authPriv"}:
                if auth_protocol not in _SNMP_AUTH_PROTOCOLS:
                    raise APIError(
                        422,
                        "ACCESS_TEMPLATE_SNMP_AUTH_PROTOCOL_INVALID",
                        "Unsupported SNMPv3 authentication protocol.",
                    )
                cleaned["auth_protocol"] = auth_protocol
            else:
                cleaned.pop("auth_protocol", None)

            privacy_protocol = str(cleaned.get("privacy_protocol", "AES")).strip().upper()
            if level == "authPriv":
                if privacy_protocol not in _SNMP_PRIVACY_PROTOCOLS:
                    raise APIError(
                        422,
                        "ACCESS_TEMPLATE_SNMP_PRIVACY_PROTOCOL_INVALID",
                        "Unsupported SNMPv3 privacy protocol.",
                    )
                cleaned["privacy_protocol"] = privacy_protocol
            else:
                cleaned.pop("privacy_protocol", None)

            if is_active and "security_name" not in secret_keys:
                raise APIError(
                    422,
                    "ACCESS_TEMPLATE_INCOMPLETE",
                    "Active SNMP v3 templates require a security_name secret.",
                )
            if is_active and level in {"authNoPriv", "authPriv"} and "auth_secret" not in secret_keys:
                raise APIError(
                    422,
                    "ACCESS_TEMPLATE_INCOMPLETE",
                    "Authenticated SNMPv3 templates require an auth_secret.",
                )
            if is_active and level == "authPriv" and "privacy_secret" not in secret_keys:
                raise APIError(
                    422,
                    "ACCESS_TEMPLATE_INCOMPLETE",
                    "SNMPv3 authPriv templates require a privacy_secret.",
                )
    elif normalized_protocol == "SSH":
        variant = variant or "PASSWORD_OR_KEY"
        if is_active and "username" not in secret_keys:
            raise APIError(
                422,
                "ACCESS_TEMPLATE_INCOMPLETE",
                "Active SSH templates require a username secret.",
            )
        if is_active and not ({"password", "private_key"} & secret_keys):
            raise APIError(
                422,
                "ACCESS_TEMPLATE_INCOMPLETE",
                "Active SSH templates require password or private_key credentials.",
            )
    elif normalized_protocol == "TELNET":
        variant = variant or "PASSWORD"
        if is_active and not {"username", "password"}.issubset(secret_keys):
            raise APIError(
                422,
                "ACCESS_TEMPLATE_INCOMPLETE",
                "Active Telnet templates require username and password secrets.",
            )
    else:
        variant = variant or "FORM_POST"
        if variant not in _WEB_AUTH_MODES:
            raise APIError(
                422,
                "ACCESS_TEMPLATE_WEB_AUTH_MODE_INVALID",
                "WEB authentication mode must be NONE, HTTP_BASIC, HTTP_DIGEST, or FORM_POST.",
            )

        if variant == "FORM_POST":
            credential_mode = str(cleaned.get("credential_mode", "USERNAME_PASSWORD")).strip().upper()
            if credential_mode not in _WEB_CREDENTIAL_MODES:
                raise APIError(
                    422,
                    "ACCESS_TEMPLATE_WEB_CREDENTIAL_MODE_INVALID",
                    "WEB form credential mode must be USERNAME_PASSWORD or PASSWORD_ONLY.",
                )
            cleaned["credential_mode"] = credential_mode
            required = {"password"} if credential_mode == "PASSWORD_ONLY" else {"username", "password"}
            if is_active and not required.issubset(secret_keys):
                raise APIError(
                    422,
                    "ACCESS_TEMPLATE_INCOMPLETE",
                    "Active WEB form templates require a password and, when configured, a username secret.",
                )

            login_page_path = _web_path(cleaned.get("login_page_path"), field_name="login_page_path", default="/")
            submit_path = _web_path(
                cleaned.get("login_submit_path"),
                field_name="login_submit_path",
                default=login_page_path or "/",
            )
            cleaned["login_page_path"] = login_page_path or "/"
            cleaned["login_submit_path"] = submit_path or cleaned["login_page_path"]
            password_field = str(cleaned.get("password_field", "password")).strip()
            if not _WEB_FIELD_NAME_RE.fullmatch(password_field):
                raise APIError(
                    422,
                    "ACCESS_TEMPLATE_WEB_FIELD_INVALID",
                    "WEB form field names contain unsupported characters.",
                )
            cleaned["password_field"] = password_field
            if credential_mode == "USERNAME_PASSWORD":
                username_field = str(cleaned.get("username_field", "username")).strip()
                if not _WEB_FIELD_NAME_RE.fullmatch(username_field):
                    raise APIError(
                        422,
                        "ACCESS_TEMPLATE_WEB_FIELD_INVALID",
                        "WEB form field names contain unsupported characters.",
                    )
                cleaned["username_field"] = username_field
            else:
                cleaned.pop("username_field", None)

            success_path = _web_path(
                cleaned.get("success_path_prefix"),
                field_name="success_path_prefix",
                default=None,
            )
            if success_path:
                cleaned["success_path_prefix"] = success_path
            else:
                cleaned.pop("success_path_prefix", None)
            for marker_key in ("success_text", "failure_text"):
                marker = str(cleaned.get(marker_key, "")).strip()
                if len(marker) > 200:
                    raise APIError(
                        422,
                        "ACCESS_TEMPLATE_WEB_MARKER_INVALID",
                        f"{marker_key} must not exceed 200 characters.",
                    )
                if marker:
                    cleaned[marker_key] = marker
                else:
                    cleaned.pop(marker_key, None)
            cleaned["capture_hidden_fields"] = bool(cleaned.get("capture_hidden_fields", True))
        elif variant in {"HTTP_BASIC", "HTTP_DIGEST"}:
            if is_active and not {"username", "password"}.issubset(secret_keys):
                raise APIError(
                    422,
                    "ACCESS_TEMPLATE_INCOMPLETE",
                    "HTTP Basic and Digest WEB templates require username and password secrets.",
                )
            cleaned["credential_mode"] = "USERNAME_PASSWORD"
            for key in (
                "login_page_path",
                "login_submit_path",
                "username_field",
                "password_field",
                "success_path_prefix",
                "success_text",
                "failure_text",
                "capture_hidden_fields",
            ):
                cleaned.pop(key, None)
        else:
            cleaned.pop("credential_mode", None)
            for key in (
                "login_page_path",
                "login_submit_path",
                "username_field",
                "password_field",
                "success_path_prefix",
                "success_text",
                "failure_text",
                "capture_hidden_fields",
            ):
                cleaned.pop(key, None)

    return normalized_protocol, variant, cleaned


async def secret_provider_map(db: AsyncSession, template_id: UUID) -> dict[str, str]:
    rows = (
        await db.execute(
            select(AccessTemplateSecret.secret_key, AccessTemplateSecret.provider).where(
                AccessTemplateSecret.template_id == template_id
            )
        )
    ).all()
    return {key: provider for key, provider in rows}


async def resolved_secrets(db: AsyncSession, template_id: UUID) -> dict[str, str]:
    rows = list(
        (
            await db.scalars(
                select(AccessTemplateSecret).where(
                    AccessTemplateSecret.template_id == template_id
                )
            )
        ).all()
    )
    values: dict[str, str] = {}
    for row in rows:
        if row.provider == "ENV_REFERENCE":
            try:
                values[row.secret_key] = resolve_secret_reference(row.reference)
            except RemoteAccessSecretError as exc:
                raise AccessTemplateSecretError(
                    "ACCESS_TEMPLATE_ENV_SECRET_NOT_AVAILABLE"
                ) from exc
        else:
            values[row.secret_key] = decrypt_secret(
                template_id=template_id,
                secret_key=row.secret_key,
                payload=row.encrypted_payload or "",
            )
    return values


async def apply_secret_inputs(
    db: AsyncSession,
    template: AccessTemplate,
    secret_inputs: dict[str, Any],
) -> None:
    existing = {
        row.secret_key: row
        for row in (
            await db.scalars(
                select(AccessTemplateSecret).where(
                    AccessTemplateSecret.template_id == template.id
                )
            )
        ).all()
    }
    for secret_key, item in secret_inputs.items():
        if item is None:
            row = existing.get(secret_key)
            if row is not None:
                await db.delete(row)
            continue
        row = existing.get(secret_key)
        if row is None:
            row = AccessTemplateSecret(
                template_id=template.id,
                secret_key=secret_key,
                provider=item.provider,
            )
            db.add(row)
        row.provider = item.provider
        row.key_version = 1
        if item.provider == "ENV_REFERENCE":
            row.reference = item.reference
            row.encrypted_payload = None
        else:
            row.reference = None
            row.encrypted_payload = encrypt_secret(
                template_id=template.id,
                secret_key=secret_key,
                plaintext=item.value,
            )


async def resolve_effective_access(
    db: AsyncSession,
    *,
    device_id: UUID,
    protocol: str,
) -> EffectiveAccess:
    normalized_protocol = protocol.strip().upper()
    device = await db.scalar(
        select(Device).where(Device.id == device_id, Device.deleted_at.is_(None))
    )
    if device is None:
        raise APIError(404, "DEVICE_NOT_FOUND", "Device not found.")

    rows = (
        await db.execute(
            select(AccessTemplateAssignment, AccessTemplate)
            .join(
                AccessTemplate,
                AccessTemplate.id == AccessTemplateAssignment.template_id,
            )
            .where(
                AccessTemplate.protocol == normalized_protocol,
                AccessTemplate.is_active.is_(True),
                AccessTemplate.deleted_at.is_(None),
                AccessTemplateAssignment.enabled.is_(True),
            )
        )
    ).all()
    if not rows:
        return EffectiveAccess(status="NONE")

    context = effective_group_context_subquery()
    geo = (
        await db.execute(
            select(
                context.c.network_id,
                context.c.city_id,
                context.c.location_id,
                context.c.sector_id,
            )
            .where(context.c.device_id == device_id)
            .limit(1)
        )
    ).first()
    network_id = geo.network_id if geo else None
    city_id = geo.city_id if geo else None
    location_id = geo.location_id if geo else None
    sector_id = geo.sector_id if geo else None

    group_cache: dict[UUID, bool] = {}
    matches: list[tuple[AccessTemplateAssignment, AccessTemplate]] = []
    for assignment, template in rows:
        matched = False
        if assignment.scope_type == "DEVICE":
            matched = assignment.device_id == device_id
        elif assignment.scope_type == "NETWORK":
            matched = assignment.network_id == network_id
        elif assignment.scope_type == "CITY":
            matched = assignment.city_id == city_id
        elif assignment.scope_type == "LOCATION":
            matched = assignment.location_id == location_id
        elif assignment.scope_type == "LOGICAL_SECTOR":
            matched = assignment.sector_id == sector_id
        elif assignment.scope_type == "DEVICE_GROUP" and assignment.group_id is not None:
            if assignment.group_id not in group_cache:
                group_cache[assignment.group_id] = device_id in await effective_group_device_ids(
                    db, assignment.group_id
                )
            matched = group_cache[assignment.group_id]
        if matched:
            matches.append((assignment, template))

    if not matches:
        return EffectiveAccess(status="NONE")

    matches.sort(
        key=lambda item: (_SCOPE_RANK[item[0].scope_type], item[0].priority),
        reverse=True,
    )
    top_assignment, top_template = matches[0]
    top_key = (_SCOPE_RANK[top_assignment.scope_type], top_assignment.priority)
    conflicts = [
        (assignment, template)
        for assignment, template in matches
        if (_SCOPE_RANK[assignment.scope_type], assignment.priority) == top_key
    ]
    if len({template.id for _assignment, template in conflicts}) > 1:
        return EffectiveAccess(status="CONFLICT")
    return EffectiveAccess(
        status="RESOLVED",
        template=top_template,
        assignment=top_assignment,
    )


def build_snmp_runtime_credential(
    template: AccessTemplate,
    secrets: dict[str, str],
) -> dict[str, str]:
    """Translate one resolved Access Template to the existing SNMP collector contract."""

    if template.protocol != "SNMP":
        raise AccessTemplateSecretError("PROTOCOL_NOT_SUPPORTED")
    variant = (template.protocol_variant or "V2C").strip().upper()
    template_settings = dict(template.settings_json or {})

    if variant in {"V1", "V2C"}:
        community = secrets.get("community")
        if not community:
            raise AccessTemplateSecretError("SNMP_COMMUNITY_REJECTED")
        return {
            "version": "1" if variant == "V1" else "2c",
            "community": community,
        }

    if variant != "V3":
        raise AccessTemplateSecretError("SNMP_VERSION_MISMATCH")

    security_name = secrets.get("security_name")
    if not security_name:
        raise AccessTemplateSecretError("AUTHENTICATION_FAILED")
    try:
        level = _normalize_snmp_security_level(template_settings.get("security_level"))
    except APIError as exc:
        raise AccessTemplateSecretError("SNMP_VERSION_MISMATCH") from exc

    credential = {
        "version": "3",
        "username": security_name,
        "security_level": level,
    }
    context_name = str(template_settings.get("context_name", "")).strip()
    if context_name:
        credential["context_name"] = context_name
    if level in {"authNoPriv", "authPriv"}:
        auth_secret = secrets.get("auth_secret")
        if not auth_secret:
            raise AccessTemplateSecretError("AUTHENTICATION_FAILED")
        credential["auth_protocol"] = str(
            template_settings.get("auth_protocol", "SHA")
        ).strip().upper()
        credential["auth_password"] = auth_secret
    if level == "authPriv":
        privacy_secret = secrets.get("privacy_secret")
        if not privacy_secret:
            raise AccessTemplateSecretError("AUTHENTICATION_FAILED")
        credential["priv_protocol"] = str(
            template_settings.get("privacy_protocol", "AES")
        ).strip().upper()
        credential["priv_password"] = privacy_secret
    return credential


async def resolve_snmp_runtime_access(
    db: AsyncSession,
    *,
    device_id: UUID,
) -> SNMPRuntimeAccess | None:
    """Resolve SNMP Access Template material inside the consuming worker process.

    NONE deliberately returns ``None`` so pre-0038 ``Device.credential_reference``
    deployments remain compatible. No resolved secret is written to PostgreSQL,
    Redis, Celery payloads, audit metadata, or operational logs.
    """

    effective = await resolve_effective_access(
        db,
        device_id=device_id,
        protocol="SNMP",
    )
    if effective.status == "NONE":
        return None
    if effective.status == "CONFLICT":
        raise AccessTemplateSecretError("CONFIGURATION_CONFLICT")
    if effective.template is None:
        raise AccessTemplateSecretError("ACCESS_TEMPLATE_RESOLUTION_FAILED")

    template = effective.template
    secrets = await resolved_secrets(db, template.id)
    credential = build_snmp_runtime_credential(template, secrets)
    template_settings = dict(template.settings_json or {})
    return SNMPRuntimeAccess(
        credential=credential,
        port=int(template_settings.get("port", 161)),
        timeout_seconds=int(template_settings.get("timeout_seconds", 10)),
        retries=int(template_settings.get("retries", 1)),
    )


def assignment_scope_id(row: AccessTemplateAssignment) -> UUID:
    mapping = {
        "DEVICE": row.device_id,
        "DEVICE_GROUP": row.group_id,
        "LOGICAL_SECTOR": row.sector_id,
        "LOCATION": row.location_id,
        "NETWORK": row.network_id,
        "CITY": row.city_id,
    }
    value = mapping[row.scope_type]
    if value is None:
        raise ValueError("ACCESS_TEMPLATE_ASSIGNMENT_INVALID")
    return value
