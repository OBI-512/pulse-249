from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import APIError
from ..models import AccessTemplateSecret


_PROTOCOL_SECRET_KEYS = {
    "SSH": {"username", "password", "private_key", "private_key_passphrase"},
    "TELNET": {"username", "password"},
    "WEB": {"username", "password"},
}
_SNMP_V1_V2_KEYS = {"community"}
_SNMP_V3_KEYS = {"security_name", "auth_secret", "privacy_secret"}
_SNMP_ALL_KEYS = _SNMP_V1_V2_KEYS | _SNMP_V3_KEYS


def relevant_secret_keys(
    protocol: str,
    protocol_variant: str | None,
    template_settings: dict[str, Any] | None = None,
) -> set[str]:
    """Return the secret-key namespace meaningful for one definition.

    Invalid protocols/variants are deliberately left to the canonical template
    validator so callers continue to receive its established API error codes.
    """

    normalized_protocol = str(protocol or "").strip().upper()
    if normalized_protocol == "SNMP":
        variant = str(protocol_variant or "V2C").strip().upper()
        if variant in {"V1", "V2C"}:
            return set(_SNMP_V1_V2_KEYS)
        if variant == "V3":
            return set(_SNMP_V3_KEYS)
        return set(_SNMP_ALL_KEYS)
    if normalized_protocol == "WEB":
        variant = str(protocol_variant or "FORM_POST").strip().upper()
        if variant == "NONE":
            return set()
        if variant == "FORM_POST":
            mode = str((template_settings or {}).get("credential_mode", "USERNAME_PASSWORD")).strip().upper()
            if mode == "PASSWORD_ONLY":
                return {"password"}
        return set(_PROTOCOL_SECRET_KEYS["WEB"])
    return set(_PROTOCOL_SECRET_KEYS.get(normalized_protocol, set()))


def calculate_secret_key_transition(
    *,
    protocol: str,
    protocol_variant: str | None,
    existing_keys: set[str],
    changes: dict[str, Any],
    template_settings: dict[str, Any] | None = None,
) -> tuple[set[str], set[str]]:
    """Calculate post-update keys and obsolete keys without touching values.

    Protocol/variant/credential-mode transitions never silently retain secret
    material that is no longer meaningful. WEB/NONE is credential-free and
    FORM_POST/PASSWORD_ONLY prunes any previously stored username row.
    """

    normalized_protocol = str(protocol or "").strip().upper()
    normalized_variant = str(
        protocol_variant or ("FORM_POST" if normalized_protocol == "WEB" else "")
    ).strip().upper()
    allowed = relevant_secret_keys(protocol, protocol_variant, template_settings)
    supplied = {key for key, value in changes.items() if value is not None}

    if normalized_protocol == "WEB" and normalized_variant == "NONE":
        if supplied:
            raise APIError(
                422,
                "ACCESS_TEMPLATE_SECRET_KEY_INVALID",
                "WEB authentication mode NONE does not accept device credentials.",
            )
        return set(), set(existing_keys)

    if not allowed:
        return set(existing_keys), set()

    invalid = supplied - allowed
    if invalid:
        raise APIError(
            422,
            "ACCESS_TEMPLATE_SECRET_KEY_INVALID",
            "Secret keys are not valid for the selected protocol variant or credential mode.",
        )

    removals = {key for key, value in changes.items() if value is None}
    stale = set(existing_keys) - allowed
    resulting = ((set(existing_keys) & allowed) - removals) | supplied
    return resulting, stale


async def prune_template_secret_keys(
    db: AsyncSession,
    *,
    template_id: UUID,
    secret_keys: set[str],
) -> None:
    """Delete obsolete encrypted/reference rows without ever resolving values."""

    if not secret_keys:
        return
    rows = list(
        (
            await db.scalars(
                select(AccessTemplateSecret).where(
                    AccessTemplateSecret.template_id == template_id,
                    AccessTemplateSecret.secret_key.in_(secret_keys),
                )
            )
        ).all()
    )
    for row in rows:
        await db.delete(row)
