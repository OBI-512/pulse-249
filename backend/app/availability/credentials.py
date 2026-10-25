from __future__ import annotations

import json
import os
import re


_ENV_REFERENCE = re.compile(r"^env://([A-Z][A-Z0-9_]{0,127})$")
_ALLOWED_KEYS = {
    "version",
    "community",
    "username",
    "security_level",
    "auth_protocol",
    "auth_password",
    "priv_protocol",
    "priv_password",
}


class AvailabilityCredentialError(ValueError):
    pass


def resolve_snmp_credential(reference: str | None) -> dict[str, str]:
    """Resolve an SNMP credential without persisting or queueing the secret.

    C1 intentionally supports only explicit environment references of the form
    ``env://NAME``. The referenced environment value is a JSON object. This
    keeps secrets out of PostgreSQL, Redis/Celery messages, audit metadata and
    operational logs while leaving secret injection to the deployment layer.
    """

    match = _ENV_REFERENCE.fullmatch((reference or "").strip())
    if match is None:
        raise AvailabilityCredentialError("SNMP_CREDENTIAL_REFERENCE_INVALID")
    variable = match.group(1)
    raw = os.getenv(variable)
    if raw is None:
        raise AvailabilityCredentialError("SNMP_CREDENTIAL_NOT_AVAILABLE")
    if len(raw) > 16_384:
        raise AvailabilityCredentialError("SNMP_CREDENTIAL_PAYLOAD_TOO_LARGE")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AvailabilityCredentialError("SNMP_CREDENTIAL_PAYLOAD_INVALID") from exc
    if not isinstance(value, dict) or not value:
        raise AvailabilityCredentialError("SNMP_CREDENTIAL_PAYLOAD_INVALID")
    if any(key not in _ALLOWED_KEYS for key in value):
        raise AvailabilityCredentialError("SNMP_CREDENTIAL_PAYLOAD_INVALID")
    normalized: dict[str, str] = {}
    for key, item in value.items():
        if item is None:
            continue
        if not isinstance(item, str) or len(item) > 2048:
            raise AvailabilityCredentialError("SNMP_CREDENTIAL_PAYLOAD_INVALID")
        normalized[key] = item
    return normalized
