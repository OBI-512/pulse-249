from __future__ import annotations

import os
import re

_ENV_REF = re.compile(r"^env://([A-Za-z_][A-Za-z0-9_]*)$")


def resolve_secret_reference(reference: str | None) -> str | None:
    """Resolve an integration secret only from environment-backed references."""
    if not reference:
        return None
    match = _ENV_REF.fullmatch(reference.strip())
    if not match:
        raise ValueError("INTEGRATION_SECRET_REFERENCE_INVALID")
    value = os.getenv(match.group(1))
    if value is None:
        raise ValueError("INTEGRATION_SECRET_NOT_CONFIGURED")
    return value
