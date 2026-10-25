from __future__ import annotations

import os
import re


_ENV_REF = re.compile(r"^env://([A-Za-z_][A-Za-z0-9_]*)$")


class RemoteAccessSecretError(ValueError):
    pass


def resolve_secret_reference(reference: str | None) -> str:
    if not reference:
        raise RemoteAccessSecretError("REMOTE_ACCESS_CREDENTIAL_REFERENCE_MISSING")
    match = _ENV_REF.fullmatch(reference.strip())
    if match is None:
        raise RemoteAccessSecretError("REMOTE_ACCESS_CREDENTIAL_REFERENCE_INVALID")
    value = os.getenv(match.group(1))
    if value is None or value == "":
        raise RemoteAccessSecretError("REMOTE_ACCESS_CREDENTIAL_NOT_AVAILABLE")
    return value
