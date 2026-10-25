"""Reusable, recursive secret redaction for audit evidence and exports."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from enum import Enum
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import UUID


REDACTED = "[REDACTED]"
_MAX_DEPTH = 24

_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "token",
    "credential",
    "privatekey",
    "secret",
    "secretkey",
    "clientsecret",
    "apikey",
    "accesskey",
    "sessionhash",
    "passwordhash",
    "authorization",
    "connectionstring",
    "connectionuri",
    "databaseurl",
    "redisurl",
    "dsn",
    "cookie",
)
_SECRET_CONTAINER_VALUE_KEYS = {
    "value",
    "oldvalue",
    "newvalue",
    "before",
    "after",
    "previousvalue",
}
_SENSITIVE_QUERY_KEYS = {
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "secret",
    "client_secret",
}
_SECRET_REFERENCE_SCHEMES = {
    "vault",
    "secret",
    "secretsmanager",
    "aws-secretsmanager",
    "azure-keyvault",
    "keyvault",
    "gcp-secret",
}
_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
    re.IGNORECASE,
)
_BEARER_PATTERN = re.compile(r"^\s*Bearer\s+\S+", re.IGNORECASE)
_JWT_PATTERN = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_PASSWORD_HASH_PATTERN = re.compile(
    r"^(?:\$2[aby]\$|\$argon2(?:id|i|d)\$|scrypt:|pbkdf2:|pbkdf2_sha256\$)",
    re.IGNORECASE,
)
_CONNECTION_SECRET_PATTERN = re.compile(
    r"(?:^|[;\s])(?:password|passwd|pwd|token|secret)\s*=\s*[^;\s]+",
    re.IGNORECASE,
)


def _normalized_key(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def _sensitive_key(key: Any) -> bool:
    normalized = _normalized_key(key)
    if normalized in {"hash", "privatekey", "secret", "authorization"}:
        return True
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _redact_uri(value: str) -> str:
    """Remove URI user-info and secret query parameters without logging them."""

    if "://" not in value:
        return value
    try:
        parsed = urlsplit(value)
    except ValueError:
        return REDACTED
    if not parsed.scheme or not parsed.netloc:
        return value
    if parsed.scheme.lower() in _SECRET_REFERENCE_SCHEMES:
        return REDACTED

    try:
        hostname = parsed.hostname or ""
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        parsed_port = parsed.port
    except ValueError:
        return REDACTED
    port = f":{parsed_port}" if parsed_port is not None else ""
    netloc = f"{hostname}{port}"
    if parsed.username is not None or parsed.password is not None:
        netloc = f"{REDACTED}@{netloc}"

    query = urlencode(
        [
            (key, REDACTED if key.lower() in _SENSITIVE_QUERY_KEYS else item)
            for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        ],
        doseq=True,
    )
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, parsed.fragment))


def _safe_string(value: str) -> str:
    if (
        _PRIVATE_KEY_PATTERN.search(value)
        or _BEARER_PATTERN.match(value)
        or _JWT_PATTERN.match(value)
        or _PASSWORD_HASH_PATTERN.match(value)
        or _CONNECTION_SECRET_PATTERN.search(value)
    ):
        return REDACTED
    return _redact_uri(value)


def redact_audit_value(
    value: Any,
    *,
    _depth: int = 0,
    _seen: set[int] | None = None,
) -> Any:
    """Return a JSON-safe copy with secrets removed at every nesting level."""

    if _depth > _MAX_DEPTH:
        return "[MAX_DEPTH]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _safe_string(value)
    if isinstance(value, (UUID, datetime, date)):
        return value.isoformat() if hasattr(value, "isoformat") else str(value)
    if isinstance(value, Enum):
        return redact_audit_value(value.value, _depth=_depth + 1, _seen=_seen)
    if is_dataclass(value):
        value = asdict(value)
    elif hasattr(value, "model_dump"):
        value = value.model_dump()

    seen = _seen if _seen is not None else set()
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in seen:
            return "[CYCLE]"
        seen.add(identity)
        secret_container = bool(value.get("is_secret") is True or value.get("secret") is True)
        result: dict[str, Any] = {}
        for key, item in value.items():
            output_key = str(key)
            normalized = _normalized_key(key)
            if normalized in {"issecret", "secret"} and isinstance(item, bool):
                result[output_key] = item
            elif _sensitive_key(key) or (
                secret_container and normalized in _SECRET_CONTAINER_VALUE_KEYS
            ):
                result[output_key] = REDACTED
            else:
                result[output_key] = redact_audit_value(
                    item,
                    _depth=_depth + 1,
                    _seen=seen,
                )
        seen.remove(identity)
        return result

    if isinstance(value, (list, tuple, set, frozenset)):
        identity = id(value)
        if identity in seen:
            return "[CYCLE]"
        seen.add(identity)
        result = [
            redact_audit_value(item, _depth=_depth + 1, _seen=seen)
            for item in value
        ]
        seen.remove(identity)
        return result

    # Avoid arbitrary object reprs: they routinely embed credentials.
    return f"<{type(value).__name__}>"
