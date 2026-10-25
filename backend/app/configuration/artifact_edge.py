from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import os
import re
import time
from collections.abc import Mapping

from redis.asyncio import Redis

from app.configuration.contracts import validate_env_secret_reference
from app.settings import settings


_EDGE_NONCE_PREFIX = "fttw:configuration-artifact-edge-nonce:"
_EDGE_VERSION = "1"
_EDGE_CANONICAL_PREFIX = "FTTW-ARTIFACT-EDGE-V1"
_NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_SIGNATURE_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")

EDGE_VERSION_HEADER = "x-fttw-edge-version"
EDGE_SOURCE_HEADER = "x-fttw-edge-source"
EDGE_TIMESTAMP_HEADER = "x-fttw-edge-timestamp"
EDGE_NONCE_HEADER = "x-fttw-edge-nonce"
EDGE_SIGNATURE_HEADER = "x-fttw-edge-signature"
EDGE_HEADERS = (
    EDGE_VERSION_HEADER,
    EDGE_SOURCE_HEADER,
    EDGE_TIMESTAMP_HEADER,
    EDGE_NONCE_HEADER,
    EDGE_SIGNATURE_HEADER,
)


class ConfigurationArtifactEdgeError(RuntimeError):
    pass


def _normalize_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_SOURCE_INVALID"
        ) from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def _trusted_edge_peers() -> frozenset[str]:
    raw = str(settings.configuration_artifact_trusted_edge_peers or "").strip()
    if not raw:
        return frozenset()
    parts = [item.strip() for item in raw.split(",") if item.strip()]
    if not parts or len(parts) > 32:
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_PEERS_INVALID"
        )
    try:
        return frozenset(_normalize_ip(item) for item in parts)
    except ConfigurationArtifactEdgeError as exc:
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_PEERS_INVALID"
        ) from exc


def _bounded_attestation_age() -> int:
    try:
        value = int(settings.configuration_artifact_edge_attestation_max_age_seconds)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_MAX_AGE_INVALID"
        ) from exc
    if not 5 <= value <= 120:
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_MAX_AGE_INVALID"
        )
    return value


def _edge_key() -> bytes:
    try:
        normalized = validate_env_secret_reference(
            settings.configuration_artifact_edge_key_reference.strip()
        )
    except (AttributeError, ValueError) as exc:
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_KEY_REFERENCE_INVALID"
        ) from exc
    if normalized is None:
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_KEY_REFERENCE_INVALID"
        )
    raw = os.getenv(normalized[6:])
    if not raw:
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_KEY_UNAVAILABLE"
        )
    value = raw.strip()
    key: bytes | None = None
    if len(value) == 64:
        try:
            key = bytes.fromhex(value)
        except ValueError:
            key = None
    if key is None:
        try:
            padding = "=" * ((4 - len(value) % 4) % 4)
            key = base64.b64decode(
                (value + padding).encode("ascii"),
                altchars=b"-_",
                validate=True,
            )
        except (ValueError, UnicodeEncodeError, binascii.Error):
            key = None
    if key is None or len(key) != 32:
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_KEY_INVALID"
        )
    return key


def _validate_method_path(method: str, path: str) -> tuple[str, str]:
    normalized_method = str(method).strip().upper()
    normalized_path = str(path)
    if normalized_method != "GET":
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_METHOD_INVALID"
        )
    if (
        not normalized_path.startswith("/configuration-artifacts/")
        or len(normalized_path) > 512
        or "\n" in normalized_path
        or "\r" in normalized_path
        or "?" in normalized_path
    ):
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_PATH_INVALID"
        )
    return normalized_method, normalized_path


def _canonical_message(
    *,
    method: str,
    path: str,
    source_ip: str,
    timestamp: int,
    nonce: str,
) -> bytes:
    normalized_method, normalized_path = _validate_method_path(method, path)
    normalized_source = _normalize_ip(source_ip)
    if not _NONCE_PATTERN.fullmatch(str(nonce)):
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_NONCE_INVALID"
        )
    try:
        timestamp_value = int(timestamp)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_TIMESTAMP_INVALID"
        ) from exc
    return (
        f"{_EDGE_CANONICAL_PREFIX}\n"
        f"{normalized_method}\n"
        f"{normalized_path}\n"
        f"{normalized_source}\n"
        f"{timestamp_value}\n"
        f"{nonce}"
    ).encode("utf-8")


def build_edge_attestation_signature(
    *,
    method: str,
    path: str,
    source_ip: str,
    timestamp: int,
    nonce: str,
    key: bytes | None = None,
) -> str:
    signing_key = key if key is not None else _edge_key()
    if not isinstance(signing_key, bytes) or len(signing_key) != 32:
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_KEY_INVALID"
        )
    canonical = _canonical_message(
        method=method,
        path=path,
        source_ip=source_ip,
        timestamp=timestamp,
        nonce=nonce,
    )
    return hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()


def _header_value(headers: Mapping[str, str], name: str) -> str:
    value = headers.get(name)
    return str(value).strip() if value is not None else ""


def _nonce_key(*, trusted_peer: str, nonce: str) -> str:
    digest = hashlib.sha256(
        f"{trusted_peer}\0{nonce}".encode("utf-8")
    ).hexdigest()
    return f"{_EDGE_NONCE_PREFIX}{digest}"


async def resolve_effective_artifact_source(
    *,
    direct_peer: str,
    method: str,
    path: str,
    headers: Mapping[str, str],
    redis: Redis,
    now: float | None = None,
) -> str:
    peer = _normalize_ip(direct_peer)
    trusted_peers = _trusted_edge_peers()
    presented = any(_header_value(headers, name) for name in EDGE_HEADERS)

    if peer not in trusted_peers:
        if presented:
            raise ConfigurationArtifactEdgeError(
                "CONFIGURATION_ARTIFACT_EDGE_UNTRUSTED_PEER"
            )
        _validate_method_path(method, path)
        return peer

    values = {name: _header_value(headers, name) for name in EDGE_HEADERS}
    if any(not value for value in values.values()):
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_ATTESTATION_REQUIRED"
        )
    if values[EDGE_VERSION_HEADER] != _EDGE_VERSION:
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_VERSION_INVALID"
        )

    source = _normalize_ip(values[EDGE_SOURCE_HEADER])
    nonce = values[EDGE_NONCE_HEADER]
    signature = values[EDGE_SIGNATURE_HEADER]
    if not _NONCE_PATTERN.fullmatch(nonce):
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_NONCE_INVALID"
        )
    if not _SIGNATURE_PATTERN.fullmatch(signature):
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_SIGNATURE_INVALID"
        )
    try:
        timestamp = int(values[EDGE_TIMESTAMP_HEADER])
    except (TypeError, ValueError, OverflowError) as exc:
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_TIMESTAMP_INVALID"
        ) from exc

    maximum_age = _bounded_attestation_age()
    current = float(time.time() if now is None else now)
    if abs(current - float(timestamp)) > maximum_age:
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_ATTESTATION_STALE"
        )

    expected = build_edge_attestation_signature(
        method=method,
        path=path,
        source_ip=source,
        timestamp=timestamp,
        nonce=nonce,
    )
    if not hmac.compare_digest(expected, signature.lower()):
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_SIGNATURE_INVALID"
        )

    try:
        created = await redis.set(
            _nonce_key(trusted_peer=peer, nonce=nonce),
            "1",
            ex=maximum_age * 2,
            nx=True,
        )
    except Exception as exc:
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_REPLAY_BACKEND_UNAVAILABLE"
        ) from exc
    if not created:
        raise ConfigurationArtifactEdgeError(
            "CONFIGURATION_ARTIFACT_EDGE_REPLAY"
        )
    return source
