from __future__ import annotations

import base64
import binascii
import hashlib
import os
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.configuration.contracts import validate_env_secret_reference
from app.settings import settings


_MAGIC = b"FTTWCFG1"
_NONCE_BYTES = 12
_AES_GCM_TAG_BYTES = 16


class ConfigurationArtifactError(RuntimeError):
    pass


def _resolve_key(reference: str) -> bytes:
    try:
        normalized = validate_env_secret_reference(reference)
    except ValueError as exc:
        raise ConfigurationArtifactError(
            "CONFIGURATION_ARTIFACT_KEY_REFERENCE_INVALID"
        ) from exc
    if normalized is None:
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_KEY_REFERENCE_INVALID")
    name = normalized[6:]
    raw = os.getenv(name)
    if not raw:
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_KEY_UNAVAILABLE")
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
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_KEY_INVALID")
    return key


def artifact_key_reference() -> str:
    try:
        reference = validate_env_secret_reference(
            settings.configuration_artifact_key_reference.strip()
        )
    except ValueError as exc:
        raise ConfigurationArtifactError(
            "CONFIGURATION_ARTIFACT_KEY_REFERENCE_INVALID"
        ) from exc
    if reference is None:
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_KEY_REFERENCE_INVALID")
    return reference


def _secure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError as exc:
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_PERMISSION_FAILED") from exc


def artifact_root(*, writable: bool = True) -> Path:
    root = (Path(settings.data_root) / "configurations").resolve()
    if writable:
        _secure_dir(root)
    elif not root.is_dir():
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_MISSING")
    return root


def _artifact_path(device_id: UUID, snapshot_id: UUID) -> Path:
    root = artifact_root()
    device_root = (root / str(device_id)).resolve()
    if device_root.parent != root:
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_PATH_INVALID")
    _secure_dir(device_root)
    path = (device_root / f"{snapshot_id}.aesgcm").resolve()
    if path.parent != device_root:
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_PATH_INVALID")
    return path


def _aad(*, device_id: UUID, snapshot_id: UUID) -> bytes:
    return f"FTTW-CONFIG-V1:{device_id}:{snapshot_id}".encode("ascii")


def encrypt_snapshot(
    *,
    device_id: UUID,
    snapshot_id: UUID,
    plaintext: bytes,
) -> dict[str, object]:
    if not isinstance(plaintext, bytes):
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_PAYLOAD_INVALID")
    if not plaintext:
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_EMPTY")
    if len(plaintext) > settings.configuration_artifact_max_bytes:
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_TOO_LARGE")

    reference = artifact_key_reference()
    key = _resolve_key(reference)
    nonce = os.urandom(_NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(
        nonce,
        plaintext,
        _aad(device_id=device_id, snapshot_id=snapshot_id),
    )
    payload = _MAGIC + nonce + ciphertext
    path = _artifact_path(device_id, snapshot_id)
    temp = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    try:
        temp.write_bytes(payload)
        os.chmod(temp, 0o600)
        temp.replace(path)
        os.chmod(path, 0o600)
    except OSError as exc:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_WRITE_FAILED") from exc

    return {
        "artifact_path": str(path.relative_to(artifact_root())),
        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "artifact_size_bytes": len(payload),
        "encryption_scheme": "AES_256_GCM",
        "encryption_key_reference": reference,
    }


def decrypt_snapshot(
    *,
    device_id: UUID,
    snapshot_id: UUID,
    artifact_path: str,
    expected_sha256: str,
    key_reference: str,
) -> bytes:
    # Decryption must remain compatible with read-only artifact mounts. Writers
    # establish directory permissions; readers only resolve and validate them.
    root = artifact_root(writable=False)
    path = (root / artifact_path).resolve()
    if root not in path.parents or not path.is_file():
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_MISSING")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_MISSING") from exc
    maximum = (
        len(_MAGIC)
        + _NONCE_BYTES
        + _AES_GCM_TAG_BYTES
        + int(settings.configuration_artifact_max_bytes)
    )
    if size <= len(_MAGIC) + _NONCE_BYTES + _AES_GCM_TAG_BYTES or size > maximum:
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_SIZE_INVALID")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_READ_FAILED") from exc
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_CHECKSUM_MISMATCH")
    if not payload.startswith(_MAGIC):
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_FORMAT_INVALID")
    nonce_start = len(_MAGIC)
    nonce = payload[nonce_start : nonce_start + _NONCE_BYTES]
    ciphertext = payload[nonce_start + _NONCE_BYTES :]
    try:
        plaintext = AESGCM(_resolve_key(key_reference)).decrypt(
            nonce,
            ciphertext,
            _aad(device_id=device_id, snapshot_id=snapshot_id),
        )
    except Exception as exc:
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_DECRYPT_FAILED") from exc
    if len(plaintext) > settings.configuration_artifact_max_bytes:
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_TOO_LARGE")
    return plaintext
