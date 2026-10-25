from __future__ import annotations

import asyncio
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import APIError
from ..models import AccessTemplate, DeviceRemoteAccessProfile
from ..remote_gateway.ssh_transport import (
    SSH_HOST_KEY_LINE_METADATA_KEY,
    ssh_compatibility_options,
)
from .access_templates import resolve_effective_access
from .audit import record_audit
from .remote_access import get_management_ip


@dataclass(frozen=True)
class SSHHostKeyCandidate:
    device_id: UUID
    template_id: UUID
    template_name: str
    fingerprint: str
    key_type: str
    port: int
    compatibility_profile: str
    pinned_fingerprint: str | None
    trust_state: str
    known_hosts_line: str = field(repr=False)


async def _fingerprint_for_line(line: str) -> tuple[str, str]:
    parts = line.strip().split()
    if len(parts) < 3:
        raise APIError(502, "SSH_HOST_KEY_SCAN_FAILED", "The SSH host-key response was malformed.")
    key_type = parts[1]
    try:
        proc = await asyncio.create_subprocess_exec(
            "ssh-keygen",
            "-lf",
            "-",
            "-E",
            "sha256",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except OSError as exc:
        raise APIError(503, "SSH_CLIENT_NOT_AVAILABLE", "The SSH client utility is unavailable in this service.") from exc
    stdout, _ = await proc.communicate((line.rstrip() + "\n").encode("utf-8"))
    if proc.returncode != 0:
        raise APIError(502, "SSH_HOST_KEY_SCAN_FAILED", "The SSH host-key fingerprint could not be calculated.")
    output = stdout.decode("utf-8", "replace").strip().split()
    if len(output) < 2 or not output[1].startswith("SHA256:"):
        raise APIError(502, "SSH_HOST_KEY_SCAN_FAILED", "The SSH host-key fingerprint could not be calculated.")
    return output[1], key_type


async def _scan_host_key(
    *,
    host: str,
    port: int,
    compatibility_profile: str,
    timeout_seconds: int = 8,
) -> tuple[str, str, str]:
    """Collect one candidate host key without using device credentials.

    The candidate known_hosts file is ephemeral. StrictHostKeyChecking=accept-new
    is used only to capture the first observed key for operator confirmation.
    Authentication is explicitly disabled. The verified public key line is
    returned so an approved pin can later be reused without a second SSH probe.
    """
    options = ssh_compatibility_options(compatibility_profile)
    with tempfile.TemporaryDirectory(prefix="fttw-hostkey-discovery-") as temp_dir:
        known_hosts = Path(temp_dir) / "known_hosts"
        command = [
            "ssh",
            "-F", "/dev/null",
            "-p", str(port),
            "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "ConnectTimeout=5",
            "-o", "ConnectionAttempts=1",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "HashKnownHosts=no",
            "-o", "LogLevel=ERROR",
            *options,
            f"fttw-hostkey-discovery@{host}",
            "exit",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except OSError as exc:
            raise APIError(503, "SSH_CLIENT_NOT_AVAILABLE", "The SSH client utility is unavailable in this service.") from exc
        try:
            await asyncio.wait_for(proc.communicate(), timeout=max(3, min(int(timeout_seconds), 15)))
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
        if not known_hosts.exists():
            raise APIError(
                502,
                "SSH_HOST_KEY_SCAN_FAILED",
                "FTTW could not negotiate an SSH host key with the device using the configured compatibility profile.",
            )
        lines = [
            line.strip()
            for line in known_hosts.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if not lines:
            raise APIError(502, "SSH_HOST_KEY_SCAN_FAILED", "The device did not provide a usable SSH host key.")
        line = lines[0]
        fingerprint, key_type = await _fingerprint_for_line(line)
        return fingerprint, key_type, line


async def _ssh_template_for_host_key(
    db: AsyncSession,
    *,
    device_id: UUID,
    template: AccessTemplate | None,
) -> AccessTemplate:
    if template is not None:
        if template.protocol.strip().upper() != "SSH":
            raise APIError(422, "ACCESS_TEMPLATE_PROTOCOL_INVALID", "SSH host-key discovery requires an SSH Access Template.")
        if not template.is_active:
            raise APIError(409, "ACCESS_TEMPLATE_INACTIVE", "Inactive Access Templates cannot be used for SSH host-key discovery.")
        return template

    resolved = await resolve_effective_access(db, device_id=device_id, protocol="SSH")
    if resolved.status == "CONFLICT":
        raise APIError(409, "CONFIGURATION_CONFLICT", "Resolve the effective SSH Access Template conflict before trusting a host key.")
    if resolved.status != "RESOLVED" or resolved.template is None:
        raise APIError(409, "SSH_ACCESS_TEMPLATE_REQUIRED", "An effective SSH Access Template is required before SSH host-key discovery.")
    return resolved.template


async def discover_device_ssh_host_key(
    db: AsyncSession,
    *,
    device_id: UUID,
    template: AccessTemplate | None = None,
) -> SSHHostKeyCandidate:
    template = await _ssh_template_for_host_key(db, device_id=device_id, template=template)
    settings = dict(template.settings_json or {})
    port = int(settings.get("port", 22))
    compatibility_profile = str(settings.get("compatibility_profile", "MODERN")).strip().upper()
    management_ip = await get_management_ip(db, device_id)
    if not management_ip:
        raise APIError(409, "DEVICE_MANAGEMENT_IP_REQUIRED", "The device has no active management IP address.")

    fingerprint, key_type, known_hosts_line = await _scan_host_key(
        host=management_ip,
        port=port,
        compatibility_profile=compatibility_profile,
        timeout_seconds=int(settings.get("timeout_seconds", 10)),
    )
    profile = await db.scalar(select(DeviceRemoteAccessProfile).where(DeviceRemoteAccessProfile.device_id == device_id))
    pinned = profile.ssh_host_key_fingerprint if profile is not None else None
    trust_state = "NEW" if not pinned else "MATCH" if pinned == fingerprint else "MISMATCH"

    # Exact fingerprint matches are already trusted decisions. Cache the public
    # key material in the existing JSON metadata so the connection test in this
    # same transaction, and later Web SSH sessions after commit, can build a
    # strict known_hosts file without another synthetic SSH connection.
    if profile is not None and trust_state == "MATCH":
        metadata = dict(profile.metadata_ or {})
        if metadata.get(SSH_HOST_KEY_LINE_METADATA_KEY) != known_hosts_line:
            metadata[SSH_HOST_KEY_LINE_METADATA_KEY] = known_hosts_line
            profile.metadata_ = metadata

    return SSHHostKeyCandidate(
        device_id=device_id,
        template_id=template.id,
        template_name=template.name,
        fingerprint=fingerprint,
        key_type=key_type,
        port=port,
        compatibility_profile=compatibility_profile,
        pinned_fingerprint=pinned,
        trust_state=trust_state,
        known_hosts_line=known_hosts_line,
    )


async def trust_device_ssh_host_key(
    db: AsyncSession,
    *,
    device_id: UUID,
    actor_user_id: UUID,
    expected_fingerprint: str,
    replace_existing: bool,
    template: AccessTemplate | None = None,
    enable_remote_access: bool = True,
) -> SSHHostKeyCandidate:
    candidate = await discover_device_ssh_host_key(db, device_id=device_id, template=template)
    if candidate.fingerprint != expected_fingerprint:
        raise APIError(
            409,
            "SSH_HOST_KEY_CHANGED_DURING_CONFIRMATION",
            "The SSH host key changed while confirmation was in progress. Nothing was saved; retry discovery and verify the new fingerprint.",
        )

    profile = await db.scalar(
        select(DeviceRemoteAccessProfile)
        .where(DeviceRemoteAccessProfile.device_id == device_id)
        .with_for_update()
    )
    if profile is None:
        profile = DeviceRemoteAccessProfile(device_id=device_id)
        db.add(profile)
        await db.flush()

    previous = profile.ssh_host_key_fingerprint
    if previous and previous != candidate.fingerprint and not replace_existing:
        raise APIError(
            409,
            "SSH_HOST_KEY_REPLACE_CONFIRMATION_REQUIRED",
            "The observed SSH host key differs from the trusted key. Explicit replacement confirmation is required.",
        )

    if enable_remote_access:
        profile.ssh_enabled = True
    profile.ssh_port = candidate.port
    profile.ssh_compatibility_profile = candidate.compatibility_profile
    profile.ssh_host_key_fingerprint = candidate.fingerprint
    metadata = dict(profile.metadata_ or {})
    metadata[SSH_HOST_KEY_LINE_METADATA_KEY] = candidate.known_hosts_line
    profile.metadata_ = metadata

    await record_audit(
        db,
        action="REMOTE_ACCESS_SSH_HOST_KEY_REPLACED" if previous and previous != candidate.fingerprint else "REMOTE_ACCESS_SSH_HOST_KEY_TRUSTED",
        entity_type="Device",
        entity_id=device_id,
        actor_user_id=actor_user_id,
        description="Device-specific SSH host key trusted after explicit operator confirmation.",
        metadata={
            "template_id": str(candidate.template_id),
            "key_type": candidate.key_type,
            "port": candidate.port,
            "compatibility_profile": candidate.compatibility_profile,
            "replaced_existing": bool(previous and previous != candidate.fingerprint),
            "remote_access_enabled": bool(profile.ssh_enabled),
            "public_host_key_cached": True,
        },
    )

    return SSHHostKeyCandidate(
        device_id=candidate.device_id,
        template_id=candidate.template_id,
        template_name=candidate.template_name,
        fingerprint=candidate.fingerprint,
        key_type=candidate.key_type,
        port=candidate.port,
        compatibility_profile=candidate.compatibility_profile,
        pinned_fingerprint=candidate.fingerprint,
        trust_state="MATCH",
        known_hosts_line=candidate.known_hosts_line,
    )
