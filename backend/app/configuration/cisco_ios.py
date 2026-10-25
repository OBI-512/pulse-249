from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import re
from typing import Any, Mapping
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy import select

from app.configuration.artifact_leases import (
    IssuedArtifactLease,
    get_artifact_lease_served_count,
    issue_artifact_lease,
    revoke_artifact_lease,
)
from app.configuration.contracts import (
    AdapterDescriptor,
    ConfigurationCapability,
    ConfigurationExecutionContext,
    ConfigurationPreMutationError,
    ConfigurationTemplateDefinition,
    ConfigurationTransport,
)
from app.configuration.ssh_cli import ConfigurationSSHError, GenericSSHCLIAdapter
from app.configuration.templating import ConfigurationTemplateError
from app.db.session import AsyncSessionLocal
from app.models.configuration import ConfigurationOperation, ConfigurationSnapshot
from app.settings import settings


_CISCO_RESTORE_MODE = "CISCO_CONFIGURE_REPLACE_HTTP"
_RESTORE_KEYS = {
    "mode",
    "force",
    "confirmation_minutes",
    "revert_on_error",
}
_FAILURE_MARKERS = (
    "% invalid input",
    "% incomplete command",
    "%error",
    "% error",
    "error opening",
    "unable to",
    "connection refused",
    "no route to host",
)
_ARTIFACT_RECEIPT_WAIT_SECONDS = 5.0
_ARTIFACT_RECEIPT_POLL_SECONDS = 0.10
_LOCAL_STAGING_PREFIXES = ("flash:", "disk0:", "bootflash:", "slot0:", "disk1:")
_LOCAL_STAGING_FILE_PREFIX = "fttw-stage4p-"
_LOCAL_STAGING_ACCESS_FAILURE_MARKERS = (
    "open device ",
    "no such device",
    "bad device info block",
    "device not ready",
    "unknown device",
    "device unavailable",
)


@dataclass(frozen=True)
class CiscoRestoreTarget:
    operation_id: str
    device_id: str
    snapshot_id: str
    template_version_id: str
    expected_source_ip: str
    expected_plaintext_sha256: str


def _restore_settings(context: ConfigurationExecutionContext) -> dict[str, Any]:
    transport = dict(
        context.connection_parameters.get("template_transport_parameters") or {}
    )
    restore = transport.get("restore")
    if not isinstance(restore, dict):
        raise ConfigurationSSHError("CONFIGURATION_CISCO_RESTORE_SPEC_REQUIRED")
    if set(restore) - _RESTORE_KEYS:
        raise ConfigurationSSHError("CONFIGURATION_CISCO_RESTORE_SPEC_INVALID")
    if str(restore.get("mode") or "").upper() != _CISCO_RESTORE_MODE:
        raise ConfigurationSSHError("CONFIGURATION_CISCO_RESTORE_MODE_REQUIRED")
    if restore.get("force") is not True or restore.get("revert_on_error") is not True:
        raise ConfigurationSSHError("CONFIGURATION_CISCO_RESTORE_GUARDS_REQUIRED")
    try:
        minutes = int(restore.get("confirmation_minutes"))
    except (TypeError, ValueError, OverflowError) as exc:
        raise ConfigurationSSHError(
            "CONFIGURATION_CISCO_CONFIRMATION_TIME_INVALID"
        ) from exc
    # IOS exposes 1-120, but FTTW intentionally limits unattended provisional
    # windows to five minutes for this guarded adapter.
    if not 1 <= minutes <= 5:
        raise ConfigurationSSHError("CONFIGURATION_CISCO_CONFIRMATION_TIME_INVALID")
    return {**restore, "confirmation_minutes": minutes}


def _artifact_base_url() -> str:
    value = str(settings.configuration_artifact_public_base_url or "").strip().rstrip("/")
    if not value or len(value) > 1024:
        raise ConfigurationSSHError("CONFIGURATION_ARTIFACT_PUBLIC_URL_REQUIRED")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ConfigurationSSHError("CONFIGURATION_ARTIFACT_PUBLIC_URL_INVALID")
    return value


def _lease_url(lease: IssuedArtifactLease) -> str:
    return f"{_artifact_base_url()}/configuration-artifacts/{lease.token}"


def _has_failure(output: str) -> bool:
    lowered = (output or "").lower()
    return any(marker in lowered for marker in _FAILURE_MARKERS)


def _staged_artifact_path(target: CiscoRestoreTarget, prefix: str) -> str:
    if prefix not in _LOCAL_STAGING_PREFIXES:
        raise ConfigurationSSHError("CONFIGURATION_CISCO_LOCAL_STAGING_FILESYSTEM_INVALID")
    op = target.operation_id.replace("-", "")[:12]
    snap = target.snapshot_id.replace("-", "")[:12]
    if not op or not snap:
        raise ConfigurationSSHError("CONFIGURATION_CISCO_LOCAL_STAGING_PATH_INVALID")
    return f"{prefix}{_LOCAL_STAGING_FILE_PREFIX}{op}-{snap}.cfg"


async def _wait_for_served_receipt(
    lease: IssuedArtifactLease,
    *,
    source_ip: str,
    timeout_seconds: float = _ARTIFACT_RECEIPT_WAIT_SECONDS,
) -> int:
    """Wait briefly for the source-bound gateway served receipt to become visible.

    The gateway records the receipt before returning the artifact payload. The
    bounded poll tolerates scheduling/Redis observation latency without weakening
    the requirement: success still requires served_count >= 1 for the exact lease
    and expected source IP.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.10, float(timeout_seconds))
    last_error: BaseException | None = None
    last_count = 0

    while True:
        try:
            last_count = await get_artifact_lease_served_count(
                lease.token,
                source_ip=source_ip,
            )
            last_error = None
            if 1 <= last_count <= lease.max_reads:
                return last_count
            if last_count > lease.max_reads:
                return last_count
        except Exception as exc:
            last_error = exc

        remaining = deadline - loop.time()
        if remaining <= 0:
            if last_error is not None:
                raise last_error
            return last_count
        await asyncio.sleep(min(_ARTIFACT_RECEIPT_POLL_SECONDS, remaining))


async def _resolve_active_restore_target(
    context: ConfigurationExecutionContext,
    snapshot_payload: bytes,
    *,
    adapter_key: str,
) -> CiscoRestoreTarget:
    try:
        device_id = UUID(context.device_id)
        version_id = UUID(context.template_version_id)
    except ValueError as exc:
        raise ConfigurationSSHError("CONFIGURATION_CISCO_RESTORE_CONTEXT_INVALID") from exc

    payload_sha256 = hashlib.sha256(snapshot_payload).hexdigest()
    async with AsyncSessionLocal() as db:
        operations = list(
            (
                await db.scalars(
                    select(ConfigurationOperation).where(
                        ConfigurationOperation.device_id == device_id,
                        ConfigurationOperation.template_version_id == version_id,
                        ConfigurationOperation.status.in_(("RUNNING", "ROLLING_BACK")),
                    )
                )
            ).all()
        )
        if len(operations) != 1:
            raise ConfigurationSSHError(
                "CONFIGURATION_CISCO_ACTIVE_OPERATION_REQUIRED"
            )
        operation = operations[0]
        if operation.status == "RUNNING":
            if operation.operation_type != "RESTORE" or operation.candidate_snapshot_id is None:
                raise ConfigurationSSHError(
                    "CONFIGURATION_CISCO_RESTORE_OPERATION_INVALID"
                )
            snapshot_id = operation.candidate_snapshot_id
        else:
            if operation.pre_change_snapshot_id is None:
                raise ConfigurationSSHError(
                    "CONFIGURATION_CISCO_ROLLBACK_SNAPSHOT_REQUIRED"
                )
            snapshot_id = operation.pre_change_snapshot_id

        snapshot = await db.get(ConfigurationSnapshot, snapshot_id)
        if (
            snapshot is None
            or snapshot.device_id != device_id
            or snapshot.template_version_id != version_id
            or snapshot.adapter_key != adapter_key
            or snapshot.artifact_status != "READY"
            or not snapshot.is_restorable
            or snapshot.plaintext_sha256 != payload_sha256
            or snapshot.normalized_sha256 != payload_sha256
        ):
            raise ConfigurationSSHError(
                "CONFIGURATION_CISCO_RESTORE_SNAPSHOT_BINDING_INVALID"
            )

        return CiscoRestoreTarget(
            operation_id=str(operation.id),
            device_id=str(device_id),
            snapshot_id=str(snapshot.id),
            template_version_id=str(version_id),
            expected_source_ip=context.management_address,
            expected_plaintext_sha256=payload_sha256,
        )


async def _issue_restore_lease(target: CiscoRestoreTarget) -> IssuedArtifactLease:
    return await issue_artifact_lease(
        operation_id=target.operation_id,
        device_id=target.device_id,
        snapshot_id=target.snapshot_id,
        template_version_id=target.template_version_id,
        expected_source_ip=target.expected_source_ip,
        expected_plaintext_sha256=target.expected_plaintext_sha256,
    )


class CiscoIOSSSHCLIAdapter(GenericSSHCLIAdapter):
    descriptor = AdapterDescriptor(
        key="cisco.ios_ssh_cli",
        transport=ConfigurationTransport.SSH_CLI,
        capabilities=frozenset(
            {
                ConfigurationCapability.CAPTURE,
                ConfigurationCapability.APPLY,
                ConfigurationCapability.VERIFY,
                ConfigurationCapability.RESTORE,
                ConfigurationCapability.ROLLBACK,
                ConfigurationCapability.PROVISIONAL_COMMIT,
            }
        ),
    )

    async def validate_template(self, definition: ConfigurationTemplateDefinition) -> None:
        if definition.adapter_key != self.descriptor.key:
            raise ConfigurationTemplateError("CONFIGURATION_CISCO_ADAPTER_KEY_REQUIRED")
        original_restore = (definition.transport_parameters or {}).get("restore")
        if not isinstance(original_restore, dict) or set(original_restore) - _RESTORE_KEYS:
            raise ConfigurationTemplateError("CONFIGURATION_CISCO_RESTORE_SPEC_INVALID")
        if str(original_restore.get("mode") or "").upper() != _CISCO_RESTORE_MODE:
            raise ConfigurationTemplateError("CONFIGURATION_CISCO_RESTORE_MODE_REQUIRED")
        if (
            original_restore.get("force") is not True
            or original_restore.get("revert_on_error") is not True
        ):
            raise ConfigurationTemplateError("CONFIGURATION_CISCO_RESTORE_GUARDS_REQUIRED")
        try:
            minutes = int(original_restore.get("confirmation_minutes"))
        except (TypeError, ValueError, OverflowError) as exc:
            raise ConfigurationTemplateError(
                "CONFIGURATION_CISCO_CONFIRMATION_TIME_INVALID"
            ) from exc
        if not 1 <= minutes <= 5:
            raise ConfigurationTemplateError(
                "CONFIGURATION_CISCO_CONFIRMATION_TIME_INVALID"
            )
        if (
            ConfigurationCapability.RESTORE in definition.capabilities
            or ConfigurationCapability.APPLY in definition.capabilities
        ) and ConfigurationCapability.PROVISIONAL_COMMIT not in definition.capabilities:
            raise ConfigurationTemplateError(
                "CONFIGURATION_CISCO_PROVISIONAL_COMMIT_REQUIRED"
            )

        # Reuse the mature SSH capture/function/parameter validation without
        # allowing the generic restore implementation to interpret Cisco restore
        # data. This probe exists only for validation; runtime restore never falls
        # back to COMMAND_STREAM or SCP_LEGACY.
        probe = definition.model_copy(deep=True)
        probe.transport_parameters = dict(probe.transport_parameters)
        probe.transport_parameters["restore"] = {"mode": "COMMAND_STREAM"}
        await super().validate_template(probe)

        capture = (definition.transport_parameters or {}).get("capture") or {}
        if capture.get("restorable") is not True:
            raise ConfigurationTemplateError(
                "CONFIGURATION_CISCO_RESTORABLE_CAPTURE_REQUIRED"
            )

    async def _select_local_staging_prefix(
        self,
        context: ConfigurationExecutionContext,
    ) -> str:
        session = await self._session(context)
        try:
            output = await session.command("show file systems", timeout=30)
            if _has_failure(output):
                raise ConfigurationSSHError(
                    "CONFIGURATION_CISCO_LOCAL_STAGING_DISCOVERY_FAILED"
                )
            lines = (output or "").lower().splitlines()
            advertised = []
            for prefix in _LOCAL_STAGING_PREFIXES:
                if any(
                    prefix in line
                    and re.search(r"(?<![a-z0-9])rw(?![a-z0-9])", line)
                    for line in lines
                ):
                    advertised.append(prefix)
        finally:
            session.close()

        for prefix in advertised:
            probe = None
            try:
                probe = await self._session(context)
                output = await probe.command(f"show {prefix}", timeout=30)
                lowered = (output or "").lower()
                if _has_failure(output):
                    continue
                if any(marker in lowered for marker in _LOCAL_STAGING_ACCESS_FAILURE_MARKERS):
                    continue
                return prefix
            except Exception:
                continue
            finally:
                if probe is not None:
                    probe.close()

        raise ConfigurationSSHError(
            "CONFIGURATION_CISCO_LOCAL_STAGING_FILESYSTEM_REQUIRED"
        )

    async def _copy_artifact_to_local_file(
        self,
        context: ConfigurationExecutionContext,
        *,
        url: str,
        path: str,
    ) -> None:
        session = await self._session(context)
        try:
            prompt = session.prompt_pattern.pattern
            output = await session.command(
                f"copy {url} {path}",
                expect=rf"(?:Destination filename[^\r\n]*\?|{prompt})",
                timeout=30,
            )
            lowered = (output or "").lower()
            if "destination filename" in lowered and "?" in lowered:
                output += await session.command("", timeout=30)
            if _has_failure(output):
                raise ConfigurationSSHError(
                    "CONFIGURATION_CISCO_ARTIFACT_STAGE_COPY_FAILED"
                )
        finally:
            session.close()

    async def _delete_local_staged_file(
        self,
        context: ConfigurationExecutionContext,
        *,
        path: str,
        required: bool,
    ) -> None:
        session = None
        try:
            session = await self._session(context)
            output = await session.command(f"delete {path} /force", timeout=30)
            if _has_failure(output):
                if required:
                    raise ConfigurationSSHError(
                        "CONFIGURATION_CISCO_ARTIFACT_STAGE_CLEANUP_FAILED"
                    )
                return
        except Exception:
            if required:
                raise
        finally:
            if session is not None:
                session.close()

    async def _run_artifact_preflight_copy(
        self,
        context: ConfigurationExecutionContext,
        *,
        url: str,
        path: str,
    ) -> None:
        try:
            await self._copy_artifact_to_local_file(
                context,
                url=url,
                path=path,
            )
        except ConfigurationSSHError as exc:
            if str(exc) == "CONFIGURATION_CISCO_ARTIFACT_STAGE_COPY_FAILED":
                raise ConfigurationPreMutationError(
                    "CONFIGURATION_CISCO_ARTIFACT_PREFLIGHT_DEVICE_REJECTED"
                ) from exc
            raise ConfigurationPreMutationError(
                "CONFIGURATION_CISCO_ARTIFACT_PREFLIGHT_TRANSPORT_FAILED"
            ) from exc
        except Exception as exc:
            raise ConfigurationPreMutationError(
                "CONFIGURATION_CISCO_ARTIFACT_PREFLIGHT_TRANSPORT_FAILED"
            ) from exc

    async def preflight_restore(
        self,
        context: ConfigurationExecutionContext,
        snapshot: bytes,
    ) -> Mapping[str, Any]:
        if not snapshot:
            raise ConfigurationPreMutationError(
                "CONFIGURATION_RESTORE_SNAPSHOT_EMPTY"
            )
        if len(snapshot) > settings.configuration_artifact_max_bytes:
            raise ConfigurationPreMutationError(
                "CONFIGURATION_ARTIFACT_TOO_LARGE"
            )

        try:
            _restore_settings(context)
            target = await _resolve_active_restore_target(
                context,
                snapshot,
                adapter_key=self.descriptor.key,
            )
            lease = await _issue_restore_lease(target)
        except ConfigurationPreMutationError:
            raise
        except Exception as exc:
            raise ConfigurationPreMutationError(
                "CONFIGURATION_CISCO_ARTIFACT_PREFLIGHT_PREPARE_FAILED"
            ) from exc

        staged_path: str | None = None
        try:
            try:
                staging_prefix = await self._select_local_staging_prefix(context)
                staged_path = _staged_artifact_path(target, staging_prefix)
                await self._delete_local_staged_file(
                    context,
                    path=staged_path,
                    required=False,
                )
            except Exception as exc:
                raise ConfigurationPreMutationError(
                    "CONFIGURATION_CISCO_ARTIFACT_PREFLIGHT_PREPARE_FAILED"
                ) from exc

            await self._run_artifact_preflight_copy(
                context,
                url=_lease_url(lease),
                path=staged_path,
            )
            try:
                served_count = await _wait_for_served_receipt(
                    lease,
                    source_ip=target.expected_source_ip,
                )
            except Exception as exc:
                raise ConfigurationPreMutationError(
                    "CONFIGURATION_CISCO_ARTIFACT_PREFLIGHT_UNCONFIRMED"
                ) from exc
            if served_count < 1 or served_count > lease.max_reads:
                raise ConfigurationPreMutationError(
                    "CONFIGURATION_CISCO_ARTIFACT_PREFLIGHT_UNCONFIRMED"
                )

            try:
                await self._delete_local_staged_file(
                    context,
                    path=staged_path,
                    required=True,
                )
                staged_path = None
            except Exception as exc:
                raise ConfigurationPreMutationError(
                    "CONFIGURATION_CISCO_ARTIFACT_PREFLIGHT_CLEANUP_FAILED"
                ) from exc
        except Exception:
            if staged_path is not None:
                await self._delete_local_staged_file(
                    context,
                    path=staged_path,
                    required=False,
                )
            try:
                await revoke_artifact_lease(lease.token)
            except Exception:
                pass
            raise

        try:
            await revoke_artifact_lease(lease.token)
        except Exception as exc:
            raise ConfigurationPreMutationError(
                "CONFIGURATION_CISCO_ARTIFACT_PREFLIGHT_CLEANUP_FAILED"
            ) from exc

        return {
            "preflight": "CISCO_ARTIFACT_FETCH_CONFIRMED",
            "operation_id": target.operation_id,
            "snapshot_id": target.snapshot_id,
        }

    async def _best_effort_revert(self, context: ConfigurationExecutionContext) -> None:
        session = None
        try:
            session = await self._session(context)
            await session.command("configure revert now", timeout=30)
        except Exception:
            # The authoritative core rollback path runs after this method raises.
            # Do not hide the primary failure with a best-effort revert failure.
            pass
        finally:
            if session is not None:
                session.close()

    async def _run_replace_command(
        self,
        context: ConfigurationExecutionContext,
        *,
        url: str,
        confirmation_minutes: int,
    ) -> None:
        session = await self._session(context)
        try:
            output = await session.command(
                f"configure replace {url} force time {confirmation_minutes}",
                timeout=max(30, min(300, confirmation_minutes * 30)),
            )
            if _has_failure(output):
                raise ConfigurationSSHError(
                    "CONFIGURATION_CISCO_REPLACE_DEVICE_REJECTED"
                )
            # Do not treat vendor-facing prose as the authoritative success
            # contract. This command phase only rejects explicit device/transport
            # failures. restore() remains fail-closed on objective evidence: a
            # source-bound served receipt, exact provisional capture, confirm,
            # and exact confirmed capture are all required before success.
        finally:
            session.close()

    async def _confirm_replace(self, context: ConfigurationExecutionContext) -> None:
        session = await self._session(context)
        try:
            output = await session.command("configure confirm", timeout=30)
            if _has_failure(output):
                raise ConfigurationSSHError(
                    "CONFIGURATION_CISCO_CONFIRM_DEVICE_REJECTED"
                )
        finally:
            session.close()

    async def restore(
        self,
        context: ConfigurationExecutionContext,
        snapshot: bytes,
    ) -> Mapping[str, Any]:
        if not snapshot:
            raise ConfigurationSSHError("CONFIGURATION_RESTORE_SNAPSHOT_EMPTY")
        if len(snapshot) > settings.configuration_artifact_max_bytes:
            raise ConfigurationSSHError("CONFIGURATION_ARTIFACT_TOO_LARGE")

        restore = _restore_settings(context)
        target = await _resolve_active_restore_target(
            context,
            snapshot,
            adapter_key=self.descriptor.key,
        )
        lease = await _issue_restore_lease(target)
        staged_path: str | None = None
        lease_revoked = False
        replacement_attempted = False
        try:
            staging_prefix = await self._select_local_staging_prefix(context)
            staged_path = _staged_artifact_path(target, staging_prefix)

            # A previous interrupted attempt may have left the deterministic
            # staging filename behind. Removal is safe before a new copy and does
            # not modify running configuration.
            await self._delete_local_staged_file(
                context,
                path=staged_path,
                required=False,
            )

            await self._copy_artifact_to_local_file(
                context,
                url=_lease_url(lease),
                path=staged_path,
            )
            try:
                served_count = await _wait_for_served_receipt(
                    lease,
                    source_ip=target.expected_source_ip,
                )
            except Exception as exc:
                raise ConfigurationSSHError(
                    "CONFIGURATION_CISCO_ARTIFACT_DELIVERY_UNCONFIRMED"
                ) from exc
            if served_count < 1 or served_count > lease.max_reads:
                raise ConfigurationSSHError(
                    "CONFIGURATION_CISCO_ARTIFACT_DELIVERY_UNCONFIRMED"
                )

            # Once the exact artifact has been staged and its source-bound served
            # receipt is proven, the capability URL is no longer needed. Revoke it
            # before the running configuration mutation begins.
            await revoke_artifact_lease(lease.token)
            lease_revoked = True

            replacement_attempted = True
            await self._run_replace_command(
                context,
                url=staged_path,
                confirmation_minutes=int(restore["confirmation_minutes"]),
            )

            provisional = await self.capture(context)
            if provisional.payload != snapshot:
                raise ConfigurationSSHError(
                    "CONFIGURATION_CISCO_RESTORE_PRECONFIRM_MISMATCH"
                )

            # The staged configuration is no longer needed once IOS has applied
            # it and the exact provisional running state has been verified. Remove
            # it before confirming the timed replacement.
            await self._delete_local_staged_file(
                context,
                path=staged_path,
                required=True,
            )
            staged_path = None

            await self._confirm_replace(context)

            confirmed = await self.capture(context)
            if confirmed.payload != snapshot:
                raise ConfigurationSSHError(
                    "CONFIGURATION_CISCO_RESTORE_POSTCONFIRM_MISMATCH"
                )

            result = {
                "restore_mode": _CISCO_RESTORE_MODE,
                "operation_id": target.operation_id,
                "snapshot_id": target.snapshot_id,
                "confirmed": True,
                "verified_sha256": target.expected_plaintext_sha256,
            }
        except Exception:
            if staged_path is not None:
                await self._delete_local_staged_file(
                    context,
                    path=staged_path,
                    required=False,
                )
            if replacement_attempted and restore.get("revert_on_error") is True:
                await self._best_effort_revert(context)
            if not lease_revoked:
                try:
                    await revoke_artifact_lease(lease.token)
                except Exception:
                    pass
            raise

        if not lease_revoked:
            await revoke_artifact_lease(lease.token)
        return result


CISCO_IOS_ADAPTER = CiscoIOSSSHCLIAdapter()
