from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from uuid import UUID

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.configuration.artifacts import ConfigurationArtifactError, decrypt_snapshot, encrypt_snapshot
from app.configuration.contracts import (
    ConfigurationCapability,
    ConfigurationExecutionContext,
    ConfigurationPreMutationError,
    ConfigurationTemplateDefinition,
)
from app.configuration.registry import registry
from app.configuration.ssh_cli import ConfigurationSSHError
from app.configuration.templating import (
    ConfigurationTemplateError,
    definition_sha256,
    function_from_row,
    resolve_parameters,
    unified_diff_text,
)
from app.core.exceptions import APIError
from app.models import (
    AccessTemplateSecret,
    ConfigurationFunction,
    ConfigurationOperation,
    ConfigurationOperationStep,
    ConfigurationSnapshot,
    ConfigurationTemplate,
    ConfigurationTemplateVersion,
    Device,
    DeviceConfigurationBinding,
    DeviceConfigurationState,
    DeviceRemoteAccessProfile,
    DeviceType,
    User,
)
from app.remote_gateway.secrets import RemoteAccessSecretError, resolve_secret_reference
from app.remote_gateway.ssh_transport import (
    SSH_HOST_KEY_LINE_METADATA_KEY,
    SSHTransportError,
)
from app.security.authorization import user_has_permission
from app.security.resource_scope import load_effective_resource_scope
from app.security.scope_queries import require_device
from app.services.access_template_runtime import (
    access_template_ready,
    resolve_ssh_runtime_access,
    resolve_telnet_runtime_access,
)
from app.services.access_templates import (
    AccessTemplateSecretError,
    resolve_effective_access,
)
from app.services.audit import record_audit, record_failure_audit
from app.services.authorization_snapshot import scope_fingerprint, scope_snapshot
from app.services.remote_access import get_management_ip, profile_is_ready
from app.settings import settings


UTC = timezone.utc


def _trusted_ssh_host_key_line(profile: DeviceRemoteAccessProfile) -> str | None:
    value = dict(profile.metadata_ or {}).get(SSH_HOST_KEY_LINE_METADATA_KEY)
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > 16384:
        return None
    return value


class ConfigurationVerificationError(RuntimeError):
    pass


class ConfigurationDeviceRejectionError(RuntimeError):
    pass


def utcnow() -> datetime:
    return datetime.now(UTC)


def _capability_set(values: list[str] | set[str]) -> set[ConfigurationCapability]:
    try:
        return {ConfigurationCapability(str(item)) for item in values}
    except ValueError as exc:
        raise ConfigurationTemplateError("CONFIGURATION_TEMPLATE_CAPABILITY_INVALID") from exc


def _definition_from_version(
    version: ConfigurationTemplateVersion,
    functions: list[ConfigurationFunction],
) -> ConfigurationTemplateDefinition:
    payload = {
        "adapter_key": version.adapter_key,
        "transport": version.transport,
        "capabilities": version.capabilities or [],
        "parameters": (version.parameter_schema or {}).get("parameters", []),
        "transport_parameters": version.transport_parameters or {},
        "functions": [function_from_row(row).model_dump(mode="json") for row in functions],
    }
    return ConfigurationTemplateDefinition.model_validate(payload)


async def _functions_for_version(
    db: AsyncSession,
    version_id: UUID,
) -> list[ConfigurationFunction]:
    return list(
        (
            await db.scalars(
                select(ConfigurationFunction)
                .where(ConfigurationFunction.template_version_id == version_id)
                .order_by(ConfigurationFunction.default_order, ConfigurationFunction.id)
            )
        ).all()
    )


async def _write_definition(
    db: AsyncSession,
    *,
    version: ConfigurationTemplateVersion,
    definition: ConfigurationTemplateDefinition,
) -> None:
    adapter = registry.get(definition.adapter_key)
    registry.validate_capabilities(definition.adapter_key, set(definition.capabilities))
    if adapter.descriptor.transport != definition.transport:
        raise APIError(
            422,
            "CONFIGURATION_ADAPTER_TRANSPORT_MISMATCH",
            "The adapter transport does not match the template transport.",
        )
    try:
        await adapter.validate_template(definition)
    except (ConfigurationTemplateError, ValueError) as exc:
        raise APIError(422, str(exc), "The configuration template definition is invalid.") from exc

    version.adapter_key = definition.adapter_key
    version.transport = definition.transport.value
    version.capabilities = sorted(item.value for item in definition.capabilities)
    version.parameter_schema = {
        "parameters": [item.model_dump(mode="json") for item in definition.parameters]
    }
    version.transport_parameters = definition.transport_parameters
    await db.execute(
        delete(ConfigurationFunction).where(
            ConfigurationFunction.template_version_id == version.id
        )
    )
    for function in definition.functions:
        db.add(
            ConfigurationFunction(
                template_version_id=version.id,
                code=function.code,
                name=function.name,
                category=function.category,
                description=function.description,
                parameter_schema={
                    "parameters": [
                        item.model_dump(mode="json") for item in function.parameters
                    ]
                },
                execution_spec=function.execution_spec,
                verification_spec=function.verification_spec,
                rollback_spec=function.rollback_spec,
                required_capabilities=sorted(
                    item.value for item in function.required_capabilities
                ),
                default_order=function.default_order,
                enabled=function.enabled,
                is_destructive=function.is_destructive,
            )
        )
    await db.flush()


async def create_template(
    db: AsyncSession,
    *,
    payload,
    actor_user_id: UUID,
) -> tuple[ConfigurationTemplate, ConfigurationTemplateVersion]:
    if await db.scalar(
        select(ConfigurationTemplate.id).where(
            func.lower(ConfigurationTemplate.code) == payload.code.strip().lower()
        )
    ):
        raise APIError(
            409,
            "CONFIGURATION_TEMPLATE_CODE_EXISTS",
            "A configuration template with this code already exists.",
        )
    device_type = await db.get(DeviceType, payload.device_type_id)
    if device_type is None:
        raise APIError(404, "DEVICE_TYPE_NOT_FOUND", "Device type not found.")
    template = ConfigurationTemplate(
        code=payload.code.strip(),
        name=payload.name.strip(),
        vendor=payload.vendor.strip(),
        model=payload.model.strip() if payload.model else None,
        series=payload.series.strip() if payload.series else None,
        device_type_id=payload.device_type_id,
        description=payload.description.strip() if payload.description else None,
        is_active=True,
    )
    db.add(template)
    await db.flush()
    version = ConfigurationTemplateVersion(
        template_id=template.id,
        version_number=1,
        status="DRAFT",
        adapter_key=payload.definition.adapter_key,
        transport=payload.definition.transport.value,
        capabilities=[],
        parameter_schema={},
        transport_parameters={},
        change_note="Initial draft",
    )
    db.add(version)
    await db.flush()
    await _write_definition(db, version=version, definition=payload.definition)
    await record_audit(
        db,
        action="CONFIGURATION_TEMPLATE_CREATED",
        entity_type="ConfigurationTemplate",
        entity_id=template.id,
        actor_user_id=actor_user_id,
        description="Configuration template and initial draft created.",
        metadata={"code": template.code, "vendor": template.vendor, "version": 1},
    )
    return template, version


async def update_draft_version(
    db: AsyncSession,
    *,
    template_id: UUID,
    version_id: UUID,
    payload,
    actor_user_id: UUID,
) -> ConfigurationTemplateVersion:
    version = await db.scalar(
        select(ConfigurationTemplateVersion)
        .where(
            ConfigurationTemplateVersion.id == version_id,
            ConfigurationTemplateVersion.template_id == template_id,
        )
        .with_for_update()
    )
    if version is None:
        raise APIError(
            404,
            "CONFIGURATION_TEMPLATE_VERSION_NOT_FOUND",
            "Configuration template version not found.",
        )
    if version.status != "DRAFT":
        raise APIError(
            409,
            "CONFIGURATION_TEMPLATE_VERSION_IMMUTABLE",
            "Published or retired template versions cannot be edited.",
        )
    version.change_note = payload.change_note.strip() if payload.change_note else None
    await _write_definition(db, version=version, definition=payload.definition)
    await record_audit(
        db,
        action="CONFIGURATION_TEMPLATE_DRAFT_UPDATED",
        entity_type="ConfigurationTemplateVersion",
        entity_id=version.id,
        actor_user_id=actor_user_id,
        description="Configuration template draft updated.",
        metadata={"template_id": str(template_id)},
    )
    return version


async def create_template_version(
    db: AsyncSession,
    *,
    template_id: UUID,
    payload,
    actor_user_id: UUID,
) -> ConfigurationTemplateVersion:
    template = await db.scalar(
        select(ConfigurationTemplate)
        .where(
            ConfigurationTemplate.id == template_id,
            ConfigurationTemplate.is_active.is_(True),
        )
        .with_for_update()
    )
    if template is None:
        raise APIError(
            404, "CONFIGURATION_TEMPLATE_NOT_FOUND", "Configuration template not found."
        )
    max_version = int(
        await db.scalar(
            select(func.max(ConfigurationTemplateVersion.version_number)).where(
                ConfigurationTemplateVersion.template_id == template_id
            )
        )
        or 0
    )
    version = ConfigurationTemplateVersion(
        template_id=template_id,
        version_number=max_version + 1,
        status="DRAFT",
        adapter_key=payload.definition.adapter_key,
        transport=payload.definition.transport.value,
        capabilities=[],
        parameter_schema={},
        transport_parameters={},
        change_note=payload.change_note,
    )
    db.add(version)
    await db.flush()
    await _write_definition(db, version=version, definition=payload.definition)
    await record_audit(
        db,
        action="CONFIGURATION_TEMPLATE_VERSION_CREATED",
        entity_type="ConfigurationTemplateVersion",
        entity_id=version.id,
        actor_user_id=actor_user_id,
        description="New configuration template draft version created.",
        metadata={"template_id": str(template_id), "version": version.version_number},
    )
    return version


async def publish_template_version(
    db: AsyncSession,
    *,
    template_id: UUID,
    version_id: UUID,
    actor_user_id: UUID,
) -> ConfigurationTemplateVersion:
    versions = list(
        (
            await db.scalars(
                select(ConfigurationTemplateVersion)
                .where(ConfigurationTemplateVersion.template_id == template_id)
                .with_for_update()
            )
        ).all()
    )
    target = next((row for row in versions if row.id == version_id), None)
    if target is None:
        raise APIError(
            404,
            "CONFIGURATION_TEMPLATE_VERSION_NOT_FOUND",
            "Configuration template version not found.",
        )
    if target.status != "DRAFT":
        raise APIError(
            409,
            "CONFIGURATION_TEMPLATE_VERSION_NOT_DRAFT",
            "Only a draft template version can be published.",
        )
    functions = await _functions_for_version(db, target.id)
    definition = _definition_from_version(target, functions)
    adapter = registry.get(target.adapter_key)
    try:
        await adapter.validate_template(definition)
    except (ConfigurationTemplateError, ValueError) as exc:
        raise APIError(422, str(exc), "The configuration template cannot be published.") from exc

    for row in versions:
        if row.status == "PUBLISHED":
            row.status = "RETIRED"
    await db.flush()

    target.status = "PUBLISHED"
    target.content_sha256 = definition_sha256(definition)
    target.published_at = utcnow()
    target.published_by_user_id = actor_user_id
    await db.flush()
    await record_audit(
        db,
        action="CONFIGURATION_TEMPLATE_VERSION_PUBLISHED",
        entity_type="ConfigurationTemplateVersion",
        entity_id=target.id,
        actor_user_id=actor_user_id,
        description="Configuration template version published.",
        metadata={
            "template_id": str(template_id),
            "version": target.version_number,
            "content_sha256": target.content_sha256,
        },
    )
    return target


async def bind_device(
    db: AsyncSession,
    *,
    device: Device,
    payload,
    actor_user_id: UUID,
) -> DeviceConfigurationBinding:
    version = await db.scalar(
        select(ConfigurationTemplateVersion).where(
            ConfigurationTemplateVersion.id == payload.template_version_id
        )
    )
    if version is None or version.status != "PUBLISHED":
        raise APIError(
            422,
            "CONFIGURATION_TEMPLATE_PUBLISHED_VERSION_REQUIRED",
            "The device must be bound to a published template version.",
        )
    template = await db.get(ConfigurationTemplate, version.template_id)
    if template is None or not template.is_active:
        raise APIError(
            422,
            "CONFIGURATION_TEMPLATE_INACTIVE",
            "The selected configuration template is inactive.",
        )
    try:
        await _assert_version_integrity(db, version)
    except (KeyError, ValueError, ConfigurationTemplateError) as exc:
        raise APIError(
            422,
            "CONFIGURATION_TEMPLATE_VERSION_INTEGRITY_FAILED",
            "The published configuration template version failed its integrity check.",
        ) from exc
    if template.device_type_id != device.device_type_id:
        raise APIError(
            422,
            "CONFIGURATION_TEMPLATE_DEVICE_TYPE_MISMATCH",
            "The template device type does not match this device.",
        )
    try:
        adapter = registry.get(version.adapter_key)
        adapter.validate_connection_overrides(payload.connection_overrides or {})
    except (KeyError, ValueError, ConfigurationTemplateError) as exc:
        raise APIError(
            422,
            str(exc).strip("'"),
            "The device configuration connection overrides are invalid for this adapter.",
        ) from exc
    if payload.credential_source == "REMOTE_ACCESS_PROFILE":
        if payload.connection_overrides:
            raise APIError(
                422,
                "CONFIGURATION_REMOTE_PROFILE_OVERRIDE_FORBIDDEN",
                "SSH connection metadata must be managed on the remote-access profile when that profile supplies credentials.",
            )
        if version.transport != "SSH_CLI":
            raise APIError(
                422,
                "CONFIGURATION_REMOTE_PROFILE_TRANSPORT_UNSUPPORTED",
                "The existing remote-access profile can only back SSH_CLI configuration templates.",
            )
        profile = await db.scalar(
            select(DeviceRemoteAccessProfile).where(
                DeviceRemoteAccessProfile.device_id == device.id
            )
        )
        if not profile_is_ready(profile):
            raise APIError(
                422,
                "CONFIGURATION_REMOTE_ACCESS_PROFILE_NOT_READY",
                "The device SSH remote-access profile is not ready.",
            )
    elif payload.credential_source == "ACCESS_TEMPLATE":
        if payload.connection_overrides:
            raise APIError(
                422,
                "CONFIGURATION_ACCESS_TEMPLATE_OVERRIDE_FORBIDDEN",
                "Access Template connection settings cannot be overridden on the configuration binding.",
            )
        if version.transport == "SSH_CLI":
            ready = await access_template_ready(db, device_id=device.id, protocol="SSH")
            if ready is not True:
                raise APIError(
                    422,
                    "CONFIGURATION_ACCESS_TEMPLATE_NOT_READY",
                    "The device has no ready effective SSH Access Template.",
                )
            profile = await db.scalar(
                select(DeviceRemoteAccessProfile).where(
                    DeviceRemoteAccessProfile.device_id == device.id
                )
            )
            if profile is None or not profile.ssh_host_key_fingerprint:
                raise APIError(
                    422,
                    "CONFIGURATION_HOST_KEY_FINGERPRINT_REQUIRED",
                    "SSH configuration through an Access Template still requires a device-specific pinned SHA256 host-key fingerprint.",
                )
        elif version.transport == "TELNET_CLI":
            ready = await access_template_ready(db, device_id=device.id, protocol="TELNET")
            if ready is not True:
                raise APIError(
                    422,
                    "CONFIGURATION_ACCESS_TEMPLATE_NOT_READY",
                    "The device has no ready effective Telnet Access Template.",
                )
        else:
            raise APIError(
                422,
                "CONFIGURATION_ACCESS_TEMPLATE_TRANSPORT_UNSUPPORTED",
                "Access Template credentials currently support SSH_CLI and TELNET_CLI configuration transports.",
            )
    elif version.transport == "SSH_CLI" and not (
        payload.connection_overrides or {}
    ).get("host_key_fingerprint"):
        raise APIError(
            422,
            "CONFIGURATION_HOST_KEY_FINGERPRINT_REQUIRED",
            "SSH configuration templates using ENV_REFERENCE credentials require a pinned SHA256 host-key fingerprint in the device binding.",
        )

    active_operation = await db.scalar(
        select(ConfigurationOperation.id).where(
            ConfigurationOperation.device_id == device.id,
            ConfigurationOperation.status.in_(("QUEUED", "RUNNING", "ROLLING_BACK")),
        )
    )
    if active_operation is not None:
        raise APIError(
            409,
            "CONFIGURATION_DEVICE_OPERATION_ACTIVE",
            "The device configuration binding cannot change while an operation is active.",
        )

    binding = await db.scalar(
        select(DeviceConfigurationBinding)
        .where(DeviceConfigurationBinding.device_id == device.id)
        .with_for_update()
    )
    if binding is None:
        binding = DeviceConfigurationBinding(
            device_id=device.id, template_version_id=version.id
        )
        db.add(binding)
    binding.template_version_id = version.id
    binding.credential_source = payload.credential_source
    binding.credential_reference = payload.credential_reference
    binding.connection_overrides = payload.connection_overrides
    binding.enabled = payload.enabled
    binding.bound_by_user_id = actor_user_id
    binding.bound_at = utcnow()
    await db.flush()
    await record_audit(
        db,
        action="DEVICE_CONFIGURATION_TEMPLATE_BOUND",
        entity_type="Device",
        entity_id=device.id,
        actor_user_id=actor_user_id,
        description="Device bound to a published configuration template version.",
        metadata={
            "template_id": str(template.id),
            "template_version_id": str(version.id),
            "credential_source": binding.credential_source,
        },
    )
    return binding


def _required_permission(operation_type: str) -> str:
    return {
        "CAPTURE": "device.configuration.capture",
        "APPLY": "device.configuration.apply",
        "VERIFY": "device.configuration.capture",
        "RESTORE": "device.configuration.restore",
    }[operation_type]


def _required_capabilities(operation_type: str) -> set[ConfigurationCapability]:
    return {
        "CAPTURE": {ConfigurationCapability.CAPTURE},
        "VERIFY": {ConfigurationCapability.CAPTURE, ConfigurationCapability.VERIFY},
        "RESTORE": {
            ConfigurationCapability.CAPTURE,
            ConfigurationCapability.RESTORE,
            ConfigurationCapability.ROLLBACK,
        },
        "APPLY": {
            ConfigurationCapability.CAPTURE,
            ConfigurationCapability.APPLY,
            ConfigurationCapability.VERIFY,
            ConfigurationCapability.RESTORE,
            ConfigurationCapability.ROLLBACK,
        },
    }[operation_type]


def _validate_operation_capabilities(
    version: ConfigurationTemplateVersion,
    operation_type: str,
) -> None:
    required = _required_capabilities(operation_type)
    declared = _capability_set(set(version.capabilities or []))
    if not required.issubset(declared):
        raise ConfigurationTemplateError(
            "CONFIGURATION_TEMPLATE_CAPABILITY_UNAVAILABLE"
        )
    registry.validate_capabilities(version.adapter_key, required)


async def _assert_version_integrity(
    db: AsyncSession,
    version: ConfigurationTemplateVersion,
) -> ConfigurationTemplateDefinition:
    if version.status not in {"PUBLISHED", "RETIRED"} or not version.content_sha256:
        raise ConfigurationTemplateError(
            "CONFIGURATION_TEMPLATE_VERSION_INTEGRITY_FAILED"
        )
    functions = await _functions_for_version(db, version.id)
    definition = _definition_from_version(version, functions)
    if definition_sha256(definition) != version.content_sha256:
        raise ConfigurationTemplateError(
            "CONFIGURATION_TEMPLATE_VERSION_INTEGRITY_FAILED"
        )
    adapter = registry.get(version.adapter_key)
    try:
        await adapter.validate_template(definition)
    except (ConfigurationTemplateError, ValueError) as exc:
        raise ConfigurationTemplateError(
            "CONFIGURATION_TEMPLATE_VERSION_INTEGRITY_FAILED"
        ) from exc
    return definition


def _canonical_request_value(value):
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in {float("inf"), float("-inf")}:
            raise APIError(422, "CONFIGURATION_REQUEST_VALUE_INVALID", "Configuration request values must be finite JSON values.")
        return value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, list | tuple):
        return [_canonical_request_value(item) for item in value]
    if isinstance(value, dict):
        output = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise APIError(422, "CONFIGURATION_REQUEST_VALUE_INVALID", "Configuration request object keys must be strings.")
            output[key] = _canonical_request_value(item)
        return output
    raise APIError(422, "CONFIGURATION_REQUEST_VALUE_INVALID", "Configuration request contains an unsupported value type.")


def _request_fingerprint(
    *,
    operation_type: str,
    steps: list | None,
    snapshot_id: UUID | None,
) -> str:
    payload = {
        "operation_type": operation_type,
        "snapshot_id": str(snapshot_id) if snapshot_id else None,
        "steps": [
            {
                "function_id": str(item.function_id),
                "parameters": _canonical_request_value(dict(item.parameters or {})),
            }
            for item in (steps or [])
        ],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


async def queue_operation(
    db: AsyncSession,
    *,
    device: Device,
    actor: User,
    scope,
    operation_type: str,
    idempotency_key: str | None,
    steps: list | None = None,
    snapshot_id: UUID | None = None,
) -> tuple[ConfigurationOperation, bool]:
    request_fingerprint = _request_fingerprint(
        operation_type=operation_type,
        steps=steps,
        snapshot_id=snapshot_id,
    )
    if idempotency_key:
        existing_op = await db.scalar(
            select(ConfigurationOperation).where(
                ConfigurationOperation.actor_user_id == actor.id,
                ConfigurationOperation.device_id == device.id,
                ConfigurationOperation.idempotency_key == idempotency_key,
            )
        )
        if existing_op is not None:
            existing_fingerprint = str(
                (existing_op.request_summary or {}).get("request_fingerprint") or ""
            )
            if (
                existing_op.operation_type == operation_type
                and existing_fingerprint == request_fingerprint
            ):
                return existing_op, False
            raise APIError(
                409,
                "CONFIGURATION_IDEMPOTENCY_KEY_REUSED",
                "The idempotency key was already used for a different configuration request.",
            )

    binding = await db.scalar(
        select(DeviceConfigurationBinding).where(
            DeviceConfigurationBinding.device_id == device.id,
            DeviceConfigurationBinding.enabled.is_(True),
        )
    )
    if binding is None:
        raise APIError(
            422,
            "CONFIGURATION_DEVICE_NOT_BOUND",
            "The device is not bound to an enabled configuration template.",
        )
    version = await db.get(ConfigurationTemplateVersion, binding.template_version_id)
    if version is None or version.status not in {"PUBLISHED", "RETIRED"}:
        raise APIError(
            422,
            "CONFIGURATION_TEMPLATE_VERSION_UNAVAILABLE",
            "The bound configuration template version is unavailable.",
        )
    try:
        await _assert_version_integrity(db, version)
        _validate_operation_capabilities(version, operation_type)
    except (KeyError, ValueError, ConfigurationTemplateError) as exc:
        raise APIError(
            422,
            "CONFIGURATION_OPERATION_CAPABILITY_UNAVAILABLE",
            "The bound template version or adapter does not support the requested guarded operation.",
        ) from exc

    existing = await db.scalar(
        select(ConfigurationOperation.id).where(
            ConfigurationOperation.device_id == device.id,
            ConfigurationOperation.status.in_(("QUEUED", "RUNNING", "ROLLING_BACK")),
        )
    )
    if existing is not None:
        raise APIError(
            409,
            "CONFIGURATION_DEVICE_OPERATION_ACTIVE",
            "Another configuration operation is already active for this device.",
        )

    selected_snapshot = None
    if snapshot_id is not None:
        selected_snapshot = await db.scalar(
            select(ConfigurationSnapshot).where(
                ConfigurationSnapshot.id == snapshot_id,
                ConfigurationSnapshot.device_id == device.id,
                ConfigurationSnapshot.artifact_status == "READY",
            )
        )
        if selected_snapshot is None:
            raise APIError(
                404,
                "CONFIGURATION_SNAPSHOT_NOT_FOUND",
                "Configuration snapshot not found.",
            )
        if (
            selected_snapshot.template_version_id != version.id
            or selected_snapshot.adapter_key != version.adapter_key
        ):
            raise APIError(
                409,
                "CONFIGURATION_SNAPSHOT_TEMPLATE_VERSION_MISMATCH",
                "The selected snapshot was captured under a different template version or adapter.",
            )
        if operation_type == "RESTORE" and not selected_snapshot.is_restorable:
            raise APIError(
                422,
                "CONFIGURATION_SNAPSHOT_NOT_RESTORABLE",
                "The selected snapshot cannot be restored.",
            )

    operation = ConfigurationOperation(
        device_id=device.id,
        template_version_id=version.id,
        actor_user_id=actor.id,
        operation_type=operation_type,
        status="QUEUED",
        idempotency_key=idempotency_key,
        candidate_snapshot_id=selected_snapshot.id if selected_snapshot else None,
        authorization_scope=scope_snapshot(scope),
        authorization_scope_fingerprint=scope_fingerprint(scope),
        request_summary={
            "required_permission": _required_permission(operation_type),
            "request_fingerprint": request_fingerprint,
            "phase": "F1_PACKAGE_2",
        },
    )
    db.add(operation)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise APIError(
            409,
            "CONFIGURATION_OPERATION_CONFLICT",
            "A conflicting configuration operation already exists.",
        ) from exc

    if operation_type == "APPLY":
        rows = await _functions_for_version(db, version.id)
        by_id = {row.id: row for row in rows if row.enabled}
        for order, requested in enumerate(steps or []):
            row = by_id.get(requested.function_id)
            if row is None:
                raise APIError(
                    422,
                    "CONFIGURATION_FUNCTION_UNAVAILABLE",
                    "A selected configuration function is unavailable for the bound template version.",
                )
            definition = function_from_row(row)
            if ConfigurationCapability.APPLY not in {
                ConfigurationCapability(str(item)) for item in definition.required_capabilities
            }:
                raise APIError(
                    422,
                    "CONFIGURATION_FUNCTION_NOT_APPLICABLE",
                    "A selected function is not declared as an APPLY function.",
                )
            try:
                _, summary = resolve_parameters(definition.parameters, requested.parameters)
            except ConfigurationTemplateError as exc:
                raise APIError(
                    422,
                    str(exc),
                    f"Parameters for function '{row.code}' are invalid.",
                ) from exc
            db.add(
                ConfigurationOperationStep(
                    operation_id=operation.id,
                    function_id=row.id,
                    step_order=order,
                    function_code_snapshot=row.code,
                    function_name_snapshot=row.name,
                    status="PENDING",
                    parameter_summary=summary,
                )
            )
        await db.flush()

    await record_audit(
        db,
        action=f"DEVICE_CONFIGURATION_{operation_type}_QUEUED",
        entity_type="ConfigurationOperation",
        entity_id=operation.id,
        actor_user_id=actor.id,
        description="Single-device configuration operation queued.",
        metadata={
            "device_id": str(device.id),
            "operation_type": operation_type,
            "template_version_id": str(version.id),
        },
    )
    return operation, True


async def _execution_target_fingerprint(
    db: AsyncSession,
    operation: ConfigurationOperation,
) -> str:
    binding = await db.scalar(
        select(DeviceConfigurationBinding).where(
            DeviceConfigurationBinding.device_id == operation.device_id,
            DeviceConfigurationBinding.enabled.is_(True),
        )
    )
    if binding is None or binding.template_version_id != operation.template_version_id:
        raise ConfigurationTemplateError("CONFIGURATION_BINDING_CHANGED")
    management = await get_management_ip(db, operation.device_id)
    if not management:
        raise ConfigurationTemplateError("CONFIGURATION_MANAGEMENT_IP_REQUIRED")

    payload: dict[str, object] = {
        "device_id": str(operation.device_id),
        "management_address": str(management),
        "template_version_id": str(binding.template_version_id),
        "credential_source": binding.credential_source,
        "credential_reference": binding.credential_reference,
        "connection_overrides": _canonical_request_value(
            dict(binding.connection_overrides or {})
        ),
    }
    if binding.credential_source == "REMOTE_ACCESS_PROFILE":
        profile = await db.scalar(
            select(DeviceRemoteAccessProfile).where(
                DeviceRemoteAccessProfile.device_id == operation.device_id
            )
        )
        if not profile_is_ready(profile):
            raise ConfigurationTemplateError(
                "CONFIGURATION_REMOTE_ACCESS_PROFILE_NOT_READY"
            )
        payload["remote_access_profile"] = {
            "ssh_port": profile.ssh_port,
            "ssh_compatibility_profile": profile.ssh_compatibility_profile,
            "ssh_host_key_fingerprint": profile.ssh_host_key_fingerprint,
            "ssh_username_reference": profile.ssh_username_reference,
            "ssh_password_reference": profile.ssh_password_reference,
            "ssh_private_key_reference": profile.ssh_private_key_reference,
        }
    elif binding.credential_source == "ACCESS_TEMPLATE":
        version = await db.get(ConfigurationTemplateVersion, binding.template_version_id)
        if version is None:
            raise ConfigurationTemplateError("CONFIGURATION_TEMPLATE_VERSION_UNAVAILABLE")
        protocol = "SSH" if version.transport == "SSH_CLI" else "TELNET" if version.transport == "TELNET_CLI" else None
        if protocol is None:
            raise ConfigurationTemplateError("CONFIGURATION_ACCESS_TEMPLATE_TRANSPORT_UNSUPPORTED")
        effective = await resolve_effective_access(
            db, device_id=operation.device_id, protocol=protocol
        )
        if effective.status == "CONFLICT":
            raise ConfigurationTemplateError("CONFIGURATION_CONFLICT")
        if effective.status != "RESOLVED" or effective.template is None or effective.assignment is None:
            raise ConfigurationTemplateError("CONFIGURATION_ACCESS_TEMPLATE_NOT_READY")
        secret_rows = list(
            (
                await db.scalars(
                    select(AccessTemplateSecret)
                    .where(AccessTemplateSecret.template_id == effective.template.id)
                    .order_by(AccessTemplateSecret.secret_key)
                )
            ).all()
        )
        secret_state = []
        for row in secret_rows:
            secret_state.append(
                {
                    "secret_key": row.secret_key,
                    "provider": row.provider,
                    "key_version": row.key_version,
                    "reference": row.reference,
                    "encrypted_payload_sha256": hashlib.sha256(
                        (row.encrypted_payload or "").encode("utf-8")
                    ).hexdigest()
                    if row.encrypted_payload
                    else None,
                    "updated_at": row.updated_at.isoformat() if row.updated_at else None,
                }
            )
        payload["access_template"] = {
            "template_id": str(effective.template.id),
            "assignment_id": str(effective.assignment.id),
            "protocol": effective.template.protocol,
            "protocol_variant": effective.template.protocol_variant,
            "settings": _canonical_request_value(dict(effective.template.settings_json or {})),
            "template_updated_at": effective.template.updated_at.isoformat() if effective.template.updated_at else None,
            "secret_state": secret_state,
        }
        if protocol == "SSH":
            profile = await db.scalar(
                select(DeviceRemoteAccessProfile).where(
                    DeviceRemoteAccessProfile.device_id == operation.device_id
                )
            )
            if profile is None or not profile.ssh_host_key_fingerprint:
                raise ConfigurationTemplateError("CONFIGURATION_HOST_KEY_FINGERPRINT_REQUIRED")
            payload["access_template"]["ssh_host_key_fingerprint"] = profile.ssh_host_key_fingerprint
    encoded = json.dumps(
        _canonical_request_value(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


async def _initialize_execution_target_guard(
    db: AsyncSession,
    operation: ConfigurationOperation,
) -> None:
    current = await _execution_target_fingerprint(db, operation)
    summary = dict(operation.request_summary or {})
    existing = str(summary.get("execution_target_fingerprint") or "")
    if existing and existing != current:
        raise ConfigurationTemplateError("CONFIGURATION_EXECUTION_TARGET_CHANGED")
    if not existing:
        summary["execution_target_fingerprint"] = current
        operation.request_summary = summary
        await db.flush()


async def _assert_execution_target_unchanged(
    db: AsyncSession,
    operation: ConfigurationOperation,
) -> None:
    expected = str(
        (operation.request_summary or {}).get("execution_target_fingerprint") or ""
    )
    if not expected:
        raise ConfigurationTemplateError("CONFIGURATION_EXECUTION_TARGET_GUARD_MISSING")
    current = await _execution_target_fingerprint(db, operation)
    if current != expected:
        raise ConfigurationTemplateError("CONFIGURATION_EXECUTION_TARGET_CHANGED")


async def _connection_context(
    db: AsyncSession,
    operation: ConfigurationOperation,
) -> tuple[ConfigurationExecutionContext, ConfigurationTemplateVersion, object]:
    await _assert_execution_target_unchanged(db, operation)
    binding = await db.scalar(
        select(DeviceConfigurationBinding).where(
            DeviceConfigurationBinding.device_id == operation.device_id,
            DeviceConfigurationBinding.enabled.is_(True),
        )
    )
    if binding is None or binding.template_version_id != operation.template_version_id:
        raise ConfigurationTemplateError("CONFIGURATION_BINDING_CHANGED")
    version = await db.get(ConfigurationTemplateVersion, binding.template_version_id)
    if version is None:
        raise ConfigurationTemplateError("CONFIGURATION_TEMPLATE_VERSION_UNAVAILABLE")
    await _assert_version_integrity(db, version)
    _validate_operation_capabilities(version, operation.operation_type)
    management = await get_management_ip(db, operation.device_id)
    if not management:
        raise ConfigurationTemplateError("CONFIGURATION_MANAGEMENT_IP_REQUIRED")

    connection: dict[str, object] = dict(binding.connection_overrides or {})
    connection["template_transport_parameters"] = version.transport_parameters or {}
    for key in ("prompt_pattern", "command_timeout_seconds"):
        if key in (version.transport_parameters or {}):
            connection[key] = (version.transport_parameters or {})[key]

    if binding.credential_source == "REMOTE_ACCESS_PROFILE":
        profile = await db.scalar(
            select(DeviceRemoteAccessProfile).where(
                DeviceRemoteAccessProfile.device_id == operation.device_id
            )
        )
        if not profile_is_ready(profile):
            raise ConfigurationTemplateError("CONFIGURATION_REMOTE_ACCESS_PROFILE_NOT_READY")
        connection.update(
            {
                "port": profile.ssh_port,
                "compatibility_profile": profile.ssh_compatibility_profile,
                "host_key_fingerprint": profile.ssh_host_key_fingerprint,
                "trusted_host_key_line": _trusted_ssh_host_key_line(profile),
                "username": resolve_secret_reference(profile.ssh_username_reference),
                "password": resolve_secret_reference(profile.ssh_password_reference)
                if profile.ssh_password_reference
                else None,
                "private_key": resolve_secret_reference(profile.ssh_private_key_reference)
                if profile.ssh_private_key_reference
                else None,
            }
        )
    elif binding.credential_source == "ACCESS_TEMPLATE":
        if binding.connection_overrides:
            raise ConfigurationTemplateError("CONFIGURATION_ACCESS_TEMPLATE_OVERRIDE_FORBIDDEN")
        if version.transport == "SSH_CLI":
            runtime = await resolve_ssh_runtime_access(db, device_id=operation.device_id)
            if runtime is None:
                raise ConfigurationTemplateError("CONFIGURATION_ACCESS_TEMPLATE_NOT_READY")
            if runtime.private_key and runtime.private_key_passphrase:
                raise ConfigurationTemplateError(
                    "CONFIGURATION_SSH_PRIVATE_KEY_PASSPHRASE_UNSUPPORTED"
                )
            profile = await db.scalar(
                select(DeviceRemoteAccessProfile).where(
                    DeviceRemoteAccessProfile.device_id == operation.device_id
                )
            )
            if profile is None or not profile.ssh_host_key_fingerprint:
                raise ConfigurationTemplateError("CONFIGURATION_HOST_KEY_FINGERPRINT_REQUIRED")
            connection.update(
                {
                    "port": runtime.port,
                    "compatibility_profile": runtime.compatibility_profile,
                    "host_key_fingerprint": profile.ssh_host_key_fingerprint,
                "trusted_host_key_line": _trusted_ssh_host_key_line(profile),
                    "username": runtime.username,
                    "password": runtime.password,
                    "private_key": runtime.private_key,
                }
            )
        elif version.transport == "TELNET_CLI":
            if not settings.telnet_access_enabled:
                raise ConfigurationTemplateError("CONFIGURATION_TELNET_DISABLED")
            runtime = await resolve_telnet_runtime_access(db, device_id=operation.device_id)
            if runtime is None:
                raise ConfigurationTemplateError("CONFIGURATION_ACCESS_TEMPLATE_NOT_READY")
            connection.update(
                {
                    "port": runtime.port,
                    "username": runtime.username,
                    "password": runtime.password,
                }
            )
        else:
            raise ConfigurationTemplateError(
                "CONFIGURATION_ACCESS_TEMPLATE_TRANSPORT_UNSUPPORTED"
            )
    else:
        secret = resolve_secret_reference(binding.credential_reference)
        try:
            payload = json.loads(secret)
        except json.JSONDecodeError as exc:
            raise ConfigurationTemplateError("CONFIGURATION_CREDENTIAL_JSON_INVALID") from exc
        if not isinstance(payload, dict) or not payload or len(payload) > 32:
            raise ConfigurationTemplateError("CONFIGURATION_CREDENTIAL_JSON_INVALID")
        reserved = {
            "template_transport_parameters",
            "prompt_pattern",
            "command_timeout_seconds",
            "port",
            "host_key_fingerprint",
            "compatibility_profile",
        }
        for key, value in payload.items():
            if (
                not isinstance(key, str)
                or not key
                or len(key) > 80
                or not key.replace("_", "A").isalnum()
                or key[0].isdigit()
                or key in reserved
                or not isinstance(value, str)
                or not value
                or len(value) > 131072
            ):
                raise ConfigurationTemplateError(
                    "CONFIGURATION_CREDENTIAL_JSON_FIELD_UNSUPPORTED"
                )
        connection.update(payload)

    adapter = registry.get(version.adapter_key)
    try:
        adapter.validate_connection_overrides(binding.connection_overrides or {})
    except ValueError as exc:
        raise ConfigurationTemplateError(str(exc).strip("'")) from exc
    return (
        ConfigurationExecutionContext(
            device_id=str(operation.device_id),
            management_address=management,
            template_version_id=str(version.id),
            connection_parameters=connection,
        ),
        version,
        adapter,
    )


async def _persist_capture_result(
    db: AsyncSession,
    *,
    operation: ConfigurationOperation,
    adapter,
    kind: str,
    result,
) -> tuple[ConfigurationSnapshot, bytes]:
    """Persist an already-captured payload without performing another device read."""
    if not result.payload:
        raise ConfigurationTemplateError("CONFIGURATION_CAPTURE_EMPTY")
    if len(result.payload) > settings.configuration_artifact_max_bytes:
        raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_TOO_LARGE")
    snapshot = ConfigurationSnapshot(
        device_id=operation.device_id,
        template_version_id=operation.template_version_id,
        created_by_user_id=operation.actor_user_id,
        snapshot_kind=kind,
        adapter_key=adapter.descriptor.key,
        artifact_status="PENDING",
        is_restorable=False,
        metadata_={
            "operation_id": str(operation.id),
            "source": "DEVICE",
            **dict(result.metadata or {}),
        },
    )
    db.add(snapshot)
    await db.flush()
    artifact = encrypt_snapshot(
        device_id=operation.device_id,
        snapshot_id=snapshot.id,
        plaintext=result.payload,
    )
    for key, value in artifact.items():
        setattr(snapshot, key, value)
    snapshot.normalized_sha256 = hashlib.sha256(result.payload).hexdigest()
    snapshot.artifact_status = "READY"
    snapshot.is_restorable = bool(result.restorable)
    await db.flush()
    return snapshot, result.payload


async def _capture_snapshot(
    db: AsyncSession,
    *,
    operation: ConfigurationOperation,
    context: ConfigurationExecutionContext,
    adapter,
    kind: str,
) -> tuple[ConfigurationSnapshot, bytes]:
    result = await adapter.capture(context)
    return await _persist_capture_result(
        db,
        operation=operation,
        adapter=adapter,
        kind=kind,
        result=result,
    )


async def _load_snapshot_bytes(snapshot: ConfigurationSnapshot) -> bytes:
    if (
        not snapshot.artifact_path
        or not snapshot.artifact_sha256
        or not snapshot.encryption_key_reference
    ):
        raise ConfigurationArtifactError("CONFIGURATION_SNAPSHOT_ARTIFACT_INCOMPLETE")
    return decrypt_snapshot(
        device_id=snapshot.device_id,
        snapshot_id=snapshot.id,
        artifact_path=snapshot.artifact_path,
        expected_sha256=snapshot.artifact_sha256,
        key_reference=snapshot.encryption_key_reference,
    )


async def _operation_steps(
    db: AsyncSession,
    operation: ConfigurationOperation,
) -> list[tuple[ConfigurationOperationStep, ConfigurationFunction, dict, dict]]:
    steps = list(
        (
            await db.scalars(
                select(ConfigurationOperationStep)
                .where(ConfigurationOperationStep.operation_id == operation.id)
                .order_by(ConfigurationOperationStep.step_order)
            )
        ).all()
    )
    if operation.operation_type == "APPLY" and not steps:
        raise ConfigurationTemplateError("CONFIGURATION_OPERATION_STEPS_REQUIRED")
    output = []
    for step in steps:
        function = await db.get(ConfigurationFunction, step.function_id)
        if function is None or function.template_version_id != operation.template_version_id:
            raise ConfigurationTemplateError("CONFIGURATION_FUNCTION_CHANGED")
        if (
            function.code != step.function_code_snapshot
            or function.name != step.function_name_snapshot
        ):
            raise ConfigurationTemplateError("CONFIGURATION_FUNCTION_CHANGED")
        definition = function_from_row(function)
        provided: dict[str, object] = {}
        for item in definition.parameters:
            if item.name not in (step.parameter_summary or {}):
                continue
            stored = step.parameter_summary[item.name]
            if item.sensitive:
                if not isinstance(stored, dict) or not stored.get("reference"):
                    raise ConfigurationTemplateError(
                        "CONFIGURATION_SENSITIVE_PARAMETER_REFERENCE_REQUIRED"
                    )
                provided[item.name] = stored["reference"]
            else:
                provided[item.name] = stored
        values, _ = resolve_parameters(
            definition.parameters,
            provided,
            secret_resolver=resolve_secret_reference,
        )
        output.append(
            (
                step,
                function,
                values,
                {
                    "execution_spec": function.execution_spec or {},
                    "verification_spec": function.verification_spec or {},
                    "rollback_spec": function.rollback_spec or {},
                    "parameters": values,
                },
            )
        )
    return output


async def _state_row(db: AsyncSession, device_id: UUID) -> DeviceConfigurationState:
    row = await db.scalar(
        select(DeviceConfigurationState)
        .where(DeviceConfigurationState.device_id == device_id)
        .with_for_update()
    )
    if row is None:
        row = DeviceConfigurationState(device_id=device_id, drift_status="UNKNOWN")
        db.add(row)
        await db.flush()
    return row


async def _mark_failure(
    db: AsyncSession,
    operation: ConfigurationOperation,
    *,
    stage: str,
    code: str,
    status: str = "FAILED",
    message: str | None = None,
) -> None:
    operation.status = status
    operation.failure_stage = stage
    operation.failure_code = code[:120]
    operation.failure_message = message or (
        "The configuration operation did not complete successfully. "
        "Review the sanitized failure code."
    )
    operation.finished_at = utcnow()
    await record_audit(
        db,
        action=f"DEVICE_CONFIGURATION_{operation.operation_type}_FAILED",
        entity_type="ConfigurationOperation",
        entity_id=operation.id,
        actor_user_id=operation.actor_user_id,
        result="FAILURE",
        description="Single-device configuration operation failed.",
        metadata={
            "device_id": str(operation.device_id),
            "failure_stage": stage,
            "failure_code": code[:120],
        },
    )


async def _reauthorize(db: AsyncSession, operation: ConfigurationOperation) -> None:
    user = await db.scalar(
        select(User).where(
            User.id == operation.actor_user_id,
            User.is_active.is_(True),
        )
    )
    if user is None:
        raise PermissionError("CONFIGURATION_ACTOR_INACTIVE")
    required = str(
        (operation.request_summary or {}).get("required_permission")
        or _required_permission(operation.operation_type)
    )
    if not await user_has_permission(
        db, user_id=user.id, permission_code=required
    ):
        raise PermissionError("CONFIGURATION_PERMISSION_REVOKED")
    scope = await load_effective_resource_scope(db, user.id)
    if scope_fingerprint(scope) != operation.authorization_scope_fingerprint:
        raise PermissionError("CONFIGURATION_SCOPE_CHANGED")
    try:
        await require_device(db, scope, operation.device_id)
    except Exception as exc:
        raise PermissionError("CONFIGURATION_DEVICE_SCOPE_REVOKED") from exc


def _classify_failure(exc: BaseException) -> tuple[str, str]:
    controlled = (
        ConfigurationVerificationError,
        ConfigurationDeviceRejectionError,
        ConfigurationTemplateError,
        ConfigurationPreMutationError,
        ConfigurationSSHError,
        SSHTransportError,
        RemoteAccessSecretError,
        AccessTemplateSecretError,
        ConfigurationArtifactError,
        PermissionError,
    )
    if isinstance(exc, AccessTemplateSecretError):
        raw_code = str(exc).strip("'\"").strip().upper()
        if raw_code and len(raw_code) <= 106 and all(
            character.isalnum() or character == "_" for character in raw_code
        ):
            code = f"CONFIGURATION_{raw_code}"
        else:
            code = "CONFIGURATION_ACCESS_TEMPLATE_SECRET_ERROR"
    else:
        code = (
            str(exc).strip("'")
            if isinstance(exc, controlled)
            else f"CONFIGURATION_INTERNAL_{type(exc).__name__.upper()}"
        )
        if not code or len(code) > 120 or not code.startswith("CONFIGURATION_"):
            code = f"CONFIGURATION_{type(exc).__name__.upper()}"
    if isinstance(exc, PermissionError):
        return "AUTHORIZATION", code
    if isinstance(exc, ConfigurationVerificationError) or "VERIFICATION" in code or "VERIFY_" in code:
        return "VERIFICATION", code
    if isinstance(exc, ConfigurationDeviceRejectionError) or "DEVICE_REJECTION" in code:
        return "DEVICE_REJECTION", code
    if isinstance(exc, ConfigurationTemplateError):
        return "VALIDATION", code
    if isinstance(
        exc,
        (
            ConfigurationPreMutationError,
            ConfigurationSSHError,
            SSHTransportError,
            RemoteAccessSecretError,
            AccessTemplateSecretError,
        ),
    ):
        return "TRANSPORT", code
    if isinstance(exc, ConfigurationArtifactError):
        return "INTERNAL", code
    return "INTERNAL", code


async def _prepare_pre_change_snapshot(
    db: AsyncSession,
    *,
    operation: ConfigurationOperation,
    context: ConfigurationExecutionContext,
    adapter,
) -> UUID:
    first = await adapter.capture(context)
    second = await adapter.capture(context)

    for result in (first, second):
        if not result.payload:
            raise ConfigurationTemplateError("CONFIGURATION_CAPTURE_EMPTY")
        if len(result.payload) > settings.configuration_artifact_max_bytes:
            raise ConfigurationArtifactError("CONFIGURATION_ARTIFACT_TOO_LARGE")
        if not result.restorable:
            raise ConfigurationTemplateError(
                "CONFIGURATION_PRE_CHANGE_SNAPSHOT_NOT_RESTORABLE"
            )

    if first.payload != second.payload:
        raise ConfigurationVerificationError(
            "CONFIGURATION_PRE_CHANGE_CAPTURE_UNSTABLE"
        )

    snapshot, _ = await _persist_capture_result(
        db,
        operation=operation,
        adapter=adapter,
        kind="PRE_CHANGE",
        result=first,
    )
    if not snapshot.is_restorable:
        raise ConfigurationTemplateError(
            "CONFIGURATION_PRE_CHANGE_SNAPSHOT_NOT_RESTORABLE"
        )
    operation.pre_change_snapshot_id = snapshot.id
    # This commit is intentionally before the first mutating device command.
    # A rollback checkpoint is persisted only after two independent restorable
    # captures prove the same exact pre-change payload.
    await db.commit()
    return snapshot.id


async def _rollback_to_pre_change(
    db: AsyncSession,
    *,
    operation_id: UUID,
    stage: str,
    code: str,
) -> str:
    operation = await db.scalar(
        select(ConfigurationOperation)
        .where(ConfigurationOperation.id == operation_id)
        .with_for_update()
    )
    if operation is None:
        return "MISSING"
    pre_id = operation.pre_change_snapshot_id
    if pre_id is None:
        await _mark_failure(db, operation, stage=stage, code=code)
        await db.commit()
        return operation.status

    operation.status = "ROLLING_BACK"
    operation.failure_stage = stage
    operation.failure_code = code[:120]
    # Persist the rollback safety state before observability. The independent
    # failure-audit helper is deliberately non-raising, so audit persistence
    # can never prevent the automatic rollback from being attempted.
    await db.commit()
    await record_failure_audit(
        action="DEVICE_CONFIGURATION_PRIMARY_FAILURE_RECORDED",
        entity_type="ConfigurationOperation",
        entity_id=operation.id,
        actor_user_id=operation.actor_user_id,
        description=(
            "Configuration operation failed before automatic rollback; "
            "the primary failure was preserved independently of rollback outcome."
        ),
        metadata={
            "device_id": str(operation.device_id),
            "operation_type": operation.operation_type,
            "primary_failure_stage": stage,
            "primary_failure_code": code[:120],
            "pre_change_snapshot_id": str(pre_id),
        },
    )

    try:
        operation = await db.scalar(
            select(ConfigurationOperation)
            .where(ConfigurationOperation.id == operation_id)
            .with_for_update()
        )
        context, _, adapter = await _connection_context(db, operation)
        pre = await db.get(ConfigurationSnapshot, pre_id)
        if pre is None or not pre.is_restorable:
            raise ConfigurationArtifactError(
                "CONFIGURATION_PRE_CHANGE_SNAPSHOT_NOT_RESTORABLE"
            )
        pre_payload = await _load_snapshot_bytes(pre)
        await adapter.restore(context, pre_payload)
        rollback_capture, _ = await _capture_snapshot(
            db,
            operation=operation,
            context=context,
            adapter=adapter,
            kind="ROLLBACK",
        )
        operation.rollback_snapshot_id = pre.id
        operation.result_snapshot_id = rollback_capture.id
        if (
            not pre.normalized_sha256
            or rollback_capture.normalized_sha256 != pre.normalized_sha256
        ):
            raise ConfigurationVerificationError(
                "CONFIGURATION_ROLLBACK_VERIFICATION_FAILED"
            )
        state = await _state_row(db, operation.device_id)
        state.last_known_good_snapshot_id = pre.id
        state.last_verified_snapshot_id = rollback_capture.id
        state.last_operation_id = operation.id
        state.drift_status = "IN_SYNC"
        state.last_verified_at = utcnow()
        operation.status = "ROLLED_BACK"
        operation.failure_message = (
            "The requested change failed and the pre-change configuration "
            "was restored and verified."
        )
        operation.finished_at = utcnow()
        await record_audit(
            db,
            action="DEVICE_CONFIGURATION_ROLLED_BACK",
            entity_type="ConfigurationOperation",
            entity_id=operation.id,
            actor_user_id=operation.actor_user_id,
            result="FAILURE",
            description="Configuration change failed; verified rollback completed.",
            metadata={
                "device_id": str(operation.device_id),
                "failure_stage": stage,
                "failure_code": code[:120],
                "snapshot_id": str(pre.id),
            },
        )
        await db.commit()
        return operation.status
    except Exception as rollback_exc:
        await db.rollback()
        operation = await db.scalar(
            select(ConfigurationOperation)
            .where(ConfigurationOperation.id == operation_id)
            .with_for_update()
        )
        if operation is None:
            return "MISSING"
        operation.status = "ROLLBACK_FAILED"
        operation.failure_stage = "ROLLBACK"
        operation.failure_code = (
            f"CONFIGURATION_ROLLBACK_{type(rollback_exc).__name__.upper()}"[:120]
        )
        operation.failure_message = (
            "The requested change failed and rollback could not be verified. "
            "Manual intervention is required."
        )
        operation.finished_at = utcnow()
        state = await _state_row(db, operation.device_id)
        state.drift_status = "UNVERIFIED"
        state.last_operation_id = operation.id
        await record_audit(
            db,
            action="DEVICE_CONFIGURATION_ROLLBACK_FAILED",
            entity_type="ConfigurationOperation",
            entity_id=operation.id,
            actor_user_id=operation.actor_user_id,
            result="FAILURE",
            description=(
                "Configuration rollback could not be verified; manual intervention required."
            ),
            metadata={
                "device_id": str(operation.device_id),
                "failure_code": operation.failure_code,
                "primary_failure_stage": stage,
                "primary_failure_code": code[:120],
                "pre_change_snapshot_id": str(pre_id),
            },
        )
        await db.commit()
        return operation.status


async def mark_interrupted_operation(db: AsyncSession, operation_id: UUID) -> str:
    operation = await db.scalar(
        select(ConfigurationOperation)
        .where(ConfigurationOperation.id == operation_id)
        .with_for_update()
    )
    if operation is None:
        return "MISSING"
    if operation.status not in {"RUNNING", "ROLLING_BACK"}:
        return operation.status

    running_steps = list(
        (
            await db.scalars(
                select(ConfigurationOperationStep).where(
                    ConfigurationOperationStep.operation_id == operation.id,
                    ConfigurationOperationStep.status == "RUNNING",
                )
            )
        ).all()
    )
    for step in running_steps:
        step.status = "FAILED"
        step.failure_code = "CONFIGURATION_WORKER_INTERRUPTED"
        step.failure_message = (
            "Worker interruption left the function outcome unverified."
        )
        step.finished_at = utcnow()

    if operation.status == "ROLLING_BACK":
        primary_failure_stage = operation.failure_stage
        primary_failure_code = operation.failure_code
        operation.status = "ROLLBACK_FAILED"
        operation.failure_stage = "ROLLBACK"
        operation.failure_code = "CONFIGURATION_ROLLBACK_WORKER_INTERRUPTED"
        operation.failure_message = (
            "The configuration worker was interrupted during rollback. "
            "Rollback outcome is unverified and manual intervention is required."
        )
        operation.finished_at = utcnow()
        await record_audit(
            db,
            action="DEVICE_CONFIGURATION_ROLLBACK_FAILED",
            entity_type="ConfigurationOperation",
            entity_id=operation.id,
            actor_user_id=operation.actor_user_id,
            result="FAILURE",
            description="Configuration rollback worker was interrupted; outcome is unverified.",
            metadata={
                "device_id": str(operation.device_id),
                "failure_code": operation.failure_code,
                "primary_failure_stage": primary_failure_stage,
                "primary_failure_code": primary_failure_code,
                "pre_change_snapshot_id": str(operation.pre_change_snapshot_id)
                if operation.pre_change_snapshot_id
                else None,
            },
        )
    else:
        await _mark_failure(
            db,
            operation,
            stage="INTERNAL",
            code="CONFIGURATION_WORKER_INTERRUPTED",
            message=(
                "The configuration worker was interrupted while the operation was running. "
                "Automatic replay was blocked; verify the device before retrying."
            ),
        )

    state = await _state_row(db, operation.device_id)
    state.drift_status = "UNVERIFIED"
    state.last_operation_id = operation.id
    await db.commit()
    return operation.status


async def execute_operation(db: AsyncSession, operation_id: UUID) -> str:
    operation = await db.scalar(
        select(ConfigurationOperation)
        .where(ConfigurationOperation.id == operation_id)
        .with_for_update()
    )
    if operation is None:
        return "MISSING"
    if operation.status != "QUEUED":
        return operation.status

    created_at = operation.created_at
    if created_at is not None:
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)
        max_age = max(60, min(int(settings.configuration_queue_max_age_seconds), 86400))
        if (utcnow() - created_at).total_seconds() > max_age:
            await _mark_failure(
                db,
                operation,
                stage="INTERNAL",
                code="CONFIGURATION_QUEUE_EXPIRED",
                message=(
                    "The queued configuration request exceeded its safe execution window "
                    "and was not sent to the device."
                ),
            )
            await db.commit()
            return operation.status

    try:
        await _reauthorize(db, operation)
    except Exception:
        await _mark_failure(
            db,
            operation,
            stage="AUTHORIZATION",
            code="CONFIGURATION_AUTHORIZATION_REVALIDATION_FAILED",
        )
        await db.commit()
        return operation.status

    operation.status = "RUNNING"
    operation.started_at = operation.started_at or utcnow()
    await db.commit()

    current_step_id: UUID | None = None
    mutation_attempted = False
    pre_mutation_failure = False
    try:
        operation = await db.scalar(
            select(ConfigurationOperation)
            .where(ConfigurationOperation.id == operation_id)
            .with_for_update()
        )
        await _initialize_execution_target_guard(db, operation)
        await db.commit()
        operation = await db.scalar(
            select(ConfigurationOperation)
            .where(ConfigurationOperation.id == operation_id)
            .with_for_update()
        )
        context, version, adapter = await _connection_context(db, operation)

        if operation.operation_type == "CAPTURE":
            snapshot, _ = await _capture_snapshot(
                db,
                operation=operation,
                context=context,
                adapter=adapter,
                kind="CAPTURE",
            )
            operation.result_snapshot_id = snapshot.id
            operation.status = "SUCCEEDED"
            operation.finished_at = utcnow()
            await record_audit(
                db,
                action="DEVICE_CONFIGURATION_CAPTURED",
                entity_type="ConfigurationSnapshot",
                entity_id=snapshot.id,
                actor_user_id=operation.actor_user_id,
                description="Encrypted configuration snapshot captured.",
                metadata={
                    "device_id": str(operation.device_id),
                    "sha256": snapshot.artifact_sha256,
                    "restorable": snapshot.is_restorable,
                },
            )

        elif operation.operation_type == "VERIFY":
            target = await db.get(ConfigurationSnapshot, operation.candidate_snapshot_id)
            if (
                target is None
                or target.artifact_status != "READY"
                or target.template_version_id != operation.template_version_id
                or target.adapter_key != adapter.descriptor.key
            ):
                raise ConfigurationTemplateError(
                    "CONFIGURATION_VERIFY_SNAPSHOT_MISSING"
                )
            current, _ = await _capture_snapshot(
                db,
                operation=operation,
                context=context,
                adapter=adapter,
                kind="POST_CHANGE",
            )
            operation.result_snapshot_id = current.id
            matched = bool(
                target.normalized_sha256
                and current.normalized_sha256 == target.normalized_sha256
            )
            operation.verification_summary = {
                "matched_snapshot": matched,
                "target_snapshot_id": str(target.id),
            }
            if not matched:
                raise ConfigurationVerificationError(
                    "CONFIGURATION_VERIFY_MISMATCH"
                )
            state = await _state_row(db, operation.device_id)
            if target.is_restorable:
                state.last_known_good_snapshot_id = target.id
            state.last_verified_snapshot_id = current.id
            state.last_operation_id = operation.id
            state.drift_status = "IN_SYNC"
            state.last_verified_at = utcnow()
            operation.status = "SUCCEEDED"
            operation.finished_at = utcnow()

        elif operation.operation_type == "RESTORE":
            target = await db.get(ConfigurationSnapshot, operation.candidate_snapshot_id)
            if target is None or target.artifact_status != "READY" or not target.is_restorable:
                raise ConfigurationTemplateError(
                    "CONFIGURATION_RESTORE_SNAPSHOT_INVALID"
                )
            await _prepare_pre_change_snapshot(
                db,
                operation=operation,
                context=context,
                adapter=adapter,
            )
            # From the durable PRE_CHANGE checkpoint until an adapter preflight
            # begins, the remaining core work is known to be non-mutating.
            pre_mutation_failure = True
            operation = await db.scalar(
                select(ConfigurationOperation)
                .where(ConfigurationOperation.id == operation_id)
                .with_for_update()
            )
            context, _, adapter = await _connection_context(db, operation)
            await _reauthorize(db, operation)
            target = await db.get(ConfigurationSnapshot, operation.candidate_snapshot_id)
            if (
                target is None
                or target.template_version_id != operation.template_version_id
                or target.adapter_key != adapter.descriptor.key
                or not target.is_restorable
            ):
                raise ConfigurationTemplateError(
                    "CONFIGURATION_RESTORE_SNAPSHOT_TEMPLATE_MISMATCH"
                )
            target_payload = await _load_snapshot_bytes(target)

            # Optional adapter-specific readiness proof. This hook is
            # contractually non-mutating; Cisco uses it to prove the router can
            # fetch an authorized artifact before configure replace is allowed.
            # An adapter receives the pre-mutation exemption only when it
            # explicitly raises ConfigurationPreMutationError. Any unexpected
            # adapter exception remains conservative and may trigger rollback.
            pre_mutation_failure = False
            try:
                await adapter.preflight_restore(context, target_payload)
            except ConfigurationPreMutationError:
                pre_mutation_failure = True
                raise

            # A successful preflight is also non-mutating by contract.
            pre_mutation_failure = True

            # Close the preflight-to-mutation gap: re-read the operation,
            # execution-target fingerprint, authorization and target binding
            # immediately before invoking the mutation-capable adapter method.
            operation = await db.scalar(
                select(ConfigurationOperation)
                .where(ConfigurationOperation.id == operation_id)
                .with_for_update()
            )
            context, _, adapter = await _connection_context(db, operation)
            await _reauthorize(db, operation)
            target = await db.get(ConfigurationSnapshot, operation.candidate_snapshot_id)
            if (
                target is None
                or target.template_version_id != operation.template_version_id
                or target.adapter_key != adapter.descriptor.key
                or not target.is_restorable
            ):
                raise ConfigurationTemplateError(
                    "CONFIGURATION_RESTORE_SNAPSHOT_TEMPLATE_MISMATCH"
                )
            target_payload = await _load_snapshot_bytes(target)

            mutation_attempted = True
            pre_mutation_failure = False
            await adapter.restore(context, target_payload)
            post, _ = await _capture_snapshot(
                db,
                operation=operation,
                context=context,
                adapter=adapter,
                kind="POST_CHANGE",
            )
            operation.result_snapshot_id = post.id
            if (
                not target.normalized_sha256
                or post.normalized_sha256 != target.normalized_sha256
            ):
                raise ConfigurationVerificationError(
                    "CONFIGURATION_RESTORE_VERIFICATION_FAILED"
                )
            state = await _state_row(db, operation.device_id)
            state.last_known_good_snapshot_id = target.id
            state.last_verified_snapshot_id = post.id
            state.last_operation_id = operation.id
            state.drift_status = "IN_SYNC"
            state.last_verified_at = utcnow()
            operation.verification_summary = {
                "restored": True,
                "target_snapshot_id": str(target.id),
            }
            operation.status = "SUCCEEDED"
            operation.finished_at = utcnow()

        elif operation.operation_type == "APPLY":
            await _prepare_pre_change_snapshot(
                db,
                operation=operation,
                context=context,
                adapter=adapter,
            )
            operation = await db.scalar(
                select(ConfigurationOperation)
                .where(ConfigurationOperation.id == operation_id)
                .with_for_update()
            )
            context, _, adapter = await _connection_context(db, operation)
            steps = await _operation_steps(db, operation)
            function_specs = [item[3] for item in steps]
            await adapter.validate_candidate(context, b"", function_specs)

            for step, _function, _values, spec in steps:
                current_step_id = step.id
                step.status = "RUNNING"
                step.started_at = step.started_at or utcnow()
                step.failure_code = None
                step.failure_message = None
                await db.commit()

                operation = await db.scalar(
                    select(ConfigurationOperation)
                    .where(ConfigurationOperation.id == operation_id)
                    .with_for_update()
                )
                context, _, adapter = await _connection_context(db, operation)
                await _reauthorize(db, operation)
                step = await db.get(ConfigurationOperationStep, current_step_id)
                await adapter.apply(context, b"", [spec])
                verify = await adapter.verify(context, None, [spec])
                step.verification_summary = dict(verify.summary or {})
                if not verify.success:
                    step.status = "FAILED"
                    step.failure_code = "CONFIGURATION_STEP_VERIFICATION_FAILED"
                    step.failure_message = "The function verification rule did not pass."
                    step.finished_at = utcnow()
                    await db.commit()
                    raise ConfigurationVerificationError(
                        "CONFIGURATION_STEP_VERIFICATION_FAILED"
                    )
                step.status = "SUCCEEDED"
                step.finished_at = utcnow()
                await db.commit()

            operation = await db.scalar(
                select(ConfigurationOperation)
                .where(ConfigurationOperation.id == operation_id)
                .with_for_update()
            )
            context, _, adapter = await _connection_context(db, operation)
            final_verify = await adapter.verify(context, None, function_specs)
            operation.verification_summary = dict(final_verify.summary or {})
            if not final_verify.success:
                raise ConfigurationVerificationError(
                    "CONFIGURATION_FINAL_VERIFICATION_FAILED"
                )
            post, _ = await _capture_snapshot(
                db,
                operation=operation,
                context=context,
                adapter=adapter,
                kind="POST_CHANGE",
            )
            if not post.is_restorable:
                raise ConfigurationVerificationError(
                    "CONFIGURATION_POST_CHANGE_SNAPSHOT_NOT_RESTORABLE"
                )
            operation.result_snapshot_id = post.id
            state = await _state_row(db, operation.device_id)
            state.last_known_good_snapshot_id = post.id
            state.last_verified_snapshot_id = post.id
            state.last_operation_id = operation.id
            state.drift_status = "IN_SYNC"
            state.last_verified_at = utcnow()
            operation.verification_summary = {
                **dict(operation.verification_summary or {}),
                "verified_steps": len(steps),
                "post_change_snapshot_id": str(post.id),
            }
            operation.status = "SUCCEEDED"
            operation.finished_at = utcnow()
        else:
            raise ConfigurationTemplateError(
                "CONFIGURATION_OPERATION_TYPE_UNSUPPORTED"
            )

        if operation.status == "SUCCEEDED":
            await record_audit(
                db,
                action=f"DEVICE_CONFIGURATION_{operation.operation_type}_SUCCEEDED",
                entity_type="ConfigurationOperation",
                entity_id=operation.id,
                actor_user_id=operation.actor_user_id,
                description=(
                    "Single-device configuration operation completed successfully."
                ),
                metadata={
                    "device_id": str(operation.device_id),
                    "result_snapshot_id": str(operation.result_snapshot_id)
                    if operation.result_snapshot_id
                    else None,
                },
            )
        await db.commit()
        return operation.status

    except Exception as exc:
        stage, code = _classify_failure(exc)
        pre_mutation_failure = bool(
            operation.operation_type == "RESTORE"
            and operation.pre_change_snapshot_id
            and pre_mutation_failure
            and not mutation_attempted
        )
        await db.rollback()

    if current_step_id is not None:
        step = await db.get(ConfigurationOperationStep, current_step_id)
        if step is not None and step.status in {"PENDING", "RUNNING"}:
            step.status = "FAILED"
            step.failure_code = code[:120]
            step.failure_message = "The function did not complete successfully."
            step.finished_at = utcnow()
            await db.commit()

    operation = await db.scalar(
        select(ConfigurationOperation)
        .where(ConfigurationOperation.id == operation_id)
        .with_for_update()
    )
    if operation is None:
        return "MISSING"

    if pre_mutation_failure:
        await _mark_failure(
            db,
            operation,
            stage=stage,
            code=code,
            message=(
                "The restore stopped before the first mutating device command. "
                "No automatic rollback was required; device state remains unverified."
            ),
        )
        state = await _state_row(db, operation.device_id)
        state.drift_status = "UNVERIFIED"
        state.last_operation_id = operation.id
        await db.commit()
        return operation.status

    if operation.operation_type in {"APPLY", "RESTORE"} and operation.pre_change_snapshot_id:
        return await _rollback_to_pre_change(
            db,
            operation_id=operation_id,
            stage=stage,
            code=code,
        )

    await _mark_failure(db, operation, stage=stage, code=code)
    if operation.operation_type in {"VERIFY"}:
        state = await _state_row(db, operation.device_id)
        state.drift_status = "DRIFTED" if stage == "VERIFICATION" else "UNVERIFIED"
        state.last_operation_id = operation.id
    await db.commit()
    return operation.status


async def diff_snapshots(
    db: AsyncSession,
    *,
    device_id: UUID,
    from_snapshot_id: UUID,
    to_snapshot_id: UUID,
) -> tuple[str, bool]:
    rows = list(
        (
            await db.scalars(
                select(ConfigurationSnapshot).where(
                    ConfigurationSnapshot.device_id == device_id,
                    ConfigurationSnapshot.id.in_([from_snapshot_id, to_snapshot_id]),
                    ConfigurationSnapshot.artifact_status == "READY",
                )
            )
        ).all()
    )
    by_id = {row.id: row for row in rows}
    before = by_id.get(from_snapshot_id)
    after = by_id.get(to_snapshot_id)
    if before is None or after is None:
        raise APIError(
            404,
            "CONFIGURATION_SNAPSHOT_NOT_FOUND",
            "One or both configuration snapshots were not found.",
        )
    version_id = after.template_version_id or before.template_version_id
    if version_id is None:
        raise APIError(
            409,
            "CONFIGURATION_TEMPLATE_VERSION_UNAVAILABLE",
            "Snapshot template metadata is unavailable.",
        )
    if (
        before.template_version_id is not None
        and after.template_version_id is not None
        and before.template_version_id != after.template_version_id
    ):
        raise APIError(
            409,
            "CONFIGURATION_DIFF_TEMPLATE_VERSION_MISMATCH",
            "Snapshots from different template versions cannot be displayed as a trusted diff.",
        )
    version = await db.get(ConfigurationTemplateVersion, version_id)
    if version is None:
        raise APIError(
            409,
            "CONFIGURATION_TEMPLATE_VERSION_UNAVAILABLE",
            "Snapshot template metadata is unavailable.",
        )
    try:
        await _assert_version_integrity(db, version)
    except (KeyError, ValueError, ConfigurationTemplateError) as exc:
        raise APIError(
            409,
            "CONFIGURATION_TEMPLATE_VERSION_INTEGRITY_FAILED",
            "Snapshot display metadata failed its published-version integrity check.",
        ) from exc
    params = version.transport_parameters or {}
    if params.get("allow_display_diff") is not True:
        raise APIError(
            409,
            "CONFIGURATION_DIFF_DISABLED",
            "Display diff is disabled for this template until explicit redaction rules are configured.",
        )
    adapter = registry.get(version.adapter_key)
    try:
        before_raw = await _load_snapshot_bytes(before)
        after_raw = await _load_snapshot_bytes(after)
        before_text = adapter.normalize_for_diff(
            adapter.sanitize_for_display(before_raw, params), params
        )
        after_text = adapter.normalize_for_diff(
            adapter.sanitize_for_display(after_raw, params), params
        )
    except ConfigurationArtifactError as exc:
        raise APIError(
            503,
            str(exc),
            "Configuration artifact data is currently unavailable.",
        ) from exc
    except (ValueError, ConfigurationTemplateError) as exc:
        raise APIError(
            409,
            "CONFIGURATION_DIFF_ADAPTER_UNAVAILABLE",
            "This adapter does not expose a safe display-diff implementation.",
        ) from exc
    diff = unified_diff_text(
        before_text,
        after_text,
        from_name=str(before.id),
        to_name=str(after.id),
        max_lines=4000,
    )
    return diff, diff.endswith("... diff truncated after 4000 lines ...")


async def mark_dispatch_failure(db: AsyncSession, operation_id: UUID) -> None:
    operation = await db.scalar(
        select(ConfigurationOperation)
        .where(ConfigurationOperation.id == operation_id)
        .with_for_update()
    )
    if operation is None or operation.status != "QUEUED":
        return
    await _mark_failure(
        db,
        operation,
        stage="INTERNAL",
        code="CONFIGURATION_TASK_DISPATCH_FAILED",
        message="The configuration operation could not be submitted to the isolated configuration worker.",
    )
    await db.commit()
