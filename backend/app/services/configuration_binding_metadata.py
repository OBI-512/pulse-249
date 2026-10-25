from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.configuration.registry import registry
from app.configuration.templating import ConfigurationTemplateError
from app.core.exceptions import APIError
from app.models import (
    ConfigurationOperation,
    ConfigurationTemplate,
    ConfigurationTemplateVersion,
    Device,
    DeviceConfigurationBinding,
)
from app.services.audit import record_audit
from app.services import configuration as _configuration_service
from app.services.configuration import _assert_version_integrity


_original_bind_device = _configuration_service.bind_device


async def bind_device_for_assignment(
    db: AsyncSession,
    *,
    device: Device,
    payload,
    actor_user_id: UUID,
) -> DeviceConfigurationBinding:
    """Refine the authoritative binding contract for disabled metadata staging.

    Enabled bindings delegate to the pre-TP4 implementation and therefore keep
    full runtime credential/trust readiness checks. A disabled binding may be
    staged after the same published-version, integrity, device-type, adapter,
    transport/source-shape and active-operation checks, but without requiring
    credentials or trust to be operational yet.
    """

    if payload.enabled:
        return await _original_bind_device(
            db,
            device=device,
            payload=payload,
            actor_user_id=actor_user_id,
        )

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

    overrides = dict(payload.connection_overrides or {})
    try:
        adapter = registry.get(version.adapter_key)
        adapter.validate_connection_overrides(overrides)
    except (KeyError, ValueError, ConfigurationTemplateError) as exc:
        raise APIError(
            422,
            str(exc).strip("'") or "CONFIGURATION_CONNECTION_OVERRIDE_INVALID",
            "The device configuration connection overrides are invalid for this adapter.",
        ) from exc

    if payload.credential_source == "REMOTE_ACCESS_PROFILE":
        if overrides:
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
    elif payload.credential_source == "ACCESS_TEMPLATE":
        if overrides:
            raise APIError(
                422,
                "CONFIGURATION_ACCESS_TEMPLATE_OVERRIDE_FORBIDDEN",
                "Access Template connection settings cannot be overridden on the configuration binding.",
            )
        if version.transport not in {"SSH_CLI", "TELNET_CLI"}:
            raise APIError(
                422,
                "CONFIGURATION_ACCESS_TEMPLATE_TRANSPORT_UNSUPPORTED",
                "Access Template credentials currently support SSH_CLI and TELNET_CLI configuration transports.",
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
            device_id=device.id,
            template_version_id=version.id,
        )
        db.add(binding)
    binding.template_version_id = version.id
    binding.credential_source = payload.credential_source
    binding.credential_reference = payload.credential_reference
    binding.connection_overrides = overrides
    binding.enabled = False
    binding.bound_by_user_id = actor_user_id
    binding.bound_at = _configuration_service.utcnow()
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
            "enabled": False,
            "metadata_only": True,
        },
    )
    return binding


# Importing this TP4 refinement installs it on the existing configuration
# service module. API startup imports the device-import extension before the
# configuration and TP4 batch routers, so those existing consumers receive the
# refined function. The enabled path still delegates to the original function.
_configuration_service.bind_device = bind_device_for_assignment
