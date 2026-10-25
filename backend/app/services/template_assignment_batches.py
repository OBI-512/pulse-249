from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.configuration.registry import registry
from app.configuration.templating import ConfigurationTemplateError
from app.core.exceptions import APIError
from app.models import (
    AccessTemplate,
    AccessTemplateRevision,
    ConfigurationOperation,
    ConfigurationTemplate,
    ConfigurationTemplateVersion,
    Device,
    DeviceConfigurationBinding,
    DeviceRemoteAccessProfile,
    DeviceType,
    TemplateAssignmentBatch,
    TemplateAssignmentBatchTarget,
    User,
)
from app.schemas.configuration import DeviceConfigurationBindingWrite
from app.schemas.pagination import PageResult
from app.schemas.template_assignment_batches import (
    AccessTemplateAssignmentOption,
    ConfigurationTemplateAssignmentOption,
    TemplateAssignmentBatchPreviewRequest,
)
from app.security.authorization import user_has_permission
from app.security.permissions import Permission as PermissionCode
from app.security.resource_scope import scope_for_actor
from app.security.scope_queries import require_device
from app.services.access_template_assignments import (
    apply_device_access_assignment,
    preview_device_access_assignment,
    visible_active_template_for_assignment,
)
from app.services.access_template_runtime import access_template_ready
from app.services.audit import record_audit
from app.services.authorization_snapshot import scope_fingerprint, scope_snapshot
from app.services.configuration import _assert_version_integrity, bind_device
from app.services.remote_access import profile_is_ready


UTC = timezone.utc
PREVIEW_TTL = timedelta(hours=24)
TERMINAL_STATUSES = frozenset({"SUCCEEDED", "PARTIAL", "FAILED", "EXPIRED"})
_VERSION_TOKEN = re.compile(r"\d+|[A-Za-z]+")


def utcnow() -> datetime:
    return datetime.now(UTC)


def _portable(metadata: dict[str, Any] | None) -> dict[str, Any]:
    value = dict(metadata or {}).get("portable")
    return dict(value) if isinstance(value, dict) else {}


def _compatibility(metadata: dict[str, Any] | None) -> dict[str, Any]:
    value = _portable(metadata).get("compatibility")
    return dict(value) if isinstance(value, dict) else {}


def _qualification(metadata: dict[str, Any] | None) -> dict[str, Any]:
    value = _portable(metadata).get("upstream_qualification")
    return dict(value) if isinstance(value, dict) else {}


def _version_key(value: str) -> tuple[tuple[int, int | str], ...]:
    output: list[tuple[int, int | str]] = []
    for token in _VERSION_TOKEN.findall(value.strip()):
        if token.isdigit():
            output.append((0, int(token)))
        else:
            output.append((1, token.lower()))
    return tuple(output)


def _firmware_matches(firmware: str, contract: dict[str, Any]) -> bool:
    mode = str(contract.get("mode") or "ANY").upper()
    if mode == "ANY":
        return True
    if mode == "EXACT":
        return firmware == str(contract.get("exact") or "")
    if mode == "SET":
        return firmware in {str(item) for item in (contract.get("values") or [])}
    if mode == "RANGE":
        current = _version_key(firmware)
        minimum = contract.get("minimum")
        maximum = contract.get("maximum")
        if minimum and current < _version_key(str(minimum)):
            return False
        if maximum and current > _version_key(str(maximum)):
            return False
        return True
    return False


def compatibility_warnings(
    *,
    device: Device,
    device_type_code: str,
    metadata: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    compatibility = _compatibility(metadata)
    qualification = _qualification(metadata)
    warnings: list[dict[str, Any]] = []
    expected_type = compatibility.get("device_type_code")
    if expected_type and str(expected_type).upper() != device_type_code.upper():
        warnings.append({"code": "TEMPLATE_DEVICE_TYPE_COMPATIBILITY_MISMATCH"})
    expected_vendor = compatibility.get("vendor")
    if expected_vendor and device.vendor and str(expected_vendor).casefold() != device.vendor.casefold():
        warnings.append({"code": "TEMPLATE_VENDOR_MISMATCH"})
    models = {str(item).casefold() for item in (compatibility.get("models") or [])}
    if models and device.model and device.model.casefold() not in models:
        warnings.append({"code": "TEMPLATE_MODEL_MISMATCH"})
    series = {str(item).casefold() for item in (compatibility.get("series") or [])}
    device_series = str((device.metadata_ or {}).get("series") or "").strip()
    if series and device_series and device_series.casefold() not in series:
        warnings.append({"code": "TEMPLATE_SERIES_MISMATCH"})
    firmware_contract = compatibility.get("firmware")
    if isinstance(firmware_contract, dict) and str(firmware_contract.get("mode") or "ANY").upper() != "ANY":
        firmware = str((device.metadata_ or {}).get("firmware_version") or "").strip()
        if not firmware:
            warnings.append({"code": "TEMPLATE_FIRMWARE_EVIDENCE_UNAVAILABLE"})
        elif not _firmware_matches(firmware, firmware_contract):
            warnings.append({"code": "TEMPLATE_FIRMWARE_MISMATCH"})
    status = str(qualification.get("status") or "").upper()
    if status in {"UNQUALIFIED", "DEPRECATED"}:
        warnings.append({"code": f"TEMPLATE_QUALIFICATION_{status}"})
    scope = str(qualification.get("scope") or "").upper()
    if qualification and scope and scope != "REAL_DEVICE":
        warnings.append({"code": "TEMPLATE_QUALIFICATION_NOT_REAL_DEVICE"})
    return warnings[:32]


async def list_access_assignment_options(
    db: AsyncSession,
    *,
    actor: User,
    search: str | None,
    protocol: str | None,
    page: int,
    page_size: int,
) -> PageResult[AccessTemplateAssignmentOption]:
    filters = [
        AccessTemplate.deleted_at.is_(None),
        AccessTemplate.is_active.is_(True),
        (AccessTemplate.owner_user_id == actor.id) | (AccessTemplate.visibility == "SHARED"),
        select(AccessTemplateRevision.id)
        .where(
            AccessTemplateRevision.template_id == AccessTemplate.id,
            AccessTemplateRevision.lifecycle_status == "ACTIVE",
        )
        .exists(),
    ]
    if protocol:
        normalized = protocol.strip().upper()
        if normalized not in {"SSH", "SNMP", "WEB", "TELNET"}:
            raise APIError(422, "ACCESS_TEMPLATE_PROTOCOL_INVALID", "Unsupported Access Template protocol.")
        filters.append(AccessTemplate.protocol == normalized)
    if search and search.strip():
        pattern = f"%{search.strip()}%"
        filters.append(
            or_(
                AccessTemplate.name.ilike(pattern),
                AccessTemplate.description.ilike(pattern),
                AccessTemplate.protocol.ilike(pattern),
            )
        )
    statement = select(AccessTemplate).where(*filters)
    total = int(
        (
            await db.scalar(
                select(func.count()).select_from(statement.order_by(None).subquery())
            )
        )
        or 0
    )
    rows = list(
        (
            await db.scalars(
                statement.order_by(AccessTemplate.protocol, AccessTemplate.name, AccessTemplate.id)
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).all()
    )
    items = [
        AccessTemplateAssignmentOption(
            id=row.id,
            name=row.name,
            protocol=row.protocol,
            lifecycle_status="ACTIVE",
            visibility=row.visibility,
            compatibility=_compatibility(row.metadata_),
            qualification=_qualification(row.metadata_),
        )
        for row in rows
    ]
    return PageResult(items=items, total=total, page=page, page_size=page_size)


async def list_configuration_assignment_options(
    db: AsyncSession,
    *,
    search: str | None,
    page: int,
    page_size: int,
) -> PageResult[ConfigurationTemplateAssignmentOption]:
    statement = (
        select(ConfigurationTemplate, ConfigurationTemplateVersion, DeviceType)
        .join(
            ConfigurationTemplateVersion,
            ConfigurationTemplateVersion.template_id == ConfigurationTemplate.id,
        )
        .join(DeviceType, DeviceType.id == ConfigurationTemplate.device_type_id)
        .where(
            ConfigurationTemplate.is_active.is_(True),
            ConfigurationTemplateVersion.status == "PUBLISHED",
            ConfigurationTemplateVersion.content_sha256.is_not(None),
        )
    )
    if search and search.strip():
        pattern = f"%{search.strip()}%"
        statement = statement.where(
            or_(
                ConfigurationTemplate.code.ilike(pattern),
                ConfigurationTemplate.name.ilike(pattern),
                ConfigurationTemplate.vendor.ilike(pattern),
                ConfigurationTemplate.model.ilike(pattern),
                ConfigurationTemplate.series.ilike(pattern),
                DeviceType.code.ilike(pattern),
            )
        )
    total = int(
        (
            await db.scalar(
                select(func.count()).select_from(statement.order_by(None).subquery())
            )
        )
        or 0
    )
    rows = (
        await db.execute(
            statement.order_by(
                ConfigurationTemplate.code,
                ConfigurationTemplateVersion.version_number.desc(),
            )
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()
    items = [
        ConfigurationTemplateAssignmentOption(
            template_id=template.id,
            template_version_id=version.id,
            code=template.code,
            name=template.name,
            version_number=version.version_number,
            content_sha256=str(version.content_sha256),
            device_type_id=template.device_type_id,
            device_type_code=device_type.code,
            vendor=template.vendor,
            model=template.model,
            series=template.series,
            adapter_key=version.adapter_key,
            transport=version.transport,
            compatibility=_compatibility(template.metadata_),
            qualification=_qualification(template.metadata_),
        )
        for template, version, device_type in rows
    ]
    return PageResult(items=items, total=total, page=page, page_size=page_size)


async def _require_permission(db: AsyncSession, *, actor: User, code: str) -> None:
    if not await user_has_permission(db, user_id=actor.id, permission_code=code):
        raise APIError(403, "PERMISSION_DENIED", f"Permission '{code}' is required.")


async def _require_component_permissions(
    db: AsyncSession,
    *,
    actor: User,
    has_access: bool,
    has_configuration: bool,
) -> None:
    if has_access:
        await _require_permission(
            db,
            actor=actor,
            code=PermissionCode.ACCESS_TEMPLATE_MANAGE,
        )
    if has_configuration:
        await _require_permission(
            db,
            actor=actor,
            code=PermissionCode.DEVICE_CONFIGURATION_TEMPLATE_MANAGE,
        )
        await _require_permission(
            db,
            actor=actor,
            code=PermissionCode.DEVICE_CONFIGURATION_READ,
        )


def _ordered_device_ids(values: list[UUID]) -> list[UUID]:
    return sorted(values, key=lambda value: value.bytes)


def _canonical_json(value: Any) -> Any:
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, list):
        return [_canonical_json(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _canonical_json(item) for key, item in value.items()}
    return value


def _request_summary(
    *,
    payload: TemplateAssignmentBatchPreviewRequest,
    resolved_access: list[tuple[Any, AccessTemplate, AccessTemplateRevision]],
    configuration: tuple[Any, ConfigurationTemplate, ConfigurationTemplateVersion] | None,
) -> dict[str, Any]:
    access = [
        {
            "template_id": str(template.id),
            "protocol": template.protocol,
            "revision_id": str(revision.id),
            "revision_number": revision.revision_number,
            "definition_sha256": revision.definition_sha256,
            "priority": selection.priority,
            "conflict_policy": selection.conflict_policy,
        }
        for selection, template, revision in sorted(
            resolved_access,
            key=lambda item: item[1].protocol,
        )
    ]
    config = None
    if configuration is not None:
        selection, template, version = configuration
        config = {
            "template_id": str(template.id),
            "template_version_id": str(version.id),
            "version_number": version.version_number,
            "content_sha256": version.content_sha256,
            "replace_existing": selection.replace_existing,
            "credential_mode": selection.credential_mode,
            "enabled": selection.enabled,
        }
    return {"phase": "TP4", "access": access, "configuration": config}


def _request_fingerprint(
    *,
    target_ids: list[UUID],
    summary: dict[str, Any],
) -> str:
    encoded = json.dumps(
        {
            "device_ids": [str(value) for value in target_ids],
            "request": _canonical_json(summary),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


async def _resolve_access_selections(
    db: AsyncSession,
    *,
    actor: User,
    payload: TemplateAssignmentBatchPreviewRequest,
) -> list[tuple[Any, AccessTemplate, AccessTemplateRevision]]:
    resolved: list[tuple[Any, AccessTemplate, AccessTemplateRevision]] = []
    seen_protocols: set[str] = set()
    for selection in payload.access_templates:
        template, revision = await visible_active_template_for_assignment(
            db,
            template_id=selection.template_id,
            actor=actor,
        )
        protocol = template.protocol.strip().upper()
        if protocol in seen_protocols:
            raise APIError(
                422,
                "TEMPLATE_ASSIGNMENT_DUPLICATE_PROTOCOL",
                "Only one Access Template may be selected per protocol.",
            )
        seen_protocols.add(protocol)
        resolved.append((selection, template, revision))
    return resolved


async def _resolve_configuration_selection(
    db: AsyncSession,
    *,
    payload: TemplateAssignmentBatchPreviewRequest,
) -> tuple[Any, ConfigurationTemplate, ConfigurationTemplateVersion] | None:
    selection = payload.configuration
    if selection is None:
        return None
    version = await db.scalar(
        select(ConfigurationTemplateVersion).where(
            ConfigurationTemplateVersion.id == selection.template_version_id,
            ConfigurationTemplateVersion.status == "PUBLISHED",
        )
    )
    if version is None:
        raise APIError(
            422,
            "CONFIGURATION_TEMPLATE_PUBLISHED_VERSION_REQUIRED",
            "The selected configuration template version must remain PUBLISHED.",
        )
    template = await db.scalar(
        select(ConfigurationTemplate).where(
            ConfigurationTemplate.id == version.template_id,
            ConfigurationTemplate.is_active.is_(True),
        )
    )
    if template is None:
        raise APIError(
            422,
            "CONFIGURATION_TEMPLATE_INACTIVE",
            "The selected configuration template is inactive.",
        )
    try:
        await _assert_version_integrity(db, version)
        registry.get(version.adapter_key)
    except (KeyError, ValueError, ConfigurationTemplateError) as exc:
        raise APIError(
            422,
            "CONFIGURATION_TEMPLATE_VERSION_INTEGRITY_FAILED",
            "The selected published configuration template version failed validation.",
        ) from exc
    return selection, template, version


async def _configuration_runtime_blocker(
    db: AsyncSession,
    *,
    device: Device,
    version: ConfigurationTemplateVersion,
    credential_source: str,
    connection_overrides: dict[str, Any],
    enabled: bool,
) -> dict[str, Any] | None:
    try:
        adapter = registry.get(version.adapter_key)
        adapter.validate_connection_overrides(connection_overrides or {})
    except (KeyError, ValueError, ConfigurationTemplateError):
        return {"code": "CONFIGURATION_CONNECTION_OVERRIDE_INVALID"}
    if not enabled:
        return None
    if credential_source == "REMOTE_ACCESS_PROFILE":
        if connection_overrides:
            return {"code": "CONFIGURATION_REMOTE_PROFILE_OVERRIDE_FORBIDDEN"}
        if version.transport != "SSH_CLI":
            return {"code": "CONFIGURATION_REMOTE_PROFILE_TRANSPORT_UNSUPPORTED"}
        profile = await db.scalar(
            select(DeviceRemoteAccessProfile).where(
                DeviceRemoteAccessProfile.device_id == device.id
            )
        )
        if not profile_is_ready(profile):
            return {"code": "CONFIGURATION_REMOTE_ACCESS_PROFILE_NOT_READY"}
        return None
    if credential_source == "ACCESS_TEMPLATE":
        if connection_overrides:
            return {"code": "CONFIGURATION_ACCESS_TEMPLATE_OVERRIDE_FORBIDDEN"}
        if version.transport == "SSH_CLI":
            if await access_template_ready(db, device_id=device.id, protocol="SSH") is not True:
                return {"code": "CONFIGURATION_ACCESS_TEMPLATE_NOT_READY"}
            profile = await db.scalar(
                select(DeviceRemoteAccessProfile).where(
                    DeviceRemoteAccessProfile.device_id == device.id
                )
            )
            if profile is None or not profile.ssh_host_key_fingerprint:
                return {"code": "CONFIGURATION_HOST_KEY_FINGERPRINT_REQUIRED"}
            return None
        if version.transport == "TELNET_CLI":
            if await access_template_ready(db, device_id=device.id, protocol="TELNET") is not True:
                return {"code": "CONFIGURATION_ACCESS_TEMPLATE_NOT_READY"}
            return None
        return {"code": "CONFIGURATION_ACCESS_TEMPLATE_TRANSPORT_UNSUPPORTED"}
    if credential_source == "ENV_REFERENCE":
        if version.transport == "SSH_CLI" and not connection_overrides.get("host_key_fingerprint"):
            return {"code": "CONFIGURATION_HOST_KEY_FINGERPRINT_REQUIRED"}
        return None
    return {"code": "CONFIGURATION_CREDENTIAL_SOURCE_INVALID"}


async def _preview_configuration_for_device(
    db: AsyncSession,
    *,
    device: Device,
    template: ConfigurationTemplate,
    version: ConfigurationTemplateVersion,
    selection: Any,
) -> tuple[str, dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    planned = {
        "kind": "CONFIGURATION",
        "template_id": str(template.id),
        "template_version_id": str(version.id),
        "version_number": version.version_number,
        "credential_mode": selection.credential_mode,
        "enabled": selection.enabled,
        "replace_existing": selection.replace_existing,
    }
    if template.device_type_id != device.device_type_id:
        return (
            "BLOCKED",
            planned,
            [],
            [{"code": "CONFIGURATION_TEMPLATE_DEVICE_TYPE_MISMATCH"}],
        )
    existing = await db.scalar(
        select(DeviceConfigurationBinding).where(
            DeviceConfigurationBinding.device_id == device.id
        )
    )
    if selection.credential_mode == "PRESERVE_EXISTING":
        if existing is None:
            return (
                "BLOCKED",
                planned,
                [],
                [{"code": "CONFIGURATION_BINDING_REQUIRED_FOR_PRESERVE"}],
            )
        credential_source = existing.credential_source
        credential_reference = existing.credential_reference
        connection_overrides = dict(existing.connection_overrides or {})
    else:
        credential_source = selection.credential_mode
        credential_reference = None
        connection_overrides = {}

    same = bool(
        existing is not None
        and existing.template_version_id == version.id
        and existing.credential_source == credential_source
        and existing.credential_reference == credential_reference
        and dict(existing.connection_overrides or {}) == connection_overrides
        and bool(existing.enabled) == bool(selection.enabled)
    )
    if same:
        planned["action"] = "NOOP"
        return "NOOP", planned, [], []
    if existing is not None and not selection.replace_existing:
        return (
            "BLOCKED",
            planned,
            [],
            [{"code": "CONFIGURATION_BINDING_EXISTS"}],
        )
    active_operation = await db.scalar(
        select(ConfigurationOperation.id).where(
            ConfigurationOperation.device_id == device.id,
            ConfigurationOperation.status.in_(("QUEUED", "RUNNING", "ROLLING_BACK")),
        )
    )
    if active_operation is not None:
        return (
            "BLOCKED",
            planned,
            [],
            [{"code": "CONFIGURATION_DEVICE_OPERATION_ACTIVE"}],
        )
    blocker = await _configuration_runtime_blocker(
        db,
        device=device,
        version=version,
        credential_source=credential_source,
        connection_overrides=connection_overrides,
        enabled=selection.enabled,
    )
    if blocker:
        return "BLOCKED", planned, [], [blocker]
    planned["action"] = "REPLACE" if existing is not None else "CREATE"
    planned["resolved_credential_source"] = credential_source
    return "READY", planned, [], []


async def _device_type_code(db: AsyncSession, device: Device) -> str:
    row = await db.get(DeviceType, device.device_type_id)
    if row is None:
        raise APIError(409, "DEVICE_TYPE_NOT_FOUND", "Device type is unavailable.")
    return row.code


async def _preview_target(
    db: AsyncSession,
    *,
    device: Device,
    actor: User,
    resolved_access: list[tuple[Any, AccessTemplate, AccessTemplateRevision]],
    configuration: tuple[Any, ConfigurationTemplate, ConfigurationTemplateVersion] | None,
) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    warnings: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    planned: dict[str, Any] = {"access": {}, "configuration": None}
    family_statuses: list[str] = []
    if device.lifecycle_state == "DECOMMISSIONED":
        blockers.append({"code": "TEMPLATE_ASSIGNMENT_DEVICE_DECOMMISSIONED"})
    type_code = await _device_type_code(db, device)
    for selection, template, _revision in resolved_access:
        preview = await preview_device_access_assignment(
            db,
            device_id=device.id,
            template=template,
            actor=actor,
            priority=selection.priority,
            conflict_policy=selection.conflict_policy,
        )
        planned["access"][template.protocol] = preview.planned_change
        warnings.extend(
            {
                **item,
                "kind": "ACCESS",
                "protocol": template.protocol,
            }
            for item in compatibility_warnings(
                device=device,
                device_type_code=type_code,
                metadata=template.metadata_,
            )
        )
        blockers.extend(preview.blockers)
        family_statuses.append(preview.status)
    if configuration is not None:
        selection, template, version = configuration
        status, change, config_warnings, config_blockers = await _preview_configuration_for_device(
            db,
            device=device,
            template=template,
            version=version,
            selection=selection,
        )
        planned["configuration"] = change
        warnings.extend(config_warnings)
        warnings.extend(
            {
                **item,
                "kind": "CONFIGURATION",
            }
            for item in compatibility_warnings(
                device=device,
                device_type_code=type_code,
                metadata=template.metadata_,
            )
        )
        blockers.extend(config_blockers)
        family_statuses.append(status)
    if blockers:
        return "BLOCKED", warnings[:32], blockers[:32], planned
    if family_statuses and all(status == "NOOP" for status in family_statuses):
        return "NOOP", warnings[:32], [], planned
    return "READY", warnings[:32], [], planned


async def _targets(
    db: AsyncSession,
    *,
    batch_id: UUID,
    for_update: bool = False,
) -> list[TemplateAssignmentBatchTarget]:
    statement = (
        select(TemplateAssignmentBatchTarget)
        .where(TemplateAssignmentBatchTarget.batch_id == batch_id)
        .order_by(TemplateAssignmentBatchTarget.target_ordinal)
    )
    if for_update:
        statement = statement.with_for_update()
    return list((await db.scalars(statement)).all())


async def get_batch_for_actor(
    db: AsyncSession,
    *,
    batch_id: UUID,
    actor: User,
    for_update: bool = False,
) -> tuple[TemplateAssignmentBatch, list[TemplateAssignmentBatchTarget]]:
    scope = await scope_for_actor(db, actor)
    statement = select(TemplateAssignmentBatch).where(
        TemplateAssignmentBatch.id == batch_id
    )
    if for_update:
        statement = statement.with_for_update()
    batch = await db.scalar(statement)
    if batch is None or (not scope.global_access and batch.actor_user_id != actor.id):
        raise APIError(404, "TEMPLATE_ASSIGNMENT_BATCH_NOT_FOUND", "Template assignment batch not found.")
    targets = await _targets(db, batch_id=batch.id, for_update=for_update)
    for target in targets:
        try:
            await require_device(db, scope, target.device_id)
        except APIError as exc:
            raise APIError(
                404,
                "TEMPLATE_ASSIGNMENT_BATCH_NOT_FOUND",
                "Template assignment batch not found.",
            ) from exc
    return batch, targets


async def list_batches_for_actor(
    db: AsyncSession,
    *,
    actor: User,
    limit: int,
) -> list[TemplateAssignmentBatch]:
    scope = await scope_for_actor(db, actor)
    statement = select(TemplateAssignmentBatch).order_by(
        TemplateAssignmentBatch.created_at.desc(),
        TemplateAssignmentBatch.id.desc(),
    )
    if not scope.global_access:
        statement = statement.where(TemplateAssignmentBatch.actor_user_id == actor.id)
    rows = list((await db.scalars(statement.limit(limit))).all())
    if scope.global_access:
        return rows
    return rows


async def create_preview(
    db: AsyncSession,
    *,
    payload: TemplateAssignmentBatchPreviewRequest,
    actor: User,
) -> tuple[TemplateAssignmentBatch, list[TemplateAssignmentBatchTarget], bool]:
    await _require_component_permissions(
        db,
        actor=actor,
        has_access=bool(payload.access_templates),
        has_configuration=payload.configuration is not None,
    )
    scope = await scope_for_actor(db, actor)
    target_ids = _ordered_device_ids(payload.device_ids)
    devices: dict[UUID, Device] = {}
    for device_id in target_ids:
        try:
            devices[device_id] = await require_device(db, scope, device_id)
        except APIError as exc:
            raise APIError(
                404,
                "TEMPLATE_ASSIGNMENT_TARGET_NOT_FOUND",
                "One or more selected devices are unavailable.",
            ) from exc
    resolved_access = await _resolve_access_selections(db, actor=actor, payload=payload)
    configuration = await _resolve_configuration_selection(db, payload=payload)
    summary = _request_summary(
        payload=payload,
        resolved_access=resolved_access,
        configuration=configuration,
    )
    fingerprint = _request_fingerprint(target_ids=target_ids, summary=summary)
    if payload.idempotency_key:
        existing = await db.scalar(
            select(TemplateAssignmentBatch).where(
                TemplateAssignmentBatch.actor_user_id == actor.id,
                TemplateAssignmentBatch.idempotency_key == payload.idempotency_key,
            )
        )
        if existing is not None:
            if existing.request_fingerprint != fingerprint:
                raise APIError(
                    409,
                    "TEMPLATE_ASSIGNMENT_IDEMPOTENCY_KEY_REUSED",
                    "The idempotency key was already used for a different preview request.",
                )
            return existing, await _targets(db, batch_id=existing.id), False

    batch = TemplateAssignmentBatch(
        actor_user_id=actor.id,
        status="PREVIEWED",
        idempotency_key=payload.idempotency_key,
        request_fingerprint=fingerprint,
        authorization_scope=scope_snapshot(scope),
        authorization_scope_fingerprint=scope_fingerprint(scope),
        request_summary=summary,
        target_count=len(target_ids),
        preview_expires_at=utcnow() + PREVIEW_TTL,
    )
    db.add(batch)
    await db.flush()
    targets: list[TemplateAssignmentBatchTarget] = []
    counts = {"READY": 0, "NOOP": 0, "BLOCKED": 0}
    for ordinal, device_id in enumerate(target_ids):
        preview_status, warnings, blockers, planned = await _preview_target(
            db,
            device=devices[device_id],
            actor=actor,
            resolved_access=resolved_access,
            configuration=configuration,
        )
        counts[preview_status] += 1
        target = TemplateAssignmentBatchTarget(
            batch_id=batch.id,
            device_id=device_id,
            target_ordinal=ordinal,
            preview_status=preview_status,
            apply_status="NOT_APPLIED",
            warnings=warnings,
            blockers=blockers,
            planned_changes=planned,
            family_outcomes={},
        )
        db.add(target)
        targets.append(target)
    batch.ready_count = counts["READY"]
    batch.noop_count = counts["NOOP"]
    batch.blocked_count = counts["BLOCKED"]
    await db.flush()
    await record_audit(
        db,
        action="TEMPLATE_ASSIGNMENT_BATCH_PREVIEWED",
        entity_type="TemplateAssignmentBatch",
        entity_id=batch.id,
        actor_user_id=actor.id,
        description="Bulk template assignment preview materialized without assignment mutation.",
        metadata={
            "target_count": batch.target_count,
            "ready_count": batch.ready_count,
            "noop_count": batch.noop_count,
            "blocked_count": batch.blocked_count,
            "request_fingerprint": batch.request_fingerprint,
            "access_protocols": [item[1].protocol for item in resolved_access],
            "configuration_selected": configuration is not None,
        },
    )
    return batch, targets, True


def _selection_payload_from_summary(summary: dict[str, Any]) -> TemplateAssignmentBatchPreviewRequest:
    access = [
        {
            "template_id": item["template_id"],
            "priority": item.get("priority", 0),
            "conflict_policy": item.get("conflict_policy", "FAIL_ON_CONFLICT"),
        }
        for item in (summary.get("access") or [])
    ]
    configuration = summary.get("configuration")
    config_payload = None
    if isinstance(configuration, dict):
        config_payload = {
            "template_version_id": configuration["template_version_id"],
            "replace_existing": bool(configuration.get("replace_existing")),
            "credential_mode": configuration.get("credential_mode", "ACCESS_TEMPLATE"),
            "enabled": bool(configuration.get("enabled", True)),
        }
    return TemplateAssignmentBatchPreviewRequest(
        device_ids=[UUID(int=0)],
        access_templates=access,
        configuration=config_payload,
    )


async def apply_batch(
    db: AsyncSession,
    *,
    batch_id: UUID,
    expected_request_fingerprint: str,
    actor: User,
) -> tuple[TemplateAssignmentBatch, list[TemplateAssignmentBatchTarget]]:
    batch, targets = await get_batch_for_actor(
        db,
        batch_id=batch_id,
        actor=actor,
        for_update=True,
    )
    if batch.status in TERMINAL_STATUSES:
        return batch, targets
    if batch.status != "PREVIEWED":
        raise APIError(
            409,
            "TEMPLATE_ASSIGNMENT_BATCH_NOT_APPLICABLE",
            "Only a PREVIEWED template assignment batch may be applied.",
        )
    if batch.request_fingerprint != expected_request_fingerprint:
        raise APIError(
            409,
            "TEMPLATE_ASSIGNMENT_FINGERPRINT_MISMATCH",
            "The preview fingerprint does not match this batch.",
        )
    if batch.preview_expires_at <= utcnow():
        batch.status = "EXPIRED"
        batch.finished_at = utcnow()
        await db.flush()
        return batch, targets

    summary = dict(batch.request_summary or {})
    payload_shell = _selection_payload_from_summary(summary)
    await _require_component_permissions(
        db,
        actor=actor,
        has_access=bool(payload_shell.access_templates),
        has_configuration=payload_shell.configuration is not None,
    )
    scope = await scope_for_actor(db, actor)
    if scope_fingerprint(scope) != batch.authorization_scope_fingerprint:
        raise APIError(
            409,
            "TEMPLATE_ASSIGNMENT_SCOPE_CHANGED",
            "Authorization scope changed after preview; create a new preview.",
        )
    devices: dict[UUID, Device] = {}
    for target in targets:
        try:
            devices[target.device_id] = await require_device(db, scope, target.device_id)
        except APIError as exc:
            raise APIError(
                404,
                "TEMPLATE_ASSIGNMENT_TARGET_NOT_FOUND",
                "One or more selected devices are unavailable.",
            ) from exc

    resolved_access = await _resolve_access_selections(
        db,
        actor=actor,
        payload=payload_shell,
    )
    configuration = await _resolve_configuration_selection(db, payload=payload_shell)
    expected_summary = _request_summary(
        payload=payload_shell,
        resolved_access=resolved_access,
        configuration=configuration,
    )
    if expected_summary != summary:
        raise APIError(
            409,
            "TEMPLATE_ASSIGNMENT_TEMPLATE_STATE_CHANGED",
            "Template state changed after preview; create a new preview.",
        )

    batch.status = "APPLYING"
    batch.applied_at = utcnow()
    await db.flush()

    succeeded = 0
    failed = 0
    skipped = 0
    for target in targets:
        target.failure_code = None
        target.failure_message = None
        if target.preview_status == "BLOCKED":
            target.apply_status = "SKIPPED"
            target.terminal_at = utcnow()
            skipped += 1
            continue
        device = devices[target.device_id]
        try:
            async with db.begin_nested():
                current_status, _warnings, blockers, _planned = await _preview_target(
                    db,
                    device=device,
                    actor=actor,
                    resolved_access=resolved_access,
                    configuration=configuration,
                )
                if blockers:
                    code = str(blockers[0].get("code") or "TEMPLATE_ASSIGNMENT_TARGET_CHANGED")
                    raise APIError(
                        409,
                        code,
                        "The target is no longer applicable; create a new preview.",
                    )
                outcomes: dict[str, Any] = {"access": {}, "configuration": None}
                for selection, template, _revision in resolved_access:
                    outcome = await apply_device_access_assignment(
                        db,
                        device_id=device.id,
                        template=template,
                        actor=actor,
                        priority=selection.priority,
                        conflict_policy=selection.conflict_policy,
                        batch_id=batch.id,
                    )
                    outcomes["access"][template.protocol] = outcome
                if configuration is not None:
                    selection, template, version = configuration
                    existing = await db.scalar(
                        select(DeviceConfigurationBinding)
                        .where(DeviceConfigurationBinding.device_id == device.id)
                        .with_for_update()
                    )
                    if selection.credential_mode == "PRESERVE_EXISTING":
                        if existing is None:
                            raise APIError(
                                409,
                                "CONFIGURATION_BINDING_REQUIRED_FOR_PRESERVE",
                                "The configuration binding required for credential preservation no longer exists.",
                            )
                        credential_source = existing.credential_source
                        credential_reference = existing.credential_reference
                        connection_overrides = dict(existing.connection_overrides or {})
                    else:
                        credential_source = selection.credential_mode
                        credential_reference = None
                        connection_overrides = {}
                    same = bool(
                        existing is not None
                        and existing.template_version_id == version.id
                        and existing.credential_source == credential_source
                        and existing.credential_reference == credential_reference
                        and dict(existing.connection_overrides or {}) == connection_overrides
                        and bool(existing.enabled) == bool(selection.enabled)
                    )
                    if same:
                        outcomes["configuration"] = {
                            "kind": "CONFIGURATION",
                            "status": "NOOP",
                            "template_id": str(template.id),
                            "template_version_id": str(version.id),
                        }
                    else:
                        if existing is not None and not selection.replace_existing:
                            raise APIError(
                                409,
                                "CONFIGURATION_BINDING_EXISTS",
                                "A different configuration binding now exists.",
                            )
                        binding = await bind_device(
                            db,
                            device=device,
                            payload=DeviceConfigurationBindingWrite(
                                template_version_id=version.id,
                                credential_source=credential_source,
                                credential_reference=credential_reference,
                                connection_overrides=connection_overrides,
                                enabled=selection.enabled,
                            ),
                            actor_user_id=actor.id,
                        )
                        metadata = dict(binding.metadata_ or {})
                        metadata["tp4_assignment"] = {
                            "batch_id": str(batch.id),
                            "request_fingerprint": batch.request_fingerprint,
                        }
                        binding.metadata_ = metadata
                        await db.flush()
                        outcomes["configuration"] = {
                            "kind": "CONFIGURATION",
                            "status": "SUCCEEDED",
                            "template_id": str(template.id),
                            "template_version_id": str(version.id),
                            "binding_id": str(binding.id),
                            "enabled": bool(binding.enabled),
                        }
                target.family_outcomes = outcomes
            target.apply_status = "SUCCEEDED"
            target.terminal_at = utcnow()
            succeeded += 1
        except APIError as exc:
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            code = str(detail.get("code") or "TEMPLATE_ASSIGNMENT_TARGET_FAILED")[:120]
            message = str(detail.get("message") or "Template assignment failed.")[:1000]
            target.apply_status = "FAILED"
            target.failure_code = code
            target.failure_message = message
            target.family_outcomes = {}
            target.terminal_at = utcnow()
            failed += 1
        except Exception:
            target.apply_status = "FAILED"
            target.failure_code = "TEMPLATE_ASSIGNMENT_TARGET_FAILED"
            target.failure_message = "Template assignment failed."
            target.family_outcomes = {}
            target.terminal_at = utcnow()
            failed += 1
        await db.flush()

    batch.succeeded_count = succeeded
    batch.failed_count = failed
    if succeeded == batch.target_count:
        batch.status = "SUCCEEDED"
    elif succeeded > 0:
        batch.status = "PARTIAL"
    else:
        batch.status = "FAILED"
    batch.finished_at = utcnow()
    await db.flush()
    action = {
        "SUCCEEDED": "TEMPLATE_ASSIGNMENT_BATCH_APPLIED",
        "PARTIAL": "TEMPLATE_ASSIGNMENT_BATCH_PARTIAL",
        "FAILED": "TEMPLATE_ASSIGNMENT_BATCH_FAILED",
    }[batch.status]
    await record_audit(
        db,
        action=action,
        entity_type="TemplateAssignmentBatch",
        entity_id=batch.id,
        actor_user_id=actor.id,
        description="Bulk template assignment batch reached terminal metadata state.",
        metadata={
            "target_count": batch.target_count,
            "succeeded_count": succeeded,
            "failed_count": failed,
            "skipped_count": skipped,
            "request_fingerprint": batch.request_fingerprint,
        },
    )
    return batch, targets
