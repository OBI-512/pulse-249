from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.configuration.registry import registry
from app.configuration.templating import ConfigurationTemplateError
from app.core.exceptions import APIError
from app.models import (
    AccessTemplate,
    AccessTemplateRevision,
    ConfigurationTemplate,
    ConfigurationTemplateVersion,
    ImportJob,
    ImportRecord,
    User,
)
from app.schemas.configuration import DeviceConfigurationBindingWrite
from app.security.authorization import user_has_permission
from app.security.permissions import Permission as PermissionCode
from app.security.resource_scope import EffectiveResourceScope
from app.services.access_template_assignments import apply_device_access_assignment
from app.services.audit import record_audit
from app.services.authorization_snapshot import scope_fingerprint
from app.services.configuration import _assert_version_integrity
from app.services.configuration_binding_metadata import bind_device_for_assignment
from app.services.data_exchange import (
    CONTROLLED_TYPES,
    ImportPreviewExpired,
    TEMPLATES,
    ValidationResult,
    _apply_customer,
    _apply_customer_service,
    _apply_geography,
    _apply_group,
    _prepare_row_for_subtype,
    _text,
    create_import_preview,
    utcnow,
    validate_import_row,
)
from app.services.device_registration import register_domain_device
from app.services.tabular_formats import write_tabular_template_bytes
from app.settings import settings


DEVICE_MAPPING_COLUMNS = [
    "firmware_version",
    "ssh_template_name",
    "snmp_template_name",
    "web_template_name",
    "telnet_template_name",
    "configuration_template_code",
    "configuration_template_version",
]
_ACCESS_COLUMNS = {
    "SSH": "ssh_template_name",
    "SNMP": "snmp_template_name",
    "WEB": "web_template_name",
    "TELNET": "telnet_template_name",
}


def _mapping_requested(row: dict[str, Any]) -> bool:
    return any(_text(row, key) is not None for key in DEVICE_MAPPING_COLUMNS[1:])


async def _require_permission(
    db: AsyncSession,
    *,
    actor_id: UUID,
    code: str,
) -> None:
    if not await user_has_permission(db, user_id=actor_id, permission_code=code):
        raise ValueError(f"Permission '{code}' is required for device template mapping.")


async def _require_mapping_permissions(
    db: AsyncSession,
    *,
    actor_id: UUID,
    rows: list[dict[str, Any]],
) -> None:
    has_access = any(
        any(_text(row, column) is not None for column in _ACCESS_COLUMNS.values())
        for row in rows
    )
    has_configuration = any(
        _text(row, "configuration_template_code") is not None
        or _text(row, "configuration_template_version") is not None
        for row in rows
    )
    if has_access:
        await _require_permission(
            db,
            actor_id=actor_id,
            code=PermissionCode.ACCESS_TEMPLATE_MANAGE,
        )
    if has_configuration:
        await _require_permission(
            db,
            actor_id=actor_id,
            code=PermissionCode.DEVICE_CONFIGURATION_TEMPLATE_MANAGE,
        )
        await _require_permission(
            db,
            actor_id=actor_id,
            code=PermissionCode.DEVICE_CONFIGURATION_READ,
        )


async def _resolve_access_mapping(
    db: AsyncSession,
    *,
    actor_id: UUID,
    protocol: str,
    name: str,
) -> dict[str, Any]:
    if protocol == "TELNET" and not settings.telnet_access_enabled:
        raise ValueError("TELNET_DISABLED: Telnet template mapping is disabled by policy.")
    rows = list(
        (
            await db.scalars(
                select(AccessTemplate).where(
                    AccessTemplate.name == name,
                    AccessTemplate.protocol == protocol,
                    AccessTemplate.deleted_at.is_(None),
                    AccessTemplate.is_active.is_(True),
                    (AccessTemplate.owner_user_id == actor_id)
                    | (AccessTemplate.visibility == "SHARED"),
                )
            )
        ).all()
    )
    if not rows:
        raise ValueError(
            f"{protocol} Access Template '{name}' was not found or is inactive."
        )
    if len(rows) != 1:
        raise ValueError(
            f"{protocol} Access Template name '{name}' is ambiguous; use a unique visible name."
        )
    template = rows[0]
    revision = await db.scalar(
        select(AccessTemplateRevision)
        .where(
            AccessTemplateRevision.template_id == template.id,
            AccessTemplateRevision.lifecycle_status == "ACTIVE",
        )
        .order_by(AccessTemplateRevision.revision_number.desc())
        .limit(1)
    )
    if revision is None:
        raise ValueError(
            f"{protocol} Access Template '{name}' has no ACTIVE revision."
        )
    return {
        "template_id": str(template.id),
        "template_name": template.name,
        "protocol": protocol,
        "revision_id": str(revision.id),
        "revision_number": revision.revision_number,
        "definition_sha256": revision.definition_sha256,
    }


async def _resolve_configuration_mapping(
    db: AsyncSession,
    *,
    code: str | None,
    version_text: str | None,
    device_type_id: UUID,
) -> dict[str, Any] | None:
    if (code is None) != (version_text is None):
        raise ValueError(
            "configuration_template_code and configuration_template_version must be supplied together."
        )
    if code is None:
        return None
    try:
        version_number = int(version_text or "")
    except ValueError as exc:
        raise ValueError("configuration_template_version must be an integer.") from exc
    if version_number < 1:
        raise ValueError("configuration_template_version must be at least 1.")
    row = (
        await db.execute(
            select(ConfigurationTemplate, ConfigurationTemplateVersion)
            .join(
                ConfigurationTemplateVersion,
                ConfigurationTemplateVersion.template_id == ConfigurationTemplate.id,
            )
            .where(
                ConfigurationTemplate.code == code,
                ConfigurationTemplate.is_active.is_(True),
                ConfigurationTemplateVersion.version_number == version_number,
                ConfigurationTemplateVersion.status == "PUBLISHED",
            )
        )
    ).first()
    if row is None:
        raise ValueError(
            f"Published Configuration Template '{code}' version {version_number} was not found."
        )
    template, version = row
    if template.device_type_id != device_type_id:
        raise ValueError(
            "CONFIGURATION_TEMPLATE_DEVICE_TYPE_MISMATCH: Configuration Template device type does not match the imported device."
        )
    try:
        await _assert_version_integrity(db, version)
        registry.get(version.adapter_key)
    except (KeyError, ValueError, ConfigurationTemplateError) as exc:
        raise ValueError(
            "CONFIGURATION_TEMPLATE_VERSION_INTEGRITY_FAILED: Published Configuration Template failed validation."
        ) from exc
    return {
        "template_id": str(template.id),
        "template_code": template.code,
        "template_version_id": str(version.id),
        "version_number": version.version_number,
        "content_sha256": version.content_sha256,
        "adapter_key": version.adapter_key,
        "transport": version.transport,
        "enabled": False,
        "credential_source": "ACCESS_TEMPLATE",
    }


async def validate_device_template_mapping(
    db: AsyncSession,
    *,
    actor_id: UUID,
    source_row: dict[str, Any],
    base: ValidationResult,
) -> ValidationResult:
    if base.status == "ERROR":
        return base
    requested = _mapping_requested(source_row)
    firmware = _text(source_row, "firmware_version")
    if base.status == "NOOP" and (requested or firmware):
        return ValidationResult(
            "ERROR",
            base.normalized,
            "TEMPLATE_MAPPING_REQUIRES_NEW_DEVICE",
            "Template mapping and firmware import are supported only for newly created device rows.",
        )
    normalized = dict(base.normalized)
    if firmware:
        normalized["firmware_version"] = firmware
    mappings: dict[str, Any] = {"access": {}, "configuration": None}
    try:
        for protocol, column in _ACCESS_COLUMNS.items():
            name = _text(source_row, column)
            if name:
                mappings["access"][protocol] = await _resolve_access_mapping(
                    db,
                    actor_id=actor_id,
                    protocol=protocol,
                    name=name,
                )
        mappings["configuration"] = await _resolve_configuration_mapping(
            db,
            code=_text(source_row, "configuration_template_code"),
            version_text=_text(source_row, "configuration_template_version"),
            device_type_id=UUID(normalized["device_type_id"]),
        )
    except ValueError as exc:
        text = str(exc)
        code = text.split(":", 1)[0] if ":" in text else "TEMPLATE_MAPPING_INVALID"
        return ValidationResult("ERROR", normalized, code[:120], text[:1000])
    if mappings["access"] or mappings["configuration"] is not None:
        normalized["tp4_template_mappings"] = mappings
    return ValidationResult(base.status, normalized)


async def create_import_preview_with_template_mapping(
    db: AsyncSession,
    *,
    actor_id: UUID,
    scope: EffectiveResourceScope,
    entity_type: str,
    filename: str,
    data: bytes,
    file_format: str | None = None,
    idempotency_key: str | None = None,
    expected_subtype: str | None = None,
) -> ImportJob:
    job = await create_import_preview(
        db,
        actor_id=actor_id,
        scope=scope,
        entity_type=entity_type,
        filename=filename,
        data=data,
        file_format=file_format,
        idempotency_key=idempotency_key,
        expected_subtype=expected_subtype,
    )
    if entity_type.strip().lower() != "devices":
        return job
    records = list(
        (
            await db.scalars(
                select(ImportRecord)
                .where(ImportRecord.import_job_id == job.id)
                .order_by(ImportRecord.row_number)
            )
        ).all()
    )
    await _require_mapping_permissions(
        db,
        actor_id=actor_id,
        rows=[dict(record.source_data or {}) for record in records],
    )
    counts = {"VALID": 0, "NOOP": 0, "ERROR": 0}
    mapped_rows = 0
    access_kinds: set[str] = set()
    configuration_rows = 0
    for record in records:
        base = ValidationResult(
            record.status,
            dict(record.normalized_data or {}),
            record.error_code,
            record.error_message,
        )
        result = await validate_device_template_mapping(
            db,
            actor_id=actor_id,
            source_row=dict(record.source_data or {}),
            base=base,
        )
        record.status = result.status
        record.error_code = result.error_code
        record.error_message = result.error_message
        record.normalized_data = result.normalized
        mappings = result.normalized.get("tp4_template_mappings") if result.status != "ERROR" else None
        if isinstance(mappings, dict):
            mapped_rows += 1
            access_kinds.update((mappings.get("access") or {}).keys())
            if mappings.get("configuration") is not None:
                configuration_rows += 1
        counts[result.status] += 1
    job.error_records = counts["ERROR"]
    job.validation_summary = {
        "valid": counts["VALID"],
        "noop": counts["NOOP"],
        "errors": counts["ERROR"],
    }
    metadata = dict(job.metadata_ or {})
    metadata["tp4_template_mapping"] = {
        "mapped_rows": mapped_rows,
        "access_protocols": sorted(access_kinds),
        "configuration_rows": configuration_rows,
    }
    job.metadata_ = metadata
    await db.flush()
    return job


def template_bytes_with_template_mapping(
    entity_type: str,
    format: str = "CSV",
    subtype: str | None = None,
) -> tuple[bytes, str, str]:
    entity = entity_type.strip().lower()
    if entity != "devices":
        from app.services.data_exchange import template_bytes

        return template_bytes(entity_type, format, subtype)
    selected = (subtype or "ALL").strip().upper()
    if selected != "ALL" and selected not in CONTROLLED_TYPES:
        raise ValueError("Unsupported device template subtype.")
    columns = list(TEMPLATES["devices"]) + DEVICE_MAPPING_COLUMNS
    if selected != "ALL":
        columns = [column for column in columns if column != "device_type"]
    data = write_tabular_template_bytes(
        columns,
        format,
        title="FTTW Devices Import",
    )
    media = {
        "CSV": "text/csv",
        "XLSX": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "JSON": "application/json",
    }[format.upper()]
    suffix = f"_{selected.lower()}" if selected != "ALL" else ""
    return data, f"fttw_devices{suffix}_import_template.{format.lower()}", media


async def _revalidate_device_record(
    db: AsyncSession,
    *,
    actor_id: UUID,
    scope: EffectiveResourceScope,
    record: ImportRecord,
    expected_subtype: str,
) -> ValidationResult:
    prepared = _prepare_row_for_subtype("devices", record.source_data, expected_subtype)
    base = await validate_import_row(db, scope, "devices", prepared)
    return await validate_device_template_mapping(
        db,
        actor_id=actor_id,
        source_row=prepared,
        base=base,
    )


async def _apply_device_with_template_mapping(
    db: AsyncSession,
    *,
    data: dict[str, Any],
    actor: User,
    import_job_id: UUID,
) -> None:
    metadata = {"import_source": "PHASE_D"}
    firmware = data.get("firmware_version")
    if firmware:
        metadata["firmware_version"] = str(firmware)
    result = await register_domain_device(
        db,
        device_type_id=UUID(data["device_type_id"]),
        display_name=data["display_name"],
        management_ip=data["management_ip"],
        location_id=UUID(data["location_id"]) if data.get("location_id") else None,
        sector_id=UUID(data["sector_id"]) if data.get("sector_id") else None,
        parent_device_id=UUID(data["parent_device_id"]) if data.get("parent_device_id") else None,
        hostname=data.get("hostname"),
        vendor=data.get("vendor"),
        model=data.get("model"),
        serial_number=data.get("serial_number"),
        description=data.get("description"),
        management_protocol=data.get("management_protocol"),
        credential_reference=None,
        metadata=metadata,
        ip_source="IMPORT",
    )
    mappings = data.get("tp4_template_mappings") or {}
    for protocol, snapshot in sorted((mappings.get("access") or {}).items()):
        template = await db.get(AccessTemplate, UUID(snapshot["template_id"]))
        if template is None:
            raise ValueError(f"{protocol} template disappeared during import commit.")
        outcome = await apply_device_access_assignment(
            db,
            device_id=result.device.id,
            template=template,
            actor=actor,
            priority=0,
            conflict_policy="FAIL_ON_CONFLICT",
        )
        if outcome.get("status") not in {"SUCCEEDED", "NOOP"}:
            raise ValueError(f"{protocol} template assignment failed during import commit.")
    config = mappings.get("configuration")
    if isinstance(config, dict):
        binding = await bind_device_for_assignment(
            db,
            device=result.device,
            payload=DeviceConfigurationBindingWrite(
                template_version_id=UUID(config["template_version_id"]),
                credential_source="ACCESS_TEMPLATE",
                credential_reference=None,
                connection_overrides={},
                enabled=False,
            ),
            actor_user_id=actor.id,
        )
        binding_metadata = dict(binding.metadata_ or {})
        binding_metadata["tp4_import"] = {
            "import_job_id": str(import_job_id),
            "content_sha256": config.get("content_sha256"),
        }
        binding.metadata_ = binding_metadata
        await db.flush()


async def commit_import_with_template_mapping(
    db: AsyncSession,
    *,
    job: ImportJob,
    actor_id: UUID,
    scope: EffectiveResourceScope,
    expected_file_sha256: str,
) -> ImportJob:
    if (job.entity_type or "").strip().lower() != "devices":
        from app.services.data_exchange import commit_import

        return await commit_import(
            db,
            job=job,
            actor_id=actor_id,
            scope=scope,
            expected_file_sha256=expected_file_sha256,
        )
    locked = await db.scalar(
        select(ImportJob)
        .where(ImportJob.id == job.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if locked is None or locked.created_by_user_id != actor_id:
        raise ValueError("Import job not found.")
    if locked.status == "COMMITTED":
        return locked
    if locked.status != "PREVIEWED":
        raise ValueError("Only PREVIEWED imports can be committed.")
    if locked.preview_expires_at is None or locked.preview_expires_at <= utcnow():
        locked.status = "EXPIRED"
        raise ImportPreviewExpired("Import preview expired; upload the file again.")
    if locked.file_sha256 != expected_file_sha256:
        raise ValueError("Import file checksum does not match the preview.")
    if locked.scope_fingerprint != scope_fingerprint(scope):
        raise ValueError("Authorization scope changed after preview; preview the import again.")
    records = list(
        (
            await db.scalars(
                select(ImportRecord)
                .where(ImportRecord.import_job_id == locked.id)
                .order_by(ImportRecord.row_number)
                .with_for_update()
            )
        ).all()
    )
    if any(record.status == "ERROR" for record in records):
        raise ValueError("Import contains row-level validation errors and cannot be committed.")
    await _require_mapping_permissions(
        db,
        actor_id=actor_id,
        rows=[dict(record.source_data or {}) for record in records],
    )
    expected_subtype = str((locked.metadata_ or {}).get("subtype") or "ALL")
    for record in records:
        previous = dict(record.normalized_data or {})
        check = await _revalidate_device_record(
            db,
            actor_id=actor_id,
            scope=scope,
            record=record,
            expected_subtype=expected_subtype,
        )
        if check.status == "ERROR":
            raise ValueError(
                f"Row {record.row_number} is no longer valid: {check.error_code}: {check.error_message}"
            )
        previous_mapping = previous.get("tp4_template_mappings")
        current_mapping = check.normalized.get("tp4_template_mappings")
        if previous_mapping != current_mapping:
            raise ValueError(
                f"Row {record.row_number} template mapping changed after preview; preview the import again."
            )
        if check.status == "NOOP":
            record.status = "NOOP"
        record.normalized_data = check.normalized

    actor = await db.get(User, actor_id)
    if actor is None:
        raise ValueError("Import actor no longer exists.")
    locked.status = "COMMITTING"
    imported = 0
    for record in records:
        if record.status == "NOOP":
            continue
        await _apply_device_with_template_mapping(
            db,
            data=dict(record.normalized_data or {}),
            actor=actor,
            import_job_id=locked.id,
        )
        record.status = "APPLIED"
        imported += 1
    locked.imported_records = imported
    locked.status = "COMMITTED"
    locked.committed_at = utcnow()
    mapping_meta = dict((locked.metadata_ or {}).get("tp4_template_mapping") or {})
    await record_audit(
        db,
        action="IMPORT_COMMITTED",
        entity_type="ImportJob",
        entity_id=locked.id,
        description="Validated import committed transactionally.",
        metadata={
            "import_entity_type": "devices",
            "applied_rows": imported,
            "total_rows": locked.total_records,
            "mapped_rows": int(mapping_meta.get("mapped_rows") or 0),
            "access_protocols": list(mapping_meta.get("access_protocols") or []),
            "configuration_rows": int(mapping_meta.get("configuration_rows") or 0),
        },
    )
    return locked
