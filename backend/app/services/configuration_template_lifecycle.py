from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.configuration.registry import registry
from app.configuration.templating import ConfigurationTemplateError, definition_sha256
from app.core.exceptions import APIError
from app.models import ConfigurationTemplate, ConfigurationTemplateVersion
from app.schemas.configuration import ConfigurationTemplateCreate, ConfigurationTemplateVersionUpdate
from app.schemas.configuration_template_lifecycle import ConfigurationTemplateFamilyCloneRequest
from app.services.audit import record_audit
from app.services.configuration import (
    _definition_from_version,
    _functions_for_version,
    create_template,
    create_template_version,
    update_draft_version,
)


UTC = timezone.utc


async def _version(
    db: AsyncSession,
    *,
    template_id: UUID,
    version_id: UUID,
    for_update: bool = False,
) -> ConfigurationTemplateVersion:
    stmt = select(ConfigurationTemplateVersion).where(
        ConfigurationTemplateVersion.id == version_id,
        ConfigurationTemplateVersion.template_id == template_id,
    )
    if for_update:
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    row = await db.scalar(stmt)
    if row is None:
        raise APIError(
            404,
            "CONFIGURATION_TEMPLATE_VERSION_NOT_FOUND",
            "Configuration template version not found.",
        )
    return row


async def _template(
    db: AsyncSession,
    *,
    template_id: UUID,
    for_update: bool = False,
) -> ConfigurationTemplate:
    stmt = select(ConfigurationTemplate).where(ConfigurationTemplate.id == template_id)
    if for_update:
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    row = await db.scalar(stmt)
    if row is None:
        raise APIError(
            404,
            "CONFIGURATION_TEMPLATE_NOT_FOUND",
            "Configuration template not found.",
        )
    return row


async def read_version_lifecycle(
    db: AsyncSession,
    *,
    template_id: UUID,
    version_id: UUID,
) -> dict[str, Any]:
    version = await _version(
        db,
        template_id=template_id,
        version_id=version_id,
    )
    row = (
        await db.execute(
            text(
                """
                SELECT
                    source_version_id,
                    tested_definition_sha256,
                    tested_at,
                    tested_by_user_id,
                    approved_at,
                    approved_by_user_id
                FROM configuration_template_versions
                WHERE id = :version_id
                  AND template_id = :template_id
                """
            ),
            {"version_id": version_id, "template_id": template_id},
        )
    ).mappings().one()
    return {
        "template_id": version.template_id,
        "version_id": version.id,
        "version_number": version.version_number,
        "status": version.status,
        "source_version_id": row["source_version_id"],
        "tested_definition_sha256": row["tested_definition_sha256"],
        "tested_at": row["tested_at"],
        "tested_by_user_id": row["tested_by_user_id"],
        "approved_at": row["approved_at"],
        "approved_by_user_id": row["approved_by_user_id"],
        "content_sha256": version.content_sha256,
        "published_at": version.published_at,
        "published_by_user_id": version.published_by_user_id,
    }


async def _definition_and_hash(
    db: AsyncSession,
    version: ConfigurationTemplateVersion,
):
    functions = await _functions_for_version(db, version.id)
    definition = _definition_from_version(version, functions)
    return definition, definition_sha256(definition)


async def update_configuration_template_version_lifecycle(
    db: AsyncSession,
    *,
    template_id: UUID,
    version_id: UUID,
    payload: ConfigurationTemplateVersionUpdate,
    actor_user_id: UUID,
) -> ConfigurationTemplateVersion:
    version = await _version(
        db,
        template_id=template_id,
        version_id=version_id,
        for_update=True,
    )
    previous_status = version.status
    if previous_status in {"PUBLISHED", "RETIRED"}:
        raise APIError(
            409,
            "CONFIGURATION_TEMPLATE_VERSION_IMMUTABLE",
            "Published or retired template versions cannot be edited.",
        )

    # Any definition edit invalidates prior test/approval evidence before the
    # existing draft writer persists the new validated definition.
    await db.execute(
        text(
            """
            UPDATE configuration_template_versions
            SET status = 'DRAFT',
                tested_definition_sha256 = NULL,
                tested_at = NULL,
                tested_by_user_id = NULL,
                approved_at = NULL,
                approved_by_user_id = NULL,
                content_sha256 = NULL,
                published_at = NULL,
                published_by_user_id = NULL
            WHERE id = :version_id
              AND template_id = :template_id
            """
        ),
        {"version_id": version_id, "template_id": template_id},
    )
    version.status = "DRAFT"
    version.content_sha256 = None
    version.published_at = None
    version.published_by_user_id = None
    await db.flush()

    updated = await update_draft_version(
        db,
        template_id=template_id,
        version_id=version_id,
        payload=payload,
        actor_user_id=actor_user_id,
    )
    if previous_status in {"TESTED", "APPROVED"}:
        await record_audit(
            db,
            action="CONFIGURATION_TEMPLATE_LIFECYCLE_EVIDENCE_INVALIDATED",
            entity_type="ConfigurationTemplateVersion",
            entity_id=version_id,
            actor_user_id=actor_user_id,
            description="Configuration template definition edit invalidated test/approval evidence.",
            metadata={"template_id": str(template_id), "previous_status": previous_status},
        )
    return updated


async def clone_configuration_template_version(
    db: AsyncSession,
    *,
    template_id: UUID,
    source_version_id: UUID,
    change_note: str | None,
    actor_user_id: UUID,
) -> ConfigurationTemplateVersion:
    source = await _version(
        db,
        template_id=template_id,
        version_id=source_version_id,
    )
    definition, _hash = await _definition_and_hash(db, source)
    payload = ConfigurationTemplateVersionUpdate(
        definition=definition,
        change_note=change_note or f"Cloned from version {source.version_number}",
    )
    version = await create_template_version(
        db,
        template_id=template_id,
        payload=payload,
        actor_user_id=actor_user_id,
    )
    await db.execute(
        text(
            """
            UPDATE configuration_template_versions
            SET source_version_id = :source_version_id
            WHERE id = :version_id
            """
        ),
        {"source_version_id": source.id, "version_id": version.id},
    )
    await record_audit(
        db,
        action="CONFIGURATION_TEMPLATE_VERSION_CLONED",
        entity_type="ConfigurationTemplateVersion",
        entity_id=version.id,
        actor_user_id=actor_user_id,
        description="Configuration template draft version cloned from an exact source version.",
        metadata={
            "template_id": str(template_id),
            "source_version_id": str(source.id),
            "source_version_number": source.version_number,
            "version": version.version_number,
        },
    )
    return version


async def clone_configuration_template_family(
    db: AsyncSession,
    *,
    source_template_id: UUID,
    source_version_id: UUID,
    payload: ConfigurationTemplateFamilyCloneRequest,
    actor_user_id: UUID,
) -> tuple[ConfigurationTemplate, ConfigurationTemplateVersion]:
    source_template = await _template(db, template_id=source_template_id)
    source_version = await _version(
        db,
        template_id=source_template_id,
        version_id=source_version_id,
    )
    definition, _hash = await _definition_and_hash(db, source_version)
    create_payload = ConfigurationTemplateCreate(
        code=payload.code,
        name=payload.name,
        vendor=source_template.vendor,
        model=source_template.model,
        series=source_template.series,
        device_type_id=source_template.device_type_id,
        description=(
            payload.description
            if payload.description is not None
            else source_template.description
        ),
        definition=definition,
    )
    clone, version = await create_template(
        db,
        payload=create_payload,
        actor_user_id=actor_user_id,
    )
    clone.metadata_ = dict(source_template.metadata_ or {})
    version.change_note = payload.change_note or (
        f"Family cloned from {source_template.code} version {source_version.version_number}"
    )
    await db.execute(
        text(
            """
            UPDATE configuration_template_versions
            SET source_version_id = :source_version_id,
                change_note = :change_note
            WHERE id = :version_id
            """
        ),
        {
            "source_version_id": source_version.id,
            "change_note": version.change_note,
            "version_id": version.id,
        },
    )
    await record_audit(
        db,
        action="CONFIGURATION_TEMPLATE_FAMILY_CLONED",
        entity_type="ConfigurationTemplate",
        entity_id=clone.id,
        actor_user_id=actor_user_id,
        description="Configuration template family cloned as a new inactive draft lineage.",
        metadata={
            "source_template_id": str(source_template.id),
            "source_version_id": str(source_version.id),
            "source_code": source_template.code,
            "clone_code": clone.code,
        },
    )
    return clone, version


async def test_configuration_template_version(
    db: AsyncSession,
    *,
    template_id: UUID,
    version_id: UUID,
    actor_user_id: UUID,
) -> ConfigurationTemplateVersion:
    version = await _version(
        db,
        template_id=template_id,
        version_id=version_id,
        for_update=True,
    )
    if version.status not in {"DRAFT", "TESTED"}:
        raise APIError(
            409,
            "CONFIGURATION_TEMPLATE_VERSION_NOT_TESTABLE",
            "Only a draft or already-tested configuration template version can be tested.",
        )
    definition, current_hash = await _definition_and_hash(db, version)
    adapter = registry.get(version.adapter_key)
    try:
        await adapter.validate_template(definition)
    except (ConfigurationTemplateError, ValueError) as exc:
        raise APIError(
            422,
            str(exc).strip("'"),
            "The configuration template version failed adapter validation.",
        ) from exc

    now = datetime.now(UTC)
    await db.execute(
        text(
            """
            UPDATE configuration_template_versions
            SET status = 'TESTED',
                tested_definition_sha256 = :definition_sha256,
                tested_at = :tested_at,
                tested_by_user_id = :tested_by_user_id,
                approved_at = NULL,
                approved_by_user_id = NULL
            WHERE id = :version_id
              AND template_id = :template_id
            """
        ),
        {
            "definition_sha256": current_hash,
            "tested_at": now,
            "tested_by_user_id": actor_user_id,
            "version_id": version_id,
            "template_id": template_id,
        },
    )
    version.status = "TESTED"
    await db.flush()
    await record_audit(
        db,
        action="CONFIGURATION_TEMPLATE_VERSION_TESTED",
        entity_type="ConfigurationTemplateVersion",
        entity_id=version.id,
        actor_user_id=actor_user_id,
        description="Configuration template version passed non-device adapter/definition qualification.",
        metadata={
            "template_id": str(template_id),
            "version": version.version_number,
            "definition_sha256": current_hash,
            "device_connection": False,
        },
    )
    return version


async def approve_configuration_template_version(
    db: AsyncSession,
    *,
    template_id: UUID,
    version_id: UUID,
    actor_user_id: UUID,
) -> ConfigurationTemplateVersion:
    version = await _version(
        db,
        template_id=template_id,
        version_id=version_id,
        for_update=True,
    )
    lifecycle = await read_version_lifecycle(
        db,
        template_id=template_id,
        version_id=version_id,
    )
    if version.status == "APPROVED":
        definition, current_hash = await _definition_and_hash(db, version)
        del definition
        if lifecycle["tested_definition_sha256"] != current_hash:
            raise APIError(
                409,
                "CONFIGURATION_TEMPLATE_TEST_EVIDENCE_STALE",
                "The tested definition fingerprint no longer matches this version.",
            )
        return version
    if version.status != "TESTED":
        raise APIError(
            409,
            "CONFIGURATION_TEMPLATE_VERSION_NOT_TESTED",
            "A configuration template version must pass Test before approval.",
        )
    _definition, current_hash = await _definition_and_hash(db, version)
    if lifecycle["tested_definition_sha256"] != current_hash:
        raise APIError(
            409,
            "CONFIGURATION_TEMPLATE_TEST_EVIDENCE_STALE",
            "The tested definition fingerprint no longer matches this version.",
        )
    now = datetime.now(UTC)
    await db.execute(
        text(
            """
            UPDATE configuration_template_versions
            SET status = 'APPROVED',
                approved_at = :approved_at,
                approved_by_user_id = :approved_by_user_id
            WHERE id = :version_id
              AND template_id = :template_id
            """
        ),
        {
            "approved_at": now,
            "approved_by_user_id": actor_user_id,
            "version_id": version_id,
            "template_id": template_id,
        },
    )
    version.status = "APPROVED"
    await db.flush()
    await record_audit(
        db,
        action="CONFIGURATION_TEMPLATE_VERSION_APPROVED",
        entity_type="ConfigurationTemplateVersion",
        entity_id=version.id,
        actor_user_id=actor_user_id,
        description="Tested configuration template version approved for activation.",
        metadata={
            "template_id": str(template_id),
            "version": version.version_number,
            "tested_definition_sha256": current_hash,
        },
    )
    return version


async def activate_configuration_template_version(
    db: AsyncSession,
    *,
    template_id: UUID,
    version_id: UUID,
    actor_user_id: UUID,
) -> ConfigurationTemplateVersion:
    template = await _template(db, template_id=template_id, for_update=True)
    if not template.is_active:
        raise APIError(
            409,
            "CONFIGURATION_TEMPLATE_INACTIVE",
            "Inactive configuration template families cannot activate a version.",
        )
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
    lifecycle = await read_version_lifecycle(
        db,
        template_id=template_id,
        version_id=version_id,
    )
    _definition, current_hash = await _definition_and_hash(db, target)
    if target.status == "PUBLISHED":
        if target.content_sha256 != current_hash:
            raise APIError(
                409,
                "CONFIGURATION_TEMPLATE_VERSION_INTEGRITY_FAILED",
                "The published configuration template version failed its integrity check.",
            )
        return target
    if target.status != "APPROVED":
        raise APIError(
            409,
            "CONFIGURATION_TEMPLATE_VERSION_NOT_APPROVED",
            "A configuration template version must be tested and approved before activation.",
        )
    if lifecycle["tested_definition_sha256"] != current_hash:
        raise APIError(
            409,
            "CONFIGURATION_TEMPLATE_TEST_EVIDENCE_STALE",
            "The approved test fingerprint no longer matches this version.",
        )
    if lifecycle["approved_at"] is None:
        raise APIError(
            409,
            "CONFIGURATION_TEMPLATE_APPROVAL_EVIDENCE_MISSING",
            "Approval evidence is missing for this configuration template version.",
        )

    retired_published = False
    for row in versions:
        if row.id != target.id and row.status == "PUBLISHED":
            row.status = "RETIRED"
            retired_published = True

    # PostgreSQL enforces at most one PUBLISHED version per template.
    # Flush retirement first so ORM update ordering cannot transiently
    # violate that database invariant when the replacement is published.
    if retired_published:
        await db.flush()

    now = datetime.now(UTC)
    target.status = "PUBLISHED"
    target.content_sha256 = current_hash
    target.published_at = now
    target.published_by_user_id = actor_user_id
    await db.flush()
    await record_audit(
        db,
        action="CONFIGURATION_TEMPLATE_VERSION_ACTIVATED",
        entity_type="ConfigurationTemplateVersion",
        entity_id=target.id,
        actor_user_id=actor_user_id,
        description="Approved configuration template version activated without rebinding devices.",
        metadata={
            "template_id": str(template_id),
            "version": target.version_number,
            "content_sha256": current_hash,
            "device_rebinding": False,
            "configuration_execution": False,
        },
    )
    return target
