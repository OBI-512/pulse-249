from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import time
from uuid import UUID

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import APIError
from ..models import (
    AccessTemplate,
    AccessTemplateRevision,
    AccessTemplateRevisionSecret,
    AccessTemplateSecret,
    AccessTemplateTestResult,
)
from ..remote_gateway.secrets import RemoteAccessSecretError, resolve_secret_reference
from .access_template_secret_hygiene import calculate_secret_key_transition
from .access_template_testing import (
    AccessTemplateProbeFailure,
    ProbeOutcome,
    _prepare_web_transport,
    _probe_snmp,
    _probe_ssh,
    _probe_telnet,
    _probe_web,
)
from .access_templates import (
    AccessTemplateSecretError,
    decrypt_secret,
    encrypt_secret,
    validate_template_definition,
)
from .audit import record_audit
from .remote_access import get_management_ip


UTC = timezone.utc


def utcnow() -> datetime:
    return datetime.now(UTC)


async def revision_secret_rows(
    db: AsyncSession,
    revision_id: UUID,
) -> list[AccessTemplateRevisionSecret]:
    return list(
        (
            await db.scalars(
                select(AccessTemplateRevisionSecret)
                .where(AccessTemplateRevisionSecret.revision_id == revision_id)
                .order_by(AccessTemplateRevisionSecret.secret_key)
            )
        ).all()
    )


async def revision_secret_provider_map(
    db: AsyncSession,
    revision_id: UUID,
) -> dict[str, str]:
    rows = await revision_secret_rows(db, revision_id)
    return {row.secret_key: row.provider for row in rows}


def _fingerprint_payload(
    *,
    protocol: str,
    protocol_variant: str | None,
    settings: dict,
    secret_rows: list[AccessTemplateRevisionSecret],
) -> dict:
    secrets: list[dict[str, object]] = []
    for row in sorted(secret_rows, key=lambda item: item.secret_key):
        item: dict[str, object] = {
            "secret_key": row.secret_key,
            "provider": row.provider,
            "key_version": row.key_version,
        }
        if row.provider == "ENV_REFERENCE":
            item["reference"] = row.reference or ""
        else:
            item["encrypted_payload_sha256"] = hashlib.sha256(
                (row.encrypted_payload or "").encode("utf-8")
            ).hexdigest()
        secrets.append(item)
    return {
        "protocol": protocol.strip().upper(),
        "protocol_variant": protocol_variant,
        "settings": settings or {},
        "secrets": secrets,
    }


def revision_definition_sha256_from_parts(
    *,
    protocol: str,
    protocol_variant: str | None,
    settings: dict,
    secret_rows: list[AccessTemplateRevisionSecret],
) -> str:
    payload = _fingerprint_payload(
        protocol=protocol,
        protocol_variant=protocol_variant,
        settings=settings,
        secret_rows=secret_rows,
    )
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


async def revision_definition_sha256(
    db: AsyncSession,
    *,
    template: AccessTemplate,
    revision: AccessTemplateRevision,
) -> str:
    return revision_definition_sha256_from_parts(
        protocol=template.protocol,
        protocol_variant=revision.protocol_variant,
        settings=dict(revision.settings_json or {}),
        secret_rows=await revision_secret_rows(db, revision.id),
    )


async def resolved_revision_secrets(
    db: AsyncSession,
    *,
    template_id: UUID,
    revision_id: UUID,
) -> dict[str, str]:
    rows = await revision_secret_rows(db, revision_id)
    values: dict[str, str] = {}
    for row in rows:
        if row.template_id != template_id:
            raise AccessTemplateSecretError("ACCESS_TEMPLATE_REVISION_SECRET_TEMPLATE_MISMATCH")
        if row.provider == "ENV_REFERENCE":
            try:
                values[row.secret_key] = resolve_secret_reference(row.reference)
            except RemoteAccessSecretError as exc:
                raise AccessTemplateSecretError(
                    "ACCESS_TEMPLATE_ENV_SECRET_NOT_AVAILABLE"
                ) from exc
        else:
            values[row.secret_key] = decrypt_secret(
                template_id=template_id,
                secret_key=row.secret_key,
                payload=row.encrypted_payload or "",
            )
    return values


async def _apply_revision_secret_inputs(
    db: AsyncSession,
    *,
    template: AccessTemplate,
    revision: AccessTemplateRevision,
    secret_inputs: dict[str, object | None],
) -> None:
    existing = {
        row.secret_key: row
        for row in await revision_secret_rows(db, revision.id)
    }
    for secret_key, item in secret_inputs.items():
        if item is None:
            row = existing.get(secret_key)
            if row is not None:
                await db.delete(row)
            continue
        row = existing.get(secret_key)
        if row is None:
            row = AccessTemplateRevisionSecret(
                revision_id=revision.id,
                template_id=template.id,
                secret_key=secret_key,
                provider=item.provider,
            )
            db.add(row)
        row.template_id = template.id
        row.provider = item.provider
        row.key_version = 1
        if item.provider == "ENV_REFERENCE":
            row.reference = item.reference
            row.encrypted_payload = None
        else:
            row.reference = None
            row.encrypted_payload = encrypt_secret(
                template_id=template.id,
                secret_key=secret_key,
                plaintext=item.value,
            )
    await db.flush()


async def _prune_revision_secret_keys(
    db: AsyncSession,
    *,
    revision_id: UUID,
    secret_keys: set[str],
) -> None:
    if not secret_keys:
        return
    await db.execute(
        delete(AccessTemplateRevisionSecret).where(
            AccessTemplateRevisionSecret.revision_id == revision_id,
            AccessTemplateRevisionSecret.secret_key.in_(secret_keys),
        )
    )


async def list_revisions(
    db: AsyncSession,
    *,
    template_id: UUID,
) -> list[AccessTemplateRevision]:
    return list(
        (
            await db.scalars(
                select(AccessTemplateRevision)
                .where(AccessTemplateRevision.template_id == template_id)
                .order_by(AccessTemplateRevision.revision_number.desc())
            )
        ).all()
    )


async def get_revision(
    db: AsyncSession,
    *,
    template_id: UUID,
    revision_id: UUID,
    for_update: bool = False,
) -> AccessTemplateRevision:
    stmt = select(AccessTemplateRevision).where(
        AccessTemplateRevision.id == revision_id,
        AccessTemplateRevision.template_id == template_id,
    )
    if for_update:
        stmt = stmt.with_for_update()
    row = await db.scalar(stmt)
    if row is None:
        raise APIError(
            404,
            "ACCESS_TEMPLATE_REVISION_NOT_FOUND",
            "Access Template revision not found.",
        )
    return row


async def _source_revision(
    db: AsyncSession,
    *,
    template_id: UUID,
    source_revision_id: UUID | None,
) -> AccessTemplateRevision:
    if source_revision_id is not None:
        return await get_revision(
            db,
            template_id=template_id,
            revision_id=source_revision_id,
        )
    source = await db.scalar(
        select(AccessTemplateRevision)
        .where(AccessTemplateRevision.template_id == template_id)
        .order_by(
            (AccessTemplateRevision.lifecycle_status == "ACTIVE").desc(),
            AccessTemplateRevision.revision_number.desc(),
        )
        .limit(1)
    )
    if source is None:
        raise APIError(
            409,
            "ACCESS_TEMPLATE_REVISION_SOURCE_REQUIRED",
            "The Access Template has no revision to use as a source.",
        )
    return source


async def create_revision(
    db: AsyncSession,
    *,
    template: AccessTemplate,
    source_revision_id: UUID | None,
    change_note: str | None,
    actor_user_id: UUID,
) -> AccessTemplateRevision:
    locked_template = await db.scalar(
        select(AccessTemplate)
        .where(AccessTemplate.id == template.id, AccessTemplate.deleted_at.is_(None))
        .with_for_update()
    )
    if locked_template is None:
        raise APIError(404, "ACCESS_TEMPLATE_NOT_FOUND", "Access Template not found.")
    source = await _source_revision(
        db,
        template_id=template.id,
        source_revision_id=source_revision_id,
    )
    max_revision = int(
        await db.scalar(
            select(func.max(AccessTemplateRevision.revision_number)).where(
                AccessTemplateRevision.template_id == template.id
            )
        )
        or 0
    )
    revision = AccessTemplateRevision(
        template_id=template.id,
        revision_number=max_revision + 1,
        lifecycle_status="DRAFT",
        protocol_variant=source.protocol_variant,
        settings_json=dict(source.settings_json or {}),
        source_revision_id=source.id,
        change_note=change_note.strip() if change_note else None,
        definition_sha256=None,
        legacy_backfill=False,
    )
    db.add(revision)
    await db.flush()
    for secret in await revision_secret_rows(db, source.id):
        db.add(
            AccessTemplateRevisionSecret(
                revision_id=revision.id,
                template_id=template.id,
                secret_key=secret.secret_key,
                provider=secret.provider,
                encrypted_payload=secret.encrypted_payload,
                reference=secret.reference,
                key_version=secret.key_version,
            )
        )
    await db.flush()
    await record_audit(
        db,
        action="ACCESS_TEMPLATE_REVISION_CREATED",
        entity_type="ACCESS_TEMPLATE_REVISION",
        entity_id=revision.id,
        actor_user_id=actor_user_id,
        metadata={
            "template_id": str(template.id),
            "revision_number": revision.revision_number,
            "source_revision_id": str(source.id),
        },
    )
    return revision


async def create_template_family(
    db: AsyncSession,
    *,
    name: str,
    description: str | None,
    protocol: str,
    protocol_variant: str | None,
    visibility: str,
    settings: dict,
    secrets: dict[str, object],
    change_note: str | None,
    actor_user_id: UUID,
) -> tuple[AccessTemplate, AccessTemplateRevision]:
    """Create one inactive family and its initial DRAFT revision atomically."""

    normalized_name = name.strip()
    normalized_protocol = protocol.strip().upper()
    duplicate = await db.scalar(
        select(AccessTemplate.id).where(
            AccessTemplate.owner_user_id == actor_user_id,
            AccessTemplate.name == normalized_name,
            AccessTemplate.protocol == normalized_protocol,
            AccessTemplate.deleted_at.is_(None),
        )
    )
    if duplicate is not None:
        raise APIError(
            409,
            "ACCESS_TEMPLATE_IDENTITY_EXISTS",
            "An Access Template with this owner/name/protocol identity already exists.",
        )

    secret_keys, _stale = calculate_secret_key_transition(
        protocol=normalized_protocol,
        protocol_variant=protocol_variant,
        existing_keys=set(),
        changes=secrets,
    )
    validated_protocol, validated_variant, cleaned_settings = validate_template_definition(
        protocol=normalized_protocol,
        protocol_variant=protocol_variant,
        template_settings=settings,
        secret_keys=secret_keys,
        is_active=False,
    )

    family = AccessTemplate(
        name=normalized_name,
        description=description,
        protocol=validated_protocol,
        protocol_variant=validated_variant,
        visibility=visibility,
        owner_user_id=actor_user_id,
        is_active=False,
        settings_json=dict(cleaned_settings),
    )
    db.add(family)
    await db.flush()

    revision = AccessTemplateRevision(
        template_id=family.id,
        revision_number=1,
        lifecycle_status="DRAFT",
        protocol_variant=validated_variant,
        settings_json=dict(cleaned_settings),
        source_revision_id=None,
        change_note=change_note.strip() if change_note else None,
        definition_sha256=None,
        legacy_backfill=False,
    )
    db.add(revision)
    await db.flush()
    await _apply_revision_secret_inputs(
        db,
        template=family,
        revision=revision,
        secret_inputs=secrets,
    )
    await record_audit(
        db,
        action="ACCESS_TEMPLATE_LIFECYCLE_FAMILY_CREATED",
        entity_type="ACCESS_TEMPLATE",
        entity_id=family.id,
        actor_user_id=actor_user_id,
        entity_display_snapshot={"name": family.name, "protocol": family.protocol},
        after_summary={
            "visibility": family.visibility,
            "is_active": False,
            "initial_revision_id": str(revision.id),
            "initial_revision_number": 1,
            "initial_revision_status": "DRAFT",
            "secret_keys": sorted(secret_keys),
            "device_bindings_created": 0,
            "configuration_operations_created": 0,
            "device_configuration_execution": False,
        },
    )
    return family, revision


async def update_revision(
    db: AsyncSession,
    *,
    template: AccessTemplate,
    revision_id: UUID,
    payload,
    actor_user_id: UUID,
) -> AccessTemplateRevision:
    revision = await get_revision(
        db,
        template_id=template.id,
        revision_id=revision_id,
        for_update=True,
    )
    definition_changed = any(
        value is not None
        for value in (payload.protocol_variant, payload.settings, payload.secrets)
    )
    if definition_changed and revision.lifecycle_status in {"ACTIVE", "RETIRED"}:
        raise APIError(
            409,
            "ACCESS_TEMPLATE_REVISION_IMMUTABLE",
            "Active or retired Access Template revisions cannot be edited.",
        )

    if payload.change_note is not None:
        revision.change_note = payload.change_note.strip() or None

    if definition_changed:
        existing_keys = set((await revision_secret_provider_map(db, revision.id)).keys())
        requested_variant = (
            payload.protocol_variant
            if payload.protocol_variant is not None
            else revision.protocol_variant
        )
        changes = payload.secrets or {}
        resulting_keys, stale_keys = calculate_secret_key_transition(
            protocol=template.protocol,
            protocol_variant=requested_variant,
            existing_keys=existing_keys,
            changes=changes,
        )
        _protocol, variant, cleaned_settings = validate_template_definition(
            protocol=template.protocol,
            protocol_variant=requested_variant,
            template_settings=(
                payload.settings
                if payload.settings is not None
                else dict(revision.settings_json or {})
            ),
            secret_keys=resulting_keys,
            is_active=False,
        )
        revision.protocol_variant = variant
        revision.settings_json = cleaned_settings
        if payload.secrets is not None:
            await _apply_revision_secret_inputs(
                db,
                template=template,
                revision=revision,
                secret_inputs=payload.secrets,
            )
        await _prune_revision_secret_keys(
            db,
            revision_id=revision.id,
            secret_keys=stale_keys,
        )
        revision.lifecycle_status = "DRAFT"
        revision.definition_sha256 = None
        revision.tested_at = None
        revision.tested_by_user_id = None
        revision.approved_at = None
        revision.approved_by_user_id = None
        revision.activated_at = None
        revision.activated_by_user_id = None
        revision.retired_at = None
    await db.flush()
    await record_audit(
        db,
        action="ACCESS_TEMPLATE_REVISION_UPDATED",
        entity_type="ACCESS_TEMPLATE_REVISION",
        entity_id=revision.id,
        actor_user_id=actor_user_id,
        metadata={
            "template_id": str(template.id),
            "revision_number": revision.revision_number,
            "definition_changed": definition_changed,
            "lifecycle_status": revision.lifecycle_status,
        },
    )
    return revision


def runtime_template_for_revision(
    template: AccessTemplate,
    revision: AccessTemplateRevision,
) -> AccessTemplate:
    return AccessTemplate(
        id=template.id,
        name=template.name,
        description=template.description,
        protocol=template.protocol,
        protocol_variant=revision.protocol_variant,
        visibility=template.visibility,
        owner_user_id=template.owner_user_id,
        is_active=True,
        settings_json=dict(revision.settings_json or {}),
        deleted_at=template.deleted_at,
    )


async def test_revision_connection(
    db: AsyncSession,
    *,
    template: AccessTemplate,
    revision: AccessTemplateRevision,
    device_id: UUID,
    tested_by_user_id: UUID,
) -> AccessTemplateTestResult:
    if revision.lifecycle_status == "RETIRED":
        raise APIError(
            409,
            "ACCESS_TEMPLATE_REVISION_RETIRED",
            "Retired Access Template revisions cannot be connection-tested.",
        )
    secret_rows = await revision_secret_rows(db, revision.id)
    secret_keys = {row.secret_key for row in secret_rows}
    validate_template_definition(
        protocol=template.protocol,
        protocol_variant=revision.protocol_variant,
        template_settings=dict(revision.settings_json or {}),
        secret_keys=secret_keys,
        is_active=True,
    )
    fingerprint = revision_definition_sha256_from_parts(
        protocol=template.protocol,
        protocol_variant=revision.protocol_variant,
        settings=dict(revision.settings_json or {}),
        secret_rows=secret_rows,
    )
    runtime_template = runtime_template_for_revision(template, revision)
    management_ip = await get_management_ip(db, device_id)
    started = time.perf_counter()
    outcome: ProbeOutcome
    if not management_ip:
        outcome = ProbeOutcome(
            False,
            "NETWORK_UNREACHABLE",
            "The device has no active management IP address.",
        )
    else:
        try:
            protocol = template.protocol.strip().upper()
            if protocol == "WEB":
                timeout_seconds = int(dict(revision.settings_json or {}).get("timeout_seconds", 10))
                transport = await _prepare_web_transport(
                    db,
                    device_id=device_id,
                    management_ip=management_ip,
                    timeout_seconds=timeout_seconds,
                    actor_user_id=tested_by_user_id,
                )
                secrets = await resolved_revision_secrets(
                    db,
                    template_id=template.id,
                    revision_id=revision.id,
                )
                outcome = await _probe_web(
                    template=runtime_template,
                    secrets=secrets,
                    transport=transport,
                )
            else:
                secrets = await resolved_revision_secrets(
                    db,
                    template_id=template.id,
                    revision_id=revision.id,
                )
                if protocol == "SSH":
                    outcome = await _probe_ssh(
                        db,
                        template=runtime_template,
                        device_id=device_id,
                        management_ip=management_ip,
                        secrets=secrets,
                    )
                elif protocol == "TELNET":
                    outcome = await _probe_telnet(
                        template=runtime_template,
                        management_ip=management_ip,
                        secrets=secrets,
                    )
                elif protocol == "SNMP":
                    outcome = await _probe_snmp(
                        template=runtime_template,
                        management_ip=management_ip,
                        secrets=secrets,
                    )
                else:
                    outcome = ProbeOutcome(
                        False,
                        "PROTOCOL_NOT_SUPPORTED",
                        "This Access Template protocol is not supported by the tester.",
                    )
        except AccessTemplateProbeFailure as exc:
            outcome = ProbeOutcome(False, exc.code, exc.message)
        except AccessTemplateSecretError as exc:
            code = str(exc)
            safe_code = code if code in {
                "ACCESS_TEMPLATE_MASTER_KEY_NOT_AVAILABLE",
                "ACCESS_TEMPLATE_MASTER_KEY_INVALID",
                "ACCESS_TEMPLATE_SECRET_DECRYPT_FAILED",
                "ACCESS_TEMPLATE_ENV_SECRET_NOT_AVAILABLE",
                "AUTHENTICATION_FAILED",
                "SNMP_COMMUNITY_REJECTED",
                "SNMP_VERSION_MISMATCH",
                "PROTOCOL_NOT_SUPPORTED",
                "WEB_AUTH_MODE_UNSUPPORTED",
                "WEB_AUTHENTICATION_FAILED",
            } else "AUTHENTICATION_FAILED"
            outcome = ProbeOutcome(
                False,
                safe_code,
                "The Access Template revision credentials could not be resolved or validated.",
            )
        except (ValueError, TypeError):
            outcome = ProbeOutcome(
                False,
                "PROTOCOL_NOT_SUPPORTED",
                "The Access Template revision settings are invalid for this protocol.",
            )

    latency_ms = max(0, int(round((time.perf_counter() - started) * 1000)))
    result = AccessTemplateTestResult(
        template_id=template.id,
        revision_id=revision.id,
        device_id=device_id,
        status="SUCCESS" if outcome.success else "FAILED",
        failure_code=None if outcome.success else outcome.failure_code,
        sanitized_message=outcome.sanitized_message,
        latency_ms=latency_ms,
        tested_by_user_id=tested_by_user_id,
    )
    db.add(result)
    if outcome.success and revision.lifecycle_status != "ACTIVE":
        revision.lifecycle_status = "TESTED"
        revision.definition_sha256 = fingerprint
        revision.tested_at = utcnow()
        revision.tested_by_user_id = tested_by_user_id
        revision.approved_at = None
        revision.approved_by_user_id = None
    elif not outcome.success and revision.lifecycle_status in {"TESTED", "APPROVED"}:
        revision.lifecycle_status = "DRAFT"
        revision.definition_sha256 = None
        revision.tested_at = None
        revision.tested_by_user_id = None
        revision.approved_at = None
        revision.approved_by_user_id = None
    await db.flush()
    await record_audit(
        db,
        action="ACCESS_TEMPLATE_REVISION_TEST",
        entity_type="ACCESS_TEMPLATE_TEST_RESULT",
        entity_id=result.id,
        actor_user_id=tested_by_user_id,
        metadata={
            "template_id": str(template.id),
            "revision_id": str(revision.id),
            "revision_number": revision.revision_number,
            "status": result.status,
            "failure_code": result.failure_code,
            "latency_ms": result.latency_ms,
        },
    )
    return result


async def approve_revision(
    db: AsyncSession,
    *,
    template: AccessTemplate,
    revision_id: UUID,
    actor_user_id: UUID,
) -> AccessTemplateRevision:
    revision = await get_revision(
        db,
        template_id=template.id,
        revision_id=revision_id,
        for_update=True,
    )
    if revision.lifecycle_status != "TESTED":
        raise APIError(
            409,
            "ACCESS_TEMPLATE_REVISION_NOT_TESTED",
            "Only a successfully tested Access Template revision can be approved.",
        )
    fingerprint = await revision_definition_sha256(
        db,
        template=template,
        revision=revision,
    )
    if not revision.definition_sha256 or revision.definition_sha256 != fingerprint:
        raise APIError(
            409,
            "ACCESS_TEMPLATE_REVISION_TEST_EVIDENCE_STALE",
            "The Access Template revision changed after testing and must be tested again.",
        )
    latest = await db.scalar(
        select(AccessTemplateTestResult)
        .where(AccessTemplateTestResult.revision_id == revision.id)
        .order_by(
            AccessTemplateTestResult.tested_at.desc(),
            AccessTemplateTestResult.id.desc(),
        )
        .limit(1)
    )
    if latest is None or latest.status != "SUCCESS":
        raise APIError(
            409,
            "ACCESS_TEMPLATE_REVISION_TEST_EVIDENCE_MISSING",
            "A successful revision test result is required before approval.",
        )
    revision.lifecycle_status = "APPROVED"
    revision.approved_at = utcnow()
    revision.approved_by_user_id = actor_user_id
    await db.flush()
    await record_audit(
        db,
        action="ACCESS_TEMPLATE_REVISION_APPROVED",
        entity_type="ACCESS_TEMPLATE_REVISION",
        entity_id=revision.id,
        actor_user_id=actor_user_id,
        metadata={
            "template_id": str(template.id),
            "revision_number": revision.revision_number,
            "definition_sha256": revision.definition_sha256,
        },
    )
    return revision


async def _sync_live_secret_mirror(
    db: AsyncSession,
    *,
    template: AccessTemplate,
    revision: AccessTemplateRevision,
) -> None:
    revision_rows = await revision_secret_rows(db, revision.id)
    target = {row.secret_key: row for row in revision_rows}
    live_rows = list(
        (
            await db.scalars(
                select(AccessTemplateSecret).where(
                    AccessTemplateSecret.template_id == template.id
                )
            )
        ).all()
    )
    live = {row.secret_key: row for row in live_rows}
    for key, row in live.items():
        if key not in target:
            await db.delete(row)
    for key, source in target.items():
        row = live.get(key)
        if row is None:
            row = AccessTemplateSecret(
                template_id=template.id,
                secret_key=key,
                provider=source.provider,
            )
            db.add(row)
        row.provider = source.provider
        row.encrypted_payload = source.encrypted_payload
        row.reference = source.reference
        row.key_version = source.key_version
    await db.flush()


async def activate_revision(
    db: AsyncSession,
    *,
    template: AccessTemplate,
    revision_id: UUID,
    actor_user_id: UUID,
) -> AccessTemplateRevision:
    locked_template = await db.scalar(
        select(AccessTemplate)
        .where(
            AccessTemplate.id == template.id,
            AccessTemplate.deleted_at.is_(None),
        )
        .with_for_update()
    )
    if locked_template is None:
        raise APIError(404, "ACCESS_TEMPLATE_NOT_FOUND", "Access Template not found.")
    revisions = list(
        (
            await db.scalars(
                select(AccessTemplateRevision)
                .where(AccessTemplateRevision.template_id == template.id)
                .with_for_update()
            )
        ).all()
    )
    target = next((row for row in revisions if row.id == revision_id), None)
    if target is None:
        raise APIError(
            404,
            "ACCESS_TEMPLATE_REVISION_NOT_FOUND",
            "Access Template revision not found.",
        )
    if target.lifecycle_status != "APPROVED":
        raise APIError(
            409,
            "ACCESS_TEMPLATE_REVISION_NOT_APPROVED",
            "Only an approved Access Template revision can be activated.",
        )
    fingerprint = await revision_definition_sha256(
        db,
        template=locked_template,
        revision=target,
    )
    if not target.definition_sha256 or target.definition_sha256 != fingerprint:
        raise APIError(
            409,
            "ACCESS_TEMPLATE_REVISION_APPROVAL_STALE",
            "The Access Template revision changed after approval and must be tested again.",
        )
    secret_keys = set((await revision_secret_provider_map(db, target.id)).keys())
    _protocol, variant, cleaned_settings = validate_template_definition(
        protocol=locked_template.protocol,
        protocol_variant=target.protocol_variant,
        template_settings=dict(target.settings_json or {}),
        secret_keys=secret_keys,
        is_active=True,
    )
    now = utcnow()
    for row in revisions:
        if row.id != target.id and row.lifecycle_status == "ACTIVE":
            row.lifecycle_status = "RETIRED"
            row.retired_at = now
    target.lifecycle_status = "ACTIVE"
    target.protocol_variant = variant
    target.settings_json = cleaned_settings
    target.activated_at = now
    target.activated_by_user_id = actor_user_id
    target.retired_at = None

    locked_template.protocol_variant = variant
    locked_template.settings_json = cleaned_settings
    locked_template.is_active = True
    locked_template.updated_at = now
    await _sync_live_secret_mirror(
        db,
        template=locked_template,
        revision=target,
    )
    await db.flush()
    await record_audit(
        db,
        action="ACCESS_TEMPLATE_REVISION_ACTIVATED",
        entity_type="ACCESS_TEMPLATE_REVISION",
        entity_id=target.id,
        actor_user_id=actor_user_id,
        metadata={
            "template_id": str(locked_template.id),
            "revision_number": target.revision_number,
            "definition_sha256": target.definition_sha256,
            "assignment_changes": 0,
            "device_configuration_execution": False,
        },
    )
    return target


async def clone_template_family(
    db: AsyncSession,
    *,
    source_template: AccessTemplate,
    source_revision_id: UUID | None,
    name: str,
    description: str | None,
    visibility: str,
    change_note: str | None,
    actor_user_id: UUID,
) -> tuple[AccessTemplate, AccessTemplateRevision]:
    source = await _source_revision(
        db,
        template_id=source_template.id,
        source_revision_id=source_revision_id,
    )
    normalized_name = name.strip()
    duplicate = await db.scalar(
        select(AccessTemplate.id).where(
            AccessTemplate.owner_user_id == actor_user_id,
            AccessTemplate.name == normalized_name,
            AccessTemplate.protocol == source_template.protocol,
            AccessTemplate.deleted_at.is_(None),
        )
    )
    if duplicate is not None:
        raise APIError(
            409,
            "ACCESS_TEMPLATE_IDENTITY_EXISTS",
            "An Access Template with this owner/name/protocol identity already exists.",
        )
    family = AccessTemplate(
        name=normalized_name,
        description=description,
        protocol=source_template.protocol,
        protocol_variant=source.protocol_variant,
        visibility=visibility,
        owner_user_id=actor_user_id,
        is_active=False,
        settings_json=dict(source.settings_json or {}),
    )
    db.add(family)
    await db.flush()
    revision = AccessTemplateRevision(
        template_id=family.id,
        revision_number=1,
        lifecycle_status="DRAFT",
        protocol_variant=source.protocol_variant,
        settings_json=dict(source.settings_json or {}),
        source_revision_id=source.id,
        change_note=(
            change_note.strip()
            if change_note
            else "Cloned definition; credentials intentionally not copied."
        ),
        definition_sha256=None,
        legacy_backfill=False,
    )
    db.add(revision)
    await db.flush()
    await record_audit(
        db,
        action="ACCESS_TEMPLATE_CLONED",
        entity_type="ACCESS_TEMPLATE",
        entity_id=family.id,
        actor_user_id=actor_user_id,
        metadata={
            "source_template_id": str(source_template.id),
            "source_revision_id": str(source.id),
            "new_revision_id": str(revision.id),
            "credentials_copied": False,
        },
    )
    return family, revision
