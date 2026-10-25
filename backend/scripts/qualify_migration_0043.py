"""Controlled CI qualification for migration 0042 -> 0043.

This script is intentionally compatible with the accepted pre-0043 source
(db633bc...) when copied into that worktree for fixture preparation. It uses
only Configuration models that already existed at 0042 during ``prepare`` and
raw SQL during ``validate`` so the post-migration assertions do not depend on
ORM refresh behavior.

The fixture is isolated CI data only. It creates no device connection and no
configuration execution.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any
import uuid

from sqlalchemy import select, text

from app.db.session import AsyncSessionLocal


MIGRATION_BEFORE = "0042_access_template_revisions"
MIGRATION_AFTER = "0043_config_template_lifecycle"
NAMESPACE = uuid.UUID("e0a07993-8d53-44d3-b9b2-8c49345387aa")
FIXTURE_CODE = "TP1-CI-0043"
FIXTURE_ADAPTER = "tp1.ci.noop"
FIXTURE_TRANSPORT = "SSH_CLI"
PUBLISHED_AT = datetime(2026, 9, 8, 0, 0, 0, tzinfo=timezone.utc)


def fid(label: str) -> uuid.UUID:
    return uuid.uuid5(NAMESPACE, label)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def normalize(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (uuid.UUID, datetime)):
        return str(value)
    if isinstance(value, dict):
        return {str(key): normalize(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [normalize(item) for item in value]
    return value


async def current_revision(db) -> str:
    return str((await db.execute(text("SELECT version_num FROM alembic_version"))).scalar_one())


async def query_rows(db, sql: str, params: dict[str, Any]) -> list[list[Any]]:
    result = await db.execute(text(sql), params)
    return [[normalize(value) for value in row] for row in result.fetchall()]


async def capture_fixture(db, fixture: dict[str, Any]) -> dict[str, Any]:
    template_id = fixture["template_id"]
    binding_id = fixture["binding_id"]
    snapshot_ids = fixture["snapshot_ids"]
    operation_ids = fixture["operation_ids"]

    payload = {
        "versions": await query_rows(
            db,
            """
            SELECT id, template_id, version_number, status, adapter_key, transport,
                   capabilities, parameter_schema, transport_parameters,
                   content_sha256, published_at, published_by_user_id, change_note
            FROM configuration_template_versions
            WHERE template_id = :template_id
            ORDER BY version_number
            """,
            {"template_id": template_id},
        ),
        "bindings": await query_rows(
            db,
            """
            SELECT id, device_id, template_version_id, credential_source,
                   credential_reference, connection_overrides, enabled,
                   bound_by_user_id, bound_at, metadata
            FROM device_configuration_bindings
            WHERE id = :binding_id
            ORDER BY id
            """,
            {"binding_id": binding_id},
        ),
        "snapshots": await query_rows(
            db,
            """
            SELECT id, device_id, template_version_id, created_by_user_id,
                   snapshot_kind, adapter_key, artifact_status, artifact_path,
                   artifact_sha256, plaintext_sha256, normalized_sha256,
                   artifact_size_bytes, encryption_scheme,
                   encryption_key_reference, is_restorable, metadata
            FROM configuration_snapshots
            WHERE id = ANY(:snapshot_ids)
            ORDER BY id
            """,
            {"snapshot_ids": snapshot_ids},
        ),
        "operations": await query_rows(
            db,
            """
            SELECT id, device_id, template_version_id, actor_user_id,
                   operation_type, status, idempotency_key,
                   authorization_scope, authorization_scope_fingerprint,
                   request_summary, verification_summary, failure_stage,
                   failure_code, failure_message, started_at, finished_at
            FROM configuration_operations
            WHERE id = ANY(:operation_ids)
            ORDER BY id
            """,
            {"operation_ids": operation_ids},
        ),
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return {
        "payload": payload,
        "signature": hashlib.sha256(encoded).hexdigest().upper(),
    }


async def prepare(output: Path) -> None:
    # Imported only in prepare mode so this file remains usable when copied into
    # the accepted 0042 source worktree.
    from app.models import (
        ConfigurationOperation,
        ConfigurationSnapshot,
        ConfigurationTemplate,
        ConfigurationTemplateVersion,
        Device,
        DeviceConfigurationBinding,
        DeviceType,
        User,
    )

    if len(MIGRATION_AFTER) > 32:
        raise SystemExit("STOP: target Alembic revision exceeds version_num VARCHAR(32)")

    async with AsyncSessionLocal() as db:
        revision = await current_revision(db)
        print(f"DATABASE_REVISION_BEFORE={revision}")
        if revision != MIGRATION_BEFORE:
            raise SystemExit(
                f"STOP: prepare requires {MIGRATION_BEFORE}, found {revision}"
            )

        existing = await db.scalar(
            select(ConfigurationTemplate).where(ConfigurationTemplate.code == FIXTURE_CODE)
        )
        if existing is not None:
            raise SystemExit("STOP: TP1 0043 CI fixture already exists")

        user = await db.scalar(select(User).order_by(User.id).limit(1))
        device_type = await db.scalar(select(DeviceType).order_by(DeviceType.id).limit(1))
        device = await db.scalar(select(Device).order_by(Device.id).limit(1))
        if user is None or device_type is None or device is None:
            raise SystemExit("STOP: deterministic demo seed did not create required parents")

        template = ConfigurationTemplate(
            id=fid("template"),
            code=FIXTURE_CODE,
            name="TP1 CI 0043 Migration Fixture",
            vendor="FTTW-CI",
            model="MIGRATION-0043",
            series="CONTROLLED",
            device_type_id=device_type.id,
            is_active=True,
            description="Isolated deterministic fixture for 0042 -> 0043 qualification.",
            metadata_={"fixture": "tp1-0043", "device_execution": False},
        )
        db.add(template)
        await db.flush()

        versions = []
        statuses = ("RETIRED", "RETIRED", "PUBLISHED")
        for number, status in enumerate(statuses, start=1):
            version = ConfigurationTemplateVersion(
                id=fid(f"version:{number}"),
                template_id=template.id,
                version_number=number,
                status=status,
                adapter_key=FIXTURE_ADAPTER,
                transport=FIXTURE_TRANSPORT,
                capabilities=["CI_ONLY"],
                parameter_schema={"type": "object", "additionalProperties": False},
                transport_parameters={"fixture": True, "version": number},
                content_sha256=digest(f"tp1-0043-version-{number}"),
                published_at=PUBLISHED_AT,
                published_by_user_id=user.id,
                change_note=f"TP1 0043 fixture version {number}",
            )
            db.add(version)
            versions.append(version)
        await db.flush()

        binding = DeviceConfigurationBinding(
            id=fid("binding"),
            device_id=device.id,
            template_version_id=versions[2].id,
            credential_source="REMOTE_ACCESS_PROFILE",
            credential_reference=None,
            connection_overrides={},
            enabled=True,
            bound_by_user_id=user.id,
            metadata_={"fixture": "tp1-0043"},
        )
        db.add(binding)

        snapshots = []
        operations = []
        for index in range(15):
            version = versions[index % len(versions)]
            snapshot = ConfigurationSnapshot(
                id=fid(f"snapshot:{index}"),
                device_id=device.id,
                template_version_id=version.id,
                created_by_user_id=user.id,
                snapshot_kind="CAPTURE",
                adapter_key=FIXTURE_ADAPTER,
                artifact_status="PENDING",
                is_restorable=False,
                metadata_={"fixture": "tp1-0043", "index": index},
            )
            operation = ConfigurationOperation(
                id=fid(f"operation:{index}"),
                device_id=device.id,
                template_version_id=version.id,
                actor_user_id=user.id,
                operation_type="CAPTURE",
                status="FAILED",
                idempotency_key=None,
                authorization_scope={},
                request_summary={"fixture": "tp1-0043", "index": index},
                verification_summary={},
                failure_stage="VALIDATION",
                failure_code="TP1_CI_FIXTURE",
                failure_message="Synthetic terminal CI fixture; no device execution occurred.",
                finished_at=PUBLISHED_AT,
            )
            db.add(snapshot)
            db.add(operation)
            snapshots.append(snapshot)
            operations.append(operation)

        await db.commit()

        fixture = {
            "template_id": str(template.id),
            "version_ids": [str(item.id) for item in versions],
            "binding_id": str(binding.id),
            "snapshot_ids": [str(item.id) for item in snapshots],
            "operation_ids": [str(item.id) for item in operations],
        }

    async with AsyncSessionLocal() as db:
        await db.execute(text("SET TRANSACTION READ ONLY"))
        captured = await capture_fixture(db, fixture)
        counts = {
            "versions": len(captured["payload"]["versions"]),
            "bindings": len(captured["payload"]["bindings"]),
            "snapshots": len(captured["payload"]["snapshots"]),
            "operations": len(captured["payload"]["operations"]),
        }
        expected_counts = {"versions": 3, "bindings": 1, "snapshots": 15, "operations": 15}
        print(f"PRE_REFERENCE_SIGNATURE={captured['signature']}")
        for key, value in counts.items():
            print(f"PRE_{key.upper()}={value}")
        if counts != expected_counts:
            raise SystemExit(f"STOP: fixture count mismatch: {counts!r}")

        active_ops = int((await db.execute(text(
            "SELECT COUNT(*) FROM configuration_operations "
            "WHERE id = ANY(:ids) AND status IN ('QUEUED','RUNNING','ROLLING_BACK')"
        ), {"ids": fixture["operation_ids"]})).scalar_one())
        print(f"PRE_ACTIVE_CONFIG_OPERATIONS={active_ops}")
        if active_ops != 0:
            raise SystemExit("STOP: CI fixture contains active configuration operations")

        await db.rollback()

    document = {
        "schema": 1,
        "migration_before": MIGRATION_BEFORE,
        "migration_after": MIGRATION_AFTER,
        "fixture": fixture,
        "counts": counts,
        "reference_signature": captured["signature"],
        "device_connection": False,
        "configuration_execution": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"PRE_EVIDENCE_FILE={output}")
    print("TP1_0043_PREPARE=PASS")


async def validate(input_path: Path, output: Path | None) -> None:
    pre = json.loads(input_path.read_text(encoding="utf-8"))
    if pre.get("schema") != 1:
        raise SystemExit("STOP: unsupported pre-evidence schema")
    fixture = dict(pre["fixture"])

    async with AsyncSessionLocal() as db:
        revision = await current_revision(db)
        print(f"DATABASE_REVISION_AFTER={revision}")
        if revision != MIGRATION_AFTER:
            raise SystemExit(
                f"STOP: validate requires {MIGRATION_AFTER}, found {revision}"
            )

        await db.execute(text("SET TRANSACTION READ ONLY"))
        ro = (await db.execute(text("SHOW transaction_read_only"))).scalar_one()
        print(f"POST_TRANSACTION_READ_ONLY={ro}")
        if str(ro).lower() != "on":
            raise SystemExit("STOP: validation transaction is not read-only")

        lifecycle_columns = {
            "source_version_id",
            "tested_definition_sha256",
            "tested_at",
            "tested_by_user_id",
            "approved_at",
            "approved_by_user_id",
        }
        present = set((await db.execute(text(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema='public'
              AND table_name='configuration_template_versions'
              AND column_name = ANY(:columns)
            """
        ), {"columns": sorted(lifecycle_columns)})).scalars().all())
        print(f"POST_LIFECYCLE_COLUMN_COUNT={len(present)}")
        if present != lifecycle_columns:
            raise SystemExit(f"STOP: lifecycle column mismatch: {sorted(present)!r}")

        rows = (await db.execute(text(
            """
            SELECT id, status, content_sha256, published_at, published_by_user_id,
                   source_version_id, tested_definition_sha256, tested_at,
                   tested_by_user_id, approved_at, approved_by_user_id
            FROM configuration_template_versions
            WHERE template_id = :template_id
            ORDER BY version_number
            """
        ), {"template_id": fixture["template_id"]})).mappings().all()
        print(f"POST_FIXTURE_VERSION_TOTAL={len(rows)}")
        if len(rows) != 3:
            raise SystemExit("STOP: fixture version count changed")

        statuses = [row["status"] for row in rows]
        print(f"POST_FIXTURE_STATUSES={','.join(statuses)}")
        if statuses != ["RETIRED", "RETIRED", "PUBLISHED"]:
            raise SystemExit(f"STOP: fixture statuses changed: {statuses!r}")

        for row in rows:
            if row["source_version_id"] is not None:
                raise SystemExit("STOP: 0043 invented lineage for grandfathered version")
            if row["tested_definition_sha256"] != row["content_sha256"]:
                raise SystemExit("STOP: tested hash does not match published content hash")
            if row["tested_at"] != row["published_at"]:
                raise SystemExit("STOP: grandfathered tested_at mismatch")
            if row["approved_at"] != row["published_at"]:
                raise SystemExit("STOP: grandfathered approved_at mismatch")
            if row["tested_by_user_id"] != row["published_by_user_id"]:
                raise SystemExit("STOP: grandfathered tester mismatch")
            if row["approved_by_user_id"] != row["published_by_user_id"]:
                raise SystemExit("STOP: grandfathered approver mismatch")

        captured = await capture_fixture(db, fixture)
        expected_signature = str(pre["reference_signature"]).upper()
        actual_signature = captured["signature"]
        print(f"EXPECTED_REFERENCE_SIGNATURE={expected_signature}")
        print(f"POST_REFERENCE_SIGNATURE={actual_signature}")
        if actual_signature != expected_signature:
            raise SystemExit("STOP: exact configuration reference footprint changed")

        counts = {
            "versions": len(captured["payload"]["versions"]),
            "bindings": len(captured["payload"]["bindings"]),
            "snapshots": len(captured["payload"]["snapshots"]),
            "operations": len(captured["payload"]["operations"]),
        }
        if counts != pre["counts"]:
            raise SystemExit(
                f"STOP: fixture counts changed: before={pre['counts']!r} after={counts!r}"
            )

        active_ops = int((await db.execute(text(
            "SELECT COUNT(*) FROM configuration_operations "
            "WHERE id = ANY(:ids) AND status IN ('QUEUED','RUNNING','ROLLING_BACK')"
        ), {"ids": fixture["operation_ids"]})).scalar_one())
        print(f"POST_ACTIVE_CONFIG_OPERATIONS={active_ops}")
        if active_ops != 0:
            raise SystemExit("STOP: migration created active configuration operations")

        required_checks = {
            "ck_configuration_template_versions_status",
            "ck_configuration_template_versions_publish_ready",
            "ck_configuration_template_versions_tested_hash",
            "ck_configuration_template_versions_test_ready",
            "ck_configuration_template_versions_approval_ready",
            "ck_configuration_template_versions_source_not_self",
        }
        check_names = set((await db.execute(text(
            """
            SELECT c.conname
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE n.nspname='public'
              AND t.relname='configuration_template_versions'
              AND c.contype='c'
            """
        ))).scalars().all())
        missing_checks = sorted(required_checks - check_names)
        print(f"POST_REQUIRED_CHECK_COUNT={len(required_checks - set(missing_checks))}")
        if missing_checks:
            raise SystemExit(f"STOP: missing lifecycle checks: {missing_checks!r}")

        required_fks = {
            "fk_configuration_template_versions_source",
            "fk_configuration_template_versions_tested_by",
            "fk_configuration_template_versions_approved_by",
        }
        fk_names = set((await db.execute(text(
            """
            SELECT c.conname
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE n.nspname='public'
              AND t.relname='configuration_template_versions'
              AND c.contype='f'
            """
        ))).scalars().all())
        missing_fks = sorted(required_fks - fk_names)
        print(f"POST_REQUIRED_LIFECYCLE_FK_COUNT={len(required_fks - set(missing_fks))}")
        if missing_fks:
            raise SystemExit(f"STOP: missing lifecycle foreign keys: {missing_fks!r}")

        source_index_count = int((await db.execute(text(
            """
            SELECT COUNT(*)
            FROM pg_indexes
            WHERE schemaname='public'
              AND tablename='configuration_template_versions'
              AND indexname='ix_configuration_template_versions_source'
            """
        ))).scalar_one())
        print(f"POST_SOURCE_INDEX_COUNT={source_index_count}")
        if source_index_count != 1:
            raise SystemExit("STOP: lifecycle source index missing or duplicated")

        await db.rollback()

    result = {
        "schema": 1,
        "migration": MIGRATION_AFTER,
        "reference_signature": actual_signature,
        "counts": counts,
        "device_connection": False,
        "device_mutation": False,
        "configuration_execution": False,
        "result": "PASS",
    }
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"POST_EVIDENCE_FILE={output}")

    print("EXACT_REFERENCE_FOOTPRINT_PRESERVED=PASS")
    print("GRANDFATHERED_LIFECYCLE_EVIDENCE=PASS")
    print("DEVICE_CONNECTION=NO")
    print("DEVICE_MUTATION=NO")
    print("CONFIGURATION_EXECUTION=NO")
    print("TP1_0043_VALIDATE=PASS")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="command", required=True)

    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--output", type=Path, required=True)

    validate_parser = sub.add_parser("validate")
    validate_parser.add_argument("--input", type=Path, required=True)
    validate_parser.add_argument("--output", type=Path)
    return root


async def _main() -> None:
    args = parser().parse_args()
    if args.command == "prepare":
        await prepare(args.output)
    else:
        await validate(args.input, args.output)


if __name__ == "__main__":
    asyncio.run(_main())
