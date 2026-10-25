"""Rollback-only TP1 Package 3 configuration-template lifecycle qualification.

This qualification is intended for the isolated manual GitHub Actions stack.
It exercises lifecycle service behavior without any device connection or
configuration execution and rolls every write back before exiting.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from uuid import uuid4

from sqlalchemy import select, text

from app.configuration.contracts import ConfigurationTemplateDefinition, ConfigurationTransport
from app.core.exceptions import APIError
from app.db.session import AsyncSessionLocal
from app.models import DeviceType, User
from app.schemas.configuration import ConfigurationTemplateCreate, ConfigurationTemplateVersionUpdate
from app.schemas.configuration_template_lifecycle import ConfigurationTemplateFamilyCloneRequest
from app.services.configuration import create_template
from app.services.configuration_template_lifecycle import (
    activate_configuration_template_version,
    approve_configuration_template_version,
    clone_configuration_template_family,
    clone_configuration_template_version,
    read_version_lifecycle,
    test_configuration_template_version,
    update_configuration_template_version_lifecycle,
)

TARGET_REVISION = "0043_config_template_lifecycle"
TEMP_PREFIX = "TP1-CI-P3-LC-"


def definition() -> ConfigurationTemplateDefinition:
    return ConfigurationTemplateDefinition(
        adapter_key="generic.ssh_cli",
        transport=ConfigurationTransport.SSH_CLI,
        capabilities=set(),
        parameters=[],
        transport_parameters={},
        functions=[],
    )


async def scalar_count(db, sql: str, params: dict | None = None) -> int:
    return int((await db.execute(text(sql), params or {})).scalar_one())


async def operational_fingerprint(db) -> str:
    payload: dict[str, list[list[str | None]]] = {}
    queries = {
        "bindings": """
            SELECT id, device_id, template_version_id, credential_source,
                   credential_reference, connection_overrides, enabled,
                   bound_by_user_id, bound_at, metadata
            FROM device_configuration_bindings
            ORDER BY id
        """,
        "snapshots": """
            SELECT id, device_id, template_version_id, created_by_user_id,
                   snapshot_kind, adapter_key, artifact_status, artifact_path,
                   artifact_sha256, plaintext_sha256, normalized_sha256,
                   artifact_size_bytes, encryption_scheme,
                   encryption_key_reference, is_restorable, metadata
            FROM configuration_snapshots
            ORDER BY id
        """,
        "operations": """
            SELECT id, device_id, template_version_id, actor_user_id,
                   operation_type, status, idempotency_key,
                   authorization_scope, authorization_scope_fingerprint,
                   request_summary, verification_summary, failure_stage,
                   failure_code, failure_message, started_at, finished_at
            FROM configuration_operations
            ORDER BY id
        """,
    }
    for label, sql in queries.items():
        rows = (await db.execute(text(sql))).fetchall()
        payload[label] = [
            [None if value is None else str(value) for value in row]
            for row in rows
        ]
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest().upper()


async def baseline_counts(db) -> dict[str, int]:
    return {
        "templates": await scalar_count(db, "SELECT COUNT(*) FROM configuration_templates"),
        "versions": await scalar_count(db, "SELECT COUNT(*) FROM configuration_template_versions"),
        "functions": await scalar_count(db, "SELECT COUNT(*) FROM configuration_functions"),
        "bindings": await scalar_count(db, "SELECT COUNT(*) FROM device_configuration_bindings"),
        "snapshots": await scalar_count(db, "SELECT COUNT(*) FROM configuration_snapshots"),
        "operations": await scalar_count(db, "SELECT COUNT(*) FROM configuration_operations"),
        "active_operations": await scalar_count(
            db,
            "SELECT COUNT(*) FROM configuration_operations "
            "WHERE status IN ('QUEUED','RUNNING','ROLLING_BACK')",
        ),
    }


async def main() -> None:
    base_counts: dict[str, int] = {}
    base_fingerprint = ""
    family_code = f"{TEMP_PREFIX}{uuid4().hex[:12]}"
    clone_code = f"{TEMP_PREFIX}CLONE-{uuid4().hex[:10]}"

    async with AsyncSessionLocal() as db:
        revision = str((await db.execute(text("SELECT version_num FROM alembic_version"))).scalar_one())
        print(f"DATABASE_REVISION={revision}")
        if revision != TARGET_REVISION:
            raise SystemExit(f"STOP: expected {TARGET_REVISION}, found {revision}")

        base_counts = await baseline_counts(db)
        for key, value in base_counts.items():
            print(f"PRE_{key.upper()}={value}")
        if base_counts["active_operations"] != 0:
            raise SystemExit("STOP: isolated qualification stack has active configuration operations")

        base_fingerprint = await operational_fingerprint(db)
        print(f"PRE_OPERATIONAL_FINGERPRINT={base_fingerprint}")

        actor = await db.scalar(select(User).order_by(User.id).limit(1))
        device_type = await db.scalar(select(DeviceType).order_by(DeviceType.id).limit(1))
        if actor is None or device_type is None:
            raise SystemExit("STOP: deterministic seed did not provide User and DeviceType parents")

        try:
            template, version1 = await create_template(
                db,
                payload=ConfigurationTemplateCreate(
                    code=family_code,
                    name="TP1 Package 3 Lifecycle Qualification",
                    vendor="FTTW-CI",
                    model="PACKAGE3",
                    series="CONTROLLED",
                    device_type_id=device_type.id,
                    description="Rollback-only lifecycle integration qualification.",
                    definition=definition(),
                ),
                actor_user_id=actor.id,
            )
            await db.flush()

            if version1.status != "DRAFT":
                raise SystemExit("STOP: initial configuration version is not DRAFT")

            try:
                await activate_configuration_template_version(
                    db,
                    template_id=template.id,
                    version_id=version1.id,
                    actor_user_id=actor.id,
                )
            except APIError as exc:
                code = exc.detail.get("code") if isinstance(exc.detail, dict) else None
                if exc.status_code != 409 or code != "CONFIGURATION_TEMPLATE_VERSION_NOT_APPROVED":
                    raise
            else:
                raise SystemExit("STOP: DRAFT -> PUBLISHED bypass was accepted")
            print("DRAFT_TO_PUBLISHED_BYPASS_BLOCKED=PASS")

            version1 = await test_configuration_template_version(
                db,
                template_id=template.id,
                version_id=version1.id,
                actor_user_id=actor.id,
            )
            lifecycle = await read_version_lifecycle(
                db,
                template_id=template.id,
                version_id=version1.id,
            )
            if version1.status != "TESTED" or not lifecycle["tested_definition_sha256"]:
                raise SystemExit("STOP: DRAFT -> TESTED evidence was not persisted")
            print("DRAFT_TO_TESTED=PASS")

            version1 = await update_configuration_template_version_lifecycle(
                db,
                template_id=template.id,
                version_id=version1.id,
                payload=ConfigurationTemplateVersionUpdate(
                    definition=definition(),
                    change_note="Evidence invalidation qualification edit",
                ),
                actor_user_id=actor.id,
            )
            lifecycle = await read_version_lifecycle(
                db,
                template_id=template.id,
                version_id=version1.id,
            )
            if version1.status != "DRAFT":
                raise SystemExit("STOP: tested edit did not return version to DRAFT")
            if any(
                lifecycle[key] is not None
                for key in (
                    "tested_definition_sha256",
                    "tested_at",
                    "tested_by_user_id",
                    "approved_at",
                    "approved_by_user_id",
                )
            ):
                raise SystemExit("STOP: lifecycle evidence was not cleared by edit")
            print("EDIT_INVALIDATES_TEST_APPROVAL_EVIDENCE=PASS")

            version1 = await test_configuration_template_version(
                db,
                template_id=template.id,
                version_id=version1.id,
                actor_user_id=actor.id,
            )
            version1 = await approve_configuration_template_version(
                db,
                template_id=template.id,
                version_id=version1.id,
                actor_user_id=actor.id,
            )
            if version1.status != "APPROVED":
                raise SystemExit("STOP: TESTED -> APPROVED failed")
            print("TESTED_TO_APPROVED=PASS")

            version1 = await activate_configuration_template_version(
                db,
                template_id=template.id,
                version_id=version1.id,
                actor_user_id=actor.id,
            )
            if version1.status != "PUBLISHED":
                raise SystemExit("STOP: APPROVED -> PUBLISHED failed")
            print("APPROVED_TO_PUBLISHED=PASS")

            version2 = await clone_configuration_template_version(
                db,
                template_id=template.id,
                source_version_id=version1.id,
                change_note="Package 3 same-family clone qualification",
                actor_user_id=actor.id,
            )
            lifecycle2 = await read_version_lifecycle(
                db,
                template_id=template.id,
                version_id=version2.id,
            )
            if version2.status != "DRAFT" or lifecycle2["source_version_id"] != version1.id:
                raise SystemExit("STOP: same-family clone lineage/status mismatch")
            print("SAME_FAMILY_CLONE_DRAFT_LINEAGE=PASS")

            version2 = await test_configuration_template_version(
                db,
                template_id=template.id,
                version_id=version2.id,
                actor_user_id=actor.id,
            )
            version2 = await approve_configuration_template_version(
                db,
                template_id=template.id,
                version_id=version2.id,
                actor_user_id=actor.id,
            )
            version2 = await activate_configuration_template_version(
                db,
                template_id=template.id,
                version_id=version2.id,
                actor_user_id=actor.id,
            )
            await db.refresh(version1)
            if version2.status != "PUBLISHED" or version1.status != "RETIRED":
                raise SystemExit("STOP: activation did not retire previous published version")
            print("NEW_PUBLISHED_RETIRES_PREVIOUS=PASS")

            clone_template, clone_version = await clone_configuration_template_family(
                db,
                source_template_id=template.id,
                source_version_id=version2.id,
                payload=ConfigurationTemplateFamilyCloneRequest(
                    code=clone_code,
                    name="TP1 Package 3 Family Clone Qualification",
                    description="Rollback-only cross-family lineage qualification.",
                    change_note="Package 3 family clone qualification",
                ),
                actor_user_id=actor.id,
            )
            clone_lifecycle = await read_version_lifecycle(
                db,
                template_id=clone_template.id,
                version_id=clone_version.id,
            )
            if clone_version.status != "DRAFT" or clone_lifecycle["source_version_id"] != version2.id:
                raise SystemExit("STOP: cross-family clone lineage/status mismatch")
            print("CROSS_FAMILY_CLONE_DRAFT_LINEAGE=PASS")

            binding_to_temp = await scalar_count(
                db,
                """
                SELECT COUNT(*)
                FROM device_configuration_bindings b
                JOIN configuration_template_versions v ON v.id = b.template_version_id
                WHERE v.template_id IN (:template_id, :clone_template_id)
                """,
                {"template_id": template.id, "clone_template_id": clone_template.id},
            )
            if binding_to_temp != 0:
                raise SystemExit("STOP: lifecycle operations created or moved a device binding")
            print("DEVICE_REBINDING_DELTA=0")

            active_ops = await scalar_count(
                db,
                "SELECT COUNT(*) FROM configuration_operations "
                "WHERE status IN ('QUEUED','RUNNING','ROLLING_BACK')",
            )
            op_count = await scalar_count(db, "SELECT COUNT(*) FROM configuration_operations")
            if active_ops != 0 or op_count != base_counts["operations"]:
                raise SystemExit("STOP: lifecycle qualification changed configuration operations")
            print("CONFIGURATION_OPERATION_DELTA=0")

            current_fingerprint = await operational_fingerprint(db)
            print(f"IN_TRANSACTION_OPERATIONAL_FINGERPRINT={current_fingerprint}")
            if current_fingerprint != base_fingerprint:
                raise SystemExit("STOP: binding/snapshot/operation footprint changed")
            print("OPERATIONAL_REFERENCE_FOOTPRINT_UNCHANGED=PASS")

        finally:
            await db.rollback()
            print("ROLLBACK_ONLY_TRANSACTION=ROLLED_BACK")

    async with AsyncSessionLocal() as db:
        await db.execute(text("SET TRANSACTION READ ONLY"))
        ro = str((await db.execute(text("SHOW transaction_read_only"))).scalar_one()).lower()
        print(f"POST_TRANSACTION_READ_ONLY={ro}")
        if ro != "on":
            raise SystemExit("STOP: post-rollback verification is not read-only")

        post_counts = await baseline_counts(db)
        for key, value in post_counts.items():
            print(f"POST_{key.upper()}={value}")
        if post_counts != base_counts:
            raise SystemExit(f"STOP: rollback count mismatch: before={base_counts!r} after={post_counts!r}")

        post_fingerprint = await operational_fingerprint(db)
        print(f"POST_OPERATIONAL_FINGERPRINT={post_fingerprint}")
        if post_fingerprint != base_fingerprint:
            raise SystemExit("STOP: operational fingerprint changed after rollback")

        temp_rows = await scalar_count(
            db,
            "SELECT COUNT(*) FROM configuration_templates WHERE code LIKE :prefix",
            {"prefix": f"{TEMP_PREFIX}%"},
        )
        print(f"POST_TEMP_TEMPLATE_COUNT={temp_rows}")
        if temp_rows != 0:
            raise SystemExit("STOP: rollback-only lifecycle fixture persisted")

        await db.rollback()

    print("POST_ROLLBACK_EXACT_BASELINE=PASS")
    print("DATABASE_PERSISTENT_MUTATION=NO")
    print("DEVICE_CONNECTION=NO")
    print("DEVICE_MUTATION=NO")
    print("CONFIGURATION_EXECUTION=NO")
    print("TP1_PACKAGE3_CONFIGURATION_LIFECYCLE_INTEGRATION=PASS")


if __name__ == "__main__":
    asyncio.run(main())
