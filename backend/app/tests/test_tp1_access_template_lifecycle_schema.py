from __future__ import annotations

import importlib.util
from pathlib import Path

from sqlalchemy import CheckConstraint, Index, UniqueConstraint

from app.db.base import Base
from app.models import (
    AccessTemplate,
    AccessTemplateAssignment,
    AccessTemplateRevision,
    AccessTemplateRevisionSecret,
    AccessTemplateSecret,
    AccessTemplateTestResult,
)


MIGRATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "migrations"
    / "versions"
    / "0042_access_template_lifecycle_revisions.py"
)


def _constraint_names(table) -> set[str]:
    return {constraint.name for constraint in table.constraints if constraint.name}


def _index_by_name(table, name: str) -> Index:
    matches = [index for index in table.indexes if index.name == name]
    assert len(matches) == 1
    return matches[0]


def test_revision_tables_are_registered_in_current_metadata() -> None:
    assert AccessTemplateRevision.__table__.name == "access_template_revisions"
    assert AccessTemplateRevisionSecret.__table__.name == "access_template_revision_secrets"
    assert "access_template_revisions" in Base.metadata.tables
    assert "access_template_revision_secrets" in Base.metadata.tables


def test_revision_identity_and_lifecycle_constraints_are_fail_closed() -> None:
    table = AccessTemplateRevision.__table__
    names = _constraint_names(table)

    assert "uq_access_template_revisions_number" in names
    assert "ck_access_template_revisions_number" in names
    assert "ck_access_template_revisions_lifecycle_status" in names
    assert "ck_access_template_revisions_definition_sha256" in names

    unique = next(
        constraint
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
        and constraint.name == "uq_access_template_revisions_number"
    )
    assert [column.name for column in unique.columns] == ["template_id", "revision_number"]

    lifecycle = next(
        constraint
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
        and constraint.name == "ck_access_template_revisions_lifecycle_status"
    )
    lifecycle_sql = str(lifecycle.sqltext)
    for state in ("DRAFT", "TESTED", "APPROVED", "ACTIVE", "RETIRED"):
        assert state in lifecycle_sql

    active_index = _index_by_name(table, "uq_access_template_revisions_active")
    assert active_index.unique is True
    assert [column.name for column in active_index.columns] == ["template_id"]
    where = str(active_index.dialect_options["postgresql"]["where"])
    assert "lifecycle_status = 'ACTIVE'" in where


def test_revision_definition_carries_lineage_and_lifecycle_evidence_fields() -> None:
    columns = AccessTemplateRevision.__table__.c

    assert columns.template_id.nullable is False
    assert columns.revision_number.nullable is False
    assert columns.lifecycle_status.nullable is False
    assert columns.settings.nullable is False
    assert columns.source_revision_id.nullable is True
    assert columns.definition_sha256.nullable is True
    assert columns.legacy_backfill.nullable is False
    assert columns.tested_at.nullable is True
    assert columns.tested_by_user_id.nullable is True
    assert columns.approved_at.nullable is True
    assert columns.approved_by_user_id.nullable is True
    assert columns.activated_at.nullable is True
    assert columns.activated_by_user_id.nullable is True
    assert columns.retired_at.nullable is True


def test_revision_secret_snapshot_preserves_stable_template_aad_identity() -> None:
    table = AccessTemplateRevisionSecret.__table__
    names = _constraint_names(table)

    assert table.c.revision_id.nullable is False
    assert table.c.template_id.nullable is False
    assert table.c.secret_key.nullable is False
    assert "uq_access_template_revision_secrets_key" in names
    assert "ck_access_template_revision_secrets_storage" in names
    assert "ck_access_template_revision_secrets_provider" in names
    assert "ck_access_template_revision_secrets_key_version" in names

    unique = next(
        constraint
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
        and constraint.name == "uq_access_template_revision_secrets_key"
    )
    assert [column.name for column in unique.columns] == ["revision_id", "secret_key"]


def test_package1_preserves_legacy_runtime_contracts() -> None:
    template_columns = AccessTemplate.__table__.c
    assert "protocol_variant" in template_columns
    assert "settings" in template_columns
    assert "is_active" in template_columns
    assert "deleted_at" in template_columns

    secret_columns = AccessTemplateSecret.__table__.c
    assert "template_id" in secret_columns
    assert "encrypted_payload" in secret_columns
    assert "reference" in secret_columns

    assignment_columns = AccessTemplateAssignment.__table__.c
    assert "template_id" in assignment_columns
    assert "revision_id" not in assignment_columns


def test_test_evidence_has_revision_link_without_breaking_compatibility_writer() -> None:
    table = AccessTemplateTestResult.__table__
    revision = table.c.revision_id

    # Nullable only during the Package-1 bridge. Migration 0042 backfills all
    # existing rows; Package 2 will populate revision_id on every new test.
    assert revision.nullable is True
    assert any(
        foreign_key.target_fullname == "access_template_revisions.id"
        and foreign_key.constraint.name == "fk_access_template_test_results_revision"
        for foreign_key in revision.foreign_keys
    )

    index = _index_by_name(
        table,
        "ix_access_template_test_results_revision_device_tested",
    )
    assert [column.name for column in index.columns] == [
        "revision_id",
        "device_id",
        "tested_at",
    ]


def test_0042_migration_ancestry_and_non_mutating_assignment_contract() -> None:
    spec = importlib.util.spec_from_file_location("tp1_migration_0042", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.revision == "0042_access_template_revisions"
    assert module.down_revision == "0041_config_change_batches"

    source = MIGRATION_PATH.read_text(encoding="utf-8")

    assert "UPDATE access_template_assignments" not in source
    assert "DELETE FROM access_template_assignments" not in source
    assert "decrypt_secret(" not in source
    assert "encrypt_secret(" not in source
    assert "Legacy Revision 1 backfilled by migration 0042" in source
    assert "SET revision_id = r.id" in source
    assert "FROM access_template_secrets s" in source


def test_0042_uses_deterministic_revision1_identity_and_backfill_guards() -> None:
    source = MIGRATION_PATH.read_text(encoding="utf-8")

    assert "SELECT\n                t.id," in source
    assert "r.revision_number = 1" in source
    assert "0042 backfill failed: access template without Revision 1" in source
    assert "0042 backfill failed: legacy secret without Revision 1 snapshot" in source
    assert "0042 backfill failed: historical test result without Revision 1" in source
    assert "0042 backfill failed: test result linked to another template revision" in source
