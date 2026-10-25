"""TP1 configuration-template lifecycle evidence and lineage.

Revision ID: 0043_config_template_lifecycle
Revises: 0042_access_template_revisions

This migration is additive. Existing configuration-template versions, device
bindings, snapshots, and operations remain intact. Existing published/retired
versions that carry publication integrity metadata are grandfathered with
matching tested/approved evidence so the new lifecycle constraints preserve the
accepted pre-0043 operational state.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0043_config_template_lifecycle"
down_revision = "0042_access_template_revisions"
branch_labels = None
depends_on = None


def _has_column(inspector, table_name: str, column_name: str) -> bool:
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def _has_index(inspector, table_name: str, index_name: str) -> bool:
    return any(index["name"] == index_name for index in inspector.get_indexes(table_name))


def _constraint_names(inspector, table_name: str) -> set[str]:
    names: set[str] = set()
    for item in inspector.get_check_constraints(table_name):
        name = item.get("name")
        if name:
            names.add(name)
    return names


def _foreign_key_names(inspector, table_name: str) -> set[str]:
    return {
        item.get("name")
        for item in inspector.get_foreign_keys(table_name)
        if item.get("name")
    }


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table = "configuration_template_versions"

    if not _has_column(inspector, table, "source_version_id"):
        op.add_column(
            table,
            sa.Column("source_version_id", postgresql.UUID(as_uuid=True), nullable=True),
        )
    inspector = sa.inspect(bind)
    if "fk_configuration_template_versions_source" not in _foreign_key_names(inspector, table):
        op.create_foreign_key(
            "fk_configuration_template_versions_source",
            table,
            table,
            ["source_version_id"],
            ["id"],
            ondelete="SET NULL",
        )

    inspector = sa.inspect(bind)
    additions = (
        ("tested_definition_sha256", sa.String(64)),
        ("tested_at", sa.DateTime(timezone=True)),
        ("tested_by_user_id", postgresql.UUID(as_uuid=True)),
        ("approved_at", sa.DateTime(timezone=True)),
        ("approved_by_user_id", postgresql.UUID(as_uuid=True)),
    )
    for name, type_ in additions:
        inspector = sa.inspect(bind)
        if not _has_column(inspector, table, name):
            op.add_column(table, sa.Column(name, type_, nullable=True))

    inspector = sa.inspect(bind)
    foreign_keys = _foreign_key_names(inspector, table)
    if "fk_configuration_template_versions_tested_by" not in foreign_keys:
        op.create_foreign_key(
            "fk_configuration_template_versions_tested_by",
            table,
            "users",
            ["tested_by_user_id"],
            ["id"],
            ondelete="SET NULL",
        )
    inspector = sa.inspect(bind)
    foreign_keys = _foreign_key_names(inspector, table)
    if "fk_configuration_template_versions_approved_by" not in foreign_keys:
        op.create_foreign_key(
            "fk_configuration_template_versions_approved_by",
            table,
            "users",
            ["approved_by_user_id"],
            ["id"],
            ondelete="SET NULL",
        )

    inspector = sa.inspect(bind)
    if not _has_index(inspector, table, "ix_configuration_template_versions_source"):
        op.create_index(
            "ix_configuration_template_versions_source",
            table,
            ["source_version_id"],
        )

    # Preserve accepted historical publication state by treating existing
    # integrity-verified publication metadata as grandfathered test/approval
    # evidence. No template definition, binding, snapshot, or operation changes.
    bind.execute(
        sa.text(
            """
            UPDATE configuration_template_versions
            SET tested_definition_sha256 = COALESCE(tested_definition_sha256, content_sha256),
                tested_at = COALESCE(tested_at, published_at),
                tested_by_user_id = COALESCE(tested_by_user_id, published_by_user_id),
                approved_at = COALESCE(approved_at, published_at),
                approved_by_user_id = COALESCE(approved_by_user_id, published_by_user_id)
            WHERE status IN ('PUBLISHED', 'RETIRED')
              AND content_sha256 IS NOT NULL
              AND published_at IS NOT NULL
            """
        )
    )

    inspector = sa.inspect(bind)
    checks = _constraint_names(inspector, table)
    for name in (
        "ck_configuration_template_versions_status",
        "ck_configuration_template_versions_publish_ready",
        "ck_configuration_template_versions_tested_hash",
        "ck_configuration_template_versions_test_ready",
        "ck_configuration_template_versions_approval_ready",
        "ck_configuration_template_versions_source_not_self",
    ):
        if name in checks:
            op.drop_constraint(name, table, type_="check")

    op.create_check_constraint(
        "ck_configuration_template_versions_status",
        table,
        "status IN ('DRAFT','TESTED','APPROVED','PUBLISHED','RETIRED')",
    )
    op.create_check_constraint(
        "ck_configuration_template_versions_tested_hash",
        table,
        "tested_definition_sha256 IS NULL OR char_length(tested_definition_sha256) = 64",
    )
    op.create_check_constraint(
        "ck_configuration_template_versions_test_ready",
        table,
        "status NOT IN ('TESTED','APPROVED','PUBLISHED') OR "
        "(tested_definition_sha256 IS NOT NULL AND tested_at IS NOT NULL)",
    )
    op.create_check_constraint(
        "ck_configuration_template_versions_approval_ready",
        table,
        "status NOT IN ('APPROVED','PUBLISHED') OR approved_at IS NOT NULL",
    )
    op.create_check_constraint(
        "ck_configuration_template_versions_publish_ready",
        table,
        "status <> 'PUBLISHED' OR ("
        "content_sha256 IS NOT NULL AND published_at IS NOT NULL AND "
        "tested_definition_sha256 = content_sha256 AND approved_at IS NOT NULL)",
    )
    op.create_check_constraint(
        "ck_configuration_template_versions_source_not_self",
        table,
        "source_version_id IS NULL OR source_version_id <> id",
    )

    invalid_published = int(
        bind.execute(
            sa.text(
                """
                SELECT COUNT(*)
                FROM configuration_template_versions
                WHERE status = 'PUBLISHED'
                  AND (
                    content_sha256 IS NULL
                    OR published_at IS NULL
                    OR tested_definition_sha256 IS DISTINCT FROM content_sha256
                    OR approved_at IS NULL
                  )
                """
            )
        ).scalar_one()
    )
    if invalid_published != 0:
        raise RuntimeError("0043 backfill failed: published version lacks lifecycle evidence")


def downgrade() -> None:
    bind = op.get_bind()
    table = "configuration_template_versions"

    transitional = int(
        bind.execute(
            sa.text(
                """
                SELECT COUNT(*)
                FROM configuration_template_versions
                WHERE status IN ('TESTED','APPROVED')
                """
            )
        ).scalar_one()
    )
    if transitional != 0:
        raise RuntimeError(
            "0043 downgrade blocked: TESTED/APPROVED configuration versions exist; "
            "resolve lifecycle state explicitly before downgrade"
        )

    inspector = sa.inspect(bind)
    checks = _constraint_names(inspector, table)
    for name in (
        "ck_configuration_template_versions_status",
        "ck_configuration_template_versions_publish_ready",
        "ck_configuration_template_versions_tested_hash",
        "ck_configuration_template_versions_test_ready",
        "ck_configuration_template_versions_approval_ready",
        "ck_configuration_template_versions_source_not_self",
    ):
        if name in checks:
            op.drop_constraint(name, table, type_="check")

    op.create_check_constraint(
        "ck_configuration_template_versions_status",
        table,
        "status IN ('DRAFT','PUBLISHED','RETIRED')",
    )
    op.create_check_constraint(
        "ck_configuration_template_versions_publish_ready",
        table,
        "status <> 'PUBLISHED' OR (content_sha256 IS NOT NULL AND published_at IS NOT NULL)",
    )

    inspector = sa.inspect(bind)
    if _has_index(inspector, table, "ix_configuration_template_versions_source"):
        op.drop_index("ix_configuration_template_versions_source", table_name=table)

    inspector = sa.inspect(bind)
    foreign_keys = _foreign_key_names(inspector, table)
    for name in (
        "fk_configuration_template_versions_source",
        "fk_configuration_template_versions_tested_by",
        "fk_configuration_template_versions_approved_by",
    ):
        if name in foreign_keys:
            op.drop_constraint(name, table, type_="foreignkey")

    inspector = sa.inspect(bind)
    for name in (
        "approved_by_user_id",
        "approved_at",
        "tested_by_user_id",
        "tested_at",
        "tested_definition_sha256",
        "source_version_id",
    ):
        inspector = sa.inspect(bind)
        if _has_column(inspector, table, name):
            op.drop_column(table, name)
