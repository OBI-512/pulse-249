"""TP1 access-template lifecycle revision foundation.

Revision ID: 0042_access_template_revisions
Revises: 0041_config_change_batches

This migration is deliberately backward compatible. Existing access-template
runtime tables remain in place while revision-aware structures are introduced
and deterministically backfilled. Package 2 will move runtime authoring and
resolution onto the revision lifecycle explicitly.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0042_access_template_revisions"
down_revision = "0041_config_change_batches"
branch_labels = None
depends_on = None


def _common_columns():
    return (
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def _has_column(inspector, table_name: str, column_name: str) -> bool:
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def _has_index(inspector, table_name: str, index_name: str) -> bool:
    return any(index["name"] == index_name for index in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    # 0001 creates current SQLAlchemy metadata on a clean installation. The
    # guards below therefore make live upgrades and clean installs converge.
    if not inspector.has_table("access_template_revisions"):
        op.create_table(
            "access_template_revisions",
            *_common_columns(),
            sa.Column(
                "template_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("access_templates.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("revision_number", sa.Integer(), nullable=False),
            sa.Column(
                "lifecycle_status",
                sa.String(20),
                nullable=False,
                server_default="DRAFT",
            ),
            sa.Column("protocol_variant", sa.String(40)),
            sa.Column(
                "settings",
                postgresql.JSONB(),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
            sa.Column(
                "source_revision_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("access_template_revisions.id", ondelete="SET NULL"),
            ),
            sa.Column("change_note", sa.Text()),
            sa.Column("definition_sha256", sa.String(64)),
            sa.Column(
                "legacy_backfill",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
            sa.Column("tested_at", sa.DateTime(timezone=True)),
            sa.Column(
                "tested_by_user_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
            ),
            sa.Column("approved_at", sa.DateTime(timezone=True)),
            sa.Column(
                "approved_by_user_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
            ),
            sa.Column("activated_at", sa.DateTime(timezone=True)),
            sa.Column(
                "activated_by_user_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
            ),
            sa.Column("retired_at", sa.DateTime(timezone=True)),
            sa.UniqueConstraint(
                "template_id",
                "revision_number",
                name="uq_access_template_revisions_number",
            ),
            sa.CheckConstraint(
                "revision_number >= 1",
                name="ck_access_template_revisions_number",
            ),
            sa.CheckConstraint(
                "lifecycle_status IN ('DRAFT','TESTED','APPROVED','ACTIVE','RETIRED')",
                name="ck_access_template_revisions_lifecycle_status",
            ),
            sa.CheckConstraint(
                "definition_sha256 IS NULL OR char_length(definition_sha256) = 64",
                name="ck_access_template_revisions_definition_sha256",
            ),
        )
        op.create_index(
            "ix_access_template_revisions_template_status",
            "access_template_revisions",
            ["template_id", "lifecycle_status"],
        )
        op.create_index(
            "ix_access_template_revisions_source",
            "access_template_revisions",
            ["source_revision_id"],
        )
        op.create_index(
            "uq_access_template_revisions_active",
            "access_template_revisions",
            ["template_id"],
            unique=True,
            postgresql_where=sa.text("lifecycle_status = 'ACTIVE'"),
        )

    inspector = sa.inspect(bind)
    if not inspector.has_table("access_template_revision_secrets"):
        op.create_table(
            "access_template_revision_secrets",
            *_common_columns(),
            sa.Column(
                "revision_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("access_template_revisions.id", ondelete="CASCADE"),
                nullable=False,
            ),
            # Retain the stable template identity because existing AES-GCM
            # payload AAD is bound to template_id + secret_key. The migration
            # therefore snapshots ciphertext without decrypting/re-encrypting.
            sa.Column(
                "template_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("access_templates.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("secret_key", sa.String(80), nullable=False),
            sa.Column("provider", sa.String(30), nullable=False),
            sa.Column("encrypted_payload", sa.Text()),
            sa.Column("reference", sa.String(255)),
            sa.Column("key_version", sa.Integer(), nullable=False, server_default="1"),
            sa.UniqueConstraint(
                "revision_id",
                "secret_key",
                name="uq_access_template_revision_secrets_key",
            ),
            sa.CheckConstraint(
                "provider IN ('ENCRYPTED_DATABASE','ENV_REFERENCE')",
                name="ck_access_template_revision_secrets_provider",
            ),
            sa.CheckConstraint(
                "(provider = 'ENCRYPTED_DATABASE' AND encrypted_payload IS NOT NULL AND reference IS NULL) OR "
                "(provider = 'ENV_REFERENCE' AND encrypted_payload IS NULL AND reference LIKE 'env://%')",
                name="ck_access_template_revision_secrets_storage",
            ),
            sa.CheckConstraint(
                "key_version >= 1",
                name="ck_access_template_revision_secrets_key_version",
            ),
        )
        op.create_index(
            "ix_access_template_revision_secrets_revision",
            "access_template_revision_secrets",
            ["revision_id"],
        )
        op.create_index(
            "ix_access_template_revision_secrets_template",
            "access_template_revision_secrets",
            ["template_id"],
        )

    inspector = sa.inspect(bind)
    if not _has_column(inspector, "access_template_test_results", "revision_id"):
        op.add_column(
            "access_template_test_results",
            sa.Column("revision_id", postgresql.UUID(as_uuid=True), nullable=True),
        )
        op.create_foreign_key(
            "fk_access_template_test_results_revision",
            "access_template_test_results",
            "access_template_revisions",
            ["revision_id"],
            ["id"],
            ondelete="SET NULL",
        )

    inspector = sa.inspect(bind)
    if not _has_index(
        inspector,
        "access_template_test_results",
        "ix_access_template_test_results_revision_device_tested",
    ):
        op.create_index(
            "ix_access_template_test_results_revision_device_tested",
            "access_template_test_results",
            ["revision_id", "device_id", "tested_at"],
            postgresql_where=sa.text("revision_id IS NOT NULL"),
        )

    # Deterministic Revision 1 identity: the legacy template UUID is reused as
    # the Revision 1 UUID in the separate revision table. This is collision-free
    # across tables and makes the backfill repeatable without UUID extensions.
    bind.execute(
        sa.text(
            """
            INSERT INTO access_template_revisions (
                id,
                created_at,
                updated_at,
                template_id,
                revision_number,
                lifecycle_status,
                protocol_variant,
                settings,
                source_revision_id,
                change_note,
                definition_sha256,
                legacy_backfill,
                tested_at,
                tested_by_user_id,
                approved_at,
                approved_by_user_id,
                activated_at,
                activated_by_user_id,
                retired_at
            )
            SELECT
                t.id,
                t.created_at,
                t.updated_at,
                t.id,
                1,
                CASE
                    WHEN t.deleted_at IS NULL AND t.is_active IS TRUE THEN 'ACTIVE'
                    ELSE 'RETIRED'
                END,
                t.protocol_variant,
                t.settings,
                NULL,
                'Legacy Revision 1 backfilled by migration 0042',
                NULL,
                TRUE,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                CASE
                    WHEN t.deleted_at IS NOT NULL THEN t.deleted_at
                    WHEN t.is_active IS FALSE THEN t.updated_at
                    ELSE NULL
                END
            FROM access_templates t
            WHERE NOT EXISTS (
                SELECT 1
                FROM access_template_revisions r
                WHERE r.template_id = t.id
                  AND r.revision_number = 1
            )
            """
        )
    )

    # Snapshot legacy secret storage into Revision 1 without exposing plaintext
    # and without changing the legacy runtime secret source used by Package 1.
    bind.execute(
        sa.text(
            """
            INSERT INTO access_template_revision_secrets (
                id,
                created_at,
                updated_at,
                revision_id,
                template_id,
                secret_key,
                provider,
                encrypted_payload,
                reference,
                key_version
            )
            SELECT
                s.id,
                s.created_at,
                s.updated_at,
                r.id,
                s.template_id,
                s.secret_key,
                s.provider,
                s.encrypted_payload,
                s.reference,
                s.key_version
            FROM access_template_secrets s
            JOIN access_template_revisions r
              ON r.template_id = s.template_id
             AND r.revision_number = 1
            WHERE NOT EXISTS (
                SELECT 1
                FROM access_template_revision_secrets rs
                WHERE rs.revision_id = r.id
                  AND rs.secret_key = s.secret_key
            )
            """
        )
    )

    # Historical test evidence is attributed to the exact backfilled Revision 1.
    # The column stays nullable during the compatibility bridge so existing
    # Package-1 runtime writers continue to function until Package 2 switches
    # test creation to revision-aware writes.
    bind.execute(
        sa.text(
            """
            UPDATE access_template_test_results tr
            SET revision_id = r.id
            FROM access_template_revisions r
            WHERE tr.revision_id IS NULL
              AND r.template_id = tr.template_id
              AND r.revision_number = 1
            """
        )
    )

    missing_revision_1 = bind.execute(
        sa.text(
            """
            SELECT COUNT(*)
            FROM access_templates t
            WHERE NOT EXISTS (
                SELECT 1
                FROM access_template_revisions r
                WHERE r.template_id = t.id
                  AND r.revision_number = 1
            )
            """
        )
    ).scalar_one()
    if int(missing_revision_1) != 0:
        raise RuntimeError("0042 backfill failed: access template without Revision 1")

    missing_secret_snapshot = bind.execute(
        sa.text(
            """
            SELECT COUNT(*)
            FROM access_template_secrets s
            WHERE NOT EXISTS (
                SELECT 1
                FROM access_template_revision_secrets rs
                JOIN access_template_revisions r ON r.id = rs.revision_id
                WHERE r.template_id = s.template_id
                  AND r.revision_number = 1
                  AND rs.secret_key = s.secret_key
            )
            """
        )
    ).scalar_one()
    if int(missing_secret_snapshot) != 0:
        raise RuntimeError("0042 backfill failed: legacy secret without Revision 1 snapshot")

    missing_test_revision = bind.execute(
        sa.text(
            """
            SELECT COUNT(*)
            FROM access_template_test_results
            WHERE revision_id IS NULL
            """
        )
    ).scalar_one()
    if int(missing_test_revision) != 0:
        raise RuntimeError("0042 backfill failed: historical test result without Revision 1")

    mismatched_test_revision = bind.execute(
        sa.text(
            """
            SELECT COUNT(*)
            FROM access_template_test_results tr
            JOIN access_template_revisions r ON r.id = tr.revision_id
            WHERE r.template_id <> tr.template_id
            """
        )
    ).scalar_one()
    if int(mismatched_test_revision) != 0:
        raise RuntimeError("0042 backfill failed: test result linked to another template revision")


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("access_template_test_results"):
        if _has_index(
            inspector,
            "access_template_test_results",
            "ix_access_template_test_results_revision_device_tested",
        ):
            op.drop_index(
                "ix_access_template_test_results_revision_device_tested",
                table_name="access_template_test_results",
            )

        inspector = sa.inspect(bind)
        if _has_column(inspector, "access_template_test_results", "revision_id"):
            foreign_keys = {
                fk.get("name")
                for fk in inspector.get_foreign_keys("access_template_test_results")
                if fk.get("name")
            }
            if "fk_access_template_test_results_revision" in foreign_keys:
                op.drop_constraint(
                    "fk_access_template_test_results_revision",
                    "access_template_test_results",
                    type_="foreignkey",
                )
            op.drop_column("access_template_test_results", "revision_id")

    inspector = sa.inspect(bind)
    if inspector.has_table("access_template_revision_secrets"):
        op.drop_table("access_template_revision_secrets")

    inspector = sa.inspect(bind)
    if inspector.has_table("access_template_revisions"):
        op.drop_table("access_template_revisions")
