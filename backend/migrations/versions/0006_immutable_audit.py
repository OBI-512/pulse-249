"""Add comprehensive immutable audit evidence and audit RBAC.

Revision ID: 0006_immutable_audit
Revises: 0005_recycle_invariants

The legacy 0001 migration dynamically imports current metadata. Every DDL
operation below is therefore explicit and idempotent so both an already-
migrated live database and a fresh temporary chain can traverse this revision.
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op


revision = "0006_immutable_audit"
down_revision = "0005_recycle_invariants"
branch_labels = None
depends_on = None


_NAMESPACE = uuid.UUID("8d3a2d89-4e70-4e36-9b1a-4d0f6e1c1f55")
_PERMISSIONS = (
    ("audit.read", "Audit Read"),
    ("audit.export", "Audit Export"),
)
_DEFAULT_NON_ADMIN_ROLES = (
    "operator",
    "administrative_viewer",
    "viewer",
)


def _deterministic_id(key: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, key)


def _add_audit_columns() -> None:
    statements = (
        "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS actor_username_snapshot VARCHAR(150) NULL",
        "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS entity_display_snapshot JSONB NULL",
        "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS result VARCHAR(30) NOT NULL DEFAULT 'SUCCESS'",
        "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS request_id VARCHAR(128) NULL",
        "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS source_ip VARCHAR(64) NULL",
        "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS before_summary JSONB NULL",
        "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS after_summary JSONB NULL",
    )
    for statement in statements:
        op.execute(sa.text(statement))

    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_constraint
                    WHERE conrelid = 'audit_logs'::regclass
                      AND conname = 'ck_audit_logs_result'
                ) THEN
                    ALTER TABLE audit_logs
                    ADD CONSTRAINT ck_audit_logs_result
                    CHECK (result IN ('SUCCESS','FAILURE','ATTEMPT'));
                END IF;
            END $$;
            """
        )
    )


def _add_audit_indexes() -> None:
    statements = (
        "CREATE INDEX IF NOT EXISTS ix_audit_logs_occurred_at ON audit_logs (occurred_at)",
        "CREATE INDEX IF NOT EXISTS ix_audit_logs_actor_occurred_at ON audit_logs (actor_user_id, occurred_at)",
        "CREATE INDEX IF NOT EXISTS ix_audit_logs_entity_occurred_at ON audit_logs (entity_type, entity_id, occurred_at)",
        "CREATE INDEX IF NOT EXISTS ix_audit_logs_action_occurred_at ON audit_logs (action, occurred_at)",
        "CREATE INDEX IF NOT EXISTS ix_audit_logs_result_occurred_at ON audit_logs (result, occurred_at)",
        "CREATE INDEX IF NOT EXISTS ix_audit_logs_request_id ON audit_logs (request_id)",
    )
    for statement in statements:
        op.execute(sa.text(statement))


def _install_append_only_trigger() -> None:
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION fttw_prevent_audit_mutation()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                IF current_setting('fttw.audit_maintenance', true) = 'on' THEN
                    IF TG_OP = 'DELETE' THEN
                        RETURN OLD;
                    END IF;
                    IF TG_OP = 'TRUNCATE' THEN
                        RETURN NULL;
                    END IF;
                    RETURN NEW;
                END IF;

                RAISE EXCEPTION
                    'audit_logs is append-only; use transaction-local audit maintenance for authorized maintenance'
                    USING ERRCODE = '55000';
            END;
            $$;
            """
        )
    )
    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_trigger
                    WHERE tgrelid = 'audit_logs'::regclass
                      AND tgname = 'trg_audit_logs_append_only'
                      AND NOT tgisinternal
                ) THEN
                    CREATE TRIGGER trg_audit_logs_append_only
                    BEFORE UPDATE OR DELETE ON audit_logs
                    FOR EACH ROW
                    EXECUTE FUNCTION fttw_prevent_audit_mutation();
                END IF;
            END $$;
            """
        )
    )
    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_trigger
                    WHERE tgrelid = 'audit_logs'::regclass
                      AND tgname = 'trg_audit_logs_append_only_truncate'
                      AND NOT tgisinternal
                ) THEN
                    CREATE TRIGGER trg_audit_logs_append_only_truncate
                    BEFORE TRUNCATE ON audit_logs
                    FOR EACH STATEMENT
                    EXECUTE FUNCTION fttw_prevent_audit_mutation();
                END IF;
            END $$;
            """
        )
    )


def _seed_audit_permissions() -> None:
    bind = op.get_bind()
    for code, name in _PERMISSIONS:
        bind.execute(
            sa.text(
                """
                INSERT INTO permissions (id, code, name, description)
                VALUES (:id, :code, :name, :description)
                ON CONFLICT (code) DO UPDATE
                SET name = EXCLUDED.name,
                    description = EXCLUDED.description
                """
            ),
            {
                "id": _deterministic_id(f"perm:{code}"),
                "code": code,
                "name": name,
                "description": f"{name} permission",
            },
        )
        bind.execute(
            sa.text(
                """
                INSERT INTO role_permissions (id, role_id, permission_id)
                SELECT :id, roles.id, permissions.id
                FROM roles
                CROSS JOIN permissions
                WHERE roles.code = 'administrator'
                  AND permissions.code = :code
                ON CONFLICT (role_id, permission_id) DO NOTHING
                """
            ),
            {
                "id": _deterministic_id(f"roleperm:administrator:{code}"),
                "code": code,
            },
        )

    # The old baseline seeded audit.read into every read-oriented default
    # role. Remove only those known default grants; custom role grants and all
    # direct user grants remain untouched.
    bind.execute(
        sa.text(
            """
            DELETE FROM role_permissions AS role_permission
            USING roles, permissions
            WHERE role_permission.role_id = roles.id
              AND role_permission.permission_id = permissions.id
              AND roles.code IN :role_codes
              AND permissions.code IN :permission_codes
            """
        ).bindparams(
            sa.bindparam("role_codes", expanding=True, value=list(_DEFAULT_NON_ADMIN_ROLES)),
            sa.bindparam("permission_codes", expanding=True, value=[code for code, _ in _PERMISSIONS]),
        )
    )


def upgrade() -> None:
    _add_audit_columns()
    _add_audit_indexes()
    _install_append_only_trigger()
    _seed_audit_permissions()


def downgrade() -> None:
    bind = op.get_bind()
    op.execute(sa.text("DROP TRIGGER IF EXISTS trg_audit_logs_append_only_truncate ON audit_logs"))
    op.execute(sa.text("DROP TRIGGER IF EXISTS trg_audit_logs_append_only ON audit_logs"))
    op.execute(sa.text("DROP FUNCTION IF EXISTS fttw_prevent_audit_mutation()"))

    # Restore the three historical default-role audit.read grants. Direct and
    # custom grants were never changed by upgrade.
    for role_code in _DEFAULT_NON_ADMIN_ROLES:
        bind.execute(
            sa.text(
                """
                INSERT INTO role_permissions (id, role_id, permission_id)
                SELECT :id, roles.id, permissions.id
                FROM roles
                CROSS JOIN permissions
                WHERE roles.code = :role_code
                  AND permissions.code = 'audit.read'
                ON CONFLICT (role_id, permission_id) DO NOTHING
                """
            ),
            {
                "id": _deterministic_id(f"roleperm:{role_code}:audit.read"),
                "role_code": role_code,
            },
        )

    bind.execute(
        sa.text("DELETE FROM permissions WHERE code = 'audit.export'")
    )

    for index_name in (
        "ix_audit_logs_request_id",
        "ix_audit_logs_result_occurred_at",
        "ix_audit_logs_action_occurred_at",
        "ix_audit_logs_entity_occurred_at",
        "ix_audit_logs_actor_occurred_at",
        "ix_audit_logs_occurred_at",
    ):
        op.execute(sa.text(f'DROP INDEX IF EXISTS "{index_name}"'))

    op.execute(sa.text("ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS ck_audit_logs_result"))
    for column_name in (
        "after_summary",
        "before_summary",
        "source_ip",
        "request_id",
        "result",
        "entity_display_snapshot",
        "actor_username_snapshot",
    ):
        op.execute(sa.text(f'ALTER TABLE audit_logs DROP COLUMN IF EXISTS "{column_name}"'))
