"""Finalize backend account/session controls and audit actor snapshots.

Revision ID: 0012_backend_closure
Revises: 0011_typed_settings
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op


revision = "0012_backend_closure"
down_revision = "0011_typed_settings"
branch_labels = None
depends_on = None

_NAMESPACE = uuid.UUID("8d3a2d89-4e70-4e36-9b1a-4d0f6e1c1f55")
_PERMISSIONS = (
    ("user.sessions.manage", "User Sessions Manage"),
)


def _id(value: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, value)


def upgrade() -> None:
    op.execute(sa.text("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS actor_display_name_snapshot VARCHAR(200) NULL"))
    op.execute(sa.text("CREATE INDEX IF NOT EXISTS ix_audit_logs_actor_display_snapshot ON audit_logs (actor_display_name_snapshot)"))

    bind = op.get_bind()
    for code, name in _PERMISSIONS:
        bind.execute(
            sa.text(
                """
                INSERT INTO permissions (id, code, name, description)
                VALUES (:id, :code, :name, :description)
                ON CONFLICT (code) DO UPDATE
                SET name = EXCLUDED.name, description = EXCLUDED.description
                """
            ),
            {
                "id": _id(f"perm:{code}"),
                "code": code,
                "name": name,
                "description": f"{name} permission",
            },
        )
        bind.execute(
            sa.text(
                """
                INSERT INTO role_permissions (id, role_id, permission_id)
                SELECT :id, r.id, p.id
                FROM roles r CROSS JOIN permissions p
                WHERE r.code = 'administrator' AND p.code = :code
                ON CONFLICT (role_id, permission_id) DO NOTHING
                """
            ),
            {
                "id": _id(f"roleperm:administrator:{code}"),
                "code": code,
            },
        )


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(
        sa.text("DELETE FROM permissions WHERE code IN :codes").bindparams(
            sa.bindparam("codes", expanding=True, value=[code for code, _ in _PERMISSIONS])
        )
    )
    op.execute(sa.text("DROP INDEX IF EXISTS ix_audit_logs_actor_display_snapshot"))
    op.execute(sa.text("ALTER TABLE audit_logs DROP COLUMN IF EXISTS actor_display_name_snapshot"))
