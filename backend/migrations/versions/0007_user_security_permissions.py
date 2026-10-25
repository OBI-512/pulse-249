"""Add explicit user-security permissions.

Revision ID: 0007_user_security_permissions
Revises: 0006_immutable_audit
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op


revision = "0007_user_security_permissions"
down_revision = "0006_immutable_audit"
branch_labels = None
depends_on = None


_NAMESPACE = uuid.UUID("8d3a2d89-4e70-4e36-9b1a-4d0f6e1c1f55")
_PERMISSIONS = (
    ("user.create", "User Create"),
    ("user.update", "User Update"),
    ("user.deactivate", "User Deactivate"),
    ("user.password.reset", "User Password Reset"),
    ("user.roles.manage", "User Roles Manage"),
    ("user.permissions.manage", "User Permissions Manage"),
    ("settings.secret.read", "Settings Secret Read"),
)


def _id(key: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, key)


def upgrade() -> None:
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
            {"id": _id(f"perm:{code}"), "code": code, "name": name, "description": f"{name} permission"},
        )
        bind.execute(
            sa.text(
                """
                INSERT INTO role_permissions (id, role_id, permission_id)
                SELECT :id, roles.id, permissions.id
                FROM roles CROSS JOIN permissions
                WHERE roles.code = 'administrator' AND permissions.code = :code
                ON CONFLICT (role_id, permission_id) DO NOTHING
                """
            ),
            {"id": _id(f"roleperm:administrator:{code}"), "code": code},
        )


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(
        sa.text("DELETE FROM permissions WHERE code IN :codes").bindparams(
            sa.bindparam("codes", expanding=True, value=[code for code, _ in _PERMISSIONS])
        )
    )
