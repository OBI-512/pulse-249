"""Add explicit permissions for authoritative physical movements.

Revision ID: 0003_movement_rbac
Revises: 0002_domain_hierarchy_phase1
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op


revision = "0003_movement_rbac"
down_revision = "0002_domain_hierarchy_phase1"
branch_labels = None
depends_on = None


_NAMESPACE = uuid.UUID("8d3a2d89-4e70-4e36-9b1a-4d0f6e1c1f55")
_PERMISSIONS = (
    ("physical_movement.sector", "Physical Sector Movement"),
    ("physical_movement.cpe", "Physical CPE Movement"),
    ("physical_movement.access_point", "Physical Access Point Movement"),
)


def _deterministic_id(key: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, key)


def upgrade() -> None:
    bind = op.get_bind()

    for code, name in _PERMISSIONS:
        permission_id = _deterministic_id(f"perm:{code}")
        bind.execute(
            sa.text(
                """
                INSERT INTO permissions (id, code, name, description)
                VALUES (:id, :code, :name, :description)
                ON CONFLICT (code) DO NOTHING
                """
            ),
            {
                "id": permission_id,
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


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(
        sa.text("DELETE FROM permissions WHERE code IN :codes").bindparams(
            sa.bindparam(
                "codes",
                expanding=True,
                value=[code for code, _ in _PERMISSIONS],
            )
        )
    )
