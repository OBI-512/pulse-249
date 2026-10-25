"""Add operational-log permissions.

Revision ID: 0009_operational_logs
Revises: 0008_restore_points
"""

from __future__ import annotations

import uuid
import sqlalchemy as sa
from alembic import op


revision = "0009_operational_logs"
down_revision = "0008_restore_points"
branch_labels = None
depends_on = None

_NAMESPACE = uuid.UUID("8d3a2d89-4e70-4e36-9b1a-4d0f6e1c1f55")
_PERMISSIONS = (("logs.read", "Operational Logs Read"), ("logs.export", "Operational Logs Export"))


def _id(value: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, value)


def upgrade() -> None:
    bind = op.get_bind()
    for code, name in _PERMISSIONS:
        bind.execute(sa.text("""
            INSERT INTO permissions (id, code, name, description)
            VALUES (:id, :code, :name, :description)
            ON CONFLICT (code) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description
        """), {"id": _id(f"perm:{code}"), "code": code, "name": name, "description": f"{name} permission"})
        bind.execute(sa.text("""
            INSERT INTO role_permissions (id, role_id, permission_id)
            SELECT :id, r.id, p.id FROM roles r CROSS JOIN permissions p
            WHERE r.code = 'administrator' AND p.code = :code
            ON CONFLICT (role_id, permission_id) DO NOTHING
        """), {"id": _id(f"roleperm:administrator:{code}"), "code": code})


def downgrade() -> None:
    op.execute(sa.text("DELETE FROM permissions WHERE code IN ('logs.read','logs.export')"))
