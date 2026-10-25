"""Add the least-privilege Restricted system role.

Revision ID: 0019_restricted_role
Revises: 0018_user_activity_tracking
"""
from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op

revision = "0019_restricted_role"
down_revision = "0018_user_activity_tracking"
branch_labels = None
depends_on = None

_NAMESPACE = uuid.UUID("8d3a2d89-4e70-4e36-9b1a-4d0f6e1c1f55")
_ROLE_CODE = "restricted"
_ROLE_NAME = "Restricted"
_ROLE_DESCRIPTION = (
    "Minimal role with no operational permissions; add only the required direct permissions."
)


def _id(key: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, key)


def upgrade() -> None:
    bind = op.get_bind()
    bind.execute(
        sa.text(
            """
            INSERT INTO roles (id, code, name, description)
            VALUES (:id, :code, :name, :description)
            ON CONFLICT (code) DO UPDATE
            SET name = EXCLUDED.name, description = EXCLUDED.description
            """
        ),
        {
            "id": _id(f"role:{_ROLE_CODE}"),
            "code": _ROLE_CODE,
            "name": _ROLE_NAME,
            "description": _ROLE_DESCRIPTION,
        },
    )
    # Deliberately do not create role_permissions rows. Restricted is the
    # least-privilege template; direct grants are added explicitly and the
    # existing prerequisite engine expands only genuine RBAC dependencies.


def downgrade() -> None:
    bind = op.get_bind()
    # Never delete user-role assignments during a downgrade. Remove the role
    # only when it is unassigned so rollback cannot silently deauthorize users.
    bind.execute(
        sa.text(
            """
            DELETE FROM roles r
            WHERE r.code = :code
              AND NOT EXISTS (SELECT 1 FROM user_roles ur WHERE ur.role_id = r.id)
            """
        ),
        {"code": _ROLE_CODE},
    )
