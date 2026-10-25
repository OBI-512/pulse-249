"""Add authentication-session observability and read permission.

Revision ID: 0016_session_observability
Revises: 0015_group_modes_system_groups
"""
from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op

revision = "0016_session_observability"
down_revision = "0015_group_modes_system_groups"
branch_labels = None
depends_on = None

_NAMESPACE = uuid.UUID("3a5fa3ab-0a8d-4b97-8db4-b649e0fcf45d")
_PERMISSION_CODE = "user.sessions.read"


def _id(key: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, key)


def _columns(table: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table)}


def _indexes(table: str) -> set[str]:
    return {index["name"] for index in sa.inspect(op.get_bind()).get_indexes(table)}


def upgrade() -> None:
    columns = _columns("auth_sessions")
    additions = (
        ("revoked_reason", sa.String(length=80)),
        ("login_ip", sa.String(length=64)),
        ("last_ip", sa.String(length=64)),
        ("user_agent", sa.String(length=1024)),
        ("browser_name", sa.String(length=100)),
        ("browser_version", sa.String(length=80)),
        ("os_name", sa.String(length=100)),
        ("os_version", sa.String(length=80)),
        ("device_type", sa.String(length=30)),
        ("last_seen_at", sa.DateTime(timezone=True)),
    )
    for name, column_type in additions:
        if name not in columns:
            op.add_column("auth_sessions", sa.Column(name, column_type, nullable=True))

    indexes = _indexes("auth_sessions")
    if "ix_auth_sessions_active_lookup" not in indexes:
        op.create_index(
            "ix_auth_sessions_active_lookup",
            "auth_sessions",
            ["user_id", "revoked_at", "expires_at"],
        )
    if "ix_auth_sessions_last_seen" not in indexes:
        op.create_index("ix_auth_sessions_last_seen", "auth_sessions", ["last_seen_at"])

    bind = op.get_bind()
    bind.execute(sa.text("UPDATE auth_sessions SET last_seen_at = created_at WHERE last_seen_at IS NULL"))

    bind.execute(
        sa.text(
            """
            INSERT INTO permissions (id, code, name, description)
            VALUES (:id, :code, 'User Sessions Read', 'View user authentication sessions and online-session telemetry.')
            ON CONFLICT (code) DO UPDATE
            SET name = EXCLUDED.name, description = EXCLUDED.description
            """
        ),
        {"id": _id("perm:user.sessions.read"), "code": _PERMISSION_CODE},
    )

    # Preserve existing authority: any role or direct grant that could manage
    # sessions automatically receives the new read-only permission.
    read_permission_id = bind.scalar(
        sa.text("SELECT id FROM permissions WHERE code='user.sessions.read'")
    )
    role_ids = bind.execute(
        sa.text(
            """
            SELECT existing.role_id
            FROM role_permissions existing
            JOIN permissions manage_permission ON manage_permission.id = existing.permission_id
            WHERE manage_permission.code = 'user.sessions.manage'
            """
        )
    ).scalars().all()
    for role_id in role_ids:
        bind.execute(
            sa.text(
                """
                INSERT INTO role_permissions (id, role_id, permission_id)
                VALUES (:id, :role_id, :permission_id)
                ON CONFLICT (role_id, permission_id) DO NOTHING
                """
            ),
            {
                "id": _id(f"roleperm:{role_id}:user.sessions.read"),
                "role_id": role_id,
                "permission_id": read_permission_id,
            },
        )

    user_ids = bind.execute(
        sa.text(
            """
            SELECT existing.user_id
            FROM user_permissions existing
            JOIN permissions manage_permission ON manage_permission.id = existing.permission_id
            WHERE manage_permission.code = 'user.sessions.manage'
            """
        )
    ).scalars().all()
    for user_id in user_ids:
        bind.execute(
            sa.text(
                """
                INSERT INTO user_permissions (id, user_id, permission_id)
                VALUES (:id, :user_id, :permission_id)
                ON CONFLICT (user_id, permission_id) DO NOTHING
                """
            ),
            {
                "id": _id(f"userperm:{user_id}:user.sessions.read"),
                "user_id": user_id,
                "permission_id": read_permission_id,
            },
        )


def downgrade() -> None:
    bind = op.get_bind()
    permission_id = bind.scalar(sa.text("SELECT id FROM permissions WHERE code='user.sessions.read'"))
    if permission_id is not None:
        bind.execute(sa.text("DELETE FROM role_permissions WHERE permission_id=:id"), {"id": permission_id})
        bind.execute(sa.text("DELETE FROM user_permissions WHERE permission_id=:id"), {"id": permission_id})
        bind.execute(sa.text("DELETE FROM permissions WHERE id=:id"), {"id": permission_id})

    indexes = _indexes("auth_sessions")
    if "ix_auth_sessions_last_seen" in indexes:
        op.drop_index("ix_auth_sessions_last_seen", table_name="auth_sessions")
    if "ix_auth_sessions_active_lookup" in indexes:
        op.drop_index("ix_auth_sessions_active_lookup", table_name="auth_sessions")

    columns = _columns("auth_sessions")
    for name in (
        "last_seen_at", "device_type", "os_version", "os_name", "browser_version",
        "browser_name", "user_agent", "last_ip", "login_ip", "revoked_reason",
    ):
        if name in columns:
            op.drop_column("auth_sessions", name)
            columns.remove(name)
