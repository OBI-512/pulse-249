"""Add the brokered Remote Access Gateway foundation.

Revision ID: 0029_remote_access_gateway
Revises: 0028_integration_foundation
"""
from __future__ import annotations

import uuid

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0029_remote_access_gateway"
down_revision = "0028_integration_foundation"
branch_labels = None
depends_on = None

_NAMESPACE = uuid.UUID("8d3a2d89-4e70-4e36-9b1a-4d0f6e1c1f55")
_PERMISSIONS = (
    ("device.remote_access.ssh", "Device Remote Access - SSH"),
    ("device.remote_access.web", "Device Remote Access - Web GUI"),
)


def _id(key: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, key)


def _ensure_permission_catalog() -> None:
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
                SELECT :id, roles.id, permissions.id
                FROM roles CROSS JOIN permissions
                WHERE roles.code = 'administrator' AND permissions.code = :code
                ON CONFLICT (role_id, permission_id) DO NOTHING
                """
            ),
            {
                "id": _id(f"roleperm:administrator:{code}"),
                "code": code,
            },
        )


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())

    # See 0001_initial_schema.py: a fresh installation creates current metadata
    # first. Incremental upgrades from 0028 do not yet have these tables.
    if not inspector.has_table("device_remote_access_profiles"):
        op.create_table(
            "device_remote_access_profiles",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
            sa.Column("ssh_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("ssh_port", sa.Integer(), nullable=False, server_default="22"),
            sa.Column("ssh_username_reference", sa.String(255)),
            sa.Column("ssh_password_reference", sa.String(255)),
            sa.Column("ssh_private_key_reference", sa.String(255)),
            sa.Column("ssh_host_key_fingerprint", sa.String(160)),
            sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.UniqueConstraint("device_id", name="uq_device_remote_access_profiles_device"),
            sa.CheckConstraint("ssh_port BETWEEN 1 AND 65535", name="ck_device_remote_access_profiles_ssh_port"),
            sa.CheckConstraint(
                "(ssh_enabled = false) OR "
                "(ssh_username_reference IS NOT NULL AND ssh_host_key_fingerprint IS NOT NULL AND "
                "(ssh_password_reference IS NOT NULL OR ssh_private_key_reference IS NOT NULL))",
                name="ck_device_remote_access_profiles_ssh_ready",
            ),
        )

    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("remote_access_sessions"):
        op.create_table(
            "remote_access_sessions",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
            sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
            sa.Column("auth_session_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("auth_sessions.id", ondelete="SET NULL")),
            sa.Column("mode", sa.String(10), nullable=False, server_default="SSH"),
            sa.Column("status", sa.String(20), nullable=False, server_default="ISSUED"),
            sa.Column("ticket_hash", sa.String(64), nullable=False),
            sa.Column("issued_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("consumed_at", sa.DateTime(timezone=True)),
            sa.Column("activated_at", sa.DateTime(timezone=True)),
            sa.Column("last_activity_at", sa.DateTime(timezone=True)),
            sa.Column("ended_at", sa.DateTime(timezone=True)),
            sa.Column("revoked_at", sa.DateTime(timezone=True)),
            sa.Column("revoked_reason", sa.String(80)),
            sa.Column("source_ip", sa.String(64)),
            sa.Column("gateway_instance", sa.String(120)),
            sa.Column("error_message", sa.Text()),
            sa.UniqueConstraint("ticket_hash", name="uq_remote_access_sessions_ticket_hash"),
            sa.CheckConstraint("mode IN ('SSH','WEB')", name="ck_remote_access_sessions_mode"),
            sa.CheckConstraint(
                "status IN ('ISSUED','ACTIVE','CLOSED','REVOKED','FAILED')",
                name="ck_remote_access_sessions_status",
            ),
        )
        op.create_index("ix_remote_access_sessions_actor_status", "remote_access_sessions", ["actor_user_id", "status"])
        op.create_index("ix_remote_access_sessions_device_status", "remote_access_sessions", ["device_id", "status"])
        op.create_index("ix_remote_access_sessions_expiry", "remote_access_sessions", ["expires_at"])

    _ensure_permission_catalog()


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("remote_access_sessions"):
        op.drop_index("ix_remote_access_sessions_expiry", table_name="remote_access_sessions")
        op.drop_index("ix_remote_access_sessions_device_status", table_name="remote_access_sessions")
        op.drop_index("ix_remote_access_sessions_actor_status", table_name="remote_access_sessions")
        op.drop_table("remote_access_sessions")
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("device_remote_access_profiles"):
        op.drop_table("device_remote_access_profiles")
    bind = op.get_bind()
    bind.execute(
        sa.text("DELETE FROM permissions WHERE code IN :codes").bindparams(
            sa.bindparam("codes", expanding=True, value=[code for code, _ in _PERMISSIONS])
        )
    )
