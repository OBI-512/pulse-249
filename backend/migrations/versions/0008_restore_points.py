"""Add durable restore-point metadata and permissions.

Revision ID: 0008_restore_points
Revises: 0007_user_security_permissions
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op


revision = "0008_restore_points"
down_revision = "0007_user_security_permissions"
branch_labels = None
depends_on = None


_NAMESPACE = uuid.UUID("8d3a2d89-4e70-4e36-9b1a-4d0f6e1c1f55")
_PERMISSIONS = (
    ("restore_points.read", "Restore Points Read"),
    ("restore_points.create", "Restore Points Create"),
    ("restore_points.restore", "Restore Points Restore"),
    ("restore_points.delete", "Restore Points Delete"),
)


def _id(value: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, value)


def upgrade() -> None:
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS restore_points (
            id UUID PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            source VARCHAR(20) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
            created_by_user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
            description TEXT NULL,
            artifact_name VARCHAR(255) NULL UNIQUE,
            artifact_size INTEGER NULL,
            sha256 VARCHAR(64) NULL,
            manifest_checksum VARCHAR(64) NULL,
            postgres_major_version VARCHAR(20) NULL,
            pg_dump_version VARCHAR(80) NULL,
            application_version VARCHAR(80) NULL,
            image_identifier VARCHAR(255) NULL,
            alembic_revision VARCHAR(100) NULL,
            schema_fingerprint VARCHAR(64) NULL,
            retention_until TIMESTAMPTZ NULL,
            pinned BOOLEAN NOT NULL DEFAULT FALSE,
            started_at TIMESTAMPTZ NULL,
            completed_at TIMESTAMPTZ NULL,
            failure_code VARCHAR(100) NULL,
            failure_message TEXT NULL,
            request_id VARCHAR(128) NULL,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            CONSTRAINT ck_restore_points_source CHECK (source IN ('MANUAL','AUTOMATIC','EMERGENCY')),
            CONSTRAINT ck_restore_points_status CHECK (status IN ('PENDING','CREATING','READY','FAILED','VERIFYING','RESTORING','RESTORED','DELETED'))
        )
    """))
    for statement in (
        "CREATE INDEX IF NOT EXISTS ix_restore_points_status_created ON restore_points (status, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS ix_restore_points_retention ON restore_points (retention_until)",
    ):
        op.execute(sa.text(statement))
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
    op.execute(sa.text("DROP TABLE IF EXISTS restore_points"))
    op.execute(sa.text("DELETE FROM permissions WHERE code IN ('restore_points.read','restore_points.create','restore_points.restore','restore_points.delete')"))
