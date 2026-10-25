"""Strengthen DeviceIP integrity and measured relationship lookup indexes.

Revision ID: 0010_integrity_hardening
Revises: 0009_operational_logs
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0010_integrity_hardening"
down_revision = "0009_operational_logs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(sa.text("""
        DO $$ BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conrelid = 'device_ips'::regclass
                  AND conname = 'ck_device_ips_primary_requires_management'
            ) THEN
                ALTER TABLE device_ips
                ADD CONSTRAINT ck_device_ips_primary_requires_management
                CHECK (NOT is_primary OR is_management);
            END IF;
        END $$;
    """))
    for statement in (
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_active_device_ips_primary ON device_ips (device_id) WHERE deleted_at IS NULL AND is_primary",
        "CREATE INDEX IF NOT EXISTS ix_device_hierarchy_links_parent ON device_hierarchy_links (parent_device_id) WHERE deleted_at IS NULL",
        "CREATE INDEX IF NOT EXISTS ix_device_group_memberships_group ON device_group_memberships (group_id) WHERE deleted_at IS NULL",
        "CREATE INDEX IF NOT EXISTS ix_customer_services_sector_status ON customer_services (sector_id, status) WHERE deleted_at IS NULL",
    ):
        op.execute(sa.text(statement))


def downgrade() -> None:
    for index in (
        "ix_customer_services_sector_status",
        "ix_device_group_memberships_group",
        "ix_device_hierarchy_links_parent",
        "uq_active_device_ips_primary",
    ):
        op.execute(sa.text(f"DROP INDEX IF EXISTS {index}"))
    op.execute(sa.text("ALTER TABLE device_ips DROP CONSTRAINT IF EXISTS ck_device_ips_primary_requires_management"))
