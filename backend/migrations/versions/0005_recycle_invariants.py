"""Enforce paired recycle tombstones and mark populated upgrades seeded.

Revision ID: 0005_recycle_invariants
Revises: 0004_recycle_bin

0004 had already been applied to the validated live database before these
additional invariants were identified.  They therefore live in this new,
immutable incremental revision rather than amending applied history.
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op


revision = "0005_recycle_invariants"
down_revision = "0004_recycle_bin"
branch_labels = None
depends_on = None


_NAMESPACE = uuid.UUID("8d3a2d89-4e70-4e36-9b1a-4d0f6e1c1f55")
_RECOVERABLE_TABLES = (
    "networks",
    "cities",
    "locations",
    "devices",
    "sectors",
    "customers",
    "customer_services",
    "device_ips",
    "device_placements",
    "device_hierarchy_links",
    "device_interfaces",
    "device_relationships",
    "device_groups",
    "device_group_memberships",
)


def _deterministic_id(key: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, key)


def upgrade() -> None:
    for table_name in _RECOVERABLE_TABLES:
        op.execute(
            sa.text(
                f"""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1
                        FROM pg_constraint
                        WHERE conrelid = '{table_name}'::regclass
                          AND conname = 'ck_{table_name}_recycle_tombstone_pair'
                    ) THEN
                        ALTER TABLE "{table_name}"
                        ADD CONSTRAINT "ck_{table_name}_recycle_tombstone_pair"
                        CHECK (
                            (deleted_at IS NULL AND deletion_batch_id IS NULL)
                            OR
                            (deleted_at IS NOT NULL AND deletion_batch_id IS NOT NULL)
                        );
                    END IF;
                END $$;
                """
            )
        )

    # An already populated deployment must never rerun demo seeding after a
    # restart.  A truly empty fresh chain receives no marker here; the normal
    # seed command owns its initial data and writes the marker only after its
    # complete transaction succeeds.
    op.execute(
        sa.text(
            """
            INSERT INTO system_settings (id, key, value, description, is_secret)
            SELECT
                :id,
                'internal.demo_seed.version',
                '{"version": 1}'::jsonb,
                'Internal marker for successful one-time baseline seeding.',
                FALSE
            WHERE EXISTS (SELECT 1 FROM networks LIMIT 1)
               OR EXISTS (SELECT 1 FROM devices LIMIT 1)
               OR EXISTS (SELECT 1 FROM customers LIMIT 1)
            ON CONFLICT (key) DO NOTHING
            """
        ).bindparams(id=_deterministic_id("setting:internal.demo_seed.version"))
    )


def downgrade() -> None:
    # The marker may have been created by the seed command rather than this
    # migration, so downgrade deliberately leaves it intact.
    for table_name in reversed(_RECOVERABLE_TABLES):
        op.execute(
            sa.text(
                f'ALTER TABLE "{table_name}" '
                f'DROP CONSTRAINT IF EXISTS "ck_{table_name}_recycle_tombstone_pair"'
            )
        )
