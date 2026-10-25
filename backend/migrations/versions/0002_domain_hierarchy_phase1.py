"""Phase 1 authoritative customer-device hierarchy constraints.

Revision ID: 0002_domain_hierarchy_phase1
Revises: 0001_initial_schema
"""

from alembic import op


revision = "0002_domain_hierarchy_phase1"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # child_device_id uniqueness and the supported relationship-type check
    # already belong to the clean initial schema.  A partial unique index is
    # the ordinary relational constraint that expresses one AP per CPE.
    # IF NOT EXISTS makes this safe for a fresh database whose metadata-based
    # initial migration already created the model index.
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS
        uq_device_hierarchy_cpe_access_point_parent
        ON device_hierarchy_links (parent_device_id)
        WHERE relationship_type = 'CPE_ACCESS_POINT'
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_device_hierarchy_cpe_access_point_parent")
