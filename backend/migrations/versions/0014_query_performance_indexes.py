"""Add targeted indexes for paged management queries.

Revision ID: 0014_query_performance_indexes
Revises: 0013_lifecycle_group_hardening
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0014_query_performance_indexes"
down_revision = "0013_lifecycle_group_hardening"
branch_labels = None
depends_on = None

_INDEXES = {
    "devices": [
        ("ix_devices_type_display_active", ["device_type_id", "display_name"], "deleted_at IS NULL"),
        ("ix_devices_display_active", ["display_name"], "deleted_at IS NULL"),
    ],
    "device_ips": [
        ("ix_device_ips_device_priority_active", ["device_id", "is_management", "is_primary"], "deleted_at IS NULL"),
    ],
    "device_candidates": [
        ("ix_device_candidates_state_created", ["state", "created_at"], None),
    ],
    "device_placements": [
        ("ix_device_placements_geography_active", ["network_id", "city_id", "location_id"], "deleted_at IS NULL"),
        ("ix_device_placements_sector_active", ["sector_id"], "deleted_at IS NULL"),
    ],
    "device_hierarchy_links": [
        ("ix_device_hierarchy_parent_type_active", ["parent_device_id", "relationship_type"], "deleted_at IS NULL"),
    ],
    "customer_services": [
        ("ix_customer_services_sector_active", ["sector_id"], "deleted_at IS NULL"),
    ],
    "device_group_memberships": [
        ("ix_device_group_memberships_group_active", ["group_id", "device_id"], "deleted_at IS NULL"),
    ],
    "customers": [
        ("ix_customers_status_name_active", ["status", "name"], "deleted_at IS NULL"),
    ],
}


def _existing(bind, table: str) -> set[str]:
    return {row["name"] for row in sa.inspect(bind).get_indexes(table) if row.get("name")}


def upgrade() -> None:
    bind = op.get_bind()
    for table, indexes in _INDEXES.items():
        existing = _existing(bind, table)
        for name, columns, predicate in indexes:
            if name not in existing:
                kwargs = {"postgresql_where": sa.text(predicate)} if predicate else {}
                op.create_index(name, table, columns, **kwargs)


def downgrade() -> None:
    bind = op.get_bind()
    for table, indexes in reversed(list(_INDEXES.items())):
        existing = _existing(bind, table)
        for name, _columns, _predicate in reversed(indexes):
            if name in existing:
                op.drop_index(name, table_name=table)
