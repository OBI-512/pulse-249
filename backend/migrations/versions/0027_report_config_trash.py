"""Report configuration trash lifecycle and automatic purge retention.

Revision ID: 0027_report_config_trash
Revises: 0026_phase_d_reporting
"""
from __future__ import annotations

import uuid

from alembic import op
import sqlalchemy as sa

revision = "0027_report_config_trash"
down_revision = "0026_phase_d_reporting"
branch_labels = None
depends_on = None

_NAMESPACE = uuid.UUID("91df1e58-813b-41c4-8aa6-62e6dc1f2177")


def _id(key: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, key)


def _columns(bind, table: str) -> set[str]:
    return {row["name"] for row in sa.inspect(bind).get_columns(table)}


def _indexes(bind, table: str) -> set[str]:
    return {row["name"] for row in sa.inspect(bind).get_indexes(table) if row.get("name")}


def _checks(bind, table: str) -> set[str]:
    return {row["name"] for row in sa.inspect(bind).get_check_constraints(table) if row.get("name")}


def _add_lifecycle_columns(bind, table: str, *, prefix: str) -> None:
    columns = _columns(bind, table)
    if "deleted_at" not in columns:
        op.add_column(table, sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))
    if "purge_after" not in columns:
        op.add_column(table, sa.Column("purge_after", sa.DateTime(timezone=True), nullable=True))

    checks = _checks(bind, table)
    check_name = f"ck_{prefix}_trash_state"
    if check_name not in checks:
        op.create_check_constraint(
            check_name,
            table,
            "(deleted_at IS NULL AND purge_after IS NULL) OR (deleted_at IS NOT NULL AND purge_after IS NOT NULL)",
        )

    indexes = _indexes(bind, table)
    owner_deleted = f"ix_{prefix}_owner_deleted"
    if owner_deleted not in indexes:
        op.create_index(owner_deleted, table, ["owner_user_id", "deleted_at"])
    purge_index = f"ix_{prefix}_purge_after"
    if purge_index not in indexes:
        op.create_index(purge_index, table, ["purge_after"])


def upgrade() -> None:
    bind = op.get_bind()
    _add_lifecycle_columns(bind, "report_definitions", prefix="report_definitions")
    _add_lifecycle_columns(bind, "report_schedules", prefix="report_schedules")

    exists = bind.execute(sa.text(
        "SELECT 1 FROM data_retention_policies WHERE data_class = 'REPORT_CONFIGURATION_TRASH' LIMIT 1"
    )).scalar_one_or_none()
    if exists is None:
        bind.execute(
            sa.text(
                "INSERT INTO data_retention_policies "
                "(id, data_class, enabled, retain_days, rollup_after_days, batch_hours, description) "
                "VALUES (:id, 'REPORT_CONFIGURATION_TRASH', true, 30, NULL, 24, :description)"
            ),
            {
                "id": _id("retention:report_configuration_trash"),
                "description": "Deleted saved report definitions and schedules are recoverable for thirty days before automatic purge.",
            },
        )


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text("DELETE FROM data_retention_policies WHERE data_class = 'REPORT_CONFIGURATION_TRASH'"))

    for table, prefix in (
        ("report_schedules", "report_schedules"),
        ("report_definitions", "report_definitions"),
    ):
        indexes = _indexes(bind, table)
        for index_name in (f"ix_{prefix}_purge_after", f"ix_{prefix}_owner_deleted"):
            if index_name in indexes:
                op.drop_index(index_name, table_name=table)
        checks = _checks(bind, table)
        check_name = f"ck_{prefix}_trash_state"
        if check_name in checks:
            op.drop_constraint(check_name, table, type_="check")
        columns = _columns(bind, table)
        if "purge_after" in columns:
            op.drop_column(table, "purge_after")
        if "deleted_at" in columns:
            op.drop_column(table, "deleted_at")
