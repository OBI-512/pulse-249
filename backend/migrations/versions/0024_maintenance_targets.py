"""Expand maintenance targets to City and Group.

Revision ID: 0024_maintenance_targets
Revises: 0023_maintenance_notifications
"""
from alembic import op
import sqlalchemy as sa

revision = "0024_maintenance_targets"
down_revision = "0023_maintenance_notifications"
branch_labels = None
depends_on = None

_CONSTRAINT = "ck_maintenance_windows_target_type"

def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("maintenance_windows"):
        return
    constraints = {row["name"] for row in inspector.get_check_constraints("maintenance_windows")}
    if _CONSTRAINT in constraints:
        op.drop_constraint(_CONSTRAINT, "maintenance_windows", type_="check")
    op.create_check_constraint(
        _CONSTRAINT,
        "maintenance_windows",
        "target_type IN ('DEVICE','LOCATION','CITY','GROUP','NETWORK')",
    )

def downgrade() -> None:
    bind = op.get_bind()
    if not sa.inspect(bind).has_table("maintenance_windows"):
        return
    maintenance_windows = sa.table(
        "maintenance_windows",
        sa.column("target_type", sa.String()),
    )
    op.execute(maintenance_windows.delete().where(maintenance_windows.c.target_type.in_(["CITY", "GROUP"])))
    op.drop_constraint(_CONSTRAINT, "maintenance_windows", type_="check")
    op.create_check_constraint(
        _CONSTRAINT,
        "maintenance_windows",
        "target_type IN ('DEVICE','LOCATION','NETWORK')",
    )
