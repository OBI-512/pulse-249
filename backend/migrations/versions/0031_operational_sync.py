"""Synchronize operational state from authoritative availability.

Revision ID: 0031_operational_sync
Revises: 0030_ssh_compat_profile
"""

from alembic import op
import sqlalchemy as sa


revision = "0031_operational_sync"
down_revision = "0030_ssh_compat_profile"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("devices"):
        return

    columns = {column["name"] for column in inspector.get_columns("devices")}
    added_override = "manual_degraded_override" not in columns
    if added_override:
        op.add_column(
            "devices",
            sa.Column(
                "manual_degraded_override",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
        )
        # Preserve the intent of existing manually DEGRADED devices as the new
        # persistent override before availability becomes authoritative.
        bind.execute(
            sa.text(
                """
                UPDATE devices
                SET manual_degraded_override = (operational_state = 'DEGRADED')
                """
            )
        )

    inspector = sa.inspect(bind)
    if inspector.has_table("device_availability"):
        bind.execute(
            sa.text(
                """
                UPDATE devices AS d
                SET operational_state = CASE da.status
                    WHEN 'ONLINE' THEN CASE
                        WHEN d.manual_degraded_override THEN 'DEGRADED'
                        ELSE 'UP'
                    END
                    WHEN 'OFFLINE' THEN 'DOWN'
                    WHEN 'SUSPECT' THEN 'UNKNOWN'
                    WHEN 'UNKNOWN' THEN 'UNKNOWN'
                    WHEN 'MAINTENANCE' THEN d.operational_state
                    ELSE 'UNKNOWN'
                END
                FROM device_availability AS da
                WHERE da.device_id = d.id
                  AND d.lifecycle_state <> 'DECOMMISSIONED'
                """
            )
        )
        # Devices without a current availability row have no authoritative
        # reachability evidence and therefore remain UNKNOWN until reconciled.
        bind.execute(
            sa.text(
                """
                UPDATE devices AS d
                SET operational_state = 'UNKNOWN'
                WHERE d.lifecycle_state NOT IN ('MAINTENANCE', 'DECOMMISSIONED')
                  AND NOT EXISTS (
                      SELECT 1 FROM device_availability AS da
                      WHERE da.device_id = d.id
                  )
                """
            )
        )

    bind.execute(
        sa.text(
            """
            UPDATE devices
            SET operational_state = 'UNKNOWN'
            WHERE lifecycle_state = 'DECOMMISSIONED'
            """
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("devices"):
        return
    columns = {column["name"] for column in inspector.get_columns("devices")}
    if "manual_degraded_override" in columns:
        op.drop_column("devices", "manual_degraded_override")
