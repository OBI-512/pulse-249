"""F3 durable bulk/scheduled configuration orchestration foundation.

Revision ID: 0041_config_change_batches
Revises: 0040_remote_template_binding
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# Keep the Alembic revision identifier within the legacy alembic_version
# VARCHAR(32) contract used by the existing database. The descriptive filename
# remains 0041_configuration_change_batches.py.
revision = "0041_config_change_batches"
down_revision = "0040_remote_template_binding"
branch_labels = None
depends_on = None


def _common_columns():
    return (
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    # 0001 materializes current SQLAlchemy metadata on a clean installation.
    # Guard both tables so live upgrades and clean installs converge safely.
    if not inspector.has_table("configuration_batches"):
        op.create_table(
            "configuration_batches",
            *_common_columns(),
            sa.Column(
                "actor_user_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
            ),
            sa.Column("operation_type", sa.String(20), nullable=False),
            sa.Column(
                "status",
                sa.String(20),
                nullable=False,
                server_default="QUEUED",
            ),
            sa.Column("idempotency_key", sa.String(128)),
            sa.Column("request_fingerprint", sa.String(64), nullable=False),
            sa.Column(
                "authorization_scope",
                postgresql.JSONB(),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
            sa.Column("authorization_scope_fingerprint", sa.String(64)),
            sa.Column(
                "request_summary",
                postgresql.JSONB(),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
            sa.Column(
                "rollout_mode",
                sa.String(24),
                nullable=False,
                server_default="ALL_AT_ONCE",
            ),
            sa.Column(
                "rollout_parameters",
                postgresql.JSONB(),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
            sa.Column("not_before", sa.DateTime(timezone=True)),
            sa.Column(
                "maintenance_policy",
                sa.String(32),
                nullable=False,
                server_default="NONE",
            ),
            sa.Column("target_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("dispatched_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("succeeded_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("failed_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("aborted_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("queued_at", sa.DateTime(timezone=True)),
            sa.Column("started_at", sa.DateTime(timezone=True)),
            sa.Column("paused_at", sa.DateTime(timezone=True)),
            sa.Column("aborted_at", sa.DateTime(timezone=True)),
            sa.Column("finished_at", sa.DateTime(timezone=True)),
            sa.CheckConstraint(
                "operation_type IN ('CAPTURE','APPLY','VERIFY','RESTORE')",
                name="ck_configuration_batches_operation_type",
            ),
            sa.CheckConstraint(
                "status IN ('QUEUED','SCHEDULED','RUNNING','PAUSED','ABORTING','ABORTED','SUCCEEDED','PARTIAL','FAILED','CANCELLED')",
                name="ck_configuration_batches_status",
            ),
            sa.CheckConstraint(
                "rollout_mode IN ('ALL_AT_ONCE','CANARY_PERCENTAGE','WAVES')",
                name="ck_configuration_batches_rollout_mode",
            ),
            sa.CheckConstraint(
                "maintenance_policy IN ('NONE','REQUIRE_ACTIVE_WINDOW')",
                name="ck_configuration_batches_maintenance_policy",
            ),
            sa.CheckConstraint(
                "char_length(request_fingerprint) = 64",
                name="ck_configuration_batches_request_fingerprint",
            ),
            sa.CheckConstraint(
                "authorization_scope_fingerprint IS NULL OR char_length(authorization_scope_fingerprint) = 64",
                name="ck_configuration_batches_scope_fingerprint",
            ),
            sa.CheckConstraint(
                "target_count >= 0 AND dispatched_count >= 0 AND succeeded_count >= 0 "
                "AND failed_count >= 0 AND aborted_count >= 0",
                name="ck_configuration_batches_nonnegative_counters",
            ),
            sa.CheckConstraint(
                "dispatched_count <= target_count AND succeeded_count <= target_count "
                "AND failed_count <= target_count AND aborted_count <= target_count",
                name="ck_configuration_batches_counter_bounds",
            ),
        )
        op.create_index(
            "uq_configuration_batches_actor_idempotency",
            "configuration_batches",
            ["actor_user_id", "idempotency_key"],
            unique=True,
            postgresql_where=sa.text("idempotency_key IS NOT NULL"),
        )
        op.create_index(
            "ix_configuration_batches_status_not_before",
            "configuration_batches",
            ["status", "not_before"],
        )
        op.create_index(
            "ix_configuration_batches_actor_created",
            "configuration_batches",
            ["actor_user_id", "created_at"],
        )

    inspector = sa.inspect(bind)
    if not inspector.has_table("configuration_batch_targets"):
        op.create_table(
            "configuration_batch_targets",
            *_common_columns(),
            sa.Column(
                "batch_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("configuration_batches.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "device_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("devices.id", ondelete="RESTRICT"),
                nullable=False,
            ),
            sa.Column("target_ordinal", sa.Integer(), nullable=False),
            sa.Column("wave_number", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("status", sa.String(20), nullable=False, server_default="WAITING"),
            sa.Column(
                "configuration_operation_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("configuration_operations.id", ondelete="RESTRICT"),
            ),
            sa.Column("failure_code", sa.String(120)),
            sa.Column("failure_message", sa.Text()),
            sa.Column("dispatched_at", sa.DateTime(timezone=True)),
            sa.Column("terminal_at", sa.DateTime(timezone=True)),
            sa.UniqueConstraint(
                "batch_id", "device_id", name="uq_configuration_batch_targets_batch_device"
            ),
            sa.UniqueConstraint(
                "batch_id",
                "target_ordinal",
                name="uq_configuration_batch_targets_batch_ordinal",
            ),
            sa.UniqueConstraint(
                "configuration_operation_id",
                name="uq_configuration_batch_targets_operation",
            ),
            sa.CheckConstraint(
                "target_ordinal >= 0",
                name="ck_configuration_batch_targets_ordinal",
            ),
            sa.CheckConstraint(
                "wave_number >= 0",
                name="ck_configuration_batch_targets_wave",
            ),
            sa.CheckConstraint(
                "status IN ('WAITING','READY','DISPATCHED','SUCCEEDED','FAILED','SKIPPED','ABORTED')",
                name="ck_configuration_batch_targets_status",
            ),
            sa.CheckConstraint(
                "(configuration_operation_id IS NULL AND status IN ('WAITING','READY','SKIPPED','ABORTED')) "
                "OR (configuration_operation_id IS NOT NULL AND status IN ('DISPATCHED','SUCCEEDED','FAILED','ABORTED'))",
                name="ck_configuration_batch_targets_operation_status",
            ),
        )
        op.create_index(
            "ix_configuration_batch_targets_batch_wave_status",
            "configuration_batch_targets",
            ["batch_id", "wave_number", "status"],
        )
        op.create_index(
            "ix_configuration_batch_targets_device_created",
            "configuration_batch_targets",
            ["device_id", "created_at"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("configuration_batch_targets"):
        op.drop_table("configuration_batch_targets")

    inspector = sa.inspect(bind)
    if inspector.has_table("configuration_batches"):
        op.drop_table("configuration_batches")
