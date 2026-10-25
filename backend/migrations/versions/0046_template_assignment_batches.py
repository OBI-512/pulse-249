"""TP4 metadata-only bulk template assignment evidence.

Revision ID: 0046_template_assignment_batches
Revises: 0045_web_tls_trust

The new tables are deliberately separate from F3 configuration execution
batches. They persist preview/apply evidence only and contain no
ConfigurationOperation linkage or execution dispatch state.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0046_template_assignment_batches"
down_revision = "0045_web_tls_trust"
branch_labels = None
depends_on = None

_BATCH_TABLE = "template_assignment_batches"
_TARGET_TABLE = "template_assignment_batch_targets"


def _create_batch_table() -> None:
    op.create_table(
        _BATCH_TABLE,
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("status", sa.String(20), server_default="PREVIEWED", nullable=False),
        sa.Column("idempotency_key", sa.String(128)),
        sa.Column("request_fingerprint", sa.String(64), nullable=False),
        sa.Column("authorization_scope", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("authorization_scope_fingerprint", sa.String(64)),
        sa.Column("request_summary", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("target_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("ready_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("noop_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("blocked_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("succeeded_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("failed_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("preview_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "status IN ('PREVIEWED','APPLYING','SUCCEEDED','PARTIAL','FAILED','EXPIRED')",
            name="ck_template_assignment_batches_status",
        ),
        sa.CheckConstraint(
            "char_length(request_fingerprint) = 64",
            name="ck_template_assignment_batches_request_fingerprint",
        ),
        sa.CheckConstraint(
            "authorization_scope_fingerprint IS NULL OR char_length(authorization_scope_fingerprint) = 64",
            name="ck_template_assignment_batches_scope_fingerprint",
        ),
        sa.CheckConstraint(
            "target_count >= 0 AND ready_count >= 0 AND noop_count >= 0 AND blocked_count >= 0 "
            "AND succeeded_count >= 0 AND failed_count >= 0",
            name="ck_template_assignment_batches_nonnegative_counters",
        ),
        sa.CheckConstraint(
            "ready_count <= target_count AND noop_count <= target_count AND blocked_count <= target_count "
            "AND succeeded_count <= target_count AND failed_count <= target_count",
            name="ck_template_assignment_batches_counter_bounds",
        ),
    )
    op.create_index(
        "uq_template_assignment_batches_actor_idempotency",
        _BATCH_TABLE,
        ["actor_user_id", "idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )
    op.create_index(
        "ix_template_assignment_batches_actor_created",
        _BATCH_TABLE,
        ["actor_user_id", "created_at"],
    )
    op.create_index(
        "ix_template_assignment_batches_status_expiry",
        _BATCH_TABLE,
        ["status", "preview_expires_at"],
    )


def _create_target_table() -> None:
    op.create_table(
        _TARGET_TABLE,
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("batch_id", postgresql.UUID(as_uuid=True), sa.ForeignKey(f"{_BATCH_TABLE}.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("target_ordinal", sa.Integer(), nullable=False),
        sa.Column("preview_status", sa.String(20), server_default="READY", nullable=False),
        sa.Column("apply_status", sa.String(20), server_default="NOT_APPLIED", nullable=False),
        sa.Column("warnings", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("blockers", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("planned_changes", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("family_outcomes", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("failure_code", sa.String(120)),
        sa.Column("failure_message", sa.Text()),
        sa.Column("terminal_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("batch_id", "device_id", name="uq_template_assignment_batch_targets_batch_device"),
        sa.UniqueConstraint("batch_id", "target_ordinal", name="uq_template_assignment_batch_targets_batch_ordinal"),
        sa.CheckConstraint("target_ordinal >= 0", name="ck_template_assignment_batch_targets_ordinal"),
        sa.CheckConstraint(
            "preview_status IN ('READY','NOOP','BLOCKED')",
            name="ck_template_assignment_batch_targets_preview_status",
        ),
        sa.CheckConstraint(
            "apply_status IN ('NOT_APPLIED','SUCCEEDED','FAILED','SKIPPED')",
            name="ck_template_assignment_batch_targets_apply_status",
        ),
    )
    op.create_index(
        "ix_template_assignment_batch_targets_batch_preview",
        _TARGET_TABLE,
        ["batch_id", "preview_status"],
    )
    op.create_index(
        "ix_template_assignment_batch_targets_batch_apply",
        _TARGET_TABLE,
        ["batch_id", "apply_status"],
    )
    op.create_index(
        "ix_template_assignment_batch_targets_device_created",
        _TARGET_TABLE,
        ["device_id", "created_at"],
    )


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table(_BATCH_TABLE):
        _create_batch_table()

    inspector = sa.inspect(bind)
    if not inspector.has_table(_TARGET_TABLE):
        _create_target_table()


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table(_TARGET_TABLE):
        op.drop_table(_TARGET_TABLE)

    inspector = sa.inspect(bind)
    if inspector.has_table(_BATCH_TABLE):
        op.drop_table(_BATCH_TABLE)
