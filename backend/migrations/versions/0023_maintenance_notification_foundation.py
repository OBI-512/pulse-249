"""Add C3 maintenance windows and notification foundation.

Revision ID: 0023_maintenance_notifications
Revises: 0022_alarm_event_engine

The replacement baseline creates current SQLAlchemy metadata in migration 0001,
so this revision is idempotent on fresh installs while remaining incremental
for deployed 0022 databases.
"""
from __future__ import annotations

import json
import uuid

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op


revision = "0023_maintenance_notifications"
down_revision = "0022_alarm_event_engine"
branch_labels = None
depends_on = None

_NAMESPACE = uuid.UUID("4bd6f28e-4417-4bf8-8124-383476c439b5")
_PERMISSIONS = (
    ("maintenance.read", "Maintenance Read", ("administrator", "operator", "administrative_viewer", "viewer")),
    ("maintenance.manage", "Maintenance Manage", ("administrator", "operator")),
    ("notification.read", "Notification Read", ("administrator", "operator", "administrative_viewer", "viewer")),
    ("notification.manage", "Notification Manage", ("administrator",)),
)
_SETTINGS = (
    ("notifications.enabled", {"value": False}, "Enable outbound alarm notification delivery."),
    ("notifications.dispatch_limit_per_tick", {"value": 100}, "Maximum notification deliveries claimed per dispatcher tick."),
    ("notifications.task_batch_size", {"value": 25}, "Maximum notification deliveries carried by one worker task."),
    ("notifications.max_outstanding", {"value": 500}, "Backpressure cap for claimed notification deliveries."),
    ("notifications.lease_seconds", {"value": 120}, "Idempotency lease duration for claimed notification deliveries."),
    ("notifications.worker_concurrency", {"value": 8}, "Concurrent external notification sends inside one worker batch."),
)


def _id(key: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, key)


def _inspector(bind):
    return sa.inspect(bind)


def _has_table(bind, table_name: str) -> bool:
    return _inspector(bind).has_table(table_name)


def _index_names(bind, table_name: str) -> set[str]:
    return {row["name"] for row in _inspector(bind).get_indexes(table_name) if row.get("name")}


def _create_maintenance_windows(bind) -> None:
    if _has_table(bind, "maintenance_windows"):
        return
    op.create_table(
        "maintenance_windows",
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("target_type", sa.String(length=20), nullable=False),
        sa.Column("target_id", sa.UUID(), nullable=False),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_user_id", sa.UUID(), nullable=True),
        sa.Column("cancelled_by_user_id", sa.UUID(), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("target_type IN ('DEVICE','LOCATION','NETWORK')", name="ck_maintenance_windows_target_type"),
        sa.CheckConstraint("ends_at > starts_at", name="ck_maintenance_windows_time_range"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["cancelled_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )


def _create_notification_policies(bind) -> None:
    if not _has_table(bind, "notification_policies"):
        op.create_table(
            "notification_policies",
            sa.Column("name", sa.String(length=160), nullable=False),
            sa.Column("enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
            sa.Column("alarm_type", sa.String(length=80), nullable=True),
            sa.Column("minimum_severity", sa.String(length=20), server_default="MAJOR", nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("id", sa.UUID(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.CheckConstraint(
                "minimum_severity IN ('INFO','WARNING','MINOR','MAJOR','CRITICAL')",
                name="ck_notification_policies_minimum_severity",
            ),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("name"),
        )
    if not _has_table(bind, "notification_policy_steps"):
        op.create_table(
            "notification_policy_steps",
            sa.Column("policy_id", sa.UUID(), nullable=False),
            sa.Column("step_order", sa.Integer(), nullable=False),
            sa.Column("delay_seconds", sa.Integer(), server_default="0", nullable=False),
            sa.Column("channel_type", sa.String(length=20), nullable=False),
            sa.Column("destination", sa.String(length=500), nullable=False),
            sa.Column("max_attempts", sa.Integer(), server_default="3", nullable=False),
            sa.Column("retry_base_seconds", sa.Integer(), server_default="30", nullable=False),
            sa.Column("retry_max_seconds", sa.Integer(), server_default="900", nullable=False),
            sa.Column("id", sa.UUID(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.CheckConstraint("step_order >= 1", name="ck_notification_policy_steps_order"),
            sa.CheckConstraint("delay_seconds >= 0", name="ck_notification_policy_steps_delay"),
            sa.CheckConstraint("channel_type IN ('EMAIL','WEBHOOK')", name="ck_notification_policy_steps_channel_type"),
            sa.CheckConstraint("max_attempts BETWEEN 1 AND 10", name="ck_notification_policy_steps_max_attempts"),
            sa.CheckConstraint("retry_base_seconds BETWEEN 5 AND 3600", name="ck_notification_policy_steps_retry_base"),
            sa.CheckConstraint("retry_max_seconds BETWEEN 5 AND 86400", name="ck_notification_policy_steps_retry_max"),
            sa.CheckConstraint("retry_max_seconds >= retry_base_seconds", name="ck_notification_policy_steps_retry_order"),
            sa.ForeignKeyConstraint(["policy_id"], ["notification_policies.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("policy_id", "step_order", name="uq_notification_policy_steps_order"),
        )


def _create_notification_deliveries(bind) -> None:
    if _has_table(bind, "notification_deliveries"):
        return
    op.create_table(
        "notification_deliveries",
        sa.Column("alarm_id", sa.UUID(), nullable=False),
        sa.Column("event_id", sa.UUID(), nullable=True),
        sa.Column("policy_id", sa.UUID(), nullable=False),
        sa.Column("policy_step_id", sa.UUID(), nullable=False),
        sa.Column("occurrence_number", sa.Integer(), nullable=False),
        sa.Column("channel_type", sa.String(length=20), nullable=False),
        sa.Column("destination", sa.String(length=500), nullable=False),
        sa.Column("status", sa.String(length=20), server_default="PENDING", nullable=False),
        sa.Column("scheduled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=120), nullable=True),
        sa.Column("response_status", sa.Integer(), nullable=True),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("claim_token", sa.UUID(), nullable=True),
        sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("maintenance_window_id", sa.UUID(), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("channel_type IN ('EMAIL','WEBHOOK')", name="ck_notification_deliveries_channel_type"),
        sa.CheckConstraint("status IN ('PENDING','SUPPRESSED','CLAIMED','SENT','FAILED','CANCELLED')", name="ck_notification_deliveries_status"),
        sa.CheckConstraint("occurrence_number >= 1", name="ck_notification_deliveries_occurrence"),
        sa.CheckConstraint("attempt_count >= 0", name="ck_notification_deliveries_attempt_count"),
        sa.ForeignKeyConstraint(["alarm_id"], ["alarms.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["event_id"], ["operational_events.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["policy_id"], ["notification_policies.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["policy_step_id"], ["notification_policy_steps.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["maintenance_window_id"], ["maintenance_windows.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )


def _ensure_indexes(bind) -> None:
    definitions = {
        "maintenance_windows": (
            ("ix_maintenance_windows_target_time", ["target_type", "target_id", "starts_at", "ends_at"], False, None),
            ("ix_maintenance_windows_active_time", ["starts_at", "ends_at"], False, sa.text("enabled AND cancelled_at IS NULL")),
        ),
        "notification_policies": (
            ("ix_notification_policies_enabled_alarm", ["enabled", "alarm_type"], False, None),
        ),
        "notification_policy_steps": (
            ("ix_notification_policy_steps_policy_order", ["policy_id", "step_order"], False, None),
        ),
        "notification_deliveries": (
            ("uq_notification_deliveries_idempotency", ["idempotency_key"], True, None),
            ("ix_notification_deliveries_due", ["status", "next_attempt_at"], False, None),
            ("ix_notification_deliveries_alarm_status", ["alarm_id", "status"], False, None),
            ("ix_notification_deliveries_claim_expires", ["claim_expires_at"], False, None),
        ),
    }
    for table, rows in definitions.items():
        existing = _index_names(bind, table)
        for name, columns, unique, predicate in rows:
            if name not in existing:
                op.create_index(name, table, columns, unique=unique, postgresql_where=predicate)


def _extend_alarm_history_constraint(bind) -> None:
    constraints = {row.get("name"): row.get("sqltext", "") for row in _inspector(bind).get_check_constraints("alarm_history")}
    sql = constraints.get("ck_alarm_history_action", "")
    if "NOTIFICATION_SUPPRESSED" in sql:
        return
    if "ck_alarm_history_action" in constraints:
        op.drop_constraint("ck_alarm_history_action", "alarm_history", type_="check")
    op.create_check_constraint(
        "ck_alarm_history_action",
        "alarm_history",
        "action IN ('OPENED','REOPENED','ACKNOWLEDGED','ASSIGNED','UNASSIGNED','MANUALLY_CLEARED','AUTO_CLEARED','NOTIFICATION_SUPPRESSED')",
    )


def _seed_permissions(bind) -> None:
    for code, name, role_codes in _PERMISSIONS:
        bind.execute(sa.text(
            """
            INSERT INTO permissions (id, code, name, description)
            VALUES (:id, :code, :name, :description)
            ON CONFLICT (code) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description
            """
        ), {"id": _id(f"perm:{code}"), "code": code, "name": name, "description": f"{name} permission"})
        for role_code in role_codes:
            bind.execute(sa.text(
                """
                INSERT INTO role_permissions (id, role_id, permission_id)
                SELECT :id, r.id, p.id FROM roles r CROSS JOIN permissions p
                WHERE r.code = :role_code AND p.code = :code
                ON CONFLICT (role_id, permission_id) DO NOTHING
                """
            ), {"id": _id(f"roleperm:{role_code}:{code}"), "role_code": role_code, "code": code})


def _seed_settings(bind) -> None:
    for key, value, description in _SETTINGS:
        bind.execute(sa.text(
            """
            INSERT INTO system_settings (id, key, value, description, is_secret)
            VALUES (:id, :key, CAST(:value AS jsonb), :description, false)
            ON CONFLICT (key) DO NOTHING
            """
        ), {"id": uuid.uuid4(), "key": key, "value": json.dumps(value, separators=(",", ":")), "description": description})


def upgrade() -> None:
    bind = op.get_bind()
    _create_maintenance_windows(bind)
    _create_notification_policies(bind)
    _create_notification_deliveries(bind)
    _ensure_indexes(bind)
    _extend_alarm_history_constraint(bind)
    _seed_permissions(bind)
    _seed_settings(bind)


def downgrade() -> None:
    bind = op.get_bind()
    for table in ("notification_deliveries", "notification_policy_steps", "notification_policies", "maintenance_windows"):
        if _has_table(bind, table):
            op.drop_table(table)
    if _has_table(bind, "alarm_history"):
        op.drop_constraint("ck_alarm_history_action", "alarm_history", type_="check")
        op.create_check_constraint(
            "ck_alarm_history_action",
            "alarm_history",
            "action IN ('OPENED','REOPENED','ACKNOWLEDGED','ASSIGNED','UNASSIGNED','MANUALLY_CLEARED','AUTO_CLEARED')",
        )
    bind.execute(sa.text("DELETE FROM system_settings WHERE key LIKE 'notifications.%'"))
    codes = [code for code, _, _ in _PERMISSIONS]
    bind.execute(sa.text("DELETE FROM user_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE code IN :codes)").bindparams(sa.bindparam("codes", expanding=True, value=codes)))
    bind.execute(sa.text("DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE code IN :codes)").bindparams(sa.bindparam("codes", expanding=True, value=codes)))
    bind.execute(sa.text("DELETE FROM permissions WHERE code IN :codes").bindparams(sa.bindparam("codes", expanding=True, value=codes)))
