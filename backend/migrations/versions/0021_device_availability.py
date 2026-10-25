"""Add C1 server-authoritative device availability engine state.

Revision ID: 0021_device_availability
Revises: 0020_user_resource_scopes

The replacement baseline creates current SQLAlchemy metadata in migration 0001,
so this migration supports both an existing 0020 database and a fresh database
where ``device_availability`` was already materialized by metadata.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import uuid

import sqlalchemy as sa
from alembic import op


revision = "0021_device_availability"
down_revision = "0020_user_resource_scopes"
branch_labels = None
depends_on = None

_SETTINGS = (
    ("availability.enabled", {"value": True}, "Enable server-authoritative availability polling."),
    ("availability.interval_seconds", {"value": 300}, "Target interval between device availability checks."),
    ("availability.failure_threshold", {"value": 2}, "Consecutive failed checks required before OFFLINE."),
    ("availability.probe_timeout_seconds", {"value": 2}, "Per-attempt availability probe timeout."),
    ("availability.probe_retries", {"value": 1}, "Retry attempts inside one scheduled availability check."),
    ("availability.dispatch_limit_per_tick", {"value": 100}, "Maximum devices claimed by each one-second dispatcher tick."),
    ("availability.task_batch_size", {"value": 50}, "Maximum devices carried by one availability worker task."),
    ("availability.max_outstanding_devices", {"value": 2000}, "Backpressure cap for leased/published availability checks."),
    ("availability.worker_concurrency", {"value": 32}, "Async probe concurrency inside one Celery batch task."),
    ("availability.lease_seconds", {"value": 180}, "Idempotency lease duration for a claimed availability check."),
    ("availability.tcp_ports", {"value": [22, 80, 443]}, "TCP availability profile ports."),
)


def _inspector(bind):
    return sa.inspect(bind)


def _has_table(bind, table_name: str) -> bool:
    return _inspector(bind).has_table(table_name)


def _index_names(bind, table_name: str) -> set[str]:
    return {row["name"] for row in _inspector(bind).get_indexes(table_name) if row.get("name")}


def _create_table(bind) -> None:
    if not _has_table(bind, "device_availability"):
        op.create_table(
            "device_availability",
            sa.Column("device_id", sa.UUID(), nullable=False),
            sa.Column("status", sa.String(length=20), server_default="UNKNOWN", nullable=False),
            sa.Column("profile", sa.String(length=20), server_default="ICMP", nullable=False),
            sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
            sa.Column("last_check_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_failure_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("status_changed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("consecutive_failures", sa.Integer(), server_default="0", nullable=False),
            sa.Column("latency_ms", sa.Float(), nullable=True),
            sa.Column("last_result_code", sa.String(length=80), nullable=True),
            sa.Column("next_check_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("last_dispatched_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("lease_token", sa.UUID(), nullable=True),
            sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("id", sa.UUID(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.CheckConstraint(
                "status IN ('ONLINE','SUSPECT','OFFLINE','UNKNOWN','MAINTENANCE')",
                name="ck_device_availability_status",
            ),
            sa.CheckConstraint(
                "profile IN ('ICMP','TCP','SNMP')",
                name="ck_device_availability_profile",
            ),
            sa.CheckConstraint(
                "consecutive_failures >= 0",
                name="ck_device_availability_consecutive_failures",
            ),
            sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )


def _ensure_indexes(bind) -> None:
    existing = _index_names(bind, "device_availability")
    if "uq_device_availability_device" not in existing:
        op.create_index("uq_device_availability_device", "device_availability", ["device_id"], unique=True)
    if "ix_device_availability_status" not in existing:
        op.create_index("ix_device_availability_status", "device_availability", ["status"], unique=False)
    if "ix_device_availability_due" not in existing:
        op.create_index(
            "ix_device_availability_due",
            "device_availability",
            ["next_check_at"],
            unique=False,
            postgresql_where=sa.text("enabled"),
        )
    if "ix_device_availability_lease_expires" not in existing:
        op.create_index("ix_device_availability_lease_expires", "device_availability", ["lease_expires_at"], unique=False)


def _seed_settings(bind) -> None:
    import json

    for key, value, description in _SETTINGS:
        bind.execute(
            sa.text(
                """
                INSERT INTO system_settings (id, key, value, description, is_secret)
                VALUES (:id, :key, CAST(:value AS jsonb), :description, false)
                ON CONFLICT (key) DO NOTHING
                """
            ),
            {
                "id": uuid.uuid4(),
                "key": key,
                "value": json.dumps(value, separators=(",", ":")),
                "description": description,
            },
        )


def _backfill_devices(bind) -> None:
    existing = set(bind.execute(sa.text("SELECT device_id FROM device_availability")).scalars())
    rows = list(bind.execute(sa.text(
        "SELECT id, lifecycle_state, management_protocol FROM devices WHERE deleted_at IS NULL ORDER BY id"
    )).mappings())
    now = datetime.now(timezone.utc)
    values = []
    slot = 0
    for row in rows:
        if row["id"] in existing:
            continue
        protocol = (row["management_protocol"] or "").strip().upper()
        profile = protocol if protocol in {"ICMP", "TCP", "SNMP"} else "ICMP"
        status = "MAINTENANCE" if row["lifecycle_state"] == "MAINTENANCE" else "UNKNOWN"
        values.append({
            "id": uuid.uuid4(),
            "device_id": row["id"],
            "status": status,
            "profile": profile,
            "status_changed_at": now,
            "next_check_at": now + timedelta(seconds=slot % 300),
        })
        slot += 1
    if values:
        bind.execute(sa.text(
            """
            INSERT INTO device_availability
                (id, device_id, status, profile, enabled, status_changed_at,
                 consecutive_failures, next_check_at)
            VALUES
                (:id, :device_id, :status, :profile, true, :status_changed_at, 0, :next_check_at)
            ON CONFLICT (device_id) DO NOTHING
            """
        ), values)


def upgrade() -> None:
    bind = op.get_bind()
    _create_table(bind)
    _ensure_indexes(bind)
    _seed_settings(bind)
    _backfill_devices(bind)


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text(
        "DELETE FROM system_settings WHERE key LIKE 'availability.%'"
    ))
    if _has_table(bind, "device_availability"):
        op.drop_table("device_availability")
