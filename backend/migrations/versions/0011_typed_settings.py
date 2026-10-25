"""Seed the immutable, typed operational-settings registry.

Revision ID: 0011_typed_settings
Revises: 0010_integrity_hardening
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from alembic import op


revision = "0011_typed_settings"
down_revision = "0010_integrity_hardening"
branch_labels = None
depends_on = None


_NAMESPACE = uuid.UUID("90ba4bb7-95c4-42d1-b355-1a26b98a7b91")
_SETTINGS = (
    ("system.timezone", {"value": "UTC"}, "Default operational timezone."),
    ("auth.session_lifetime_minutes", {"value": 480}, "Session lifetime in minutes."),
    ("auth.login_rate_limit", {"attempts": 5, "window_seconds": 900}, "Failed-login threshold and rolling window."),
    ("auth.password.min_length", {"value": 12}, "Minimum password length."),
    ("auth.password.require_complexity", {"value": False}, "Require three password character classes."),
    ("discovery.default_timeout_seconds", {"value": 10}, "Default discovery timeout in seconds."),
    ("discovery.default_retries", {"value": 1}, "Default discovery retry count."),
    ("restore_points.enabled", {"value": True}, "Enable scheduled restore-point creation."),
    ("restore_points.schedule_time", {"value": "00:00"}, "Daily restore-point schedule in the configured timezone."),
    ("restore_points.timezone", {"value": "UTC"}, "IANA timezone for scheduled restore points."),
    ("restore_points.retention_days", {"value": 30}, "Restore-point artifact retention in days."),
    ("recycle_bin.retention_days", {"value": 30}, "Recycle-bin retention in days."),
    ("logs.retention_days", {"value": 30}, "Retention period for rotated operational logs."),
)


def upgrade() -> None:
    bind = op.get_bind()
    statement = sa.text(
        """
        INSERT INTO system_settings (id, key, value, description, is_secret)
        VALUES (:id, :key, :value, :description, false)
        ON CONFLICT (key) DO NOTHING
        """
    ).bindparams(sa.bindparam("value", type_=JSONB))
    for key, value, description in _SETTINGS:
        bind.execute(statement, {
            "id": uuid.uuid5(_NAMESPACE, key),
            "key": key,
            "value": value,
            "description": description,
        })


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(
        sa.text("DELETE FROM system_settings WHERE key IN :keys").bindparams(
            sa.bindparam("keys", expanding=True, value=[key for key, _, _ in _SETTINGS])
        )
    )
