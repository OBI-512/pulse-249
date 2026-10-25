"""Add password lifecycle state and password-history hashes.

Revision ID: 0017_password_lifecycle
Revises: 0016_session_observability
"""
from __future__ import annotations

import uuid

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from alembic import op

revision = "0017_password_lifecycle"
down_revision = "0016_session_observability"
branch_labels = None
depends_on = None


_SETTINGS_NAMESPACE = uuid.UUID("90ba4bb7-95c4-42d1-b355-1a26b98a7b91")
_NEW_SETTINGS = (
    ("auth.password.history_count", {"value": 5}, "Number of previous password hashes blocked from reuse."),
    ("auth.password.min_edit_distance", {"value": 3}, "Minimum edit distance from the current password when the current secret is available."),
    ("auth.password.max_age_days", {"value": 0}, "Maximum password age in days; 0 disables periodic expiration."),
    ("auth.password.expiry_warning_days", {"value": 14}, "Warning window before password expiration."),
    ("auth.session_online_window_minutes", {"value": 5}, "Recent-activity window used to classify active sessions as online."),
)


def _columns(table: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table)}


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _indexes(table: str) -> set[str]:
    return {index["name"] for index in sa.inspect(op.get_bind()).get_indexes(table)}


def upgrade() -> None:
    bind = op.get_bind()

    # Adopt the newly agreed moderate local-system defaults without clobbering
    # administrators who already customized these two legacy settings.
    bind.execute(
        sa.text(
            """
            UPDATE system_settings
            SET value = CAST(:new_value AS jsonb),
                description = 'Minimum password length.'
            WHERE key = 'auth.password.min_length'
              AND value = CAST(:old_value AS jsonb)
            """
        ),
        {"new_value": '{"value": 8}', "old_value": '{"value": 12}'},
    )
    bind.execute(
        sa.text(
            """
            UPDATE system_settings
            SET value = CAST(:new_value AS jsonb),
                description = 'Require uppercase, lowercase, number, and symbol characters.'
            WHERE key = 'auth.password.require_complexity'
              AND value = CAST(:old_value AS jsonb)
            """
        ),
        {"new_value": '{"value": true}', "old_value": '{"value": false}'},
    )

    insert_setting = sa.text(
        """
        INSERT INTO system_settings (id, key, value, description, is_secret)
        VALUES (:id, :key, :value, :description, false)
        ON CONFLICT (key) DO NOTHING
        """
    ).bindparams(sa.bindparam("value", type_=JSONB))
    for key, value, description in _NEW_SETTINGS:
        bind.execute(
            insert_setting,
            {
                "id": uuid.uuid5(_SETTINGS_NAMESPACE, key),
                "key": key,
                "value": value,
                "description": description,
            },
        )

    columns = _columns("users")
    if "must_change_password" not in columns:
        op.add_column(
            "users",
            sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.false()),
        )
    if "password_change_reason" not in columns:
        op.add_column("users", sa.Column("password_change_reason", sa.String(length=40), nullable=True))
    if "password_changed_at" not in columns:
        op.add_column("users", sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True))

    # Existing accounts are explicitly grandfathered: deployment must not force
    # all current operators through the first-login flow. The timestamp starts
    # their optional aging clock from this migration if aging is later enabled.
    op.execute(sa.text("UPDATE users SET must_change_password = FALSE WHERE must_change_password IS NULL"))
    op.execute(
        sa.text(
            "UPDATE users SET password_changed_at = COALESCE(password_changed_at, CURRENT_TIMESTAMP) "
            "WHERE password_hash IS NOT NULL"
        )
    )

    if "password_history" not in _tables():
        op.create_table(
            "password_history",
            sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("password_hash", sa.String(length=512), nullable=False),
        )
    if "ix_password_history_user_created" not in _indexes("password_history"):
        op.create_index(
            "ix_password_history_user_created",
            "password_history",
            ["user_id", "created_at"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(
        sa.text("DELETE FROM system_settings WHERE key IN :keys").bindparams(
            sa.bindparam("keys", expanding=True, value=[key for key, _, _ in _NEW_SETTINGS])
        )
    )
    bind.execute(
        sa.text(
            """
            UPDATE system_settings
            SET value = CAST(:old_value AS jsonb)
            WHERE key = 'auth.password.min_length'
              AND value = CAST(:new_value AS jsonb)
            """
        ),
        {"old_value": '{"value": 12}', "new_value": '{"value": 8}'},
    )
    bind.execute(
        sa.text(
            """
            UPDATE system_settings
            SET value = CAST(:old_value AS jsonb)
            WHERE key = 'auth.password.require_complexity'
              AND value = CAST(:new_value AS jsonb)
            """
        ),
        {"old_value": '{"value": false}', "new_value": '{"value": true}'},
    )

    if "password_history" in _tables():
        if "ix_password_history_user_created" in _indexes("password_history"):
            op.drop_index("ix_password_history_user_created", table_name="password_history")
        op.drop_table("password_history")

    columns = _columns("users")
    for name in ("password_changed_at", "password_change_reason", "must_change_password"):
        if name in columns:
            op.drop_column("users", name)
            columns.remove(name)
