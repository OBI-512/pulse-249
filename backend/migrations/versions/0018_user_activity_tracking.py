"""Separate human user activity from session/network liveness.

Revision ID: 0018_user_activity_tracking
Revises: 0017_password_lifecycle
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0018_user_activity_tracking"
down_revision = "0017_password_lifecycle"
branch_labels = None
depends_on = None


def _columns(table: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table)}


def _indexes(table: str) -> set[str]:
    return {index["name"] for index in sa.inspect(op.get_bind()).get_indexes(table)}


def upgrade() -> None:
    columns = _columns("auth_sessions")
    if "last_user_activity_at" not in columns:
        op.add_column(
            "auth_sessions",
            sa.Column("last_user_activity_at", sa.DateTime(timezone=True), nullable=True),
        )

    # Grandfather current sessions without making every existing operator look
    # idle immediately after deployment. Future status calculations use only
    # this human-activity field; keep-alive traffic continues to update
    # last_seen_at separately.
    op.execute(
        sa.text(
            "UPDATE auth_sessions "
            "SET last_user_activity_at = COALESCE(last_user_activity_at, last_seen_at, created_at) "
            "WHERE last_user_activity_at IS NULL"
        )
    )

    if "ix_auth_sessions_user_activity" not in _indexes("auth_sessions"):
        op.create_index(
            "ix_auth_sessions_user_activity",
            "auth_sessions",
            ["last_user_activity_at"],
        )


def downgrade() -> None:
    if "ix_auth_sessions_user_activity" in _indexes("auth_sessions"):
        op.drop_index("ix_auth_sessions_user_activity", table_name="auth_sessions")
    if "last_user_activity_at" in _columns("auth_sessions"):
        op.drop_column("auth_sessions", "last_user_activity_at")
