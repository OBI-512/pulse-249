"""Bind brokered Web sessions to the Access Template selected at ticket issue time.

Revision ID: 0040_remote_template_binding
Revises: 0039_web_access_templates
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0040_remote_template_binding"
down_revision = "0039_web_access_templates"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("remote_access_sessions") or not inspector.has_table("access_templates"):
        return
    columns = {column["name"] for column in inspector.get_columns("remote_access_sessions")}
    if "access_template_id" not in columns:
        op.add_column(
            "remote_access_sessions",
            sa.Column("access_template_id", sa.UUID(), nullable=True),
        )
        op.create_foreign_key(
            "fk_remote_access_sessions_access_template",
            "remote_access_sessions",
            "access_templates",
            ["access_template_id"],
            ["id"],
            ondelete="SET NULL",
        )
        op.create_index(
            "ix_remote_access_sessions_access_template",
            "remote_access_sessions",
            ["access_template_id"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("remote_access_sessions"):
        return
    columns = {column["name"] for column in inspector.get_columns("remote_access_sessions")}
    if "access_template_id" not in columns:
        return
    indexes = {item["name"] for item in inspector.get_indexes("remote_access_sessions")}
    if "ix_remote_access_sessions_access_template" in indexes:
        op.drop_index("ix_remote_access_sessions_access_template", table_name="remote_access_sessions")
    foreign_keys = {item.get("name") for item in inspector.get_foreign_keys("remote_access_sessions")}
    if "fk_remote_access_sessions_access_template" in foreign_keys:
        op.drop_constraint(
            "fk_remote_access_sessions_access_template",
            "remote_access_sessions",
            type_="foreignkey",
        )
    op.drop_column("remote_access_sessions", "access_template_id")
