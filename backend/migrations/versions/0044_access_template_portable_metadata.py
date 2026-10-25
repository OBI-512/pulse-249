"""TP2 portable Access Template family metadata.

Revision ID: 0044_access_template_metadata
Revises: 0043_config_template_lifecycle

This migration is additive. It creates a non-runtime JSONB metadata location on
Access Template families so portable compatibility, qualification, and package
provenance never contaminate executable template settings.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0044_access_template_metadata"
down_revision = "0043_config_template_lifecycle"
branch_labels = None
depends_on = None


def _has_column(inspector, table_name: str, column_name: str) -> bool:
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not _has_column(inspector, "access_templates", "metadata"):
        op.add_column(
            "access_templates",
            sa.Column(
                "metadata",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _has_column(inspector, "access_templates", "metadata"):
        op.drop_column("access_templates", "metadata")
