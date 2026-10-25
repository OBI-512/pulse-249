"""Allow protocol-default Web-GUI management ports.

Revision ID: 0037_web_management_port
Revises: 0036_config_foundation
"""

from alembic import op
import sqlalchemy as sa


revision = "0037_web_management_port"
down_revision = "0036_config_foundation"
branch_labels = None
depends_on = None


TABLE = "device_remote_access_profiles"
COLUMN = "web_port"


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table(TABLE):
        return
    columns = {column["name"]: column for column in inspector.get_columns(TABLE)}
    column = columns.get(COLUMN)
    if column is None:
        return
    if not column["nullable"] or column.get("default") is not None:
        op.alter_column(
            TABLE,
            COLUMN,
            existing_type=sa.Integer(),
            nullable=True,
            server_default=None,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table(TABLE):
        return
    columns = {column["name"]: column for column in inspector.get_columns(TABLE)}
    if COLUMN not in columns:
        return
    op.execute(
        "UPDATE device_remote_access_profiles "
        "SET web_port = CASE WHEN web_scheme = 'HTTP' THEN 80 ELSE 443 END "
        "WHERE web_port IS NULL"
    )
    op.alter_column(
        TABLE,
        COLUMN,
        existing_type=sa.Integer(),
        nullable=False,
        server_default="443",
    )
