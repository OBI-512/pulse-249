"""Allow WEB Access Templates for brokered GUI authentication.

Revision ID: 0039_web_access_templates
Revises: 0038_access_templates
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0039_web_access_templates"
down_revision = "0038_access_templates"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("access_templates"):
        return
    op.drop_constraint("ck_access_templates_protocol", "access_templates", type_="check")
    op.create_check_constraint(
        "ck_access_templates_protocol",
        "access_templates",
        "protocol IN ('SNMP','SSH','TELNET','WEB')",
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("access_templates"):
        return
    count = bind.execute(sa.text("SELECT COUNT(*) FROM access_templates WHERE protocol = 'WEB'"))
    if int(count.scalar_one()) > 0:
        raise RuntimeError("Cannot downgrade 0039 while WEB Access Templates exist.")
    op.drop_constraint("ck_access_templates_protocol", "access_templates", type_="check")
    op.create_check_constraint(
        "ck_access_templates_protocol",
        "access_templates",
        "protocol IN ('SNMP','SSH','TELNET')",
    )
