"""Add native Web-GUI proxy profile controls.

Revision ID: 0032_web_gui_proxy
Revises: 0031_operational_sync
"""

from alembic import op
import sqlalchemy as sa


revision = "0032_web_gui_proxy"
down_revision = "0031_operational_sync"
branch_labels = None
depends_on = None


def _columns(inspector):
    return {column["name"] for column in inspector.get_columns("device_remote_access_profiles")}


def _checks(inspector):
    return {item["name"] for item in inspector.get_check_constraints("device_remote_access_profiles")}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("device_remote_access_profiles"):
        return

    columns = _columns(inspector)
    additions = [
        ("web_enabled", sa.Column("web_enabled", sa.Boolean(), nullable=False, server_default=sa.false())),
        ("web_scheme", sa.Column("web_scheme", sa.String(8), nullable=False, server_default="HTTPS")),
        ("web_port", sa.Column("web_port", sa.Integer(), nullable=False, server_default="443")),
        ("web_tls_mode", sa.Column("web_tls_mode", sa.String(20), nullable=False, server_default="SYSTEM")),
        ("web_tls_ca_reference", sa.Column("web_tls_ca_reference", sa.String(255))),
        ("web_tls_pinned_certificate_reference", sa.Column("web_tls_pinned_certificate_reference", sa.String(255))),
    ]
    for name, column in additions:
        if name not in columns:
            op.add_column("device_remote_access_profiles", column)

    inspector = sa.inspect(bind)
    checks = _checks(inspector)
    definitions = [
        ("ck_device_remote_access_profiles_web_port", "web_port BETWEEN 1 AND 65535"),
        ("ck_device_remote_access_profiles_web_scheme", "web_scheme IN ('HTTP','HTTPS')"),
        ("ck_device_remote_access_profiles_web_tls_mode", "web_tls_mode IN ('SYSTEM','PRIVATE_CA','PINNED_CERT')"),
        (
            "ck_device_remote_access_profiles_web_ready",
            "(web_enabled = false) OR (web_scheme = 'HTTP') OR "
            "(web_scheme = 'HTTPS' AND (web_tls_mode = 'SYSTEM' OR "
            "(web_tls_mode = 'PRIVATE_CA' AND web_tls_ca_reference IS NOT NULL) OR "
            "(web_tls_mode = 'PINNED_CERT' AND web_tls_pinned_certificate_reference IS NOT NULL)))",
        ),
    ]
    for name, expression in definitions:
        if name not in checks:
            op.create_check_constraint(name, "device_remote_access_profiles", expression)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("device_remote_access_profiles"):
        return
    checks = _checks(inspector)
    for name in [
        "ck_device_remote_access_profiles_web_ready",
        "ck_device_remote_access_profiles_web_tls_mode",
        "ck_device_remote_access_profiles_web_scheme",
        "ck_device_remote_access_profiles_web_port",
    ]:
        if name in checks:
            op.drop_constraint(name, "device_remote_access_profiles", type_="check")
    inspector = sa.inspect(bind)
    columns = _columns(inspector)
    for name in [
        "web_tls_pinned_certificate_reference",
        "web_tls_ca_reference",
        "web_tls_mode",
        "web_port",
        "web_scheme",
        "web_enabled",
    ]:
        if name in columns:
            op.drop_column("device_remote_access_profiles", name)
