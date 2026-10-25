"""Add per-device legacy Web-GUI TLS certificate compatibility.

Revision ID: 0033_web_tls_compat
Revises: 0032_web_gui_proxy
"""

from alembic import op
import sqlalchemy as sa


revision = "0033_web_tls_compat"
down_revision = "0032_web_gui_proxy"
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
    if "web_tls_compat_profile" not in columns:
        op.add_column(
            "device_remote_access_profiles",
            sa.Column("web_tls_compat_profile", sa.String(32), nullable=False, server_default="MODERN"),
        )

    inspector = sa.inspect(bind)
    checks = _checks(inspector)
    definitions = [
        (
            "ck_device_remote_access_profiles_web_tls_compat_profile",
            "web_tls_compat_profile IN ('MODERN','LEGACY_WEAK_CERT_KEY')",
        ),
        (
            "ck_device_remote_access_profiles_web_tls_legacy_pin",
            "web_tls_compat_profile = 'MODERN' OR "
            "(web_scheme = 'HTTPS' AND web_tls_mode = 'PINNED_CERT')",
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
        "ck_device_remote_access_profiles_web_tls_legacy_pin",
        "ck_device_remote_access_profiles_web_tls_compat_profile",
    ]:
        if name in checks:
            op.drop_constraint(name, "device_remote_access_profiles", type_="check")
    inspector = sa.inspect(bind)
    if "web_tls_compat_profile" in _columns(inspector):
        op.drop_column("device_remote_access_profiles", "web_tls_compat_profile")
