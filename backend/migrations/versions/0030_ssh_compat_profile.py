"""Add explicit per-device SSH compatibility profile.

Revision ID: 0030_ssh_compat_profile
Revises: 0029_remote_access_gateway
"""

from alembic import op
import sqlalchemy as sa


revision = "0030_ssh_compat_profile"
down_revision = "0029_remote_access_gateway"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("device_remote_access_profiles"):
        return

    columns = {column["name"] for column in inspector.get_columns("device_remote_access_profiles")}
    if "ssh_compatibility_profile" not in columns:
        op.add_column(
            "device_remote_access_profiles",
            sa.Column(
                "ssh_compatibility_profile",
                sa.String(length=40),
                nullable=False,
                server_default="MODERN",
            ),
        )

    inspector = sa.inspect(bind)
    checks = {item["name"] for item in inspector.get_check_constraints("device_remote_access_profiles")}
    if "ck_device_remote_access_profiles_ssh_compatibility" not in checks:
        op.create_check_constraint(
            "ck_device_remote_access_profiles_ssh_compatibility",
            "device_remote_access_profiles",
            "ssh_compatibility_profile IN ('MODERN','LEGACY_SSH_RSA_DH1_CBC')",
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("device_remote_access_profiles"):
        return
    checks = {item["name"] for item in inspector.get_check_constraints("device_remote_access_profiles")}
    if "ck_device_remote_access_profiles_ssh_compatibility" in checks:
        op.drop_constraint(
            "ck_device_remote_access_profiles_ssh_compatibility",
            "device_remote_access_profiles",
            type_="check",
        )
    columns = {column["name"] for column in inspector.get_columns("device_remote_access_profiles")}
    if "ssh_compatibility_profile" in columns:
        op.drop_column("device_remote_access_profiles", "ssh_compatibility_profile")
