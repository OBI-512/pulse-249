"""Access Templates credential and assignment foundation.

Revision ID: 0038_access_templates
Revises: 0037_web_management_port
"""
from __future__ import annotations

import uuid

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0038_access_templates"
down_revision = "0037_web_management_port"
branch_labels = None
depends_on = None

_NAMESPACE = uuid.UUID("3d7c4878-0f0f-4f50-b48a-7b6bd2727382")
_PERMISSIONS = (
    ("access_template.read", "Access Template Read"),
    ("access_template.manage", "Access Template Manage"),
    ("access_template.test", "Access Template Test"),
    ("device.remote_access.telnet", "Device Remote Access Telnet"),
)


def _id(key: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, key)


def _common_columns():
    return (
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def _ensure_permission_catalog() -> None:
    bind = op.get_bind()
    for code, name in _PERMISSIONS:
        bind.execute(
            sa.text(
                """
                INSERT INTO permissions (id, code, name, description)
                VALUES (:id, :code, :name, :description)
                ON CONFLICT (code) DO UPDATE
                SET name = EXCLUDED.name, description = EXCLUDED.description
                """
            ),
            {"id": _id(f"perm:{code}"), "code": code, "name": name, "description": f"{name} permission"},
        )
        bind.execute(
            sa.text(
                """
                INSERT INTO role_permissions (id, role_id, permission_id)
                SELECT :id, roles.id, permissions.id
                FROM roles CROSS JOIN permissions
                WHERE roles.code = 'administrator' AND permissions.code = :code
                ON CONFLICT (role_id, permission_id) DO NOTHING
                """
            ),
            {"id": _id(f"roleperm:administrator:{code}"), "code": code},
        )


def _extend_runtime_contracts() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("device_remote_access_profiles"):
        # Reusable SSH Access Templates own credentials, while this per-device
        # profile remains the authoritative SSH enable switch and host-key pin.
        op.drop_constraint(
            "ck_device_remote_access_profiles_ssh_ready",
            "device_remote_access_profiles",
            type_="check",
        )
        op.create_check_constraint(
            "ck_device_remote_access_profiles_ssh_ready",
            "device_remote_access_profiles",
            "(ssh_enabled = false) OR ssh_host_key_fingerprint IS NOT NULL",
        )

    inspector = sa.inspect(bind)
    if inspector.has_table("remote_access_sessions"):
        op.drop_constraint("ck_remote_access_sessions_mode", "remote_access_sessions", type_="check")
        op.create_check_constraint(
            "ck_remote_access_sessions_mode",
            "remote_access_sessions",
            "mode IN ('SSH','TELNET','WEB')",
        )

    inspector = sa.inspect(bind)
    if inspector.has_table("configuration_template_versions"):
        op.drop_constraint(
            "ck_configuration_template_versions_transport",
            "configuration_template_versions",
            type_="check",
        )
        op.create_check_constraint(
            "ck_configuration_template_versions_transport",
            "configuration_template_versions",
            "transport IN ('SSH_CLI','TELNET_CLI','HTTP_API','NETCONF','RESTCONF','VENDOR_API','OTHER')",
        )

    inspector = sa.inspect(bind)
    if inspector.has_table("device_configuration_bindings"):
        op.drop_constraint(
            "ck_device_configuration_bindings_credential_source",
            "device_configuration_bindings",
            type_="check",
        )
        op.drop_constraint(
            "ck_device_configuration_bindings_credential_reference",
            "device_configuration_bindings",
            type_="check",
        )
        op.create_check_constraint(
            "ck_device_configuration_bindings_credential_source",
            "device_configuration_bindings",
            "credential_source IN ('REMOTE_ACCESS_PROFILE','ENV_REFERENCE','ACCESS_TEMPLATE')",
        )
        op.create_check_constraint(
            "ck_device_configuration_bindings_credential_reference",
            "device_configuration_bindings",
            "(credential_source IN ('REMOTE_ACCESS_PROFILE','ACCESS_TEMPLATE') AND credential_reference IS NULL) OR "
            "(credential_source = 'ENV_REFERENCE' AND credential_reference LIKE 'env://%')",
        )


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("access_templates"):
        op.create_table(
            "access_templates",
            *_common_columns(),
            sa.Column("name", sa.String(160), nullable=False),
            sa.Column("description", sa.Text()),
            sa.Column("protocol", sa.String(20), nullable=False),
            sa.Column("protocol_variant", sa.String(40)),
            sa.Column("visibility", sa.String(20), nullable=False, server_default="PRIVATE"),
            sa.Column("owner_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("settings", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("deleted_at", sa.DateTime(timezone=True)),
            sa.CheckConstraint("protocol IN ('SNMP','SSH','TELNET')", name="ck_access_templates_protocol"),
            sa.CheckConstraint("visibility IN ('PRIVATE','SHARED')", name="ck_access_templates_visibility"),
        )
        op.create_index(
            "uq_active_access_templates_owner_name_protocol", "access_templates",
            ["owner_user_id", "name", "protocol"], unique=True,
            postgresql_where=sa.text("deleted_at IS NULL"),
        )
        op.create_index(
            "ix_access_templates_protocol_active", "access_templates", ["protocol", "is_active"],
            postgresql_where=sa.text("deleted_at IS NULL"),
        )
        op.create_index(
            "ix_access_templates_owner_visibility", "access_templates", ["owner_user_id", "visibility"],
            postgresql_where=sa.text("deleted_at IS NULL"),
        )

    inspector = sa.inspect(bind)
    if not inspector.has_table("access_template_secrets"):
        op.create_table(
            "access_template_secrets",
            *_common_columns(),
            sa.Column("template_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("access_templates.id", ondelete="CASCADE"), nullable=False),
            sa.Column("secret_key", sa.String(80), nullable=False),
            sa.Column("provider", sa.String(30), nullable=False),
            sa.Column("encrypted_payload", sa.Text()),
            sa.Column("reference", sa.String(255)),
            sa.Column("key_version", sa.Integer(), nullable=False, server_default="1"),
            sa.UniqueConstraint("template_id", "secret_key", name="uq_access_template_secrets_key"),
            sa.CheckConstraint("provider IN ('ENCRYPTED_DATABASE','ENV_REFERENCE')", name="ck_access_template_secrets_provider"),
            sa.CheckConstraint(
                "(provider = 'ENCRYPTED_DATABASE' AND encrypted_payload IS NOT NULL AND reference IS NULL) OR "
                "(provider = 'ENV_REFERENCE' AND encrypted_payload IS NULL AND reference LIKE 'env://%')",
                name="ck_access_template_secrets_storage",
            ),
            sa.CheckConstraint("key_version >= 1", name="ck_access_template_secrets_key_version"),
        )
        op.create_index("ix_access_template_secrets_template", "access_template_secrets", ["template_id"])

    inspector = sa.inspect(bind)
    if not inspector.has_table("access_template_assignments"):
        op.create_table(
            "access_template_assignments",
            *_common_columns(),
            sa.Column("template_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("access_templates.id", ondelete="CASCADE"), nullable=False),
            sa.Column("scope_type", sa.String(30), nullable=False),
            sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE")),
            sa.Column("group_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("device_groups.id", ondelete="CASCADE")),
            sa.Column("sector_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("sectors.id", ondelete="CASCADE")),
            sa.Column("location_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("locations.id", ondelete="CASCADE")),
            sa.Column("network_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("networks.id", ondelete="CASCADE")),
            sa.Column("city_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("cities.id", ondelete="CASCADE")),
            sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
            sa.CheckConstraint(
                "scope_type IN ('DEVICE','DEVICE_GROUP','LOGICAL_SECTOR','LOCATION','NETWORK','CITY')",
                name="ck_access_template_assignments_scope_type",
            ),
            sa.CheckConstraint(
                "(scope_type = 'DEVICE' AND device_id IS NOT NULL AND group_id IS NULL AND sector_id IS NULL AND location_id IS NULL AND network_id IS NULL AND city_id IS NULL) OR "
                "(scope_type = 'DEVICE_GROUP' AND device_id IS NULL AND group_id IS NOT NULL AND sector_id IS NULL AND location_id IS NULL AND network_id IS NULL AND city_id IS NULL) OR "
                "(scope_type = 'LOGICAL_SECTOR' AND device_id IS NULL AND group_id IS NULL AND sector_id IS NOT NULL AND location_id IS NULL AND network_id IS NULL AND city_id IS NULL) OR "
                "(scope_type = 'LOCATION' AND device_id IS NULL AND group_id IS NULL AND sector_id IS NULL AND location_id IS NOT NULL AND network_id IS NULL AND city_id IS NULL) OR "
                "(scope_type = 'NETWORK' AND device_id IS NULL AND group_id IS NULL AND sector_id IS NULL AND location_id IS NULL AND network_id IS NOT NULL AND city_id IS NULL) OR "
                "(scope_type = 'CITY' AND device_id IS NULL AND group_id IS NULL AND sector_id IS NULL AND location_id IS NULL AND network_id IS NULL AND city_id IS NOT NULL)",
                name="ck_access_template_assignments_target",
            ),
        )
        op.create_index("ix_access_template_assignments_template_enabled", "access_template_assignments", ["template_id", "enabled"])
        for suffix, column in (("device", "device_id"), ("group", "group_id"), ("sector", "sector_id"), ("location", "location_id"), ("network", "network_id"), ("city", "city_id")):
            op.create_index(
                f"ix_access_template_assignments_{suffix}", "access_template_assignments", [column],
                postgresql_where=sa.text(f"{column} IS NOT NULL"),
            )

    inspector = sa.inspect(bind)
    if not inspector.has_table("access_template_test_results"):
        op.create_table(
            "access_template_test_results",
            *_common_columns(),
            sa.Column("template_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("access_templates.id", ondelete="CASCADE"), nullable=False),
            sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("failure_code", sa.String(120)),
            sa.Column("sanitized_message", sa.Text()),
            sa.Column("latency_ms", sa.Integer()),
            sa.Column("tested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("tested_by_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
            sa.CheckConstraint("status IN ('SUCCESS','FAILED')", name="ck_access_template_test_results_status"),
            sa.CheckConstraint("latency_ms IS NULL OR latency_ms >= 0", name="ck_access_template_test_results_latency"),
        )
        op.create_index(
            "ix_access_template_test_results_template_device_tested", "access_template_test_results",
            ["template_id", "device_id", "tested_at"],
        )

    _extend_runtime_contracts()
    _ensure_permission_catalog()


def _assert_runtime_downgrade_safe(bind) -> None:
    checks = (
        ("remote_access_sessions", "mode = 'TELNET'", "Telnet remote-access sessions"),
        ("configuration_template_versions", "transport = 'TELNET_CLI'", "Telnet configuration templates"),
        ("device_configuration_bindings", "credential_source = 'ACCESS_TEMPLATE'", "Access-Template configuration bindings"),
        (
            "device_remote_access_profiles",
            "ssh_enabled = true AND (ssh_username_reference IS NULL OR (ssh_password_reference IS NULL AND ssh_private_key_reference IS NULL))",
            "SSH profiles relying on Access Template credentials",
        ),
    )
    inspector = sa.inspect(bind)
    for table, where, label in checks:
        if not inspector.has_table(table):
            continue
        count = int(bind.execute(sa.text(f"SELECT count(*) FROM {table} WHERE {where}")).scalar_one())
        if count:
            raise RuntimeError(
                f"0038 downgrade refused: {label} exist. Remove or migrate feature data before downgrade."
            )


def _restore_runtime_contracts(bind) -> None:
    inspector = sa.inspect(bind)
    if inspector.has_table("device_configuration_bindings"):
        op.drop_constraint(
            "ck_device_configuration_bindings_credential_reference",
            "device_configuration_bindings",
            type_="check",
        )
        op.drop_constraint(
            "ck_device_configuration_bindings_credential_source",
            "device_configuration_bindings",
            type_="check",
        )
        op.create_check_constraint(
            "ck_device_configuration_bindings_credential_source",
            "device_configuration_bindings",
            "credential_source IN ('REMOTE_ACCESS_PROFILE','ENV_REFERENCE')",
        )
        op.create_check_constraint(
            "ck_device_configuration_bindings_credential_reference",
            "device_configuration_bindings",
            "(credential_source = 'REMOTE_ACCESS_PROFILE' AND credential_reference IS NULL) OR "
            "(credential_source = 'ENV_REFERENCE' AND credential_reference LIKE 'env://%')",
        )

    inspector = sa.inspect(bind)
    if inspector.has_table("configuration_template_versions"):
        op.drop_constraint(
            "ck_configuration_template_versions_transport",
            "configuration_template_versions",
            type_="check",
        )
        op.create_check_constraint(
            "ck_configuration_template_versions_transport",
            "configuration_template_versions",
            "transport IN ('SSH_CLI','HTTP_API','NETCONF','RESTCONF','VENDOR_API','OTHER')",
        )

    inspector = sa.inspect(bind)
    if inspector.has_table("remote_access_sessions"):
        op.drop_constraint("ck_remote_access_sessions_mode", "remote_access_sessions", type_="check")
        op.create_check_constraint(
            "ck_remote_access_sessions_mode",
            "remote_access_sessions",
            "mode IN ('SSH','WEB')",
        )

    inspector = sa.inspect(bind)
    if inspector.has_table("device_remote_access_profiles"):
        op.drop_constraint(
            "ck_device_remote_access_profiles_ssh_ready",
            "device_remote_access_profiles",
            type_="check",
        )
        op.create_check_constraint(
            "ck_device_remote_access_profiles_ssh_ready",
            "device_remote_access_profiles",
            "(ssh_enabled = false) OR "
            "(ssh_username_reference IS NOT NULL AND ssh_host_key_fingerprint IS NOT NULL AND "
            "(ssh_password_reference IS NOT NULL OR ssh_private_key_reference IS NOT NULL))",
        )


def downgrade() -> None:
    bind = op.get_bind()
    _assert_runtime_downgrade_safe(bind)
    _restore_runtime_contracts(bind)

    for table in ("access_template_test_results", "access_template_assignments", "access_template_secrets", "access_templates"):
        if sa.inspect(bind).has_table(table):
            op.drop_table(table)

    for code, _name in _PERMISSIONS:
        bind.execute(sa.text("DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE code = :code)"), {"code": code})
        bind.execute(sa.text("DELETE FROM user_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE code = :code)"), {"code": code})
        bind.execute(sa.text("DELETE FROM permissions WHERE code = :code"), {"code": code})
