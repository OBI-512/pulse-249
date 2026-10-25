"""Phase F1 vendor-neutral configuration foundation.

Revision ID: 0036_config_foundation
Revises: 0035_remove_web_tls10_compat
"""
from __future__ import annotations

import uuid

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0036_config_foundation"
down_revision = "0035_remove_web_tls10_compat"
branch_labels = None
depends_on = None

_NAMESPACE = uuid.UUID("d5f7976a-09ee-4ab8-8f08-c6d2bcbb19b2")
_PERMISSIONS = (
    ("device.configuration.read", "Device Configuration Read"),
    ("device.configuration.capture", "Device Configuration Capture"),
    ("device.configuration.apply", "Device Configuration Apply"),
    ("device.configuration.restore", "Device Configuration Restore"),
    ("device.configuration.template.read", "Device Configuration Template Read"),
    ("device.configuration.template.manage", "Device Configuration Template Manage"),
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
        # Fail closed by default: only Administrator receives newly introduced
        # configuration authority. Other roles require deliberate grants.
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


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    # 0001 materializes current SQLAlchemy metadata on a clean installation.
    # Live upgrades from 0035 do not have these Phase-F tables yet.
    if not inspector.has_table("configuration_templates"):
        op.create_table(
            "configuration_templates",
            *_common_columns(),
            sa.Column("code", sa.String(80), nullable=False),
            sa.Column("name", sa.String(160), nullable=False),
            sa.Column("vendor", sa.String(100), nullable=False),
            sa.Column("model", sa.String(150)),
            sa.Column("series", sa.String(150)),
            sa.Column("device_type_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("device_types.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("description", sa.Text()),
            sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.UniqueConstraint("code", name="uq_configuration_templates_code"),
        )
        op.create_index("ix_configuration_templates_vendor_model", "configuration_templates", ["vendor", "model", "series"])
        op.create_index("ix_configuration_templates_type_active", "configuration_templates", ["device_type_id", "is_active"])

    inspector = sa.inspect(bind)
    if not inspector.has_table("configuration_template_versions"):
        op.create_table(
            "configuration_template_versions",
            *_common_columns(),
            sa.Column("template_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("configuration_templates.id", ondelete="CASCADE"), nullable=False),
            sa.Column("version_number", sa.Integer(), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, server_default="DRAFT"),
            sa.Column("adapter_key", sa.String(120), nullable=False),
            sa.Column("transport", sa.String(30), nullable=False),
            sa.Column("capabilities", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
            sa.Column("parameter_schema", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("transport_parameters", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("content_sha256", sa.String(64)),
            sa.Column("published_at", sa.DateTime(timezone=True)),
            sa.Column("published_by_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
            sa.Column("change_note", sa.Text()),
            sa.UniqueConstraint("template_id", "version_number", name="uq_configuration_template_versions_number"),
            sa.CheckConstraint("status IN ('DRAFT','PUBLISHED','RETIRED')", name="ck_configuration_template_versions_status"),
            sa.CheckConstraint("transport IN ('SSH_CLI','HTTP_API','NETCONF','RESTCONF','VENDOR_API','OTHER')", name="ck_configuration_template_versions_transport"),
            sa.CheckConstraint("version_number >= 1", name="ck_configuration_template_versions_number"),
            sa.CheckConstraint("status <> 'PUBLISHED' OR (content_sha256 IS NOT NULL AND published_at IS NOT NULL)", name="ck_configuration_template_versions_publish_ready"),
        )
        op.create_index("ix_configuration_template_versions_template_status", "configuration_template_versions", ["template_id", "status"])
        op.create_index("uq_configuration_template_versions_published", "configuration_template_versions", ["template_id"], unique=True, postgresql_where=sa.text("status = 'PUBLISHED'"))

    inspector = sa.inspect(bind)
    if not inspector.has_table("configuration_functions"):
        op.create_table(
            "configuration_functions",
            *_common_columns(),
            sa.Column("template_version_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("configuration_template_versions.id", ondelete="CASCADE"), nullable=False),
            sa.Column("code", sa.String(80), nullable=False),
            sa.Column("name", sa.String(160), nullable=False),
            sa.Column("category", sa.String(60), nullable=False, server_default="CUSTOM"),
            sa.Column("description", sa.Text()),
            sa.Column("parameter_schema", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("execution_spec", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("verification_spec", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("rollback_spec", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("required_capabilities", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
            sa.Column("default_order", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("is_destructive", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.UniqueConstraint("template_version_id", "code", name="uq_configuration_functions_version_code"),
            sa.CheckConstraint("default_order >= 0", name="ck_configuration_functions_default_order"),
        )
        op.create_index("ix_configuration_functions_version_order", "configuration_functions", ["template_version_id", "default_order"])

    inspector = sa.inspect(bind)
    if not inspector.has_table("device_configuration_bindings"):
        op.create_table(
            "device_configuration_bindings",
            *_common_columns(),
            sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
            sa.Column("template_version_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("configuration_template_versions.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("credential_source", sa.String(30), nullable=False, server_default="REMOTE_ACCESS_PROFILE"),
            sa.Column("credential_reference", sa.String(255)),
            sa.Column("connection_overrides", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("bound_by_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
            sa.Column("bound_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.UniqueConstraint("device_id", name="uq_device_configuration_bindings_device"),
            sa.CheckConstraint("credential_source IN ('REMOTE_ACCESS_PROFILE','ENV_REFERENCE')", name="ck_device_configuration_bindings_credential_source"),
            sa.CheckConstraint("(credential_source = 'REMOTE_ACCESS_PROFILE' AND credential_reference IS NULL) OR (credential_source = 'ENV_REFERENCE' AND credential_reference LIKE 'env://%')", name="ck_device_configuration_bindings_credential_reference"),
        )
        op.create_index("ix_device_configuration_bindings_version_enabled", "device_configuration_bindings", ["template_version_id", "enabled"])

    inspector = sa.inspect(bind)
    if not inspector.has_table("configuration_snapshots"):
        op.create_table(
            "configuration_snapshots",
            *_common_columns(),
            sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
            sa.Column("template_version_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("configuration_template_versions.id", ondelete="SET NULL")),
            sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
            sa.Column("snapshot_kind", sa.String(20), nullable=False),
            sa.Column("adapter_key", sa.String(120), nullable=False),
            sa.Column("artifact_status", sa.String(20), nullable=False, server_default="PENDING"),
            sa.Column("artifact_path", sa.Text()),
            sa.Column("artifact_sha256", sa.String(64)),
            sa.Column("plaintext_sha256", sa.String(64)),
            sa.Column("normalized_sha256", sa.String(64)),
            sa.Column("artifact_size_bytes", sa.Integer()),
            sa.Column("encryption_scheme", sa.String(40)),
            sa.Column("encryption_key_reference", sa.String(255)),
            sa.Column("is_restorable", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.CheckConstraint("snapshot_kind IN ('CAPTURE','PRE_CHANGE','POST_CHANGE','ROLLBACK','CANDIDATE')", name="ck_configuration_snapshots_kind"),
            sa.CheckConstraint("artifact_status IN ('PENDING','READY','FAILED')", name="ck_configuration_snapshots_artifact_status"),
            sa.CheckConstraint("artifact_size_bytes IS NULL OR artifact_size_bytes >= 0", name="ck_configuration_snapshots_artifact_size"),
            sa.CheckConstraint("encryption_scheme IS NULL OR encryption_scheme = 'AES_256_GCM'", name="ck_configuration_snapshots_encryption_scheme"),
            sa.CheckConstraint("encryption_key_reference IS NULL OR encryption_key_reference LIKE 'env://%'", name="ck_configuration_snapshots_encryption_key_reference"),
            sa.CheckConstraint("(artifact_status <> 'READY') OR (artifact_path IS NOT NULL AND artifact_sha256 IS NOT NULL AND artifact_size_bytes IS NOT NULL AND encryption_scheme IS NOT NULL AND encryption_key_reference LIKE 'env://%')", name="ck_configuration_snapshots_ready_artifact"),
            sa.CheckConstraint("(is_restorable = false) OR artifact_status = 'READY'", name="ck_configuration_snapshots_restorable_ready"),
        )
        op.create_index("ix_configuration_snapshots_device_created", "configuration_snapshots", ["device_id", "created_at"])
        op.create_index("ix_configuration_snapshots_device_kind", "configuration_snapshots", ["device_id", "snapshot_kind"])

    inspector = sa.inspect(bind)
    if not inspector.has_table("configuration_operations"):
        op.create_table(
            "configuration_operations",
            *_common_columns(),
            sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
            sa.Column("template_version_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("configuration_template_versions.id", ondelete="SET NULL")),
            sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
            sa.Column("operation_type", sa.String(20), nullable=False),
            sa.Column("status", sa.String(24), nullable=False, server_default="QUEUED"),
            sa.Column("idempotency_key", sa.String(128)),
            sa.Column("pre_change_snapshot_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("configuration_snapshots.id", ondelete="SET NULL")),
            sa.Column("candidate_snapshot_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("configuration_snapshots.id", ondelete="SET NULL")),
            sa.Column("result_snapshot_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("configuration_snapshots.id", ondelete="SET NULL")),
            sa.Column("rollback_snapshot_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("configuration_snapshots.id", ondelete="SET NULL")),
            sa.Column("authorization_scope", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("authorization_scope_fingerprint", sa.String(64)),
            sa.Column("request_summary", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("verification_summary", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("failure_stage", sa.String(30)),
            sa.Column("failure_code", sa.String(120)),
            sa.Column("failure_message", sa.Text()),
            sa.Column("started_at", sa.DateTime(timezone=True)),
            sa.Column("finished_at", sa.DateTime(timezone=True)),
            sa.CheckConstraint("operation_type IN ('CAPTURE','APPLY','VERIFY','RESTORE')", name="ck_configuration_operations_type"),
            sa.CheckConstraint("status IN ('QUEUED','RUNNING','SUCCEEDED','FAILED','ROLLING_BACK','ROLLED_BACK','ROLLBACK_FAILED','CANCELLED')", name="ck_configuration_operations_status"),
            sa.CheckConstraint("failure_stage IS NULL OR failure_stage IN ('AUTHORIZATION','VALIDATION','TRANSPORT','DEVICE_REJECTION','VERIFICATION','ROLLBACK','INTERNAL')", name="ck_configuration_operations_failure_stage"),
        )
        op.create_index("ix_configuration_operations_device_created", "configuration_operations", ["device_id", "created_at"])
        op.create_index("ix_configuration_operations_status_created", "configuration_operations", ["status", "created_at"])
        op.create_index("uq_configuration_operations_active_device", "configuration_operations", ["device_id"], unique=True, postgresql_where=sa.text("status IN ('QUEUED','RUNNING','ROLLING_BACK')"))
        op.create_index("uq_configuration_operations_actor_idempotency", "configuration_operations", ["actor_user_id", "device_id", "idempotency_key"], unique=True, postgresql_where=sa.text("idempotency_key IS NOT NULL"))

    inspector = sa.inspect(bind)
    if not inspector.has_table("configuration_operation_steps"):
        op.create_table(
            "configuration_operation_steps",
            *_common_columns(),
            sa.Column("operation_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("configuration_operations.id", ondelete="CASCADE"), nullable=False),
            sa.Column("function_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("configuration_functions.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("step_order", sa.Integer(), nullable=False),
            sa.Column("function_code_snapshot", sa.String(80), nullable=False),
            sa.Column("function_name_snapshot", sa.String(160), nullable=False),
            sa.Column("status", sa.String(24), nullable=False, server_default="PENDING"),
            sa.Column("parameter_summary", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("verification_summary", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("failure_code", sa.String(120)),
            sa.Column("failure_message", sa.Text()),
            sa.Column("started_at", sa.DateTime(timezone=True)),
            sa.Column("finished_at", sa.DateTime(timezone=True)),
            sa.UniqueConstraint("operation_id", "step_order", name="uq_configuration_operation_steps_order"),
            sa.CheckConstraint("step_order >= 0", name="ck_configuration_operation_steps_order"),
            sa.CheckConstraint("status IN ('PENDING','RUNNING','SUCCEEDED','FAILED','SKIPPED','ROLLING_BACK','ROLLED_BACK','ROLLBACK_FAILED')", name="ck_configuration_operation_steps_status"),
        )
        op.create_index("ix_configuration_operation_steps_operation_status", "configuration_operation_steps", ["operation_id", "status"])

    inspector = sa.inspect(bind)
    if not inspector.has_table("device_configuration_states"):
        op.create_table(
            "device_configuration_states",
            *_common_columns(),
            sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
            sa.Column("last_known_good_snapshot_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("configuration_snapshots.id", ondelete="SET NULL")),
            sa.Column("last_verified_snapshot_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("configuration_snapshots.id", ondelete="SET NULL")),
            sa.Column("last_operation_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("configuration_operations.id", ondelete="SET NULL")),
            sa.Column("drift_status", sa.String(20), nullable=False, server_default="UNKNOWN"),
            sa.Column("last_verified_at", sa.DateTime(timezone=True)),
            sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.UniqueConstraint("device_id", name="uq_device_configuration_states_device"),
            sa.CheckConstraint("drift_status IN ('UNKNOWN','IN_SYNC','DRIFTED','UNVERIFIED')", name="ck_device_configuration_states_drift_status"),
        )
        op.create_index("ix_device_configuration_states_drift", "device_configuration_states", ["drift_status"])

    _ensure_permission_catalog()


def downgrade() -> None:
    bind = op.get_bind()
    for table in (
        "device_configuration_states",
        "configuration_operation_steps",
        "configuration_operations",
        "configuration_snapshots",
        "device_configuration_bindings",
        "configuration_functions",
        "configuration_template_versions",
        "configuration_templates",
    ):
        if sa.inspect(bind).has_table(table):
            op.drop_table(table)

    codes = [code for code, _ in _PERMISSIONS]
    bind.execute(sa.text("DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE code IN :codes)").bindparams(sa.bindparam("codes", expanding=True, value=codes)))
    bind.execute(sa.text("DELETE FROM user_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE code IN :codes)").bindparams(sa.bindparam("codes", expanding=True, value=codes)))
    bind.execute(sa.text("DELETE FROM permissions WHERE code IN :codes").bindparams(sa.bindparam("codes", expanding=True, value=codes)))
