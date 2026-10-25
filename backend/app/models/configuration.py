from __future__ import annotations

from datetime import datetime
from typing import Any
import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .core import Common


class ConfigurationTemplate(Common):
    """Stable identity for a vendor/model configuration template.

    Mutable authoring happens through version rows. Devices bind to an exact
    template version so later edits never silently change historical behavior.
    """

    __tablename__ = "configuration_templates"
    __table_args__ = (
        UniqueConstraint("code", name="uq_configuration_templates_code"),
        Index("ix_configuration_templates_vendor_model", "vendor", "model", "series"),
        Index("ix_configuration_templates_type_active", "device_type_id", "is_active"),
    )

    code: Mapped[str] = mapped_column(String(80), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    vendor: Mapped[str] = mapped_column(String(100), nullable=False)
    model: Mapped[str | None] = mapped_column(String(150))
    series: Mapped[str | None] = mapped_column(String(150))
    device_type_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("device_types.id", ondelete="RESTRICT"), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    description: Mapped[str | None] = mapped_column(Text)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )


class ConfigurationTemplateVersion(Common):
    """Versioned configuration definition with explicit test/approval lifecycle."""

    __tablename__ = "configuration_template_versions"
    __table_args__ = (
        UniqueConstraint("template_id", "version_number", name="uq_configuration_template_versions_number"),
        CheckConstraint(
            "status IN ('DRAFT','TESTED','APPROVED','PUBLISHED','RETIRED')",
            name="ck_configuration_template_versions_status",
        ),
        CheckConstraint(
            "transport IN ('SSH_CLI','TELNET_CLI','HTTP_API','NETCONF','RESTCONF','VENDOR_API','OTHER')",
            name="ck_configuration_template_versions_transport",
        ),
        CheckConstraint("version_number >= 1", name="ck_configuration_template_versions_number"),
        CheckConstraint(
            "tested_definition_sha256 IS NULL OR char_length(tested_definition_sha256) = 64",
            name="ck_configuration_template_versions_tested_hash",
        ),
        CheckConstraint(
            "status NOT IN ('TESTED','APPROVED','PUBLISHED') OR "
            "(tested_definition_sha256 IS NOT NULL AND tested_at IS NOT NULL)",
            name="ck_configuration_template_versions_test_ready",
        ),
        CheckConstraint(
            "status NOT IN ('APPROVED','PUBLISHED') OR approved_at IS NOT NULL",
            name="ck_configuration_template_versions_approval_ready",
        ),
        CheckConstraint(
            "status <> 'PUBLISHED' OR ("
            "content_sha256 IS NOT NULL AND published_at IS NOT NULL AND "
            "tested_definition_sha256 = content_sha256 AND approved_at IS NOT NULL)",
            name="ck_configuration_template_versions_publish_ready",
        ),
        CheckConstraint(
            "source_version_id IS NULL OR source_version_id <> id",
            name="ck_configuration_template_versions_source_not_self",
        ),
        Index("ix_configuration_template_versions_template_status", "template_id", "status"),
        Index("ix_configuration_template_versions_source", "source_version_id"),
        Index(
            "uq_configuration_template_versions_published",
            "template_id",
            unique=True,
            postgresql_where=text("status = 'PUBLISHED'"),
        ),
    )

    template_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("configuration_templates.id", ondelete="CASCADE"), nullable=False
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="DRAFT", server_default="DRAFT"
    )
    adapter_key: Mapped[str] = mapped_column(String(120), nullable=False)
    transport: Mapped[str] = mapped_column(String(30), nullable=False)
    capabilities: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    parameter_schema: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    transport_parameters: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    source_version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey(
            "configuration_template_versions.id",
            ondelete="SET NULL",
            name="fk_configuration_template_versions_source",
        )
    )
    tested_definition_sha256: Mapped[str | None] = mapped_column(String(64))
    tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
            name="fk_configuration_template_versions_tested_by",
        )
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
            name="fk_configuration_template_versions_approved_by",
        )
    )
    content_sha256: Mapped[str | None] = mapped_column(String(64))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    published_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    change_note: Mapped[str | None] = mapped_column(Text)


class ConfigurationFunction(Common):
    """One reusable operator-defined function/patch inside a template version."""

    __tablename__ = "configuration_functions"
    __table_args__ = (
        UniqueConstraint("template_version_id", "code", name="uq_configuration_functions_version_code"),
        CheckConstraint("default_order >= 0", name="ck_configuration_functions_default_order"),
        Index("ix_configuration_functions_version_order", "template_version_id", "default_order"),
    )

    template_version_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("configuration_template_versions.id", ondelete="CASCADE"), nullable=False
    )
    code: Mapped[str] = mapped_column(String(80), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    category: Mapped[str] = mapped_column(
        String(60), nullable=False, default="CUSTOM", server_default="CUSTOM"
    )
    description: Mapped[str | None] = mapped_column(Text)
    parameter_schema: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    execution_spec: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    verification_spec: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    rollback_spec: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    required_capabilities: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    default_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    is_destructive: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )


class DeviceConfigurationBinding(Common):
    """Binds one device to one exact published template version."""

    __tablename__ = "device_configuration_bindings"
    __table_args__ = (
        UniqueConstraint("device_id", name="uq_device_configuration_bindings_device"),
        CheckConstraint(
            "credential_source IN ('REMOTE_ACCESS_PROFILE','ENV_REFERENCE','ACCESS_TEMPLATE')",
            name="ck_device_configuration_bindings_credential_source",
        ),
        CheckConstraint(
            "(credential_source IN ('REMOTE_ACCESS_PROFILE','ACCESS_TEMPLATE') AND credential_reference IS NULL) OR "
            "(credential_source = 'ENV_REFERENCE' AND credential_reference LIKE 'env://%')",
            name="ck_device_configuration_bindings_credential_reference",
        ),
        Index("ix_device_configuration_bindings_version_enabled", "template_version_id", "enabled"),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    template_version_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("configuration_template_versions.id", ondelete="RESTRICT"), nullable=False
    )
    credential_source: Mapped[str] = mapped_column(
        String(30), nullable=False, default="REMOTE_ACCESS_PROFILE", server_default="REMOTE_ACCESS_PROFILE"
    )
    credential_reference: Mapped[str | None] = mapped_column(String(255))
    connection_overrides: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    bound_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    bound_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )


class ConfigurationSnapshot(Common):
    """Immutable metadata for an encrypted device configuration artifact."""

    __tablename__ = "configuration_snapshots"
    __table_args__ = (
        CheckConstraint(
            "snapshot_kind IN ('CAPTURE','PRE_CHANGE','POST_CHANGE','ROLLBACK','CANDIDATE')",
            name="ck_configuration_snapshots_kind",
        ),
        CheckConstraint(
            "artifact_status IN ('PENDING','READY','FAILED')",
            name="ck_configuration_snapshots_artifact_status",
        ),
        CheckConstraint(
            "artifact_size_bytes IS NULL OR artifact_size_bytes >= 0",
            name="ck_configuration_snapshots_artifact_size",
        ),
        CheckConstraint(
            "encryption_scheme IS NULL OR encryption_scheme = 'AES_256_GCM'",
            name="ck_configuration_snapshots_encryption_scheme",
        ),
        CheckConstraint(
            "encryption_key_reference IS NULL OR encryption_key_reference LIKE 'env://%'",
            name="ck_configuration_snapshots_encryption_key_reference",
        ),
        CheckConstraint(
            "(artifact_status <> 'READY') OR ("
            "artifact_path IS NOT NULL AND artifact_sha256 IS NOT NULL AND artifact_size_bytes IS NOT NULL AND "
            "encryption_scheme IS NOT NULL AND encryption_key_reference LIKE 'env://%')",
            name="ck_configuration_snapshots_ready_artifact",
        ),
        CheckConstraint(
            "(is_restorable = false) OR artifact_status = 'READY'",
            name="ck_configuration_snapshots_restorable_ready",
        ),
        Index("ix_configuration_snapshots_device_created", "device_id", "created_at"),
        Index("ix_configuration_snapshots_device_kind", "device_id", "snapshot_kind"),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    template_version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("configuration_template_versions.id", ondelete="SET NULL")
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    snapshot_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    adapter_key: Mapped[str] = mapped_column(String(120), nullable=False)
    artifact_status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="PENDING", server_default="PENDING"
    )
    artifact_path: Mapped[str | None] = mapped_column(Text)
    artifact_sha256: Mapped[str | None] = mapped_column(String(64))
    plaintext_sha256: Mapped[str | None] = mapped_column(String(64))
    normalized_sha256: Mapped[str | None] = mapped_column(String(64))
    artifact_size_bytes: Mapped[int | None] = mapped_column(Integer)
    encryption_scheme: Mapped[str | None] = mapped_column(String(40))
    encryption_key_reference: Mapped[str | None] = mapped_column(String(255))
    is_restorable: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )


class ConfigurationOperation(Common):
    """Single-device configuration operation envelope and audit-safe state."""

    __tablename__ = "configuration_operations"
    __table_args__ = (
        CheckConstraint(
            "operation_type IN ('CAPTURE','APPLY','VERIFY','RESTORE')",
            name="ck_configuration_operations_type",
        ),
        CheckConstraint(
            "status IN ('QUEUED','RUNNING','SUCCEEDED','FAILED','ROLLING_BACK','ROLLED_BACK','ROLLBACK_FAILED','CANCELLED')",
            name="ck_configuration_operations_status",
        ),
        CheckConstraint(
            "failure_stage IS NULL OR failure_stage IN ("
            "'AUTHORIZATION','VALIDATION','TRANSPORT','DEVICE_REJECTION','VERIFICATION','ROLLBACK','INTERNAL')",
            name="ck_configuration_operations_failure_stage",
        ),
        Index("ix_configuration_operations_device_created", "device_id", "created_at"),
        Index("ix_configuration_operations_status_created", "status", "created_at"),
        Index(
            "uq_configuration_operations_active_device",
            "device_id",
            unique=True,
            postgresql_where=text("status IN ('QUEUED','RUNNING','ROLLING_BACK')"),
        ),
        Index(
            "uq_configuration_operations_actor_idempotency",
            "actor_user_id",
            "device_id",
            "idempotency_key",
            unique=True,
            postgresql_where=text("idempotency_key IS NOT NULL"),
        ),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    template_version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("configuration_template_versions.id", ondelete="SET NULL")
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    operation_type: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="QUEUED", server_default="QUEUED"
    )
    idempotency_key: Mapped[str | None] = mapped_column(String(128))
    pre_change_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("configuration_snapshots.id", ondelete="SET NULL")
    )
    candidate_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("configuration_snapshots.id", ondelete="SET NULL")
    )
    result_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("configuration_snapshots.id", ondelete="SET NULL")
    )
    rollback_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("configuration_snapshots.id", ondelete="SET NULL")
    )
    authorization_scope: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    authorization_scope_fingerprint: Mapped[str | None] = mapped_column(String(64))
    request_summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    verification_summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    failure_stage: Mapped[str | None] = mapped_column(String(30))
    failure_code: Mapped[str | None] = mapped_column(String(120))
    failure_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ConfigurationOperationStep(Common):
    """Ordered immutable function selection for one single-device operation."""

    __tablename__ = "configuration_operation_steps"
    __table_args__ = (
        UniqueConstraint("operation_id", "step_order", name="uq_configuration_operation_steps_order"),
        CheckConstraint("step_order >= 0", name="ck_configuration_operation_steps_order"),
        CheckConstraint(
            "status IN ('PENDING','RUNNING','SUCCEEDED','FAILED','SKIPPED','ROLLING_BACK','ROLLED_BACK','ROLLBACK_FAILED')",
            name="ck_configuration_operation_steps_status",
        ),
        Index("ix_configuration_operation_steps_operation_status", "operation_id", "status"),
    )

    operation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("configuration_operations.id", ondelete="CASCADE"), nullable=False
    )
    function_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("configuration_functions.id", ondelete="RESTRICT"), nullable=False
    )
    step_order: Mapped[int] = mapped_column(Integer, nullable=False)
    function_code_snapshot: Mapped[str] = mapped_column(String(80), nullable=False)
    function_name_snapshot: Mapped[str] = mapped_column(String(160), nullable=False)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="PENDING", server_default="PENDING"
    )
    parameter_summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    verification_summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    failure_code: Mapped[str | None] = mapped_column(String(120))
    failure_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DeviceConfigurationState(Common):
    """Current verified configuration state; LKG changes only after verification."""

    __tablename__ = "device_configuration_states"
    __table_args__ = (
        UniqueConstraint("device_id", name="uq_device_configuration_states_device"),
        CheckConstraint(
            "drift_status IN ('UNKNOWN','IN_SYNC','DRIFTED','UNVERIFIED')",
            name="ck_device_configuration_states_drift_status",
        ),
        Index("ix_device_configuration_states_drift", "drift_status"),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    last_known_good_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("configuration_snapshots.id", ondelete="SET NULL")
    )
    last_verified_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("configuration_snapshots.id", ondelete="SET NULL")
    )
    last_operation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("configuration_operations.id", ondelete="SET NULL")
    )
    drift_status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="UNKNOWN", server_default="UNKNOWN"
    )
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
