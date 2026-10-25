from __future__ import annotations

from datetime import datetime
from typing import Any
import uuid

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .core import Common


class AccessTemplate(Common):
    """Stable reusable access-template family identity.

    Package 1 deliberately retains the legacy mutable definition columns below
    so existing runtime resolution remains unchanged while revision-aware
    lifecycle structures are introduced alongside it. Package 2 moves authoring
    and resolution onto AccessTemplateRevision explicitly.
    """

    __tablename__ = "access_templates"
    __table_args__ = (
        CheckConstraint("protocol IN ('SNMP','SSH','TELNET','WEB')", name="ck_access_templates_protocol"),
        CheckConstraint("visibility IN ('PRIVATE','SHARED')", name="ck_access_templates_visibility"),
        Index(
            "uq_active_access_templates_owner_name_protocol",
            "owner_user_id", "name", "protocol",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_access_templates_protocol_active", "protocol", "is_active", postgresql_where=text("deleted_at IS NULL")),
        Index("ix_access_templates_owner_visibility", "owner_user_id", "visibility", postgresql_where=text("deleted_at IS NULL")),
    )

    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    protocol: Mapped[str] = mapped_column(String(20), nullable=False)
    protocol_variant: Mapped[str | None] = mapped_column(String(40))
    visibility: Mapped[str] = mapped_column(String(20), nullable=False, default="PRIVATE", server_default="PRIVATE")
    owner_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=text("true"))
    settings_json: Mapped[dict[str, Any]] = mapped_column("settings", JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AccessTemplateRevision(Common):
    """Versioned access-template definition and lifecycle state.

    Only one ACTIVE revision may exist for a template family. Package 1 creates
    and backfills these rows but does not yet switch runtime resolution to them.
    """

    __tablename__ = "access_template_revisions"
    __table_args__ = (
        UniqueConstraint(
            "template_id",
            "revision_number",
            name="uq_access_template_revisions_number",
        ),
        CheckConstraint(
            "revision_number >= 1",
            name="ck_access_template_revisions_number",
        ),
        CheckConstraint(
            "lifecycle_status IN ('DRAFT','TESTED','APPROVED','ACTIVE','RETIRED')",
            name="ck_access_template_revisions_lifecycle_status",
        ),
        CheckConstraint(
            "definition_sha256 IS NULL OR char_length(definition_sha256) = 64",
            name="ck_access_template_revisions_definition_sha256",
        ),
        Index(
            "ix_access_template_revisions_template_status",
            "template_id",
            "lifecycle_status",
        ),
        Index(
            "ix_access_template_revisions_source",
            "source_revision_id",
        ),
        Index(
            "uq_access_template_revisions_active",
            "template_id",
            unique=True,
            postgresql_where=text("lifecycle_status = 'ACTIVE'"),
        ),
    )

    template_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("access_templates.id", ondelete="CASCADE"),
        nullable=False,
    )
    revision_number: Mapped[int] = mapped_column(Integer, nullable=False)
    lifecycle_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="DRAFT",
        server_default="DRAFT",
    )
    protocol_variant: Mapped[str | None] = mapped_column(String(40))
    settings_json: Mapped[dict[str, Any]] = mapped_column(
        "settings",
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    source_revision_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("access_template_revisions.id", ondelete="SET NULL")
    )
    change_note: Mapped[str | None] = mapped_column(Text)
    definition_sha256: Mapped[str | None] = mapped_column(String(64))
    legacy_backfill: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    activated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AccessTemplateRevisionSecret(Common):
    """Secret snapshot owned by one exact access-template revision.

    template_id is retained with revision_id because the current encrypted
    payload AAD is bound to stable template_id + secret_key. Existing ciphertext
    can therefore be snapshotted without decrypting or re-encrypting it.
    """

    __tablename__ = "access_template_revision_secrets"
    __table_args__ = (
        UniqueConstraint(
            "revision_id",
            "secret_key",
            name="uq_access_template_revision_secrets_key",
        ),
        CheckConstraint(
            "provider IN ('ENCRYPTED_DATABASE','ENV_REFERENCE')",
            name="ck_access_template_revision_secrets_provider",
        ),
        CheckConstraint(
            "(provider = 'ENCRYPTED_DATABASE' AND encrypted_payload IS NOT NULL AND reference IS NULL) OR "
            "(provider = 'ENV_REFERENCE' AND encrypted_payload IS NULL AND reference LIKE 'env://%')",
            name="ck_access_template_revision_secrets_storage",
        ),
        CheckConstraint(
            "key_version >= 1",
            name="ck_access_template_revision_secrets_key_version",
        ),
        Index("ix_access_template_revision_secrets_revision", "revision_id"),
        Index("ix_access_template_revision_secrets_template", "template_id"),
    )

    revision_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("access_template_revisions.id", ondelete="CASCADE"),
        nullable=False,
    )
    template_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("access_templates.id", ondelete="CASCADE"),
        nullable=False,
    )
    secret_key: Mapped[str] = mapped_column(String(80), nullable=False)
    provider: Mapped[str] = mapped_column(String(30), nullable=False)
    encrypted_payload: Mapped[str | None] = mapped_column(Text)
    reference: Mapped[str | None] = mapped_column(String(255))
    key_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")


class AccessTemplateSecret(Common):
    """Legacy runtime secret source retained during the TP1 compatibility bridge."""

    __tablename__ = "access_template_secrets"
    __table_args__ = (
        UniqueConstraint("template_id", "secret_key", name="uq_access_template_secrets_key"),
        CheckConstraint("provider IN ('ENCRYPTED_DATABASE','ENV_REFERENCE')", name="ck_access_template_secrets_provider"),
        CheckConstraint(
            "(provider = 'ENCRYPTED_DATABASE' AND encrypted_payload IS NOT NULL AND reference IS NULL) OR "
            "(provider = 'ENV_REFERENCE' AND encrypted_payload IS NULL AND reference LIKE 'env://%')",
            name="ck_access_template_secrets_storage",
        ),
        CheckConstraint("key_version >= 1", name="ck_access_template_secrets_key_version"),
        Index("ix_access_template_secrets_template", "template_id"),
    )

    template_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("access_templates.id", ondelete="CASCADE"), nullable=False)
    secret_key: Mapped[str] = mapped_column(String(80), nullable=False)
    provider: Mapped[str] = mapped_column(String(30), nullable=False)
    encrypted_payload: Mapped[str | None] = mapped_column(Text)
    reference: Mapped[str | None] = mapped_column(String(255))
    key_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")


class AccessTemplateAssignment(Common):
    __tablename__ = "access_template_assignments"
    __table_args__ = (
        CheckConstraint(
            "scope_type IN ('DEVICE','DEVICE_GROUP','LOGICAL_SECTOR','LOCATION','NETWORK','CITY')",
            name="ck_access_template_assignments_scope_type",
        ),
        CheckConstraint(
            "(scope_type = 'DEVICE' AND device_id IS NOT NULL AND group_id IS NULL AND sector_id IS NULL AND location_id IS NULL AND network_id IS NULL AND city_id IS NULL) OR "
            "(scope_type = 'DEVICE_GROUP' AND device_id IS NULL AND group_id IS NOT NULL AND sector_id IS NULL AND location_id IS NULL AND network_id IS NULL AND city_id IS NULL) OR "
            "(scope_type = 'LOGICAL_SECTOR' AND device_id IS NULL AND group_id IS NULL AND sector_id IS NOT NULL AND location_id IS NULL AND network_id IS NULL AND city_id IS NULL) OR "
            "(scope_type = 'LOCATION' AND device_id IS NULL AND group_id IS NULL AND sector_id IS NULL AND location_id IS NOT NULL AND network_id IS NULL AND city_id IS NULL) OR "
            "(scope_type = 'NETWORK' AND device_id IS NULL AND group_id IS NULL AND sector_id IS NULL AND location_id IS NULL AND network_id IS NOT NULL AND city_id IS NULL) OR "
            "(scope_type = 'CITY' AND device_id IS NULL AND group_id IS NULL AND sector_id IS NULL AND location_id IS NULL AND network_id IS NULL AND city_id IS NOT NULL)",
            name="ck_access_template_assignments_target",
        ),
        Index("ix_access_template_assignments_template_enabled", "template_id", "enabled"),
        Index("ix_access_template_assignments_device", "device_id", postgresql_where=text("device_id IS NOT NULL")),
        Index("ix_access_template_assignments_group", "group_id", postgresql_where=text("group_id IS NOT NULL")),
        Index("ix_access_template_assignments_sector", "sector_id", postgresql_where=text("sector_id IS NOT NULL")),
        Index("ix_access_template_assignments_location", "location_id", postgresql_where=text("location_id IS NOT NULL")),
        Index("ix_access_template_assignments_network", "network_id", postgresql_where=text("network_id IS NOT NULL")),
        Index("ix_access_template_assignments_city", "city_id", postgresql_where=text("city_id IS NOT NULL")),
    )

    template_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("access_templates.id", ondelete="CASCADE"), nullable=False)
    scope_type: Mapped[str] = mapped_column(String(30), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=text("true"))
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    group_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("device_groups.id", ondelete="CASCADE"))
    sector_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("sectors.id", ondelete="CASCADE"))
    location_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("locations.id", ondelete="CASCADE"))
    network_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("networks.id", ondelete="CASCADE"))
    city_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("cities.id", ondelete="CASCADE"))
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class AccessTemplateTestResult(Common):
    __tablename__ = "access_template_test_results"
    __table_args__ = (
        CheckConstraint("status IN ('SUCCESS','FAILED')", name="ck_access_template_test_results_status"),
        CheckConstraint("latency_ms IS NULL OR latency_ms >= 0", name="ck_access_template_test_results_latency"),
        Index("ix_access_template_test_results_template_device_tested", "template_id", "device_id", "tested_at"),
        Index(
            "ix_access_template_test_results_revision_device_tested",
            "revision_id",
            "device_id",
            "tested_at",
            postgresql_where=text("revision_id IS NOT NULL"),
        ),
    )

    template_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("access_templates.id", ondelete="CASCADE"), nullable=False)
    # Nullable only for the Package-1 compatibility bridge. Migration 0042
    # backfills all historical rows; Package 2 will populate this on new tests.
    revision_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey(
            "access_template_revisions.id",
            ondelete="SET NULL",
            name="fk_access_template_test_results_revision",
        )
    )
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    failure_code: Mapped[str | None] = mapped_column(String(120))
    sanitized_message: Mapped[str | None] = mapped_column(Text)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    tested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    tested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
