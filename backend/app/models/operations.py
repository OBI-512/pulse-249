from __future__ import annotations
from typing import Any
import uuid
from datetime import datetime
from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, desc, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from .core import Common

class ImportJob(Common):
    __tablename__ = "import_jobs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING','PREVIEWED','COMMITTING','COMMITTED','COMPLETED','FAILED','EXPIRED')",
            name="ck_import_jobs_status",
        ),
        Index("ix_import_jobs_actor_created", "created_by_user_id", "created_at"),
        Index("ix_import_jobs_status_expires", "status", "preview_expires_at"),
        Index("uq_import_jobs_actor_idempotency", "created_by_user_id", "idempotency_key", unique=True, postgresql_where=text("idempotency_key IS NOT NULL")),
    )
    source_type: Mapped[str] = mapped_column(String(40), nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(40))
    file_format: Mapped[str | None] = mapped_column(String(10))
    filename: Mapped[str | None] = mapped_column(String(500))
    file_sha256: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(40), default="PENDING", nullable=False)
    total_records: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    imported_records: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_records: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    scope_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}", nullable=False)
    scope_fingerprint: Mapped[str | None] = mapped_column(String(64))
    idempotency_key: Mapped[str | None] = mapped_column(String(255))
    preview_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    committed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    validation_summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}", nullable=False)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)

class ImportRecord(Common):
    __tablename__ = "import_records"
    __table_args__ = (
        UniqueConstraint("import_job_id", "row_number", name="uq_import_records_job_row"),
        Index("ix_import_records_job_status", "import_job_id", "status"),
    )
    import_job_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("import_jobs.id", ondelete="CASCADE"), nullable=False)
    row_number: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="PENDING", nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(120))
    error_message: Mapped[str | None] = mapped_column(Text)
    source_data: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    normalized_data: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}", nullable=False)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)

class DiscoveryJob(Common):
    __tablename__ = "discovery_jobs"
    scope_type: Mapped[str] = mapped_column(String(40), nullable=False)
    scope_value: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="PENDING", nullable=False)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)

class DiscoveryResult(Common):
    __tablename__ = "discovery_results"
    discovery_job_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("discovery_jobs.id", ondelete="CASCADE"), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False)
    discovery_method: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="DISCOVERED", nullable=False)
    vendor: Mapped[str | None] = mapped_column(String(100))
    model: Mapped[str | None] = mapped_column(String(150))
    hostname: Mapped[str | None] = mapped_column(String(255))
    serial_number: Mapped[str | None] = mapped_column(String(150))
    raw_data: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


class RestorePoint(Common):
    """Durable metadata for a whole-system PostgreSQL restore artifact."""

    __tablename__ = "restore_points"
    __table_args__ = (
        Index("ix_restore_points_status_created", "status", desc("created_at")),
        Index("ix_restore_points_retention", "retention_until"),
        CheckConstraint(
            "source IN ('MANUAL','AUTOMATIC','EMERGENCY')",
            name="ck_restore_points_source",
        ),
        CheckConstraint(
            "status IN ('PENDING','CREATING','READY','FAILED','VERIFYING','RESTORING','RESTORED','DELETED')",
            name="ck_restore_points_status",
        ),
    )

    source: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="PENDING", nullable=False)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    description: Mapped[str | None] = mapped_column(Text)
    artifact_name: Mapped[str | None] = mapped_column(String(255), unique=True)
    artifact_size: Mapped[int | None] = mapped_column(Integer)
    sha256: Mapped[str | None] = mapped_column(String(64))
    manifest_checksum: Mapped[str | None] = mapped_column(String(64))
    postgres_major_version: Mapped[str | None] = mapped_column(String(20))
    pg_dump_version: Mapped[str | None] = mapped_column(String(80))
    application_version: Mapped[str | None] = mapped_column(String(80))
    image_identifier: Mapped[str | None] = mapped_column(String(255))
    alembic_revision: Mapped[str | None] = mapped_column(String(100))
    schema_fingerprint: Mapped[str | None] = mapped_column(String(64))
    retention_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    pinned: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_code: Mapped[str | None] = mapped_column(String(100))
    failure_message: Mapped[str | None] = mapped_column(Text)
    request_id: Mapped[str | None] = mapped_column(String(128))
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)
