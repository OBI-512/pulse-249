from __future__ import annotations

from datetime import datetime
from typing import Any
import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .core import Common


TELEMETRY_METRIC_KINDS = ("GAUGE", "COUNTER", "STATE")
TELEMETRY_STATE_STATUSES = ("PENDING", "OK", "ERROR", "DISABLED")
LIFECYCLE_RUN_STATES = ("RUNNING", "COMPLETED", "FAILED", "SKIPPED")
REPORT_JOB_STATES = ("QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED", "EXPIRED")
REPORT_FORMATS = ("CSV", "XLSX", "PDF", "JSON")
REPORT_DELIVERY_STATES = ("PENDING", "SENDING", "SENT", "RETRY", "FAILED", "CANCELLED")


class TelemetryProfile(Common):
    """Per-device-type telemetry cadence and normalized metric catalog.

    A profile is intentionally independent from DeviceAvailability.  No foreign
    key or scheduler state couples the two engines.
    """

    __tablename__ = "telemetry_profiles"
    __table_args__ = (
        UniqueConstraint("device_type_id", name="uq_telemetry_profiles_device_type"),
        CheckConstraint("interval_seconds BETWEEN 60 AND 86400", name="ck_telemetry_profiles_interval"),
        CheckConstraint("timeout_seconds BETWEEN 1 AND 60", name="ck_telemetry_profiles_timeout"),
        CheckConstraint("retries BETWEEN 0 AND 3", name="ck_telemetry_profiles_retries"),
        CheckConstraint("max_metrics BETWEEN 1 AND 64", name="ck_telemetry_profiles_max_metrics"),
        Index("ix_telemetry_profiles_enabled", "enabled"),
    )

    device_type_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("device_types.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"), nullable=False)
    protocol: Mapped[str] = mapped_column(String(30), default="SNMP", server_default="SNMP", nullable=False)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=900, server_default="900", nullable=False)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=5, server_default="5", nullable=False)
    retries: Mapped[int] = mapped_column(Integer, default=1, server_default="1", nullable=False)
    max_metrics: Mapped[int] = mapped_column(Integer, default=32, server_default="32", nullable=False)
    metric_definitions: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, server_default="[]", nullable=False
    )
    vendor_extensions: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default="{}", nullable=False
    )
    description: Mapped[str | None] = mapped_column(Text)


class TelemetryDeviceState(Common):
    """Current scheduling/result state. Retention jobs never purge this table."""

    __tablename__ = "telemetry_device_state"
    __table_args__ = (
        UniqueConstraint("device_id", name="uq_telemetry_device_state_device"),
        CheckConstraint(
            "status IN ('PENDING','OK','ERROR','DISABLED')",
            name="ck_telemetry_device_state_status",
        ),
        CheckConstraint("consecutive_failures >= 0", name="ck_telemetry_device_state_failures"),
        Index("ix_telemetry_device_state_due", "enabled", "next_collect_at"),
        Index("ix_telemetry_device_state_lease", "lease_expires_at"),
        Index("ix_telemetry_device_state_status", "status"),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    profile_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("telemetry_profiles.id", ondelete="SET NULL"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="PENDING", server_default="PENDING", nullable=False)
    last_collect_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_failure_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_collect_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    last_error_code: Mapped[str | None] = mapped_column(String(120))
    last_duration_ms: Mapped[float | None] = mapped_column(Float)
    lease_token: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TelemetryMetric(Common):
    __tablename__ = "telemetry_metrics"
    __table_args__ = (
        CheckConstraint(
            "metric_kind IN ('GAUGE','COUNTER','STATE')",
            name="ck_telemetry_metrics_kind",
        ),
        Index("ix_telemetry_metrics_device_metric_time", "device_id", "metric_key", "collected_at"),
        Index("ix_telemetry_metrics_collected_at", "collected_at", postgresql_using="brin", postgresql_with={"pages_per_range": "128"}),
        Index("ix_telemetry_metrics_metric_time", "metric_key", "collected_at"),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    profile_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("telemetry_profiles.id", ondelete="SET NULL"))
    metric_key: Mapped[str] = mapped_column(String(160), nullable=False)
    metric_kind: Mapped[str] = mapped_column(String(20), default="GAUGE", server_default="GAUGE", nullable=False)
    numeric_value: Mapped[float | None] = mapped_column(Float)
    text_value: Mapped[str | None] = mapped_column(Text)
    unit: Mapped[str | None] = mapped_column(String(60))
    source: Mapped[str] = mapped_column(String(40), default="SNMP", server_default="SNMP", nullable=False)
    vendor_key: Mapped[str | None] = mapped_column(String(180))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, server_default="{}", nullable=False
    )


class TelemetryMetricRollup(Common):
    __tablename__ = "telemetry_metric_rollups"
    __table_args__ = (
        CheckConstraint("bucket_seconds IN (3600,86400)", name="ck_telemetry_rollups_bucket"),
        CheckConstraint("sample_count >= 1", name="ck_telemetry_rollups_samples"),
        UniqueConstraint(
            "device_id", "metric_key", "bucket_start", "bucket_seconds",
            name="uq_telemetry_rollup_bucket",
        ),
        Index("ix_telemetry_rollups_device_metric_time", "device_id", "metric_key", "bucket_start"),
        Index("ix_telemetry_rollups_bucket_start", "bucket_start"),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    metric_key: Mapped[str] = mapped_column(String(160), nullable=False)
    unit: Mapped[str | None] = mapped_column(String(60))
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    bucket_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False)
    min_value: Mapped[float | None] = mapped_column(Float)
    max_value: Mapped[float | None] = mapped_column(Float)
    avg_value: Mapped[float | None] = mapped_column(Float)
    sum_value: Mapped[float | None] = mapped_column(Float)
    first_value: Mapped[float | None] = mapped_column(Float)
    last_value: Mapped[float | None] = mapped_column(Float)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, server_default="{}", nullable=False
    )


class DataRetentionPolicy(Common):
    __tablename__ = "data_retention_policies"
    __table_args__ = (
        UniqueConstraint("data_class", name="uq_data_retention_policy_class"),
        CheckConstraint("retain_days BETWEEN 1 AND 3650", name="ck_data_retention_retain_days"),
        CheckConstraint(
            "rollup_after_days IS NULL OR rollup_after_days BETWEEN 1 AND 3650",
            name="ck_data_retention_rollup_days",
        ),
    )

    data_class: Mapped[str] = mapped_column(String(80), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"), nullable=False)
    retain_days: Mapped[int] = mapped_column(Integer, nullable=False)
    rollup_after_days: Mapped[int | None] = mapped_column(Integer)
    batch_hours: Mapped[int] = mapped_column(Integer, default=24, server_default="24", nullable=False)
    description: Mapped[str | None] = mapped_column(Text)


class DataLifecycleRun(Common):
    __tablename__ = "data_lifecycle_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('RUNNING','COMPLETED','FAILED','SKIPPED')",
            name="ck_data_lifecycle_runs_status",
        ),
        UniqueConstraint("idempotency_key", name="uq_data_lifecycle_runs_idempotency"),
        Index("ix_data_lifecycle_runs_class_started", "data_class", "started_at"),
        Index("ix_data_lifecycle_runs_status_started", "status", "started_at"),
    )

    data_class: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cursor_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    scanned_rows: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    rolled_up_rows: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    purged_rows: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(120))
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, server_default="{}", nullable=False
    )


class ReportDefinition(Common):
    __tablename__ = "report_definitions"
    __table_args__ = (
        CheckConstraint(
            "(deleted_at IS NULL AND purge_after IS NULL) OR (deleted_at IS NOT NULL AND purge_after IS NOT NULL)",
            name="ck_report_definitions_trash_state",
        ),
        Index("ix_report_definitions_owner_name", "owner_user_id", "name"),
        Index("ix_report_definitions_owner_deleted", "owner_user_id", "deleted_at"),
        Index("ix_report_definitions_purge_after", "purge_after"),
    )

    owner_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    report_type: Mapped[str] = mapped_column(String(80), nullable=False)
    format: Mapped[str] = mapped_column(String(10), default="CSV", server_default="CSV", nullable=False)
    filters: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}", nullable=False)
    include_sensitive: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    purge_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ReportJob(Common):
    __tablename__ = "report_jobs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('QUEUED','RUNNING','COMPLETED','FAILED','CANCELLED','EXPIRED')",
            name="ck_report_jobs_status",
        ),
        CheckConstraint("format IN ('CSV','XLSX','PDF','JSON')", name="ck_report_jobs_format"),
        Index("ix_report_jobs_owner_created", "owner_user_id", "created_at"),
        Index("ix_report_jobs_status_created", "status", "created_at"),
        Index("ix_report_jobs_expires", "expires_at"),
    )

    owner_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    definition_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("report_definitions.id", ondelete="SET NULL"))
    schedule_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("report_schedules.id", ondelete="SET NULL"))
    report_type: Mapped[str] = mapped_column(String(80), nullable=False)
    format: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="QUEUED", server_default="QUEUED", nullable=False)
    filters: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}", nullable=False)
    include_sensitive: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"), nullable=False)
    scope_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}", nullable=False)
    scope_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    permission_snapshot: Mapped[list[str]] = mapped_column(JSONB, default=list, server_default="[]", nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    row_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    artifact_name: Mapped[str | None] = mapped_column(String(255))
    artifact_size: Mapped[int | None] = mapped_column(Integer)
    artifact_sha256: Mapped[str | None] = mapped_column(String(64))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(120))
    error_message: Mapped[str | None] = mapped_column(Text)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, server_default="{}", nullable=False
    )

    @property
    def display_name(self) -> str:
        metadata = self.metadata_ or {}
        configured = str(metadata.get("display_name") or "").strip()
        if configured:
            return configured
        label = self.report_type.replace("_", " ").title()
        requested = self.requested_at.strftime("%Y-%m-%d %H:%M UTC") if self.requested_at else "Report"
        return f"{label} — {requested}"


class ReportSchedule(Common):
    __tablename__ = "report_schedules"
    __table_args__ = (
        CheckConstraint("interval_minutes BETWEEN 60 AND 525600", name="ck_report_schedules_interval"),
        CheckConstraint(
            "(deleted_at IS NULL AND purge_after IS NULL) OR (deleted_at IS NOT NULL AND purge_after IS NOT NULL)",
            name="ck_report_schedules_trash_state",
        ),
        CheckConstraint("format IN ('CSV','XLSX','PDF','JSON')", name="ck_report_schedules_format"),
        CheckConstraint("channel_type IS NULL OR channel_type IN ('EMAIL','WEBHOOK')", name="ck_report_schedules_channel"),
        Index("ix_report_schedules_due", "enabled", "next_run_at"),
        Index("ix_report_schedules_owner", "owner_user_id"),
        Index("ix_report_schedules_owner_deleted", "owner_user_id", "deleted_at"),
        Index("ix_report_schedules_purge_after", "purge_after"),
    )

    owner_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    definition_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("report_definitions.id", ondelete="SET NULL"))
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    report_type: Mapped[str] = mapped_column(String(80), nullable=False)
    format: Mapped[str] = mapped_column(String(10), nullable=False)
    filters: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}", nullable=False)
    include_sensitive: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"), nullable=False)
    interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"), nullable=False)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    channel_type: Mapped[str | None] = mapped_column(String(20))
    destination: Mapped[str | None] = mapped_column(String(500))
    max_attempts: Mapped[int] = mapped_column(Integer, default=3, server_default="3", nullable=False)
    retry_base_seconds: Mapped[int] = mapped_column(Integer, default=60, server_default="60", nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    purge_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ReportDelivery(Common):
    __tablename__ = "report_deliveries"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING','SENDING','SENT','RETRY','FAILED','CANCELLED')",
            name="ck_report_deliveries_status",
        ),
        CheckConstraint("channel_type IN ('EMAIL','WEBHOOK')", name="ck_report_deliveries_channel"),
        UniqueConstraint("idempotency_key", name="uq_report_deliveries_idempotency"),
        Index("ix_report_deliveries_due", "status", "next_attempt_at"),
        Index("ix_report_deliveries_job", "report_job_id"),
    )

    report_job_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("report_jobs.id", ondelete="CASCADE"), nullable=False)
    schedule_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("report_schedules.id", ondelete="SET NULL"))
    owner_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    channel_type: Mapped[str] = mapped_column(String(20), nullable=False)
    destination: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="PENDING", server_default="PENDING", nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(120))
    response_status: Mapped[int | None] = mapped_column(Integer)
    scope_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, server_default="{}", nullable=False
    )
