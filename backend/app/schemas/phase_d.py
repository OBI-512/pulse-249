from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class TelemetryMetricDefinition(BaseModel):
    key: str = Field(min_length=1, max_length=160)
    oid: str = Field(min_length=3, max_length=255)
    unit: str | None = Field(default=None, max_length=60)
    kind: Literal["GAUGE", "COUNTER", "STATE"] = "GAUGE"
    transform: Literal["raw", "float", "int", "timeticks_seconds"] = "float"
    vendor_key: str | None = Field(default=None, max_length=180)

    @field_validator("key", "oid")
    @classmethod
    def strip_nonempty(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("Value must not be empty.")
        return candidate


class TelemetryProfileUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    enabled: bool = True
    protocol: Literal["SNMP"] = "SNMP"
    interval_seconds: int = Field(default=900, ge=60, le=86400)
    timeout_seconds: int = Field(default=5, ge=1, le=60)
    retries: int = Field(default=1, ge=0, le=3)
    max_metrics: int = Field(default=32, ge=1, le=64)
    metric_definitions: list[TelemetryMetricDefinition] = Field(default_factory=list, max_length=64)
    vendor_extensions: dict[str, Any] = Field(default_factory=dict)
    description: str | None = Field(default=None, max_length=4000)

    @model_validator(mode="after")
    def metric_keys_are_unique(self):
        keys = [item.key for item in self.metric_definitions]
        if len(keys) != len(set(keys)):
            raise ValueError("Telemetry metric keys must be unique within a profile.")
        if len(self.metric_definitions) > self.max_metrics:
            raise ValueError("metric_definitions cannot exceed max_metrics.")
        return self


class TelemetryProfileRead(ORMModel):
    id: UUID
    device_type_id: UUID
    device_type_code: str | None = None
    device_type_name: str | None = None
    name: str
    enabled: bool
    protocol: str
    interval_seconds: int
    timeout_seconds: int
    retries: int
    max_metrics: int
    metric_definitions: list[dict[str, Any]]
    vendor_extensions: dict[str, Any]
    description: str | None
    created_at: datetime
    updated_at: datetime


class TelemetryStateRead(ORMModel):
    id: UUID
    device_id: UUID
    device_display_name: str | None = None
    profile_id: UUID | None
    enabled: bool
    status: str
    last_collect_at: datetime | None
    last_success_at: datetime | None
    last_failure_at: datetime | None
    next_collect_at: datetime | None
    consecutive_failures: int
    last_error_code: str | None
    last_duration_ms: float | None


class TelemetryMetricRead(ORMModel):
    id: UUID
    device_id: UUID
    metric_key: str
    metric_kind: str
    numeric_value: float | None
    text_value: str | None
    unit: str | None
    source: str
    vendor_key: str | None
    collected_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict, validation_alias="metadata_")


class TelemetrySeriesPoint(BaseModel):
    at: datetime
    value: float | str | None
    sample_count: int = 1
    unit: str | None = None
    source: str


class TelemetrySeriesRead(BaseModel):
    device_id: UUID
    metric_key: str
    start: datetime
    end: datetime
    resolution: Literal["raw", "hour"]
    points: list[TelemetrySeriesPoint]


class TelemetrySummaryRead(BaseModel):
    total: int
    enabled: int
    due: int
    ok: int
    error: int
    pending: int
    disabled: int
    oldest_due_at: datetime | None = None


class CollectNowRequest(BaseModel):
    device_ids: list[UUID] = Field(default_factory=list, max_length=500)


class RetentionPolicyUpdate(BaseModel):
    enabled: bool = True
    retain_days: int = Field(ge=1, le=3650)
    rollup_after_days: int | None = Field(default=None, ge=1, le=3650)
    batch_hours: int = Field(default=24, ge=1, le=168)

    @model_validator(mode="after")
    def rollup_before_retention(self):
        if self.rollup_after_days is not None and self.rollup_after_days >= self.retain_days:
            raise ValueError("rollup_after_days must be less than retain_days.")
        return self


class RetentionPolicyRead(ORMModel):
    id: UUID
    data_class: str
    enabled: bool
    retain_days: int
    rollup_after_days: int | None
    batch_hours: int
    description: str | None
    created_at: datetime
    updated_at: datetime


class LifecycleRunRead(ORMModel):
    id: UUID
    data_class: str
    status: str
    idempotency_key: str
    started_at: datetime
    completed_at: datetime | None
    cursor_at: datetime | None
    scanned_rows: int
    rolled_up_rows: int
    purged_rows: int
    error_code: str | None
    metadata: dict[str, Any] = Field(default_factory=dict, validation_alias="metadata_")


class CapacityEstimate(BaseModel):
    device_count: int
    enabled_device_fraction: float
    metrics_per_device: int
    interval_seconds: int
    raw_samples_per_day: int
    estimated_raw_bytes_per_day: int
    estimated_raw_storage_bytes: int
    estimated_hourly_rollup_bytes_per_day: int
    estimated_rollup_storage_bytes: int
    assumptions: dict[str, Any]


class CapacityModelRead(BaseModel):
    generated_at: datetime
    estimates: list[CapacityEstimate]


class ImportRecordRead(ORMModel):
    id: UUID
    row_number: int
    status: str
    error_code: str | None
    error_message: str | None
    source_data: dict[str, Any]
    normalized_data: dict[str, Any]


class ImportJobRead(ORMModel):
    id: UUID
    source_type: str
    entity_type: str | None
    file_format: str | None
    filename: str | None
    file_sha256: str | None
    status: str
    total_records: int
    imported_records: int
    error_records: int
    created_by_user_id: UUID | None
    preview_expires_at: datetime | None
    committed_at: datetime | None
    validation_summary: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class ImportPreviewRead(BaseModel):
    job: ImportJobRead
    records: list[ImportRecordRead]


class ImportConfirmRequest(BaseModel):
    expected_file_sha256: str = Field(min_length=64, max_length=64)


class ExportRequest(BaseModel):
    entity_type: Literal["geography", "devices", "customers", "customer_services", "groups", "table"]
    format: Literal["CSV", "XLSX", "JSON"] = "CSV"
    filters: dict[str, Any] = Field(default_factory=dict)


class ReportCatalogItem(BaseModel):
    code: str
    name: str
    description: str
    sensitive_fields: list[str]
    supported_formats: list[str]
    filters: list[str]


class ReportDefinitionCreate(BaseModel):
    name: str = Field(min_length=1, max_length=180)
    report_type: str = Field(min_length=1, max_length=80)
    format: Literal["CSV", "XLSX", "PDF", "JSON"] = "CSV"
    filters: dict[str, Any] = Field(default_factory=dict)
    include_sensitive: bool = False
    description: str | None = Field(default=None, max_length=4000)


class ReportDefinitionUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=180)
    report_type: str | None = Field(default=None, min_length=1, max_length=80)
    format: Literal["CSV", "XLSX", "PDF", "JSON"] | None = None
    filters: dict[str, Any] | None = None
    include_sensitive: bool | None = None
    description: str | None = Field(default=None, max_length=4000)


class ReportScheduleLinkRead(BaseModel):
    id: UUID
    name: str
    deleted_at: datetime | None = None


class ReportDefinitionRead(ORMModel):
    id: UUID
    owner_user_id: UUID
    name: str
    report_type: str
    format: str
    filters: dict[str, Any]
    include_sensitive: bool
    description: str | None
    deleted_at: datetime | None
    purge_after: datetime | None
    created_at: datetime
    updated_at: datetime
    linked_schedules: list[ReportScheduleLinkRead] = Field(default_factory=list)


class ReportRunRequest(BaseModel):
    definition_id: UUID | None = None
    schedule_id: UUID | None = None
    report_type: str | None = Field(default=None, max_length=80)
    format: Literal["CSV", "XLSX", "PDF", "JSON"] | None = None
    filters: dict[str, Any] = Field(default_factory=dict)
    include_sensitive: bool = False

    @model_validator(mode="after")
    def source_contract(self):
        if self.definition_id is not None and self.schedule_id is not None:
            raise ValueError("definition_id and schedule_id are mutually exclusive.")
        if self.definition_id is None and self.schedule_id is None and not (self.report_type or "").strip():
            raise ValueError("definition_id, schedule_id, or report_type is required.")
        return self


class ReportJobsDeleteRequest(BaseModel):
    job_ids: list[UUID] = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def unique_job_ids(self):
        if len(set(self.job_ids)) != len(self.job_ids):
            raise ValueError("job_ids must not contain duplicates.")
        return self


class ReportJobsDeleteResult(BaseModel):
    deleted: int
    deleted_ids: list[UUID]


class ReportJobRead(ORMModel):
    id: UUID
    owner_user_id: UUID
    definition_id: UUID | None
    schedule_id: UUID | None
    report_type: str
    display_name: str
    format: str
    status: str
    filters: dict[str, Any]
    include_sensitive: bool
    requested_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    row_count: int
    artifact_name: str | None
    artifact_size: int | None
    artifact_sha256: str | None
    expires_at: datetime | None
    error_code: str | None
    error_message: str | None
    created_at: datetime
    updated_at: datetime


class ReportScheduleCreate(BaseModel):
    definition_id: UUID | None = None
    name: str = Field(min_length=1, max_length=180)
    report_type: str | None = Field(default=None, max_length=80)
    format: Literal["CSV", "XLSX", "PDF", "JSON"] | None = None
    filters: dict[str, Any] = Field(default_factory=dict)
    include_sensitive: bool = False
    interval_minutes: int = Field(ge=60, le=525600)
    enabled: bool = True
    next_run_at: datetime
    channel_type: Literal["EMAIL", "WEBHOOK"] | None = None
    destination: str | None = Field(default=None, max_length=500)
    max_attempts: int = Field(default=3, ge=1, le=10)
    retry_base_seconds: int = Field(default=60, ge=5, le=3600)

    @model_validator(mode="after")
    def schedule_source_and_delivery(self):
        if self.definition_id is None and not (self.report_type or "").strip():
            raise ValueError("definition_id or report_type is required.")
        if (self.channel_type is None) != (self.destination is None):
            raise ValueError("channel_type and destination must be provided together.")
        return self


class ReportScheduleUpdate(BaseModel):
    definition_id: UUID | None = None
    name: str | None = Field(default=None, min_length=1, max_length=180)
    report_type: str | None = Field(default=None, min_length=1, max_length=80)
    format: Literal["CSV", "XLSX", "PDF", "JSON"] | None = None
    filters: dict[str, Any] | None = None
    include_sensitive: bool | None = None
    interval_minutes: int | None = Field(default=None, ge=60, le=525600)
    enabled: bool | None = None
    next_run_at: datetime | None = None
    channel_type: Literal["EMAIL", "WEBHOOK"] | None = None
    destination: str | None = Field(default=None, max_length=500)
    max_attempts: int | None = Field(default=None, ge=1, le=10)
    retry_base_seconds: int | None = Field(default=None, ge=5, le=3600)


class ReportScheduleRead(ORMModel):
    id: UUID
    owner_user_id: UUID
    definition_id: UUID | None
    name: str
    report_type: str
    format: str
    filters: dict[str, Any]
    include_sensitive: bool
    interval_minutes: int
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None
    channel_type: str | None
    destination: str | None
    max_attempts: int
    retry_base_seconds: int
    deleted_at: datetime | None
    purge_after: datetime | None
    created_at: datetime
    updated_at: datetime
    definition_name: str | None = None
    definition_deleted_at: datetime | None = None


class ReportDeliveryRead(ORMModel):
    id: UUID
    report_job_id: UUID
    schedule_id: UUID | None
    owner_user_id: UUID
    channel_type: str
    destination: str
    status: str
    attempt_count: int
    next_attempt_at: datetime
    last_attempt_at: datetime | None
    delivered_at: datetime | None
    last_error_code: str | None
    response_status: int | None
    created_at: datetime
    updated_at: datetime
