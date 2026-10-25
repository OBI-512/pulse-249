from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .pagination import PageResult


AccessProtocol = Literal["SSH", "SNMP", "WEB", "TELNET"]
AccessConflictPolicy = Literal["FAIL_ON_CONFLICT", "REPLACE_DEVICE_PROTOCOL"]
ConfigurationCredentialMode = Literal[
    "PRESERVE_EXISTING",
    "ACCESS_TEMPLATE",
    "REMOTE_ACCESS_PROFILE",
]
BatchStatus = Literal[
    "PREVIEWED",
    "APPLYING",
    "SUCCEEDED",
    "PARTIAL",
    "FAILED",
    "EXPIRED",
]
PreviewStatus = Literal["READY", "NOOP", "BLOCKED"]
ApplyStatus = Literal["NOT_APPLIED", "SUCCEEDED", "FAILED", "SKIPPED"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)


class AccessTemplateAssignmentOption(_StrictModel):
    id: UUID
    name: str
    protocol: AccessProtocol
    lifecycle_status: Literal["ACTIVE"] = "ACTIVE"
    visibility: Literal["PRIVATE", "SHARED"]
    compatibility: dict[str, Any] = Field(default_factory=dict)
    qualification: dict[str, Any] = Field(default_factory=dict)


class ConfigurationTemplateAssignmentOption(_StrictModel):
    template_id: UUID
    template_version_id: UUID
    code: str
    name: str
    version_number: int
    content_sha256: str
    device_type_id: UUID
    device_type_code: str
    vendor: str
    model: str | None = None
    series: str | None = None
    adapter_key: str
    transport: str
    compatibility: dict[str, Any] = Field(default_factory=dict)
    qualification: dict[str, Any] = Field(default_factory=dict)


class AccessTemplateBulkSelection(_StrictModel):
    template_id: UUID
    priority: int = Field(default=0, ge=-100000, le=100000)
    conflict_policy: AccessConflictPolicy = "FAIL_ON_CONFLICT"


class ConfigurationTemplateBulkSelection(_StrictModel):
    template_version_id: UUID
    replace_existing: bool = False
    credential_mode: ConfigurationCredentialMode = "ACCESS_TEMPLATE"
    enabled: bool = True


class TemplateAssignmentBatchPreviewRequest(_StrictModel):
    device_ids: list[UUID] = Field(min_length=1, max_length=500)
    access_templates: list[AccessTemplateBulkSelection] = Field(
        default_factory=list,
        max_length=4,
    )
    configuration: ConfigurationTemplateBulkSelection | None = None
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128)

    @field_validator("device_ids")
    @classmethod
    def device_ids_must_be_unique(cls, value: list[UUID]) -> list[UUID]:
        if len(set(value)) != len(value):
            raise ValueError("device_ids must contain unique values")
        return value

    @model_validator(mode="after")
    def require_template_selection(self):
        if not self.access_templates and self.configuration is None:
            raise ValueError("At least one template family must be selected")
        return self


class TemplateAssignmentBatchApplyRequest(_StrictModel):
    expected_request_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")


class TemplateAssignmentBatchTargetRead(_StrictModel):
    id: UUID
    batch_id: UUID
    device_id: UUID
    target_ordinal: int
    preview_status: PreviewStatus
    apply_status: ApplyStatus
    warnings: list[dict[str, Any]] = Field(default_factory=list)
    blockers: list[dict[str, Any]] = Field(default_factory=list)
    planned_changes: dict[str, Any] = Field(default_factory=dict)
    family_outcomes: dict[str, Any] = Field(default_factory=dict)
    failure_code: str | None = None
    failure_message: str | None = None
    terminal_at: datetime | None = None


class TemplateAssignmentBatchRead(_StrictModel):
    id: UUID
    actor_user_id: UUID | None
    status: BatchStatus
    request_fingerprint: str
    request_summary: dict[str, Any]
    target_count: int
    ready_count: int
    noop_count: int
    blocked_count: int
    succeeded_count: int
    failed_count: int
    preview_expires_at: datetime
    applied_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class TemplateAssignmentBatchDetail(_StrictModel):
    batch: TemplateAssignmentBatchRead
    targets: list[TemplateAssignmentBatchTargetRead]


AccessTemplateAssignmentOptionPage = PageResult[AccessTemplateAssignmentOption]
ConfigurationTemplateAssignmentOptionPage = PageResult[
    ConfigurationTemplateAssignmentOption
]
