from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.configuration.contracts import ConfigurationTemplateDefinition, validate_env_secret_reference


class ConfigurationTemplateCreate(BaseModel):
    code: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    name: str = Field(min_length=1, max_length=160)
    vendor: str = Field(min_length=1, max_length=100)
    model: str | None = Field(default=None, max_length=150)
    series: str | None = Field(default=None, max_length=150)
    device_type_id: UUID
    description: str | None = Field(default=None, max_length=4000)
    definition: ConfigurationTemplateDefinition


class ConfigurationTemplateVersionUpdate(BaseModel):
    definition: ConfigurationTemplateDefinition
    change_note: str | None = Field(default=None, max_length=1000)


class ConfigurationTemplateRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    code: str
    name: str
    vendor: str
    model: str | None
    series: str | None
    device_type_id: UUID
    is_active: bool
    description: str | None
    created_at: datetime
    updated_at: datetime


class ConfigurationTemplateVersionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    template_id: UUID
    version_number: int
    status: str
    adapter_key: str
    transport: str
    capabilities: list[str]
    parameter_schema: dict[str, Any]
    transport_parameters: dict[str, Any]
    source_version_id: UUID | None
    tested_definition_sha256: str | None
    tested_at: datetime | None
    tested_by_user_id: UUID | None
    approved_at: datetime | None
    approved_by_user_id: UUID | None
    content_sha256: str | None
    published_at: datetime | None
    published_by_user_id: UUID | None
    change_note: str | None
    created_at: datetime
    updated_at: datetime


class ConfigurationFunctionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    template_version_id: UUID
    code: str
    name: str
    category: str
    description: str | None
    parameter_schema: dict[str, Any]
    execution_spec: dict[str, Any]
    verification_spec: dict[str, Any]
    rollback_spec: dict[str, Any]
    required_capabilities: list[str]
    default_order: int
    enabled: bool
    is_destructive: bool


class ConfigurationTemplateVersionDetail(BaseModel):
    version: ConfigurationTemplateVersionRead
    functions: list[ConfigurationFunctionRead]


class ConfigurationTemplateDetail(BaseModel):
    template: ConfigurationTemplateRead
    versions: list[ConfigurationTemplateVersionDetail]


class DeviceConfigurationBindingWrite(BaseModel):
    template_version_id: UUID
    credential_source: str = Field(
        default="REMOTE_ACCESS_PROFILE",
        pattern=r"^(REMOTE_ACCESS_PROFILE|ENV_REFERENCE|ACCESS_TEMPLATE)$",
    )
    credential_reference: str | None = None
    connection_overrides: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True

    @model_validator(mode="after")
    def validate_binding(self):
        if self.credential_source == "ENV_REFERENCE":
            if validate_env_secret_reference(self.credential_reference) is None:
                raise ValueError("CONFIGURATION_CREDENTIAL_REFERENCE_REQUIRED")
        elif self.credential_reference is not None:
            raise ValueError("CONFIGURATION_CREDENTIAL_REFERENCE_FORBIDDEN")
        forbidden = {
            key
            for key in self.connection_overrides
            if any(
                part in key.lower()
                for part in (
                    "password",
                    "secret",
                    "private_key",
                    "token",
                    "credential",
                )
            )
        }
        if forbidden:
            raise ValueError("CONFIGURATION_CONNECTION_OVERRIDE_SECRET_FORBIDDEN")
        return self


class DeviceConfigurationBindingRead(BaseModel):
    id: UUID
    device_id: UUID
    template_version_id: UUID
    credential_source: str
    credential_reference_configured: bool
    connection_overrides: dict[str, Any]
    enabled: bool
    bound_at: datetime


class ConfigurationStepRequest(BaseModel):
    function_id: UUID
    parameters: dict[str, Any] = Field(default_factory=dict)


class ConfigurationApplyRequest(BaseModel):
    steps: list[ConfigurationStepRequest] = Field(min_length=1, max_length=100)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128)


class ConfigurationCaptureRequest(BaseModel):
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128)


class ConfigurationRestoreRequest(BaseModel):
    snapshot_id: UUID
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128)


class ConfigurationVerifyRequest(BaseModel):
    snapshot_id: UUID
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128)


class ConfigurationOperationQueued(BaseModel):
    operation_id: UUID
    status: str


class ConfigurationOperationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    device_id: UUID
    template_version_id: UUID | None
    actor_user_id: UUID | None
    operation_type: str
    status: str
    pre_change_snapshot_id: UUID | None
    candidate_snapshot_id: UUID | None
    result_snapshot_id: UUID | None
    rollback_snapshot_id: UUID | None
    verification_summary: dict[str, Any]
    failure_stage: str | None
    failure_code: str | None
    failure_message: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ConfigurationOperationStepRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    operation_id: UUID
    function_id: UUID
    step_order: int
    function_code_snapshot: str
    function_name_snapshot: str
    status: str
    parameter_summary: dict[str, Any]
    verification_summary: dict[str, Any]
    failure_code: str | None
    failure_message: str | None
    started_at: datetime | None
    finished_at: datetime | None


class ConfigurationOperationDetail(BaseModel):
    operation: ConfigurationOperationRead
    steps: list[ConfigurationOperationStepRead]


class ConfigurationSnapshotRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    device_id: UUID
    template_version_id: UUID | None
    snapshot_kind: str
    adapter_key: str
    artifact_status: str
    artifact_sha256: str | None
    plaintext_sha256: str | None
    normalized_sha256: str | None
    artifact_size_bytes: int | None
    is_restorable: bool
    created_at: datetime


class DeviceConfigurationStateRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    device_id: UUID
    last_known_good_snapshot_id: UUID | None
    last_verified_snapshot_id: UUID | None
    last_operation_id: UUID | None
    drift_status: str
    last_verified_at: datetime | None


class ConfigurationDiffRead(BaseModel):
    from_snapshot_id: UUID
    to_snapshot_id: UUID
    diff: str
    truncated: bool = False


def public_parameter_summary(summary: dict[str, Any] | None) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in (summary or {}).items():
        if isinstance(value, dict) and value.get("sensitive") is True:
            output[key] = {"sensitive": True, "configured": bool(value.get("reference"))}
        else:
            output[key] = value
    return output
