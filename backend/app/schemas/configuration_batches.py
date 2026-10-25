from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.configuration import ConfigurationStepRequest


OperationType = Literal["CAPTURE", "APPLY", "VERIFY", "RESTORE"]
RolloutMode = Literal["ALL_AT_ONCE", "CANARY_PERCENTAGE", "WAVES"]
MaintenancePolicy = Literal["NONE", "REQUIRE_ACTIVE_WINDOW"]


class ConfigurationBatchCreate(BaseModel):
    operation_type: OperationType
    device_ids: list[UUID] = Field(min_length=1, max_length=100)
    steps: list[ConfigurationStepRequest] = Field(default_factory=list, max_length=100)
    snapshot_ids: dict[UUID, UUID] = Field(default_factory=dict)
    rollout_mode: RolloutMode = "ALL_AT_ONCE"
    canary_percent: int | None = Field(default=None, ge=1, le=100)
    wave_size: int | None = Field(default=None, ge=1, le=100)
    not_before: datetime | None = None
    maintenance_policy: MaintenancePolicy = "NONE"
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128)

    @model_validator(mode="after")
    def validate_batch_request(self):
        target_ids = set(self.device_ids)
        snapshot_target_ids = set(self.snapshot_ids)

        if self.operation_type == "APPLY":
            if not self.steps:
                raise ValueError("CONFIGURATION_BATCH_APPLY_STEPS_REQUIRED")
            if self.snapshot_ids:
                raise ValueError("CONFIGURATION_BATCH_SNAPSHOT_IDS_FORBIDDEN")
        elif self.operation_type == "CAPTURE":
            if self.steps or self.snapshot_ids:
                raise ValueError("CONFIGURATION_BATCH_CAPTURE_PAYLOAD_INVALID")
        else:
            if self.steps:
                raise ValueError("CONFIGURATION_BATCH_STEPS_FORBIDDEN")
            if snapshot_target_ids != target_ids:
                raise ValueError("CONFIGURATION_BATCH_SNAPSHOT_MAP_INCOMPLETE")

        if self.rollout_mode == "ALL_AT_ONCE":
            if self.canary_percent is not None or self.wave_size is not None:
                raise ValueError("CONFIGURATION_BATCH_ROLLOUT_PARAMETERS_INVALID")
        elif self.rollout_mode == "CANARY_PERCENTAGE":
            if self.canary_percent is None or self.wave_size is not None:
                raise ValueError("CONFIGURATION_BATCH_CANARY_PERCENT_REQUIRED")
        elif self.rollout_mode == "WAVES":
            if self.wave_size is None or self.canary_percent is not None:
                raise ValueError("CONFIGURATION_BATCH_WAVE_SIZE_REQUIRED")

        if self.not_before is not None and self.not_before.tzinfo is None:
            raise ValueError("CONFIGURATION_BATCH_NOT_BEFORE_TIMEZONE_REQUIRED")
        return self


class ConfigurationBatchRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    actor_user_id: UUID | None
    operation_type: str
    status: str
    rollout_mode: str
    rollout_parameters: dict
    not_before: datetime | None
    maintenance_policy: str
    target_count: int
    dispatched_count: int
    succeeded_count: int
    failed_count: int
    aborted_count: int
    queued_at: datetime | None
    started_at: datetime | None
    paused_at: datetime | None
    aborted_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ConfigurationBatchTargetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    batch_id: UUID
    device_id: UUID
    target_ordinal: int
    wave_number: int
    status: str
    configuration_operation_id: UUID | None
    failure_code: str | None
    failure_message: str | None
    dispatched_at: datetime | None
    terminal_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ConfigurationBatchDetail(BaseModel):
    batch: ConfigurationBatchRead
    targets: list[ConfigurationBatchTargetRead]


class ConfigurationBatchQueued(BaseModel):
    batch_id: UUID
    status: str
    created: bool
