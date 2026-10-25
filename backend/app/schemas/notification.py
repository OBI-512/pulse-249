from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class NotificationPolicyStepWrite(BaseModel):
    step_order: int = Field(ge=1, le=100)
    delay_seconds: int = Field(default=0, ge=0, le=604800)
    channel_type: str
    destination: str = Field(min_length=3, max_length=500)
    max_attempts: int = Field(default=3, ge=1, le=10)
    retry_base_seconds: int = Field(default=30, ge=5, le=3600)
    retry_max_seconds: int = Field(default=900, ge=5, le=86400)

    @field_validator("channel_type")
    @classmethod
    def normalize_channel(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in {"EMAIL", "WEBHOOK"}:
            raise ValueError("channel_type must be EMAIL or WEBHOOK")
        return normalized

    @model_validator(mode="after")
    def retry_bounds(self):
        if self.retry_max_seconds < self.retry_base_seconds:
            raise ValueError("retry_max_seconds must be >= retry_base_seconds")
        return self


class NotificationPolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=4000)
    enabled: bool = False
    alarm_type: str | None = Field(default=None, max_length=80)
    minimum_severity: str = "MAJOR"
    steps: list[NotificationPolicyStepWrite] = Field(min_length=1, max_length=20)

    @field_validator("minimum_severity")
    @classmethod
    def severity(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in {"INFO", "WARNING", "MINOR", "MAJOR", "CRITICAL"}:
            raise ValueError("invalid minimum severity")
        return normalized

    @model_validator(mode="after")
    def unique_steps(self):
        orders = [step.step_order for step in self.steps]
        if len(orders) != len(set(orders)):
            raise ValueError("notification policy step_order values must be unique")
        return self


class NotificationPolicyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=4000)
    enabled: bool | None = None
    alarm_type: str | None = Field(default=None, max_length=80)
    minimum_severity: str | None = None
    steps: list[NotificationPolicyStepWrite] | None = Field(default=None, min_length=1, max_length=20)

    @field_validator("minimum_severity")
    @classmethod
    def severity(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().upper()
        if normalized not in {"INFO", "WARNING", "MINOR", "MAJOR", "CRITICAL"}:
            raise ValueError("invalid minimum severity")
        return normalized

    @model_validator(mode="after")
    def unique_steps(self):
        if self.steps is not None:
            orders = [step.step_order for step in self.steps]
            if len(orders) != len(set(orders)):
                raise ValueError("notification policy step_order values must be unique")
        return self


class NotificationPolicyStepRead(BaseModel):
    id: UUID
    step_order: int
    delay_seconds: int
    channel_type: str
    destination: str
    max_attempts: int
    retry_base_seconds: int
    retry_max_seconds: int
    model_config = ConfigDict(from_attributes=True)


class NotificationPolicyRead(BaseModel):
    id: UUID
    name: str
    description: str | None = None
    enabled: bool
    alarm_type: str | None = None
    minimum_severity: str
    steps: list[NotificationPolicyStepRead] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class NotificationDeliveryRead(BaseModel):
    id: UUID
    alarm_id: UUID
    event_id: UUID | None = None
    policy_id: UUID
    policy_step_id: UUID
    occurrence_number: int
    channel_type: str
    destination: str
    status: str
    scheduled_at: datetime
    next_attempt_at: datetime
    attempt_count: int
    last_attempt_at: datetime | None = None
    delivered_at: datetime | None = None
    last_error_code: str | None = None
    response_status: int | None = None
    maintenance_window_id: UUID | None = None
    metadata: dict = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime
