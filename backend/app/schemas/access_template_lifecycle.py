from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from .access_templates import AccessTemplateCreate, AccessTemplateSecretInput, Visibility


LifecycleStatus = Literal["DRAFT", "TESTED", "APPROVED", "ACTIVE", "RETIRED"]


class AccessTemplateFamilyCreate(AccessTemplateCreate):
    """Create an inactive family with its initial lifecycle draft."""

    is_active: Literal[False] = False
    change_note: str | None = Field(default=None, max_length=4000)


class AccessTemplateRevisionCreate(BaseModel):
    source_revision_id: UUID | None = None
    change_note: str | None = Field(default=None, max_length=4000)


class AccessTemplateRevisionUpdate(BaseModel):
    protocol_variant: str | None = Field(default=None, max_length=40)
    settings: dict[str, Any] | None = None
    secrets: dict[str, AccessTemplateSecretInput | None] | None = None
    change_note: str | None = Field(default=None, max_length=4000)

    @model_validator(mode="after")
    def require_change(self):
        if (
            self.protocol_variant is None
            and self.settings is None
            and self.secrets is None
            and self.change_note is None
        ):
            raise ValueError("At least one revision field must be supplied.")
        return self


class AccessTemplateCloneRequest(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=4000)
    visibility: Visibility = "PRIVATE"
    source_revision_id: UUID | None = None
    change_note: str | None = Field(default=None, max_length=4000)


class AccessTemplateRevisionRead(BaseModel):
    id: UUID
    template_id: UUID
    revision_number: int
    lifecycle_status: LifecycleStatus
    protocol_variant: str | None
    settings: dict[str, Any]
    source_revision_id: UUID | None
    change_note: str | None
    definition_sha256: str | None
    legacy_backfill: bool
    secret_providers: dict[str, Literal["ENCRYPTED_DATABASE", "ENV_REFERENCE"]]
    tested_at: datetime | None
    tested_by_user_id: UUID | None
    approved_at: datetime | None
    approved_by_user_id: UUID | None
    activated_at: datetime | None
    activated_by_user_id: UUID | None
    retired_at: datetime | None
    created_at: datetime
    updated_at: datetime


class AccessTemplateCloneRead(BaseModel):
    template_id: UUID
    revision: AccessTemplateRevisionRead


class AccessTemplateRevisionTestRead(BaseModel):
    id: UUID
    template_id: UUID
    revision_id: UUID
    device_id: UUID
    status: Literal["SUCCESS", "FAILED"]
    failure_code: str | None
    sanitized_message: str | None
    latency_ms: int | None
    tested_at: datetime
    tested_by_user_id: UUID | None
