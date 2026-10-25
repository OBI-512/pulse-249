from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class ConfigurationTemplateVersionCloneRequest(BaseModel):
    change_note: str | None = Field(default=None, max_length=1000)


class ConfigurationTemplateFamilyCloneRequest(BaseModel):
    code: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    name: str = Field(min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=4000)
    change_note: str | None = Field(default=None, max_length=1000)


class ConfigurationTemplateVersionLifecycleRead(BaseModel):
    template_id: UUID
    version_id: UUID
    version_number: int
    status: str
    source_version_id: UUID | None
    tested_definition_sha256: str | None
    tested_at: datetime | None
    tested_by_user_id: UUID | None
    approved_at: datetime | None
    approved_by_user_id: UUID | None
    content_sha256: str | None
    published_at: datetime | None
    published_by_user_id: UUID | None


class ConfigurationTemplateFamilyCloneRead(BaseModel):
    template_id: UUID
    version_id: UUID
    version_number: int
    status: str
    source_version_id: UUID
