from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator


Protocol = Literal["SNMP", "SSH", "TELNET", "WEB"]
Visibility = Literal["PRIVATE", "SHARED"]
SecretProvider = Literal["ENCRYPTED_DATABASE", "ENV_REFERENCE"]
ScopeType = Literal["DEVICE", "DEVICE_GROUP", "LOGICAL_SECTOR", "LOCATION", "NETWORK", "CITY"]
WebCredentialMode = Literal["USERNAME_PASSWORD", "PASSWORD_ONLY"]


class AccessTemplateSecretInput(BaseModel):
    provider: SecretProvider = "ENCRYPTED_DATABASE"
    value: str | None = Field(default=None, min_length=1, max_length=16384)
    reference: str | None = Field(default=None, max_length=255)

    @model_validator(mode="after")
    def validate_storage(self):
        if self.provider == "ENCRYPTED_DATABASE":
            if not self.value or self.reference is not None:
                raise ValueError("ENCRYPTED_DATABASE requires value and forbids reference")
        else:
            if self.value is not None or not self.reference or not self.reference.startswith("env://"):
                raise ValueError("ENV_REFERENCE requires an env:// reference and forbids value")
        return self


class AccessTemplateCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=4000)
    protocol: Protocol
    protocol_variant: str | None = Field(default=None, max_length=40)
    visibility: Visibility = "PRIVATE"
    is_active: bool = True
    settings: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, AccessTemplateSecretInput] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        return value.strip()


class AccessTemplateUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=4000)
    protocol_variant: str | None = Field(default=None, max_length=40)
    visibility: Visibility | None = None
    is_active: bool | None = None
    settings: dict[str, Any] | None = None
    secrets: dict[str, AccessTemplateSecretInput | None] | None = None


class AccessTemplateRead(BaseModel):
    id: UUID
    name: str
    description: str | None
    protocol: Protocol
    protocol_variant: str | None
    visibility: Visibility
    owner_user_id: UUID
    is_active: bool
    settings: dict[str, Any]
    secret_providers: dict[str, SecretProvider]
    created_at: datetime
    updated_at: datetime


class AccessTemplateAssignmentCreate(BaseModel):
    scope_type: ScopeType
    scope_id: UUID
    priority: int = Field(default=0, ge=-100000, le=100000)
    enabled: bool = True


class AccessTemplateAssignmentRead(BaseModel):
    id: UUID
    template_id: UUID
    scope_type: ScopeType
    scope_id: UUID
    priority: int
    enabled: bool
    created_by_user_id: UUID | None
    created_at: datetime
    updated_at: datetime


class EffectiveAccessRead(BaseModel):
    device_id: UUID
    protocol: Protocol
    status: Literal["RESOLVED", "NONE", "CONFLICT"]
    template_id: UUID | None = None
    template_name: str | None = None
    assignment_id: UUID | None = None
    scope_type: ScopeType | None = None
    priority: int | None = None


class AccessTemplateTestRequest(BaseModel):
    device_id: UUID
    trust_host_key: bool = False
    expected_fingerprint: str | None = Field(default=None, max_length=160)
    replace_existing: bool = False

    @field_validator("expected_fingerprint")
    @classmethod
    def validate_expected_fingerprint(cls, value: str | None) -> str | None:
        if value is None:
            return value
        normalized = value.strip()
        if not normalized.startswith("SHA256:"):
            raise ValueError("Expected SSH host-key fingerprint must use SHA256:<fingerprint> format.")
        return normalized

    @model_validator(mode="after")
    def validate_host_key_confirmation(self):
        if self.trust_host_key and not self.expected_fingerprint:
            raise ValueError("trust_host_key requires expected_fingerprint.")
        if self.replace_existing and not self.trust_host_key:
            raise ValueError("replace_existing requires trust_host_key.")
        return self


class AccessTemplateTestRead(BaseModel):
    id: UUID
    template_id: UUID
    device_id: UUID
    status: Literal["SUCCESS", "FAILED"]
    failure_code: str | None
    sanitized_message: str | None
    latency_ms: int | None
    tested_at: datetime
    tested_by_user_id: UUID | None


class WebTemplateDiscoveryRequest(BaseModel):
    management_ip: str = Field(min_length=3, max_length=64)
    credential_mode: WebCredentialMode = "USERNAME_PASSWORD"
    username: SecretStr | None = None
    password: SecretStr
    timeout_seconds: int = Field(default=10, ge=1, le=30)
    apply_reference_transport: bool = True

    @field_validator("management_ip")
    @classmethod
    def normalize_management_ip(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def validate_credentials(self):
        if self.credential_mode == "USERNAME_PASSWORD":
            if self.username is None or not self.username.get_secret_value():
                raise ValueError("Username is required for username + password discovery.")
        return self


class WebTemplateDiscoveryRead(BaseModel):
    device_id: UUID
    device_name: str
    vendor: str | None = None
    model: str | None = None
    management_ip: str
    scheme: Literal["HTTP", "HTTPS"]
    port: int
    auth_mode: Literal["FORM_POST", "HTTP_BASIC", "HTTP_DIGEST"]
    credential_mode: WebCredentialMode
    settings: dict[str, Any]
    landing_path: str
    form_encoding: str | None = None
    username_field: str | None = None
    password_field: str | None = None
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = "HIGH"
    reference_transport_applied: bool = False


class AccessTemplateWebPreviewRequest(BaseModel):
    device_id: UUID
