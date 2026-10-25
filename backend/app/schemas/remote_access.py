from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator


SSH_COMPATIBILITY_PROFILES = {"MODERN", "LEGACY_SSH_RSA_DH1_CBC"}
WEB_SCHEMES = {"HTTP", "HTTPS"}
WEB_TLS_MODES = {"SYSTEM", "PRIVATE_CA", "PINNED_CERT"}
WEB_TLS_COMPAT_PROFILES = {"MODERN", "LEGACY_WEAK_CERT_KEY"}


def _normalize_web_tls_compatibility(value: str | None) -> str | None:
    if value is None:
        return value
    normalized = value.strip().upper()
    if normalized not in WEB_TLS_COMPAT_PROFILES:
        raise ValueError("Unsupported Web-GUI TLS compatibility profile.")
    return normalized


def _normalize_certificate_sha256(value: str) -> str:
    normalized = value.strip().lower().replace(":", "")
    if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise ValueError("Certificate SHA-256 fingerprint must contain exactly 64 hexadecimal characters.")
    return normalized


class DeviceRemoteAccessUpdate(BaseModel):
    ssh_enabled: bool | None = None
    ssh_port: int | None = Field(default=None, ge=1, le=65535)
    ssh_compatibility_profile: str | None = Field(default=None, max_length=40)
    ssh_username_reference: str | None = Field(default=None, max_length=255)
    ssh_password_reference: str | None = Field(default=None, max_length=255)
    ssh_private_key_reference: str | None = Field(default=None, max_length=255)
    ssh_host_key_fingerprint: str | None = Field(default=None, max_length=160)
    clear_password_reference: bool = False
    clear_private_key_reference: bool = False

    web_enabled: bool | None = None
    web_scheme: str | None = Field(default=None, max_length=8)
    web_port: int | None = Field(default=None, ge=1, le=65535)
    web_tls_mode: str | None = Field(default=None, max_length=20)
    web_tls_compat_profile: str | None = Field(default=None, max_length=32)
    web_tls_ca_reference: str | None = Field(default=None, max_length=255)
    web_tls_pinned_certificate_reference: str | None = Field(default=None, max_length=255)
    clear_web_tls_ca_reference: bool = False
    clear_web_tls_pinned_certificate_reference: bool = False

    @field_validator("ssh_compatibility_profile")
    @classmethod
    def validate_compatibility_profile(cls, value: str | None) -> str | None:
        if value is None:
            return value
        normalized = value.strip().upper()
        if normalized not in SSH_COMPATIBILITY_PROFILES:
            raise ValueError("Unsupported SSH compatibility profile.")
        return normalized

    @field_validator("web_scheme")
    @classmethod
    def validate_web_scheme(cls, value: str | None) -> str | None:
        if value is None:
            return value
        normalized = value.strip().upper()
        if normalized not in WEB_SCHEMES:
            raise ValueError("Web-GUI scheme must be HTTP or HTTPS.")
        return normalized

    @field_validator("web_tls_mode")
    @classmethod
    def validate_web_tls_mode(cls, value: str | None) -> str | None:
        if value is None:
            return value
        normalized = value.strip().upper()
        if normalized not in WEB_TLS_MODES:
            raise ValueError("Unsupported Web-GUI TLS trust mode.")
        return normalized

    @field_validator("web_tls_compat_profile")
    @classmethod
    def validate_web_tls_compat_profile(cls, value: str | None) -> str | None:
        return _normalize_web_tls_compatibility(value)

    @field_validator(
        "ssh_username_reference",
        "ssh_password_reference",
        "ssh_private_key_reference",
        "web_tls_ca_reference",
        "web_tls_pinned_certificate_reference",
    )
    @classmethod
    def validate_env_reference(cls, value: str | None) -> str | None:
        if value is None:
            return value
        normalized = value.strip()
        if not normalized.startswith("env://") or len(normalized) <= len("env://"):
            raise ValueError("Remote-access references must use env://VARIABLE references.")
        return normalized

    @field_validator("ssh_host_key_fingerprint")
    @classmethod
    def validate_fingerprint(cls, value: str | None) -> str | None:
        if value is None:
            return value
        normalized = value.strip()
        if normalized and not normalized.startswith("SHA256:"):
            raise ValueError("SSH host-key fingerprint must use SHA256:<fingerprint> format.")
        return normalized or None


class DeviceRemoteAccessRead(BaseModel):
    device_id: UUID
    ssh_enabled: bool
    ssh_port: int
    ssh_compatibility_profile: str
    ssh_host_key_fingerprint: str | None
    username_reference_configured: bool
    password_reference_configured: bool
    private_key_reference_configured: bool
    ready: bool


class DeviceWebRemoteAccessRead(BaseModel):
    device_id: UUID
    web_enabled: bool
    web_scheme: str
    web_port: int | None
    effective_web_port: int
    web_tls_mode: str
    web_tls_compat_profile: str
    tls_ca_reference_configured: bool
    tls_pinned_certificate_reference_configured: bool
    internal_tls_trust_configured: bool = False
    internal_tls_trust_fingerprint: str | None = None
    ready: bool


class DeviceAccessCapabilityRead(BaseModel):
    available: bool = False
    ready: bool = False
    reason_code: str | None = None


class DeviceAccessCapabilitiesRead(BaseModel):
    device_id: UUID
    secure_web: DeviceAccessCapabilityRead
    ssh: DeviceAccessCapabilityRead
    telnet: DeviceAccessCapabilityRead


class WebTLSInspectRequest(BaseModel):
    port: int = Field(default=443, ge=1, le=65535)
    compatibility_profile: str = Field(default="MODERN", max_length=32)

    @field_validator("compatibility_profile")
    @classmethod
    def validate_compatibility_profile(cls, value: str) -> str:
        return _normalize_web_tls_compatibility(value) or "MODERN"


class WebTLSTrustRequest(WebTLSInspectRequest):
    expected_certificate_sha256: str = Field(min_length=64, max_length=95)

    @field_validator("expected_certificate_sha256")
    @classmethod
    def validate_expected_certificate_sha256(cls, value: str) -> str:
        return _normalize_certificate_sha256(value)


class WebTLSReplaceRequest(WebTLSInspectRequest):
    current_certificate_sha256: str = Field(min_length=64, max_length=95)
    expected_new_certificate_sha256: str = Field(min_length=64, max_length=95)
    acknowledge_certificate_change: bool

    @field_validator("current_certificate_sha256", "expected_new_certificate_sha256")
    @classmethod
    def validate_certificate_sha256(cls, value: str) -> str:
        return _normalize_certificate_sha256(value)

    @model_validator(mode="after")
    def validate_acknowledgement(self):
        if self.acknowledge_certificate_change is not True:
            raise ValueError("Explicit certificate-change acknowledgement is required.")
        return self


class WebTLSCertificateInspectionRead(BaseModel):
    device_id: UUID
    device_name: str
    management_ip: str
    port: int
    compatibility_profile: str
    certificate_sha256: str
    subject: str
    issuer: str
    serial_number: str
    not_valid_before: datetime
    not_valid_after: datetime
    san_dns: list[str]
    san_ip: list[str]
    self_signed: bool
    validity_state: Literal["VALID", "EXPIRED", "NOT_YET_VALID"]
    current_trusted_certificate_sha256: str | None = None
    trust_relation: Literal["UNTRUSTED", "MATCH", "MISMATCH"]
    credentials_sent: Literal[False] = False
    application_data_sent: Literal[False] = False
    observed_at: datetime


class WebTLSTrustRead(BaseModel):
    trust_id: UUID
    device_id: UUID
    management_ip: str
    port: int
    compatibility_profile: str
    certificate_sha256: str
    subject: str
    issuer: str
    serial_number: str
    not_valid_before: datetime
    not_valid_after: datetime
    san_dns: list[str]
    san_ip: list[str]
    status: Literal["ACTIVE", "SUPERSEDED", "REVOKED"]
    trusted_at: datetime
    supersedes_trust_id: UUID | None = None


class SSHSessionActionRequest(BaseModel):
    action: Literal["LAUNCH", "DISCOVER_HOST_KEY", "TRUST_HOST_KEY"] = "LAUNCH"
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
    def validate_action(self):
        if self.action == "TRUST_HOST_KEY" and not self.expected_fingerprint:
            raise ValueError("TRUST_HOST_KEY requires expected_fingerprint.")
        if self.action != "TRUST_HOST_KEY" and self.replace_existing:
            raise ValueError("replace_existing is valid only for TRUST_HOST_KEY.")
        return self


class SSHHostKeyActionResponse(BaseModel):
    action: Literal["DISCOVER_HOST_KEY", "TRUST_HOST_KEY"]
    device_id: UUID
    template_id: UUID
    template_name: str
    fingerprint: str
    key_type: str
    port: int
    compatibility_profile: str
    pinned_fingerprint: str | None
    trust_state: Literal["NEW", "MATCH", "MISMATCH"]


class RemoteAccessLaunchResponse(BaseModel):
    session_id: UUID
    ticket: str
    expires_at: datetime
    websocket_path: str = "/ws/ssh"


class WebRemoteAccessLaunchResponse(BaseModel):
    session_id: UUID
    ticket: str
    expires_at: datetime


class RemoteAccessRevokeResponse(BaseModel):
    session_id: UUID
    status: str
