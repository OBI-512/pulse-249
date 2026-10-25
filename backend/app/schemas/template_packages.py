from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.configuration.contracts import ConfigurationTemplateDefinition


TemplateKind = Literal["ACCESS", "CONFIGURATION"]
QualificationStatus = Literal["UNQUALIFIED", "QUALIFIED", "DEPRECATED"]
QualificationScope = Literal["NONE", "DEFINITION_ONLY", "REAL_DEVICE"]
ConflictClassification = Literal[
    "NONE",
    "IDENTITY_CONFLICT",
    "PACKAGE_ALREADY_IMPORTED",
    "UNSUPPORTED_SCHEMA",
    "MINIMUM_VERSION_NOT_MET",
    "ADAPTER_NOT_AVAILABLE",
    "DEVICE_TYPE_NOT_AVAILABLE",
    "TELNET_DISABLED",
    "SECURITY_POLICY_REJECTED",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TemplatePackageProducer(_StrictModel):
    product: Literal["FTTW Network Management System"] = "FTTW Network Management System"
    application_version: str = Field(min_length=1, max_length=64)


class TemplatePackageFirmwareCompatibility(_StrictModel):
    mode: Literal["ANY", "EXACT", "RANGE", "SET"] = "ANY"
    exact: str | None = Field(default=None, max_length=160)
    minimum: str | None = Field(default=None, max_length=160)
    maximum: str | None = Field(default=None, max_length=160)
    values: list[str] = Field(default_factory=list, max_length=100)


class TemplatePackageCompatibility(_StrictModel):
    device_type_code: str | None = Field(default=None, max_length=50)
    vendor: str | None = Field(default=None, max_length=100)
    models: list[str] = Field(default_factory=list, max_length=100)
    series: list[str] = Field(default_factory=list, max_length=100)
    firmware: TemplatePackageFirmwareCompatibility = Field(
        default_factory=TemplatePackageFirmwareCompatibility
    )


class TemplatePackageQualification(_StrictModel):
    status: QualificationStatus = "UNQUALIFIED"
    scope: QualificationScope = "NONE"
    qualified_at: datetime | None = None
    tested_firmware: list[str] = Field(default_factory=list, max_length=100)
    notes: str | None = Field(default=None, max_length=4000)


class TemplatePackageProvenance(_StrictModel):
    source_family_key: str = Field(min_length=1, max_length=320)
    source_revision_number: int = Field(ge=1)
    source_lifecycle_status: str = Field(min_length=1, max_length=30)
    source_definition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class TemplatePackageManifest(_StrictModel):
    package_id: UUID
    package_version: str = Field(min_length=1, max_length=64)
    created_at: datetime
    minimum_fttw_version: str = Field(min_length=1, max_length=64)
    producer: TemplatePackageProducer
    template_kind: TemplateKind
    compatibility: TemplatePackageCompatibility
    qualification: TemplatePackageQualification
    provenance: TemplatePackageProvenance


class TemplatePackageIntegrity(_StrictModel):
    algorithm: Literal["SHA-256"] = "SHA-256"
    canonicalization: Literal["RFC8785"] = "RFC8785"
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class TemplatePackageV1(_StrictModel):
    format: Literal["FTTW_TEMPLATE_PACKAGE"]
    schema_version: Literal["1.0"]
    manifest: TemplatePackageManifest
    template: dict[str, Any]
    integrity: TemplatePackageIntegrity
    signatures: list[dict[str, Any]] = Field(default_factory=list)


class AccessPackageFamily(_StrictModel):
    name: str = Field(min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=4000)
    protocol: Literal["SNMP", "SSH", "TELNET", "WEB"]


class AccessPackageRevision(_StrictModel):
    protocol_variant: str | None = Field(default=None, max_length=40)
    settings: dict[str, Any] = Field(default_factory=dict)
    credential_slots: list[str] = Field(default_factory=list, max_length=32)
    change_note: str | None = Field(default=None, max_length=4000)


class AccessPackageTemplate(_StrictModel):
    family: AccessPackageFamily
    revision: AccessPackageRevision


class ConfigurationPackageFamily(_StrictModel):
    code: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    name: str = Field(min_length=1, max_length=160)
    vendor: str = Field(min_length=1, max_length=100)
    model: str | None = Field(default=None, max_length=150)
    series: str | None = Field(default=None, max_length=150)
    device_type_code: str = Field(min_length=1, max_length=50)
    description: str | None = Field(default=None, max_length=4000)


class ConfigurationPackageVersion(_StrictModel):
    definition: ConfigurationTemplateDefinition
    change_note: str | None = Field(default=None, max_length=1000)


class ConfigurationPackageTemplate(_StrictModel):
    family: ConfigurationPackageFamily
    version: ConfigurationPackageVersion


class TemplatePackageTargetOverrides(_StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    code: str | None = Field(
        default=None,
        min_length=2,
        max_length=80,
        pattern=r"^[A-Za-z0-9_.-]+$",
    )


class TemplatePackagePreviewRequest(_StrictModel):
    package: dict[str, Any]
    target: TemplatePackageTargetOverrides = Field(
        default_factory=TemplatePackageTargetOverrides
    )


class TemplatePackageImportRequest(TemplatePackagePreviewRequest):
    expected_package_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class TemplatePackagePreviewRead(_StrictModel):
    package_sha256: str
    schema_version: str
    template_kind: TemplateKind
    source_family_key: str
    source_revision_number: int
    compatibility: TemplatePackageCompatibility
    qualification: TemplatePackageQualification
    credential_slots: list[str] = Field(default_factory=list)
    adapter_key: str | None = None
    adapter_available: bool | None = None
    device_type_code: str | None = None
    device_type_available: bool | None = None
    target_name: str
    target_code: str | None = None
    warnings: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    conflict: ConflictClassification
    can_import: bool


class TemplatePackageImportRead(_StrictModel):
    package_sha256: str
    template_kind: TemplateKind
    template_id: UUID
    revision_or_version_id: UUID
    local_status: Literal["DRAFT"] = "DRAFT"
    target_name: str
    target_code: str | None = None
