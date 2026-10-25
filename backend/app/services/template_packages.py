from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
import os
import re
from typing import Any
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.configuration.registry import registry
from app.configuration.templating import ConfigurationTemplateError
from app.core.exceptions import APIError
from app.models import (
    AccessTemplate,
    AccessTemplateAssignment,
    AccessTemplateRevision,
    AccessTemplateTestResult,
    ConfigurationOperation,
    ConfigurationSnapshot,
    ConfigurationTemplate,
    ConfigurationTemplateVersion,
    DeviceConfigurationBinding,
    DeviceType,
)
from app.schemas.configuration import ConfigurationTemplateCreate
from app.schemas.template_packages import (
    AccessPackageTemplate,
    ConfigurationPackageTemplate,
    TemplateKind,
    TemplatePackageCompatibility,
    TemplatePackageImportRead,
    TemplatePackageManifest,
    TemplatePackagePreviewRead,
    TemplatePackageQualification,
    TemplatePackageTargetOverrides,
    TemplatePackageV1,
)
from app.services.access_template_lifecycle import (
    create_template_family,
    revision_secret_rows,
)
from app.services.access_templates import validate_template_definition
from app.services.audit import record_audit
from app.services.configuration import (
    _definition_from_version,
    _functions_for_version,
    create_template,
)
from app.settings import settings


UTC = timezone.utc
PACKAGE_FORMAT = "FTTW_TEMPLATE_PACKAGE"
PACKAGE_SCHEMA_VERSION = "1.0"
PACKAGE_MEDIA_TYPE = "application/vnd.fttw.template-package+json"
PACKAGE_VERSION = "1.0.0"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_ACCESS_CREDENTIAL_KEYS = frozenset(
    {
        "username",
        "password",
        "private_key",
        "private_key_passphrase",
        "community",
        "security_name",
        "auth_secret",
        "privacy_secret",
    }
)
_FORBIDDEN_PORTABLE_KEYS = frozenset(
    {
        "encrypted_payload",
        "secret_provider",
        "secret_providers",
        "credential_reference",
        "secret_reference",
        "host_key_fingerprint",
        "ssh_host_key_fingerprint",
        "ssh_host_key_line",
        "pinned_certificate",
        "pinned_certificate_reference",
        "tls_ca_reference",
        "tls_ca_bundle",
        "capability_token",
        "session_token",
        "session_nonce",
        "artifact_payload",
        "snapshot_payload",
        "artifact_path",
        "artifact_reference",
    }
)


def application_version() -> str:
    return os.getenv("FTTW_APPLICATION_VERSION", "1.4.0").strip() or "1.4.0"


def _json_string(value: str) -> str:
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise ValueError("RFC8785 does not permit lone surrogate code points.") from exc
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _canonical_float(value: float) -> str:
    if not math.isfinite(value):
        raise ValueError("RFC8785 does not permit NaN or Infinity.")
    if value == 0:
        return "0"
    negative = value < 0
    absolute = -value if negative else value
    rendered = repr(absolute).lower()
    sign = "-" if negative else ""
    if "e" not in rendered:
        if rendered.endswith(".0"):
            rendered = rendered[:-2]
        return sign + rendered

    mantissa, exponent_text = rendered.split("e", 1)
    exponent = int(exponent_text)
    digits = mantissa.replace(".", "")
    decimal_index = (mantissa.find(".") if "." in mantissa else len(mantissa)) + exponent

    if 1e-6 <= absolute < 1e21:
        if decimal_index <= 0:
            fixed = "0." + ("0" * (-decimal_index)) + digits
        elif decimal_index >= len(digits):
            fixed = digits + ("0" * (decimal_index - len(digits)))
        else:
            fixed = digits[:decimal_index] + "." + digits[decimal_index:]
        if "." in fixed:
            fixed = fixed.rstrip("0").rstrip(".")
        return sign + fixed

    scientific_digits = digits.rstrip("0") or "0"
    scientific_exponent = exponent + (
        (mantissa.find(".") if "." in mantissa else len(mantissa)) - 1
    )
    if len(scientific_digits) == 1:
        scientific = scientific_digits
    else:
        scientific = scientific_digits[0] + "." + scientific_digits[1:]
    exponent_sign = "+" if scientific_exponent >= 0 else "-"
    return f"{sign}{scientific}e{exponent_sign}{abs(scientific_exponent)}"


def rfc8785_canonical_json(value: Any) -> str:
    """Return RFC8785/JCS canonical JSON for package integrity.

    Package data is normal JSON data. Object keys are ordered by UTF-16 code
    units, strings use JSON escaping without ASCII forcing, and numbers use the
    ECMAScript-compatible shortest finite representation required by JCS.
    """

    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _json_string(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _canonical_float(value)
    if isinstance(value, list):
        return "[" + ",".join(rfc8785_canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("RFC8785 object keys must be strings.")
        keys = sorted(
            value,
            key=lambda item: item.encode("utf-16be", "surrogatepass"),
        )
        return "{" + ",".join(
            _json_string(key) + ":" + rfc8785_canonical_json(value[key])
            for key in keys
        ) + "}"
    raise ValueError(f"Unsupported RFC8785 value type: {type(value).__name__}")


def package_digest_target(package: dict[str, Any]) -> dict[str, Any]:
    return {
        "format": package.get("format"),
        "schema_version": package.get("schema_version"),
        "manifest": package.get("manifest"),
        "template": package.get("template"),
    }


def package_sha256(package: dict[str, Any]) -> str:
    canonical = rfc8785_canonical_json(package_digest_target(package))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def portable_definition_sha256(payload: dict[str, Any]) -> str:
    canonical = rfc8785_canonical_json(payload)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _semver(value: str) -> tuple[int, int, int, tuple[tuple[int, int | str], ...] | None]:
    match = _SEMVER_RE.fullmatch(value.strip())
    if match is None:
        raise APIError(
            422,
            "TEMPLATE_PACKAGE_SEMVER_INVALID",
            "Template package version fields must use semantic versioning.",
        )
    major, minor, patch = (int(match.group(index)) for index in (1, 2, 3))
    prerelease = match.group(4)
    parsed_prerelease: tuple[tuple[int, int | str], ...] | None = None
    if prerelease is not None:
        items: list[tuple[int, int | str]] = []
        for item in prerelease.split("."):
            if item.isdigit():
                if len(item) > 1 and item.startswith("0"):
                    raise APIError(
                        422,
                        "TEMPLATE_PACKAGE_SEMVER_INVALID",
                        "Numeric semantic-version prerelease identifiers must not contain leading zeros.",
                    )
                items.append((0, int(item)))
            else:
                items.append((1, item))
        parsed_prerelease = tuple(items)
    return major, minor, patch, parsed_prerelease


def _semver_less_than(left: str, right: str) -> bool:
    l_major, l_minor, l_patch, l_pre = _semver(left)
    r_major, r_minor, r_patch, r_pre = _semver(right)
    if (l_major, l_minor, l_patch) != (r_major, r_minor, r_patch):
        return (l_major, l_minor, l_patch) < (r_major, r_minor, r_patch)
    if l_pre is None:
        return False if r_pre is None else False
    if r_pre is None:
        return True
    for l_item, r_item in zip(l_pre, r_pre):
        if l_item == r_item:
            continue
        if l_item[0] != r_item[0]:
            return l_item[0] < r_item[0]
        return l_item[1] < r_item[1]
    return len(l_pre) < len(r_pre)


def _walk_portable_security(value: Any, *, access_payload: bool, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for raw_key, child in value.items():
            key = str(raw_key).strip().lower()
            if key in _FORBIDDEN_PORTABLE_KEYS:
                raise APIError(
                    422,
                    "TEMPLATE_PACKAGE_SECURITY_POLICY_REJECTED",
                    "Template package contains deployment-specific secret, trust, or artifact material.",
                )
            if access_payload and key in {"provider", "reference", "key_version"}:
                raise APIError(
                    422,
                    "TEMPLATE_PACKAGE_SECURITY_POLICY_REJECTED",
                    "Access Template packages may contain credential slot names only, not provider/reference metadata.",
                )
            if access_payload and path and path[-1] == "settings" and key in _ACCESS_CREDENTIAL_KEYS:
                raise APIError(
                    422,
                    "TEMPLATE_PACKAGE_SECURITY_POLICY_REJECTED",
                    "Access Template credential values must not be stored in package settings.",
                )
            _walk_portable_security(
                child,
                access_payload=access_payload,
                path=path + (key,),
            )
    elif isinstance(value, list):
        for item in value:
            _walk_portable_security(item, access_payload=access_payload, path=path)
    elif isinstance(value, str):
        lowered = value.lower()
        if "env://" in lowered or "-----begin private key-----" in lowered:
            raise APIError(
                422,
                "TEMPLATE_PACKAGE_SECURITY_POLICY_REJECTED",
                "Template package contains a prohibited secret/deployment reference.",
            )


def _schema_error(message: str = "Template package does not match the frozen V1 schema.") -> APIError:
    return APIError(422, "TEMPLATE_PACKAGE_SCHEMA_INVALID", message)


def _typed_package(raw_package: dict[str, Any]) -> tuple[TemplatePackageV1, AccessPackageTemplate | ConfigurationPackageTemplate, str]:
    if not isinstance(raw_package, dict):
        raise _schema_error()
    if raw_package.get("format") != PACKAGE_FORMAT:
        raise _schema_error("Template package format is invalid.")
    if raw_package.get("schema_version") != PACKAGE_SCHEMA_VERSION:
        raise APIError(
            422,
            "TEMPLATE_PACKAGE_SCHEMA_UNSUPPORTED",
            "Only FTTW Template Package schema version 1.0 is supported.",
        )
    if raw_package.get("signatures") not in ([], None):
        raise APIError(
            422,
            "TEMPLATE_PACKAGE_SIGNATURE_UNSUPPORTED",
            "Digital signatures are reserved and must be empty in V1 packages.",
        )
    integrity = raw_package.get("integrity")
    if not isinstance(integrity, dict):
        raise _schema_error("Template package integrity block is required.")
    if integrity.get("algorithm") != "SHA-256" or integrity.get("canonicalization") != "RFC8785":
        raise APIError(
            422,
            "TEMPLATE_PACKAGE_INTEGRITY_UNSUPPORTED",
            "V1 packages require SHA-256 over RFC8785 canonical JSON.",
        )
    expected = integrity.get("sha256")
    if not isinstance(expected, str) or _SHA256_RE.fullmatch(expected) is None:
        raise _schema_error("Template package SHA-256 is invalid.")
    try:
        actual = package_sha256(raw_package)
    except (TypeError, ValueError) as exc:
        raise _schema_error("Template package cannot be RFC8785-canonicalized.") from exc
    if actual != expected:
        raise APIError(
            422,
            "TEMPLATE_PACKAGE_INTEGRITY_FAILED",
            "Template package integrity verification failed.",
        )
    try:
        package = TemplatePackageV1.model_validate(raw_package)
    except ValidationError as exc:
        raise _schema_error() from exc
    if package.signatures:
        raise APIError(
            422,
            "TEMPLATE_PACKAGE_SIGNATURE_UNSUPPORTED",
            "Digital signatures are reserved and must be empty in V1 packages.",
        )
    if package.manifest.created_at.tzinfo is None:
        raise _schema_error("manifest.created_at must be an RFC3339 timestamp with timezone.")
    _semver(package.manifest.package_version)
    _semver(package.manifest.minimum_fttw_version)

    try:
        if package.manifest.template_kind == "ACCESS":
            payload: AccessPackageTemplate | ConfigurationPackageTemplate = (
                AccessPackageTemplate.model_validate(package.template)
            )
        else:
            payload = ConfigurationPackageTemplate.model_validate(package.template)
    except ValidationError as exc:
        raise _schema_error("Template payload does not match its declared template kind.") from exc

    portable_payload = payload.model_dump(mode="json")
    _walk_portable_security(
        portable_payload,
        access_payload=package.manifest.template_kind == "ACCESS",
    )
    definition_hash = portable_definition_sha256(portable_payload)
    if package.manifest.provenance.source_definition_sha256 != definition_hash:
        raise APIError(
            422,
            "TEMPLATE_PACKAGE_PROVENANCE_INVALID",
            "Package provenance definition hash does not match the portable template definition.",
        )
    return package, payload, actual


def template_kind_from_raw(raw_package: dict[str, Any]) -> TemplateKind:
    try:
        kind = raw_package["manifest"]["template_kind"]
    except (KeyError, TypeError):
        raise _schema_error("Template package manifest.template_kind is required.")
    if kind not in {"ACCESS", "CONFIGURATION"}:
        raise _schema_error("Template package manifest.template_kind is invalid.")
    return kind


def _sanitized_portable_metadata(
    package: TemplatePackageV1,
    *,
    package_hash: str,
    credential_slots: list[str] | None = None,
) -> dict[str, Any]:
    portable: dict[str, Any] = {
        "compatibility": package.manifest.compatibility.model_dump(mode="json"),
        "upstream_qualification": package.manifest.qualification.model_dump(mode="json"),
        "package_provenance": {
            "package_id": str(package.manifest.package_id),
            "package_version": package.manifest.package_version,
            "package_sha256": package_hash,
            "source_definition_sha256": package.manifest.provenance.source_definition_sha256,
        },
    }
    if credential_slots is not None:
        portable["credential_slots"] = list(credential_slots)
    return {"portable": portable}


def sanitized_portable_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    """Return only the bounded portable namespace when cloning a family."""
    value = dict(metadata or {})
    portable = value.get("portable")
    if not isinstance(portable, dict):
        return {}
    allowed: dict[str, Any] = {}
    for key in (
        "compatibility",
        "upstream_qualification",
        "package_provenance",
        "credential_slots",
    ):
        if key in portable:
            allowed[key] = portable[key]
    try:
        _walk_portable_security(allowed, access_payload=False)
    except APIError:
        return {}
    return {"portable": allowed}


def _stored_portable(metadata: dict[str, Any] | None) -> dict[str, Any]:
    portable = dict(metadata or {}).get("portable")
    return portable if isinstance(portable, dict) else {}


def _qualification_for_export(
    metadata: dict[str, Any] | None,
    *,
    current_definition_hash: str,
) -> TemplatePackageQualification:
    portable = _stored_portable(metadata)
    provenance = portable.get("package_provenance")
    qualification = portable.get("upstream_qualification")
    if not isinstance(provenance, dict) or not isinstance(qualification, dict):
        return TemplatePackageQualification()
    if provenance.get("source_definition_sha256") != current_definition_hash:
        return TemplatePackageQualification(
            status="UNQUALIFIED",
            scope="NONE",
            notes="Definition changed after the recorded upstream package provenance.",
        )
    try:
        return TemplatePackageQualification.model_validate(qualification)
    except ValidationError:
        return TemplatePackageQualification()


def _compatibility_for_access(metadata: dict[str, Any] | None) -> TemplatePackageCompatibility:
    compatibility = _stored_portable(metadata).get("compatibility")
    if isinstance(compatibility, dict):
        try:
            return TemplatePackageCompatibility.model_validate(compatibility)
        except ValidationError:
            pass
    return TemplatePackageCompatibility()


def _firmware_from_metadata(metadata: dict[str, Any] | None) -> dict[str, Any] | None:
    compatibility = _stored_portable(metadata).get("compatibility")
    if isinstance(compatibility, dict):
        firmware = compatibility.get("firmware")
        if isinstance(firmware, dict):
            return firmware
    return None


def _build_package(
    *,
    template_kind: TemplateKind,
    payload: dict[str, Any],
    compatibility: TemplatePackageCompatibility,
    qualification: TemplatePackageQualification,
    source_family_key: str,
    source_revision_number: int,
    source_lifecycle_status: str,
) -> dict[str, Any]:
    version = application_version()
    _semver(version)
    definition_hash = portable_definition_sha256(payload)
    manifest = TemplatePackageManifest(
        package_id=uuid4(),
        package_version=PACKAGE_VERSION,
        created_at=datetime.now(UTC),
        minimum_fttw_version=version,
        producer={
            "product": "FTTW Network Management System",
            "application_version": version,
        },
        template_kind=template_kind,
        compatibility=compatibility,
        qualification=qualification,
        provenance={
            "source_family_key": source_family_key,
            "source_revision_number": source_revision_number,
            "source_lifecycle_status": source_lifecycle_status,
            "source_definition_sha256": definition_hash,
        },
    )
    package: dict[str, Any] = {
        "format": PACKAGE_FORMAT,
        "schema_version": PACKAGE_SCHEMA_VERSION,
        "manifest": manifest.model_dump(mode="json"),
        "template": payload,
    }
    package["integrity"] = {
        "algorithm": "SHA-256",
        "canonicalization": "RFC8785",
        "sha256": package_sha256(package),
    }
    package["signatures"] = []
    return package


async def _visible_access_family(
    db: AsyncSession,
    *,
    template_id: UUID,
    actor_user_id: UUID,
) -> AccessTemplate:
    family = await db.scalar(
        select(AccessTemplate).where(
            AccessTemplate.id == template_id,
            AccessTemplate.deleted_at.is_(None),
            (AccessTemplate.owner_user_id == actor_user_id)
            | (AccessTemplate.visibility == "SHARED"),
        )
    )
    if family is None:
        raise APIError(404, "ACCESS_TEMPLATE_NOT_FOUND", "Access Template not found.")
    return family


async def _access_source_revision(
    db: AsyncSession,
    *,
    template_id: UUID,
    source_id: UUID | None,
) -> AccessTemplateRevision:
    stmt = select(AccessTemplateRevision).where(
        AccessTemplateRevision.template_id == template_id
    )
    if source_id is None:
        stmt = stmt.where(AccessTemplateRevision.lifecycle_status == "ACTIVE").order_by(
            AccessTemplateRevision.revision_number.desc()
        )
    else:
        stmt = stmt.where(AccessTemplateRevision.id == source_id)
    revision = await db.scalar(stmt.limit(1))
    if revision is None:
        if source_id is None:
            raise APIError(
                409,
                "TEMPLATE_PACKAGE_SOURCE_REQUIRED",
                "Access Template has no ACTIVE revision; select an exact source revision.",
            )
        raise APIError(404, "ACCESS_TEMPLATE_REVISION_NOT_FOUND", "Access Template revision not found.")
    return revision


async def _configuration_source(
    db: AsyncSession,
    *,
    template_id: UUID,
    source_id: UUID | None,
) -> tuple[ConfigurationTemplate, ConfigurationTemplateVersion]:
    family = await db.get(ConfigurationTemplate, template_id)
    if family is None:
        raise APIError(404, "CONFIGURATION_TEMPLATE_NOT_FOUND", "Configuration template not found.")
    stmt = select(ConfigurationTemplateVersion).where(
        ConfigurationTemplateVersion.template_id == template_id
    )
    if source_id is None:
        stmt = stmt.where(ConfigurationTemplateVersion.status == "PUBLISHED").order_by(
            ConfigurationTemplateVersion.version_number.desc()
        )
    else:
        stmt = stmt.where(ConfigurationTemplateVersion.id == source_id)
    version = await db.scalar(stmt.limit(1))
    if version is None:
        if source_id is None:
            raise APIError(
                409,
                "TEMPLATE_PACKAGE_SOURCE_REQUIRED",
                "Configuration Template has no PUBLISHED version; select an exact source version.",
            )
        raise APIError(
            404,
            "CONFIGURATION_TEMPLATE_VERSION_NOT_FOUND",
            "Configuration template version not found.",
        )
    return family, version


async def export_template_package(
    db: AsyncSession,
    *,
    template_kind: TemplateKind,
    template_id: UUID,
    source_id: UUID | None,
    actor_user_id: UUID,
) -> dict[str, Any]:
    if template_kind == "ACCESS":
        family = await _visible_access_family(
            db,
            template_id=template_id,
            actor_user_id=actor_user_id,
        )
        revision = await _access_source_revision(
            db,
            template_id=family.id,
            source_id=source_id,
        )
        rows = await revision_secret_rows(db, revision.id)
        actual_slots = sorted({row.secret_key for row in rows})
        payload_without_slots = {
            "family": {
                "name": family.name,
                "description": family.description,
                "protocol": family.protocol,
            },
            "revision": {
                "protocol_variant": revision.protocol_variant,
                "settings": dict(revision.settings_json or {}),
                "credential_slots": actual_slots,
                "change_note": revision.change_note,
            },
        }
        stored_slots = _stored_portable(family.metadata_).get("credential_slots")
        if not actual_slots and isinstance(stored_slots, list):
            candidate = sorted({str(item) for item in stored_slots})
            candidate_payload = {
                **payload_without_slots,
                "revision": {
                    **payload_without_slots["revision"],
                    "credential_slots": candidate,
                },
            }
            provenance = _stored_portable(family.metadata_).get("package_provenance")
            if (
                isinstance(provenance, dict)
                and provenance.get("source_definition_sha256")
                == portable_definition_sha256(candidate_payload)
            ):
                payload_without_slots = candidate_payload
        payload_model = AccessPackageTemplate.model_validate(payload_without_slots)
        payload = payload_model.model_dump(mode="json")
        definition_hash = portable_definition_sha256(payload)
        compatibility = _compatibility_for_access(family.metadata_)
        qualification = _qualification_for_export(
            family.metadata_, current_definition_hash=definition_hash
        )
        return _build_package(
            template_kind="ACCESS",
            payload=payload,
            compatibility=compatibility,
            qualification=qualification,
            source_family_key=f"{family.protocol}:{family.name}",
            source_revision_number=revision.revision_number,
            source_lifecycle_status=revision.lifecycle_status,
        )

    family, version_row = await _configuration_source(
        db,
        template_id=template_id,
        source_id=source_id,
    )
    device_type = await db.get(DeviceType, family.device_type_id)
    if device_type is None:
        raise APIError(
            409,
            "TEMPLATE_PACKAGE_DEVICE_TYPE_NOT_AVAILABLE",
            "Configuration Template device type is unavailable.",
        )
    functions = await _functions_for_version(db, version_row.id)
    definition = _definition_from_version(version_row, functions)
    payload_model = ConfigurationPackageTemplate(
        family={
            "code": family.code,
            "name": family.name,
            "vendor": family.vendor,
            "model": family.model,
            "series": family.series,
            "device_type_code": device_type.code,
            "description": family.description,
        },
        version={
            "definition": definition,
            "change_note": version_row.change_note,
        },
    )
    payload = payload_model.model_dump(mode="json")
    definition_hash = portable_definition_sha256(payload)
    stored_compatibility = _stored_portable(family.metadata_).get("compatibility")
    firmware = _firmware_from_metadata(family.metadata_)
    compatibility = TemplatePackageCompatibility(
        device_type_code=device_type.code,
        vendor=family.vendor,
        models=[family.model] if family.model else [],
        series=[family.series] if family.series else [],
        firmware=firmware or {},
    )
    if isinstance(stored_compatibility, dict):
        # Family semantics remain authoritative while firmware qualification can
        # preserve a sanitized imported compatibility statement.
        compatibility = compatibility.model_copy(
            update={"firmware": compatibility.firmware}
        )
    qualification = _qualification_for_export(
        family.metadata_, current_definition_hash=definition_hash
    )
    return _build_package(
        template_kind="CONFIGURATION",
        payload=payload,
        compatibility=compatibility,
        qualification=qualification,
        source_family_key=family.code,
        source_revision_number=version_row.version_number,
        source_lifecycle_status=version_row.status,
    )


async def _package_already_imported(
    db: AsyncSession,
    *,
    package: TemplatePackageV1,
    actor_user_id: UUID,
) -> bool:
    package_id = str(package.manifest.package_id)
    if package.manifest.template_kind == "ACCESS":
        rows = list(
            (
                await db.scalars(
                    select(AccessTemplate).where(
                        AccessTemplate.owner_user_id == actor_user_id,
                        AccessTemplate.deleted_at.is_(None),
                    )
                )
            ).all()
        )
    else:
        rows = list((await db.scalars(select(ConfigurationTemplate))).all())
    for row in rows:
        provenance = _stored_portable(row.metadata_).get("package_provenance")
        if isinstance(provenance, dict) and provenance.get("package_id") == package_id:
            return True
    return False


async def preview_template_package(
    db: AsyncSession,
    *,
    raw_package: dict[str, Any],
    target: TemplatePackageTargetOverrides,
    actor_user_id: UUID,
) -> TemplatePackagePreviewRead:
    package, payload, package_hash = _typed_package(raw_package)
    minimum_version = package.manifest.minimum_fttw_version
    current_version = application_version()
    _semver(current_version)

    warnings: list[str] = []
    blockers: list[str] = []
    conflict = "NONE"
    credential_slots: list[str] = []
    adapter_key: str | None = None
    adapter_available: bool | None = None
    device_type_code: str | None = None
    device_type_available: bool | None = None

    if _semver_less_than(current_version, minimum_version):
        blockers.append("MINIMUM_VERSION_NOT_MET")
        conflict = "MINIMUM_VERSION_NOT_MET"

    if package.manifest.template_kind == "ACCESS":
        assert isinstance(payload, AccessPackageTemplate)
        if target.code is not None:
            raise APIError(
                422,
                "TEMPLATE_PACKAGE_TARGET_OVERRIDE_INVALID",
                "Access Template package imports accept a name override only.",
            )
        target_name = (target.name or payload.family.name).strip()
        if not target_name:
            raise APIError(
                422,
                "TEMPLATE_PACKAGE_TARGET_OVERRIDE_INVALID",
                "Target Access Template name must not be empty.",
            )
        credential_slots = list(payload.revision.credential_slots)
        if credential_slots != sorted(set(credential_slots)):
            raise _schema_error("Access credential_slots must be a sorted set.")
        try:
            validate_template_definition(
                protocol=payload.family.protocol,
                protocol_variant=payload.revision.protocol_variant,
                template_settings=dict(payload.revision.settings),
                secret_keys=set(credential_slots),
                is_active=False,
            )
        except APIError as exc:
            raise APIError(
                422,
                "TEMPLATE_PACKAGE_DEFINITION_INVALID",
                "Access Template package definition is invalid.",
                details={"definition_error": exc.code},
            ) from exc
        if payload.family.protocol == "TELNET" and not settings.telnet_access_enabled:
            blockers.append("TELNET_DISABLED")
            if conflict == "NONE":
                conflict = "TELNET_DISABLED"
        duplicate_identity = await db.scalar(
            select(AccessTemplate.id).where(
                AccessTemplate.owner_user_id == actor_user_id,
                AccessTemplate.name == target_name,
                AccessTemplate.protocol == payload.family.protocol,
                AccessTemplate.deleted_at.is_(None),
            )
        )
        target_code = None
    else:
        assert isinstance(payload, ConfigurationPackageTemplate)
        target_name = (target.name or payload.family.name).strip()
        target_code = (target.code or payload.family.code).strip()
        if not target_name or not target_code:
            raise APIError(
                422,
                "TEMPLATE_PACKAGE_TARGET_OVERRIDE_INVALID",
                "Target Configuration Template name/code must not be empty.",
            )
        adapter_key = payload.version.definition.adapter_key
        try:
            adapter = registry.get(adapter_key)
            adapter_available = True
        except KeyError:
            adapter = None
            adapter_available = False
            blockers.append("ADAPTER_NOT_AVAILABLE")
            if conflict == "NONE":
                conflict = "ADAPTER_NOT_AVAILABLE"
        if adapter is not None:
            try:
                registry.validate_capabilities(
                    adapter_key, set(payload.version.definition.capabilities)
                )
                if adapter.descriptor.transport != payload.version.definition.transport:
                    raise ValueError("CONFIGURATION_ADAPTER_TRANSPORT_MISMATCH")
                await adapter.validate_template(payload.version.definition)
            except (ConfigurationTemplateError, ValueError) as exc:
                raise APIError(
                    422,
                    "TEMPLATE_PACKAGE_DEFINITION_INVALID",
                    "Configuration Template package definition is invalid for the registered adapter.",
                ) from exc
        if (
            payload.version.definition.transport.value == "TELNET_CLI"
            and not settings.telnet_access_enabled
        ):
            blockers.append("TELNET_DISABLED")
            if conflict == "NONE":
                conflict = "TELNET_DISABLED"
        device_type_code = payload.family.device_type_code
        device_type = await db.scalar(
            select(DeviceType).where(
                DeviceType.code == device_type_code,
                DeviceType.is_active.is_(True),
            )
        )
        device_type_available = device_type is not None
        if not device_type_available:
            blockers.append("DEVICE_TYPE_NOT_AVAILABLE")
            if conflict == "NONE":
                conflict = "DEVICE_TYPE_NOT_AVAILABLE"
        duplicate_identity = await db.scalar(
            select(ConfigurationTemplate.id).where(
                func.lower(ConfigurationTemplate.code) == target_code.lower()
            )
        )

    if await _package_already_imported(
        db,
        package=package,
        actor_user_id=actor_user_id,
    ):
        blockers.append("PACKAGE_ALREADY_IMPORTED")
        if conflict == "NONE":
            conflict = "PACKAGE_ALREADY_IMPORTED"
    if duplicate_identity is not None:
        blockers.append("IDENTITY_CONFLICT")
        if conflict == "NONE":
            conflict = "IDENTITY_CONFLICT"

    if package.manifest.qualification.status == "QUALIFIED":
        warnings.append("UPSTREAM_QUALIFICATION_REQUIRES_LOCAL_LIFECYCLE")
    if credential_slots:
        warnings.append("LOCAL_CREDENTIALS_REQUIRED_BEFORE_ACCESS_ACTIVATION")

    return TemplatePackagePreviewRead(
        package_sha256=package_hash,
        schema_version=package.schema_version,
        template_kind=package.manifest.template_kind,
        source_family_key=package.manifest.provenance.source_family_key,
        source_revision_number=package.manifest.provenance.source_revision_number,
        compatibility=package.manifest.compatibility,
        qualification=package.manifest.qualification,
        credential_slots=credential_slots,
        adapter_key=adapter_key,
        adapter_available=adapter_available,
        device_type_code=device_type_code,
        device_type_available=device_type_available,
        target_name=target_name,
        target_code=target_code,
        warnings=warnings,
        blockers=blockers,
        conflict=conflict,
        can_import=not blockers,
    )


def _import_blocker_error(preview: TemplatePackagePreviewRead) -> APIError:
    first = preview.blockers[0] if preview.blockers else "SECURITY_POLICY_REJECTED"
    code_map = {
        "MINIMUM_VERSION_NOT_MET": "TEMPLATE_PACKAGE_MINIMUM_VERSION_NOT_MET",
        "ADAPTER_NOT_AVAILABLE": "TEMPLATE_PACKAGE_ADAPTER_NOT_AVAILABLE",
        "DEVICE_TYPE_NOT_AVAILABLE": "TEMPLATE_PACKAGE_DEVICE_TYPE_NOT_AVAILABLE",
        "TELNET_DISABLED": "TEMPLATE_PACKAGE_TELNET_DISABLED",
        "PACKAGE_ALREADY_IMPORTED": "TEMPLATE_PACKAGE_ALREADY_IMPORTED",
        "IDENTITY_CONFLICT": "TEMPLATE_PACKAGE_IDENTITY_CONFLICT",
    }
    return APIError(
        409,
        code_map.get(first, "TEMPLATE_PACKAGE_IMPORT_BLOCKED"),
        f"Template package import is blocked: {first}.",
        details={"blockers": preview.blockers},
    )


async def import_template_package(
    db: AsyncSession,
    *,
    raw_package: dict[str, Any],
    expected_package_sha256: str,
    target: TemplatePackageTargetOverrides,
    actor_user_id: UUID,
) -> TemplatePackageImportRead:
    preview = await preview_template_package(
        db,
        raw_package=raw_package,
        target=target,
        actor_user_id=actor_user_id,
    )
    if preview.package_sha256 != expected_package_sha256:
        raise APIError(
            409,
            "TEMPLATE_PACKAGE_CHANGED_AFTER_PREVIEW",
            "Template package changed after preview; preview the exact package again.",
        )
    if not preview.can_import:
        raise _import_blocker_error(preview)

    package, payload, package_hash = _typed_package(raw_package)
    if package_hash != preview.package_sha256:
        raise APIError(
            409,
            "TEMPLATE_PACKAGE_CHANGED_AFTER_PREVIEW",
            "Template package changed during import validation.",
        )

    if package.manifest.template_kind == "ACCESS":
        assert isinstance(payload, AccessPackageTemplate)
        family, revision = await create_template_family(
            db,
            name=preview.target_name,
            description=payload.family.description,
            protocol=payload.family.protocol,
            protocol_variant=payload.revision.protocol_variant,
            visibility="PRIVATE",
            settings=dict(payload.revision.settings),
            secrets={},
            change_note=payload.revision.change_note,
            actor_user_id=actor_user_id,
        )
        family.metadata_ = _sanitized_portable_metadata(
            package,
            package_hash=package_hash,
            credential_slots=list(payload.revision.credential_slots),
        )
        target_code = None
        revision_or_version_id = revision.id
    else:
        assert isinstance(payload, ConfigurationPackageTemplate)
        device_type = await db.scalar(
            select(DeviceType).where(
                DeviceType.code == payload.family.device_type_code,
                DeviceType.is_active.is_(True),
            )
        )
        if device_type is None:
            raise APIError(
                409,
                "TEMPLATE_PACKAGE_DEVICE_TYPE_NOT_AVAILABLE",
                "Configuration Template device type is no longer available.",
            )
        create_payload = ConfigurationTemplateCreate(
            code=preview.target_code or payload.family.code,
            name=preview.target_name,
            vendor=payload.family.vendor,
            model=payload.family.model,
            series=payload.family.series,
            device_type_id=device_type.id,
            description=payload.family.description,
            definition=payload.version.definition,
        )
        family, version = await create_template(
            db,
            payload=create_payload,
            actor_user_id=actor_user_id,
        )
        family.metadata_ = _sanitized_portable_metadata(
            package,
            package_hash=package_hash,
        )
        version.change_note = payload.version.change_note or "Imported portable template package"
        target_code = family.code
        revision_or_version_id = version.id

    await record_audit(
        db,
        action="TEMPLATE_PACKAGE_IMPORTED",
        entity_type=(
            "AccessTemplate"
            if package.manifest.template_kind == "ACCESS"
            else "ConfigurationTemplate"
        ),
        entity_id=family.id,
        actor_user_id=actor_user_id,
        description="Portable template package imported as a local draft.",
        metadata={
            "package_sha256": package_hash,
            "template_kind": package.manifest.template_kind,
            "source_family_key": package.manifest.provenance.source_family_key,
            "target_name": family.name,
            "target_code": target_code,
            "result": "DRAFT_CREATED",
            "device_connection": False,
            "configuration_operation_created": False,
            "configuration_execution": False,
        },
    )
    await db.flush()

    # V1 import must not create downstream operational material. These checks
    # are deliberately scoped to the new family/version and fail closed if a
    # future refactor accidentally introduces side effects into this path.
    if package.manifest.template_kind == "ACCESS":
        secret_count = len(await revision_secret_rows(db, revision_or_version_id))
        assignment_count = int(
            await db.scalar(
                select(func.count()).select_from(AccessTemplateAssignment).where(
                    AccessTemplateAssignment.template_id == family.id
                )
            )
            or 0
        )
        test_count = int(
            await db.scalar(
                select(func.count()).select_from(AccessTemplateTestResult).where(
                    AccessTemplateTestResult.template_id == family.id
                )
            )
            or 0
        )
        if secret_count or assignment_count or test_count:
            raise RuntimeError("TEMPLATE_PACKAGE_IMPORT_SIDE_EFFECT_DETECTED")
    else:
        binding_count = int(
            await db.scalar(
                select(func.count()).select_from(DeviceConfigurationBinding).where(
                    DeviceConfigurationBinding.template_version_id == revision_or_version_id
                )
            )
            or 0
        )
        operation_count = int(
            await db.scalar(
                select(func.count()).select_from(ConfigurationOperation).where(
                    ConfigurationOperation.template_version_id == revision_or_version_id
                )
            )
            or 0
        )
        snapshot_count = int(
            await db.scalar(
                select(func.count()).select_from(ConfigurationSnapshot).where(
                    ConfigurationSnapshot.template_version_id == revision_or_version_id
                )
            )
            or 0
        )
        if binding_count or operation_count or snapshot_count:
            raise RuntimeError("TEMPLATE_PACKAGE_IMPORT_SIDE_EFFECT_DETECTED")

    return TemplatePackageImportRead(
        package_sha256=package_hash,
        template_kind=package.manifest.template_kind,
        template_id=family.id,
        revision_or_version_id=revision_or_version_id,
        local_status="DRAFT",
        target_name=family.name,
        target_code=target_code,
    )
