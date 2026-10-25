from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from app.api.routers.template_packages import _reject_access_credential_values
from app.core.exceptions import APIError
from app.schemas.template_packages import TemplatePackageTargetOverrides
from app.services.template_packages import (
    PACKAGE_FORMAT,
    PACKAGE_SCHEMA_VERSION,
    _semver_less_than,
    _typed_package,
    package_sha256,
    portable_definition_sha256,
    rfc8785_canonical_json,
    sanitized_portable_metadata,
    template_kind_from_raw,
)


BACKEND_ROOT = Path(__file__).resolve().parents[2]


def _access_package() -> dict:
    template = {
        "family": {
            "name": "Portable SSH",
            "description": "Reusable SSH definition",
            "protocol": "SSH",
        },
        "revision": {
            "protocol_variant": "PASSWORD_OR_KEY",
            "settings": {"port": 22, "timeout_seconds": 10},
            "credential_slots": ["password", "username"],
            "change_note": "portable source",
        },
    }
    package = {
        "format": PACKAGE_FORMAT,
        "schema_version": PACKAGE_SCHEMA_VERSION,
        "manifest": {
            "package_id": str(uuid4()),
            "package_version": "1.0.0",
            "created_at": "2026-09-08T12:00:00Z",
            "minimum_fttw_version": "1.4.0",
            "producer": {
                "product": "FTTW Network Management System",
                "application_version": "1.4.0",
            },
            "template_kind": "ACCESS",
            "compatibility": {
                "device_type_code": None,
                "vendor": None,
                "models": [],
                "series": [],
                "firmware": {
                    "mode": "ANY",
                    "exact": None,
                    "minimum": None,
                    "maximum": None,
                    "values": [],
                },
            },
            "qualification": {
                "status": "UNQUALIFIED",
                "scope": "NONE",
                "qualified_at": None,
                "tested_firmware": [],
                "notes": None,
            },
            "provenance": {
                "source_family_key": "SSH:Portable SSH",
                "source_revision_number": 1,
                "source_lifecycle_status": "ACTIVE",
                "source_definition_sha256": portable_definition_sha256(template),
            },
        },
        "template": template,
    }
    package["integrity"] = {
        "algorithm": "SHA-256",
        "canonicalization": "RFC8785",
        "sha256": package_sha256(package),
    }
    package["signatures"] = []
    return package


def test_rfc8785_number_and_key_canonicalization() -> None:
    assert rfc8785_canonical_json(
        {"z": 1e21, "b": 1, "a": 1e-6, "tiny": 1e-7, "zero": -0.0}
    ) == '{"a":0.000001,"b":1,"tiny":1e-7,"z":1e+21,"zero":0}'


def test_package_digest_is_deterministic_and_excludes_integrity() -> None:
    package = _access_package()
    first = package_sha256(package)
    package["integrity"]["sha256"] = "0" * 64
    assert package_sha256(package) == first


def test_valid_access_package_parses_without_secret_material() -> None:
    package = _access_package()
    typed, payload, digest = _typed_package(package)
    assert typed.manifest.template_kind == "ACCESS"
    assert payload.revision.credential_slots == ["password", "username"]
    assert digest == package["integrity"]["sha256"]
    serialized = str(package).lower()
    assert "env://" not in serialized
    assert "encrypted_payload" not in serialized
    assert "secret_providers" not in serialized


def test_tampered_package_fails_integrity() -> None:
    package = _access_package()
    package["template"]["revision"]["settings"]["port"] = 2222
    with pytest.raises(APIError) as exc_info:
        _typed_package(package)
    assert exc_info.value.detail["code"] == "TEMPLATE_PACKAGE_INTEGRITY_FAILED"


def test_unsupported_schema_fails_closed() -> None:
    package = _access_package()
    package["schema_version"] = "2.0"
    with pytest.raises(APIError) as exc_info:
        _typed_package(package)
    assert exc_info.value.detail["code"] == "TEMPLATE_PACKAGE_SCHEMA_UNSUPPORTED"


def test_access_package_rejects_embedded_credential_value() -> None:
    package = _access_package()
    package["template"]["revision"]["settings"]["username"] = "admin"
    package["manifest"]["provenance"]["source_definition_sha256"] = portable_definition_sha256(
        package["template"]
    )
    package["integrity"]["sha256"] = package_sha256(package)
    with pytest.raises(APIError) as exc_info:
        _typed_package(package)
    assert exc_info.value.detail["code"] == "TEMPLATE_PACKAGE_SECURITY_POLICY_REJECTED"


def test_access_boundary_rejects_nested_credential_value() -> None:
    with pytest.raises(APIError) as exc_info:
        _reject_access_credential_values(
            {
                "family": {"name": "Portable"},
                "revision": {
                    "settings": {"authentication": {"username": "admin"}},
                    "credential_slots": ["username"],
                },
            }
        )
    assert exc_info.value.detail["code"] == "TEMPLATE_PACKAGE_SECURITY_POLICY_REJECTED"


def test_package_rejects_env_reference_anywhere_in_portable_payload() -> None:
    package = _access_package()
    package["template"]["revision"]["settings"]["comment"] = "env://DO_NOT_EXPORT"
    package["manifest"]["provenance"]["source_definition_sha256"] = portable_definition_sha256(
        package["template"]
    )
    package["integrity"]["sha256"] = package_sha256(package)
    with pytest.raises(APIError) as exc_info:
        _typed_package(package)
    assert exc_info.value.detail["code"] == "TEMPLATE_PACKAGE_SECURITY_POLICY_REJECTED"


def test_semver_minimum_comparison() -> None:
    assert _semver_less_than("1.4.0", "1.5.0") is True
    assert _semver_less_than("1.4.0", "1.4.0") is False
    assert _semver_less_than("1.4.0-beta.1", "1.4.0") is True
    assert _semver_less_than("1.4.0", "1.4.0-beta.1") is False


def test_raw_kind_resolution_is_closed() -> None:
    package = _access_package()
    assert template_kind_from_raw(package) == "ACCESS"
    package["manifest"]["template_kind"] = "DEVICE"
    with pytest.raises(APIError) as exc_info:
        template_kind_from_raw(package)
    assert exc_info.value.detail["code"] == "TEMPLATE_PACKAGE_SCHEMA_INVALID"


def test_portable_metadata_sanitizer_drops_nonportable_root_data() -> None:
    metadata = {
        "portable": {
            "compatibility": {"vendor": "Example"},
            "upstream_qualification": {"status": "UNQUALIFIED", "scope": "NONE"},
            "package_provenance": {"package_id": str(uuid4())},
            "credential_slots": ["username", "password"],
            "unexpected": {"device_id": str(uuid4())},
        },
        "runtime": {"device_id": str(uuid4())},
    }
    result = sanitized_portable_metadata(metadata)
    assert set(result) == {"portable"}
    assert "unexpected" not in result["portable"]
    assert "runtime" not in result


def test_target_overrides_forbid_unknown_fields() -> None:
    with pytest.raises(Exception):
        TemplatePackageTargetOverrides.model_validate(
            {"name": "new", "device_id": str(uuid4())}
        )


def test_tp2_route_contract_is_exactly_three_dynamic_routes() -> None:
    contract = (
        BACKEND_ROOT / "scripts" / "ci_route_permission_contract_tp2_extension.json"
    ).read_text(encoding="utf-8")
    assert contract.count('"mode": "TEMPLATE_PACKAGE_EXPLICIT"') == 3
    assert '"access_template.read"' in contract
    assert '"access_template.manage"' in contract
    assert '"device.configuration.template.read"' in contract
    assert '"device.configuration.template.manage"' in contract


def test_tp2_does_not_extend_operational_data_exchange_router() -> None:
    router_source = (BACKEND_ROOT / "app" / "api" / "router.py").read_text(
        encoding="utf-8"
    )
    package_router_source = (
        BACKEND_ROOT / "app" / "api" / "routers" / "template_packages.py"
    ).read_text(encoding="utf-8")
    assert "template_packages.router" in router_source
    assert 'prefix="/template-packages"' in package_router_source
    assert "data_exchange" not in package_router_source


def test_export_boundary_revalidates_generated_package_before_response() -> None:
    source = (
        BACKEND_ROOT / "app" / "api" / "routers" / "template_packages.py"
    ).read_text(encoding="utf-8")
    export_block = source.split('@router.get("/export/{template_kind}/{template_id}")', 1)[1]
    export_block = export_block.split('@router.post("/preview"', 1)[0]
    assert "package = await export_template_package(" in export_block
    assert "await _validate_export_boundary(package)" in export_block
    assert export_block.index("await _validate_export_boundary(package)") < export_block.index("return Response(")
    assert "await adapter.validate_template(definition)" in source


def test_import_boundary_serializes_package_and_identity_conflicts() -> None:
    source = (
        BACKEND_ROOT / "app" / "api" / "routers" / "template_packages.py"
    ).read_text(encoding="utf-8")
    import_block = source.split('@router.post("/import"', 1)[1]
    assert "package, template, _package_hash = _typed_package(payload.package)" in import_block
    assert "await _lock_import_conflicts(" in import_block
    assert "pg_advisory_xact_lock" in source
    assert "TP2:PACKAGE:" in source
    assert "TP2:ACCESS:" in source
    assert "TP2:CONFIGURATION:" in source


def test_access_clone_preserves_only_sanitized_portable_metadata() -> None:
    source = (
        BACKEND_ROOT / "app" / "api" / "routers" / "access_template_lifecycle.py"
    ).read_text(encoding="utf-8")
    clone_block = source.split('"/{template_id}/clone"', 1)[1]
    assert "family.metadata_ = sanitized_portable_metadata(source.metadata_)" in clone_block
    assert clone_block.index("family.metadata_ = sanitized_portable_metadata(source.metadata_)") < clone_block.index("await db.commit()")


def test_0044_migration_is_additive_and_bounded() -> None:
    migration = (
        BACKEND_ROOT / "migrations" / "versions" / "0044_access_template_portable_metadata.py"
    ).read_text(encoding="utf-8")
    assert 'revision = "0044_access_template_metadata"' in migration
    assert 'down_revision = "0043_config_template_lifecycle"' in migration
    assert '"access_templates"' in migration
    assert '"metadata"' in migration
    assert "JSONB" in migration
    assert "create_table" not in migration
    assert "drop_table" not in migration
