from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from starlette.requests import Request

from app.schemas.template_assignment_batches import TemplateAssignmentBatchPreviewRequest
from app.security.authorization import permission_for_request
from app.services.template_assignment_batches import compatibility_warnings


BACKEND_ROOT = Path(__file__).resolve().parents[2]


def _request(path: str, method: str) -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("utf-8"),
            "query_string": b"",
            "headers": [],
            "client": ("tp4-test", 0),
            "server": ("tp4-test", 80),
            "route": SimpleNamespace(path=path),
        }
    )


def test_tp4_preview_request_requires_unique_bounded_devices_and_selection() -> None:
    first = uuid4()
    with pytest.raises(Exception):
        TemplateAssignmentBatchPreviewRequest(device_ids=[first], access_templates=[])
    with pytest.raises(Exception):
        TemplateAssignmentBatchPreviewRequest(
            device_ids=[first, first],
            access_templates=[{"template_id": str(uuid4())}],
        )
    with pytest.raises(Exception):
        TemplateAssignmentBatchPreviewRequest(
            device_ids=[uuid4() for _ in range(501)],
            access_templates=[{"template_id": str(uuid4())}],
        )


def test_tp4_preview_request_forbids_secret_adjacent_configuration_fields() -> None:
    with pytest.raises(Exception):
        TemplateAssignmentBatchPreviewRequest.model_validate(
            {
                "device_ids": [str(uuid4())],
                "configuration": {
                    "template_version_id": str(uuid4()),
                    "credential_mode": "ACCESS_TEMPLATE",
                    "credential_reference": "env://FORBIDDEN",
                },
            }
        )


def test_tp4_central_permission_contract_is_exact() -> None:
    expected = {
        ("GET", "/api/template-assignment-options/access"): "access_template.read",
        ("GET", "/api/template-assignment-options/configuration"): "device.configuration.template.read",
        ("POST", "/api/template-assignment-batches/preview"): "device.read",
        ("GET", "/api/template-assignment-batches"): "device.read",
        ("GET", "/api/template-assignment-batches/{batch_id}"): "device.read",
        ("POST", "/api/template-assignment-batches/{batch_id}/apply"): "device.read",
    }
    for (method, path), permission in expected.items():
        assert permission_for_request(_request(path, method)) == permission


def test_tp4_route_extension_contains_exactly_six_operations() -> None:
    source = (
        BACKEND_ROOT / "scripts" / "ci_route_permission_contract_tp4_extension.json"
    ).read_text(encoding="utf-8")
    assert source.count('"mode": "CENTRAL"') == 6
    assert source.count('"path": "/api/template-assignment') == 6


def test_tp4_migration_is_metadata_only_and_based_on_0045() -> None:
    source = (
        BACKEND_ROOT / "migrations" / "versions" / "0046_template_assignment_batches.py"
    ).read_text(encoding="utf-8")
    assert 'revision = "0046_template_assignment_batches"' in source
    assert 'down_revision = "0045_web_tls_trust"' in source
    assert '"template_assignment_batches"' in source
    assert '"template_assignment_batch_targets"' in source
    assert "configuration_operation_id" not in source
    assert "configuration_operations" not in source
    assert "celery" not in source.lower()
    assert "credential_reference" not in source
    assert "certificate_der" not in source


def test_tp4_models_have_no_execution_linkage() -> None:
    source = (
        BACKEND_ROOT / "app" / "models" / "template_assignment_batches.py"
    ).read_text(encoding="utf-8")
    # Check structural execution/dispatch linkage, not explanatory comments.
    for forbidden in (
        "configuration_operation_id",
        "ConfigurationOperation",
        "celery_task_id",
        "dispatch_task_id",
        "execution_operation_id",
        "credential_reference",
        "certificate_der",
    ):
        assert forbidden not in source


def test_tp4_batch_service_never_dispatches_or_constructs_configuration_operation() -> None:
    source = (
        BACKEND_ROOT / "app" / "services" / "template_assignment_batches.py"
    ).read_text(encoding="utf-8")
    assert "celery_app" not in source
    assert "send_task" not in source
    assert "queue_operation" not in source
    assert "ConfigurationOperation(" not in source
    assert "bind_device(" in source
    assert "begin_nested()" in source


def test_tp4_router_exposes_exact_six_routes() -> None:
    source = (
        BACKEND_ROOT / "app" / "api" / "routers" / "template_assignment_batches.py"
    ).read_text(encoding="utf-8")
    assert source.count("@router.") == 6
    api_router = (BACKEND_ROOT / "app" / "api" / "router.py").read_text(
        encoding="utf-8"
    )
    assert "template_assignment_batches.router" in api_router


def test_tp4_portable_compatibility_warnings_are_advisory_and_sanitized() -> None:
    device = SimpleNamespace(
        vendor="Vendor B",
        model="Model B",
        metadata_={"series": "Series B", "firmware_version": "2.0.0"},
    )
    metadata = {
        "portable": {
            "compatibility": {
                "device_type_code": "ACCESS_POINT",
                "vendor": "Vendor A",
                "models": ["Model A"],
                "series": ["Series A"],
                "firmware": {
                    "mode": "EXACT",
                    "exact": "1.0.0",
                    "minimum": None,
                    "maximum": None,
                    "values": [],
                },
            },
            "upstream_qualification": {
                "status": "UNQUALIFIED",
                "scope": "DEFINITION_ONLY",
            },
        }
    }
    warnings = compatibility_warnings(
        device=device,
        device_type_code="CPE",
        metadata=metadata,
    )
    codes = {item["code"] for item in warnings}
    assert {
        "TEMPLATE_DEVICE_TYPE_COMPATIBILITY_MISMATCH",
        "TEMPLATE_VENDOR_MISMATCH",
        "TEMPLATE_MODEL_MISMATCH",
        "TEMPLATE_SERIES_MISMATCH",
        "TEMPLATE_FIRMWARE_MISMATCH",
        "TEMPLATE_QUALIFICATION_UNQUALIFIED",
        "TEMPLATE_QUALIFICATION_NOT_REAL_DEVICE",
    }.issubset(codes)
    serialized = str(warnings).lower()
    assert "credential" not in serialized
    assert "certificate" not in serialized
