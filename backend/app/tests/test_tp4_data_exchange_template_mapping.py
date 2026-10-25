from __future__ import annotations

from pathlib import Path

from app.services import configuration as configuration_service
from app.services.configuration_binding_metadata import bind_device_for_assignment
from app.services.data_exchange_template_mapping import (
    DEVICE_MAPPING_COLUMNS,
    template_bytes_with_template_mapping,
)


BACKEND_ROOT = Path(__file__).resolve().parents[2]


def test_tp4_refines_authoritative_bind_device_contract() -> None:
    assert configuration_service.bind_device is bind_device_for_assignment


def test_device_import_csv_template_contains_tp4_mapping_columns() -> None:
    data, name, media = template_bytes_with_template_mapping("devices", "CSV", "ALL")
    header = data.decode("utf-8-sig").splitlines()[0].split(",")
    for column in DEVICE_MAPPING_COLUMNS:
        assert column in header
    assert name == "fttw_devices_import_template.csv"
    assert media == "text/csv"


def test_device_subtype_template_retains_mapping_columns_but_omits_device_type() -> None:
    data, name, _media = template_bytes_with_template_mapping(
        "devices", "CSV", "ACCESS_POINT"
    )
    header = data.decode("utf-8-sig").splitlines()[0].split(",")
    assert "device_type" not in header
    assert "firmware_version" in header
    assert "ssh_template_name" in header
    assert "configuration_template_code" in header
    assert "configuration_template_version" in header
    assert name == "fttw_devices_access_point_import_template.csv"


def test_non_device_import_templates_still_delegate_to_existing_contract() -> None:
    data, name, media = template_bytes_with_template_mapping("customers", "CSV", "ALL")
    header = data.decode("utf-8-sig").splitlines()[0]
    assert header == "customer_code,name,status"
    assert name == "fttw_customers_import_template.csv"
    assert media == "text/csv"


def test_tp4_mapping_service_uses_existing_import_preview_and_no_parallel_route() -> None:
    service = (
        BACKEND_ROOT / "app" / "services" / "data_exchange_template_mapping.py"
    ).read_text(encoding="utf-8")
    router = (
        BACKEND_ROOT / "app" / "api" / "routers" / "data_exchange.py"
    ).read_text(encoding="utf-8")
    assert "create_import_preview(" in service
    assert "commit_import_with_template_mapping" in router
    assert "create_import_preview_with_template_mapping" in router
    assert router.count('@router.post("/imports/{entity_type}/preview"') == 1
    assert router.count('@router.post("/imports/{job_id}/confirm"') == 1
    assert "/template-mapping" not in router


def test_tp4_mapping_snapshots_exact_access_and_configuration_identity() -> None:
    source = (
        BACKEND_ROOT / "app" / "services" / "data_exchange_template_mapping.py"
    ).read_text(encoding="utf-8")
    for field in (
        '"template_id"',
        '"revision_id"',
        '"revision_number"',
        '"definition_sha256"',
        '"template_version_id"',
        '"version_number"',
        '"content_sha256"',
    ):
        assert field in source
    assert "previous_mapping != current_mapping" in source


def test_tp4_import_configuration_binding_is_disabled_and_never_executes() -> None:
    source = (
        BACKEND_ROOT / "app" / "services" / "data_exchange_template_mapping.py"
    ).read_text(encoding="utf-8")
    assert 'credential_source="ACCESS_TEMPLATE"' in source
    assert "enabled=False" in source
    assert "bind_device_for_assignment(" in source
    assert "queue_operation" not in source
    assert "send_task" not in source
    assert "celery" not in source.lower()
    assert "ConfigurationOperation(" not in source


def test_tp4_import_mapping_permissions_are_compound_and_rechecked() -> None:
    source = (
        BACKEND_ROOT / "app" / "services" / "data_exchange_template_mapping.py"
    ).read_text(encoding="utf-8")
    assert "PermissionCode.ACCESS_TEMPLATE_MANAGE" in source
    assert "PermissionCode.DEVICE_CONFIGURATION_TEMPLATE_MANAGE" in source
    assert "PermissionCode.DEVICE_CONFIGURATION_READ" in source
    assert source.count("await _require_mapping_permissions(") >= 2


def test_firmware_is_device_metadata_only() -> None:
    source = (
        BACKEND_ROOT / "app" / "services" / "data_exchange_template_mapping.py"
    ).read_text(encoding="utf-8")
    assert 'metadata["firmware_version"] = str(firmware)' in source
    assert "firmware_version" not in (
        BACKEND_ROOT / "app" / "models" / "template_assignment_batches.py"
    ).read_text(encoding="utf-8")
