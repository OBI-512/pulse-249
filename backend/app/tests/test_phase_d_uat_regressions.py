from datetime import datetime, timezone
from uuid import uuid4

from app.models import DataLifecycleRun
from app.schemas.phase_d import LifecycleRunRead


def test_lifecycle_run_schema_reads_mapped_metadata_attribute():
    """Regression for UAT: ORM .metadata is SQLAlchemy MetaData, row JSON lives at metadata_."""
    row = DataLifecycleRun(
        id=uuid4(),
        data_class="TELEMETRY_RAW",
        status="COMPLETED",
        idempotency_key="uat-regression",
        started_at=datetime.now(timezone.utc),
        scanned_rows=10,
        rolled_up_rows=2,
        purged_rows=3,
        metadata_={"qualification": True},
    )

    payload = LifecycleRunRead.model_validate(row)

    assert payload.metadata == {"qualification": True}
    assert payload.model_dump()["metadata"] == {"qualification": True}


def test_phase_d_vlan_scope_filters_require_geo_read_and_validate_range():
    import pytest
    from app.security.permissions import Permission as P
    from app.services import data_exchange, reports

    for filters in ({"service_vlan_id": "222"}, {"customer_vlan_id": "333"}):
        with pytest.raises(PermissionError, match="geo.read"):
            reports.validate_report_filter_permissions(filters, {P.REPORT_READ, P.REPORT_EXPORT})
        reports.validate_report_filter_permissions(filters, {P.REPORT_READ, P.REPORT_EXPORT, P.GEO_READ})

    assert data_exchange._vlan_filter({"service_vlan_id": "222"}, "service_vlan_id") == 222
    assert reports._vlan_filter({"customer_vlan_id": 333}, "customer_vlan_id") == 333
    with pytest.raises(ValueError, match="between 2 and 4094"):
        data_exchange._vlan_filter({"customer_vlan_id": "4095"}, "customer_vlan_id")


def test_phase_d_group_filters_do_not_materialize_large_device_id_sets():
    from pathlib import Path

    services = Path(__file__).resolve().parents[1] / "services"
    for name in ("data_exchange.py", "reports.py"):
        source = (services / name).read_text(encoding="utf-8")
        assert "effective_group_device_ids" not in source
        assert "effective_group_population_subquery" in source


def test_phase_d_scope_selector_backend_keeps_group_where_authorization_and_sql_population():
    from pathlib import Path

    app_root = Path(__file__).resolve().parents[1]
    for relative in (
        "api/routers/networks.py",
        "api/routers/geo.py",
        "api/routers/customers.py",
        "api/routers/data_exchange.py",
        "api/routers/reports.py",
    ):
        source = (app_root / relative).read_text(encoding="utf-8")
        assert "require_group" in source
    group_source = (app_root / "services/group_effective.py").read_text(encoding="utf-8")
    assert "effective_group_population_subquery" in group_source
    assert "without materializing device ids" in group_source


def test_phase_d_vlan_selector_is_database_paginated_and_uses_effective_context():
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "api/routers/devices_inventory.py").read_text(encoding="utf-8")
    start = source.index('@router.get("/management/vlan-options"')
    end = source.index('@router.get("/management/page"', start)
    selector = source[start:end]
    assert "effective_group_population_subquery" in selector
    assert "effective_group_context_subquery" in selector
    assert "generate_series(2, 4094)" in selector
    assert ".offset((page - 1) * page_size).limit(page_size)" in selector
    assert "effective_group_device_ids" not in selector
