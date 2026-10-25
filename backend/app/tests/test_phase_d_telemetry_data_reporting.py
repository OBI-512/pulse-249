from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.availability.service import ensure_device_availability
from app.models import (
    AuditLog, Customer, DataLifecycleRun, Device, DeviceAvailability, DeviceType,
    ImportJob, ImportRecord, TelemetryDeviceState, TelemetryProfile, User,
)
from app.security.permissions import Permission as P
from app.security.resource_scope import EffectiveResourceScope
from app.services import data_exchange as exchange
from app.services.audit import enable_audit_maintenance
from app.services.data_lifecycle import _start_run, capacity_estimate
from app.services.reports import build_report_rows, validate_report_request
from app.services.tabular_formats import parse_tabular_bytes, write_tabular_bytes, write_tabular_template_bytes
from app.settings import settings as app_settings
from app.tasks.telemetry import _finish_failure
from app.telemetry.collectors import TelemetryCollectionError, normalize_metric_value, validate_metric_definitions
from app.telemetry.service import deterministic_jitter_seconds


def _global_scope(user_id: UUID) -> EffectiveResourceScope:
    return EffectiveResourceScope(
        user_id=user_id,
        global_access=True,
        network_ids=frozenset(),
        city_ids=frozenset(),
        location_ids=frozenset(),
        sector_ids=frozenset(),
        group_ids=frozenset(),
    )


def test_phase_d_metric_normalization_and_profile_validation_are_bounded():
    assert normalize_metric_value('12345', 'timeticks_seconds') == (123.45, None)
    assert normalize_metric_value('Timeticks: (28792300) 3 days, 7:58:43.00', 'timeticks_seconds') == (287923.0, None)
    assert normalize_metric_value('3 days, 7:58:43.00', 'timeticks_seconds') == (287923.0, None)
    assert normalize_metric_value('3:07:58:43.00', 'timeticks_seconds') == (287923.0, None)
    assert normalize_metric_value('INTEGER: 42', 'int') == (42.0, None)
    assert normalize_metric_value('12.5 Mbps', 'float') == (12.5, None)
    assert normalize_metric_value('up', 'raw') == (None, 'up')
    valid = validate_metric_definitions([
        {'key': 'sys_uptime', 'oid': '1.3.6.1.2.1.1.3.0', 'transform': 'timeticks_seconds'},
        {'key': 'if_count', 'oid': '.1.3.6.1.2.1.2.1.0', 'transform': 'int'},
    ])
    assert [row['key'] for row in valid] == ['sys_uptime', 'if_count']
    with pytest.raises(TelemetryCollectionError):
        validate_metric_definitions([
            {'key': 'dup', 'oid': '1.3.6.1.2.1.1.3.0'},
            {'key': 'dup', 'oid': '1.3.6.1.2.1.1.5.0'},
        ])


def test_phase_d_snmp_fixture_collection_preserves_metric_correctness(monkeypatch):
    from app.telemetry import collectors

    monkeypatch.setattr(collectors, "resolve_snmp_credential", lambda _ref: {"version": "2c", "community": "fixture"})
    monkeypatch.setattr(collectors, "_run_snmpget_many", lambda _context, _definitions: (["12345", "INTEGER: 8", "vendor-up"], 4.25))
    metrics, duration_ms = asyncio.run(collectors.collect_snmp_metrics(
        ip_address="192.0.2.10", credential_reference=None, timeout_seconds=1, retries=0,
        metric_definitions=[
            {"key": "sys_uptime", "oid": "1.3.6.1.2.1.1.3.0", "transform": "timeticks_seconds", "unit": "s"},
            {"key": "if_count", "oid": "1.3.6.1.2.1.2.1.0", "transform": "int", "kind": "COUNTER"},
            {"key": "vendor_state", "oid": "1.3.6.1.4.1.999.1.0", "transform": "raw", "vendor_key": "fixture.state"},
        ], max_metrics=32,
    ))
    assert duration_ms == 4.25
    assert metrics[0].numeric_value == 123.45 and metrics[0].unit == "s"
    assert metrics[1].numeric_value == 8.0 and metrics[1].kind == "COUNTER"
    assert metrics[2].text_value == "vendor-up" and metrics[2].vendor_key == "fixture.state"


def test_phase_d_jitter_and_capacity_model_are_scale_bounded():
    device_id = UUID('12345678-1234-5678-1234-567812345678')
    assert 0 <= deterministic_jitter_seconds(device_id, 900) < 90
    ten = capacity_estimate(device_count=10_000)
    twenty = capacity_estimate(device_count=20_000)
    assert twenty['raw_samples_per_day'] == ten['raw_samples_per_day'] * 2
    assert twenty['estimated_raw_storage_bytes'] == ten['estimated_raw_storage_bytes'] * 2
    assert ten['assumptions']['partitioning_review_threshold_raw_rows'] == 250_000_000
    assert ten['partitioning_review_required'] is False
    assert twenty['partitioning_review_required'] is True
    assert twenty['storage_strategy']['time_retention_index'].startswith('BRIN')


def test_phase_d_report_authorization_requires_source_export_and_sensitive_permissions():
    user_id = uuid4(); scope = _global_scope(user_id)
    base = {P.REPORT_READ, P.REPORT_EXPORT, P.DEVICE_READ}
    assert validate_report_request(report_type='inventory', format='CSV', include_sensitive=False, scope=scope, permissions=base) == ('inventory', 'CSV')
    with pytest.raises(PermissionError):
        validate_report_request(report_type='inventory', format='CSV', include_sensitive=True, scope=scope, permissions=base)
    allowed = base | {P.REPORT_SENSITIVE}
    assert validate_report_request(report_type='inventory', format='XLSX', include_sensitive=True, scope=scope, permissions=allowed) == ('inventory', 'XLSX')


def test_phase_d_tabular_contract_supports_import_export_templates_and_reports():
    parsed = parse_tabular_bytes(b"a,b\n1,2\n", filename="sample.csv")
    assert parsed.format == "csv"
    assert parsed.rows == [{"a": "1", "b": "2"}]

    csv_bytes = write_tabular_bytes(["a", "b"], [{"a": 1, "b": 2}], "CSV")
    assert csv_bytes.decode("utf-8-sig") == "a,b\n1,2\n"

    json_bytes = write_tabular_bytes(["a", "b"], [{"a": "x", "b": 2}], "JSON")
    assert parse_tabular_bytes(json_bytes, filename="sample.json").rows == [{"a": "x", "b": 2}]

    xlsx_bytes = write_tabular_bytes(["a", "b"], [{"a": "x", "b": "y"}], "XLSX")
    assert xlsx_bytes.startswith(b"PK")
    assert parse_tabular_bytes(xlsx_bytes, filename="sample.xlsx").rows == [{"a": "x", "b": "y"}]

    pdf_bytes = write_tabular_bytes(["a", "b"], [{"a": "x", "b": "y"}], "PDF", title="Phase D")
    assert pdf_bytes.startswith(b"%PDF-1.4")

    assert write_tabular_template_bytes(["a", "b"], "CSV").decode("utf-8-sig") == "a,b\n"
    json_template = parse_tabular_bytes(write_tabular_template_bytes(["a", "b"], "JSON"), filename="template.json")
    assert json_template.rows == []



def test_phase_d_operator_exports_hide_internal_device_ids():
    async def scenario():
        engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
        SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        device_id = None
        name = f'Phase D operator export {uuid4().hex[:10]}'
        try:
            async with SessionLocal() as db:
                dtype = await db.scalar(select(DeviceType).where(DeviceType.code == 'OTHER'))
                assert dtype is not None
                device = Device(device_type_id=dtype.id, display_name=name, lifecycle_state='ACTIVE', operational_state='UP', metadata_={})
                db.add(device); await db.flush(); device_id = device.id
                await db.commit()

            async with SessionLocal() as db:
                scope = _global_scope(uuid4())
                columns, exported = await exchange.export_rows(db, scope, 'devices')
                row = next(item for item in exported if item['display_name'] == name)
                assert 'device_id' not in columns
                assert 'device_id' not in row

                report_rows = await build_report_rows(
                    db, report_type='inventory', filters={}, include_sensitive=False, scope=scope,
                    permissions={P.REPORT_READ, P.REPORT_EXPORT, P.DEVICE_READ},
                )
                report_row = next(item for item in report_rows if item['display_name'] == name)
                assert 'device_id' not in report_row
        finally:
            if device_id is not None:
                async with SessionLocal() as db:
                    await db.execute(delete(Device).where(Device.id == device_id))
                    await db.commit()
            await engine.dispose()
    asyncio.run(scenario())

def test_phase_d_geography_export_executes_explicit_hierarchy_joins():
    async def scenario():
        engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
        SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with SessionLocal() as db:
                scope = _global_scope(uuid4())
                columns, rows = await exchange.export_rows(db, scope, 'geography')
                assert columns[:6] == ['level', 'name', 'code', 'network_code', 'city_code', 'location_code']
                assert all(row.get('level') in {'NETWORK', 'CITY', 'LOCATION', 'SECTOR'} for row in rows)
                data, filename, media_type, row_count = await exchange.export_bytes(db, scope, 'geography', 'CSV')
                assert data.decode('utf-8-sig').startswith('level,name,code,network_code,city_code,location_code,')
                assert filename.startswith('fttw_geography_') and filename.endswith('.csv')
                assert media_type == 'text/csv'
                assert row_count == len(rows)
        finally:
            await engine.dispose()
    asyncio.run(scenario())


def test_current_route_permission_baseline_is_consistent_and_preserves_phase_d_routes():
    path = Path(__file__).resolve().parents[2] / 'scripts' / 'ci_route_permission_contract_baseline.json'
    import json
    manifest = json.loads(path.read_text(encoding='utf-8'))
    assert manifest['route_count'] == len(manifest['routes'])
    routes = {(row['method'], row['path']): (row['permission'], row['mode']) for row in manifest['routes']}
    assert len(routes) == manifest['route_count']
    assert routes[('POST', '/api/reports/definitions/{definition_id}/restore')] == ('report.manage', 'CENTRAL')
    assert routes[('DELETE', '/api/reports/definitions/{definition_id}/permanent')] == ('report.manage', 'CENTRAL')
    assert routes[('POST', '/api/reports/schedules/{schedule_id}/restore')] == ('report.schedule', 'CENTRAL')
    assert routes[('DELETE', '/api/reports/schedules/{schedule_id}/permanent')] == ('report.schedule', 'CENTRAL')


def test_telemetry_failure_never_mutates_authoritative_availability():
    async def scenario():
        engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
        SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        device_id = None
        try:
            async with SessionLocal() as db:
                dtype = await db.scalar(select(DeviceType).where(DeviceType.code == 'OTHER'))
                assert dtype is not None
                profile = await db.scalar(select(TelemetryProfile).where(TelemetryProfile.device_type_id == dtype.id))
                assert profile is not None
                device = Device(
                    device_type_id=dtype.id,
                    display_name=f'Phase D telemetry isolation {uuid4().hex[:8]}',
                    lifecycle_state='ACTIVE', operational_state='ONLINE', metadata_={},
                )
                db.add(device); await db.flush(); device_id = device.id
                availability = await ensure_device_availability(db, device)
                availability.status = 'ONLINE'; availability.consecutive_failures = 0
                availability.last_error_code = None
                lease = uuid4()
                db.add(TelemetryDeviceState(
                    device_id=device.id, profile_id=profile.id, enabled=True, status='PENDING',
                    lease_token=lease, lease_expires_at=datetime(2035, 1, 1, tzinfo=timezone.utc),
                ))
                await db.commit()

                result = await _finish_failure(SessionLocal, {
                    'device_id': device.id, 'lease_token': lease, 'profile_id': profile.id,
                    'interval_seconds': 900,
                }, 'TELEMETRY_TEST_FAILURE', duration_ms=1.0)
                assert result == 'ERROR'

                refreshed = await db.scalar(select(DeviceAvailability).where(DeviceAvailability.device_id == device.id).execution_options(populate_existing=True))
                assert refreshed is not None
                assert refreshed.status == 'ONLINE'
                assert refreshed.consecutive_failures == 0
                assert refreshed.last_error_code is None
        finally:
            if device_id is not None:
                async with SessionLocal() as db:
                    await db.execute(delete(TelemetryDeviceState).where(TelemetryDeviceState.device_id == device_id))
                    await db.execute(delete(DeviceAvailability).where(DeviceAvailability.device_id == device_id))
                    await db.execute(delete(Device).where(Device.id == device_id))
                    await db.commit()
            await engine.dispose()
    asyncio.run(scenario())


def test_retention_run_idempotency_reuses_same_hour_key():
    async def scenario():
        engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
        SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        run_id = None
        try:
            now = datetime(2035, 2, 3, 4, 5, tzinfo=timezone.utc)
            async with SessionLocal() as db:
                first = await _start_run(db, 'PHASE_D_TEST', now=now)
                await db.commit(); run_id = first.id
            async with SessionLocal() as db:
                second = await _start_run(db, 'PHASE_D_TEST', now=now)
                assert second.id == run_id
                await db.rollback()
        finally:
            if run_id is not None:
                async with SessionLocal() as db:
                    await db.execute(delete(DataLifecycleRun).where(DataLifecycleRun.id == run_id))
                    await db.commit()
            await engine.dispose()
    asyncio.run(scenario())


def test_import_preview_detects_in_file_duplicates_without_business_mutation():
    async def scenario():
        engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
        SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        user_id = job_id = None
        code = f'PHD-{uuid4().hex[:12]}'
        try:
            async with SessionLocal() as db:
                user = User(external_subject=f'phase-d-import-{uuid4()}', username=f'phase-d-{uuid4().hex[:12]}', display_name='Phase D Import Test', is_active=True, metadata_={})
                db.add(user); await db.flush(); user_id = user.id
                csv_data = f'customer_code,name,status\n{code},One,ACTIVE\n{code},Two,ACTIVE\n'.encode()
                job = await exchange.create_import_preview(db, actor_id=user.id, scope=_global_scope(user.id), entity_type='customers', filename='customers.csv', data=csv_data)
                job_id = job.id
                await db.commit()
                assert job.validation_summary['errors'] == 1
                duplicate = await db.scalar(select(ImportRecord).where(ImportRecord.import_job_id == job.id, ImportRecord.error_code == 'DUPLICATE_IN_FILE'))
                assert duplicate is not None
                assert await db.scalar(select(func.count(Customer.id)).where(Customer.customer_code == code)) == 0
        finally:
            async with SessionLocal() as db:
                if job_id:
                    await db.execute(delete(ImportRecord).where(ImportRecord.import_job_id == job_id))
                    await db.execute(delete(ImportJob).where(ImportJob.id == job_id))
                    await enable_audit_maintenance(db)
                    await db.execute(delete(AuditLog).where(AuditLog.entity_id == job_id))
                if user_id:
                    await db.execute(delete(User).where(User.id == user_id))
                await db.commit()
            await engine.dispose()
    asyncio.run(scenario())


def test_import_commit_failure_rolls_back_all_business_rows(monkeypatch):
    async def scenario():
        engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
        SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        user_id = job_id = None
        codes = [f'PHD-{uuid4().hex[:12]}', f'PHD-{uuid4().hex[:12]}']
        original = exchange._apply_customer
        calls = 0

        async def fail_second(db, data):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError('PHASE_D_FORCED_COMMIT_FAILURE')
            await original(db, data)

        monkeypatch.setattr(exchange, '_apply_customer', fail_second)
        try:
            async with SessionLocal() as db:
                user = User(external_subject=f'phase-d-rollback-{uuid4()}', username=f'phase-d-{uuid4().hex[:12]}', display_name='Phase D Rollback Test', is_active=True, metadata_={})
                db.add(user); await db.flush(); user_id = user.id
                csv_data = ('customer_code,name,status\n' + ''.join(f'{code},Customer {i},ACTIVE\n' for i, code in enumerate(codes, 1))).encode()
                job = await exchange.create_import_preview(db, actor_id=user.id, scope=_global_scope(user.id), entity_type='customers', filename='customers.csv', data=csv_data)
                job_id = job.id; digest = job.file_sha256
                await db.commit()
                with pytest.raises(RuntimeError, match='PHASE_D_FORCED_COMMIT_FAILURE'):
                    await exchange.commit_import(db, job=job, actor_id=user.id, scope=_global_scope(user.id), expected_file_sha256=digest)
                await db.rollback()
                assert await db.scalar(select(func.count(Customer.id)).where(Customer.customer_code.in_(codes))) == 0
        finally:
            monkeypatch.setattr(exchange, '_apply_customer', original)
            async with SessionLocal() as db:
                await db.execute(delete(Customer).where(Customer.customer_code.in_(codes)))
                if job_id:
                    await db.execute(delete(ImportRecord).where(ImportRecord.import_job_id == job_id))
                    await db.execute(delete(ImportJob).where(ImportJob.id == job_id))
                    await enable_audit_maintenance(db)
                    await db.execute(delete(AuditLog).where(AuditLog.entity_id == job_id))
                if user_id:
                    await db.execute(delete(User).where(User.id == user_id))
                await db.commit()
            await engine.dispose()
    asyncio.run(scenario())


def test_report_attachment_reuses_notification_foundation(monkeypatch):
    from app import notifications as notifications_module

    captured = {}

    def fake_smtp(destination, payload, idempotency_key, attachment=None):
        captured["destination"] = destination
        captured["payload"] = payload
        captured["idempotency_key"] = idempotency_key
        captured["attachment"] = attachment

    monkeypatch.setattr(notifications_module, "_smtp_send", fake_smtp)
    attachment = ("inventory.csv", b"device,status\nAP-1,ONLINE\n", "text/csv")
    result = asyncio.run(notifications_module.deliver_notification(
        channel_type="EMAIL", destination="noc@example.test",
        payload={"kind": "REPORT", "report_type": "inventory", "row_count": 1},
        idempotency_key="phase-d-report-test", attachment=attachment,
    ))
    assert result.success is True
    assert captured["destination"] == "noc@example.test"
    assert captured["attachment"] == attachment
    assert captured["payload"]["kind"] == "REPORT"


def test_phase_d_telemetry_retention_index_is_brin():
    async def scenario():
        engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
        try:
            async with engine.connect() as conn:
                indexdef = await conn.scalar(__import__('sqlalchemy').text(
                    "SELECT indexdef FROM pg_indexes WHERE schemaname='public' AND indexname='ix_telemetry_metrics_collected_at'"
                ))
                assert indexdef is not None
                assert "using brin" in str(indexdef).lower()
        finally:
            await engine.dispose()
    asyncio.run(scenario())


def test_phase_d_granular_import_templates_and_subtype_enforcement():
    sector_template, sector_name, _ = exchange.template_bytes("geography", "CSV", "SECTOR")
    header = sector_template.decode("utf-8-sig").splitlines()[0]
    assert "level" not in header
    assert "location_code" in header and "customer_vlan_start" in header
    assert "sector" in sector_name

    ap_template, _, _ = exchange.template_bytes("devices", "CSV", "ACCESS_POINT")
    ap_header = ap_template.decode("utf-8-sig").splitlines()[0]
    assert "device_type" not in ap_header
    assert "parent_management_ip" in ap_header

    prepared = exchange._prepare_row_for_subtype("geography", {"name": "S1", "code": "S1"}, "SECTOR")
    assert prepared["level"] == "SECTOR"
    with pytest.raises(ValueError, match="does not match"):
        exchange._prepare_row_for_subtype("devices", {"device_type": "CPE"}, "ACCESS_POINT")


def test_phase_d_export_schema_supports_customer_services_without_new_route_family():
    from app.schemas.phase_d import ExportRequest
    payload = ExportRequest(entity_type="customer_services", format="CSV", filters={"subtype": "ALL"})
    assert payload.entity_type == "customer_services"


def test_phase_d_granular_exchange_preserves_domain_permission_boundaries():
    from app.api.routers.data_exchange import _export_permissions, _import_permissions

    assert _import_permissions("geography", "NETWORK") == (P.NETWORK_CREATE,)
    assert _import_permissions("geography", "SECTOR") == (P.GEO_CREATE,)
    assert _import_permissions("devices", "ACCESS_POINT") == (P.DEVICE_CREATE,)
    assert _import_permissions("customer_services", "ALL") == (P.CUSTOMER_CREATE,)
    assert _export_permissions("geography", "NETWORK") == (P.NETWORK_READ,)
    assert _export_permissions("geography", "SECTOR") == (P.GEO_READ,)
    assert _export_permissions("devices", "CPE") == (P.DEVICE_READ,)
    assert _export_permissions("groups", "ALL") == (P.GROUP_READ,)


def test_phase_d_customer_service_import_detects_all_in_file_unique_boundaries():
    normalized = {
        "customer_id": "11111111-1111-1111-1111-111111111111",
        "service_code": "SVC-1",
        "access_point_device_id": "22222222-2222-2222-2222-222222222222",
        "cpe_device_id": "33333333-3333-3333-3333-333333333333",
    }
    keys = exchange._import_conflict_keys("customer_services", normalized)
    assert len(keys) == 4
    assert ("CUSTOMER_SERVICE", "CUSTOMER", normalized["customer_id"]) in keys
    assert ("CUSTOMER_SERVICE", "SERVICE_CODE", "SVC-1") in keys
    assert ("CUSTOMER_SERVICE", "ACCESS_POINT", normalized["access_point_device_id"]) in keys
    assert ("CUSTOMER_SERVICE", "CPE", normalized["cpe_device_id"]) in keys


def test_phase_d_report_scope_filters_require_explicit_geo_and_group_read():
    from app.services.reports import validate_report_filter_permissions

    with pytest.raises(PermissionError, match="geo.read"):
        validate_report_filter_permissions({"network_id": "11111111-1111-1111-1111-111111111111"}, {P.REPORT_READ, P.REPORT_EXPORT})
    with pytest.raises(PermissionError, match="group.read"):
        validate_report_filter_permissions({"group_id": "22222222-2222-2222-2222-222222222222"}, {P.REPORT_READ, P.REPORT_EXPORT, P.GEO_READ})
    validate_report_filter_permissions(
        {"network_id": "11111111-1111-1111-1111-111111111111", "group_id": "22222222-2222-2222-2222-222222222222"},
        {P.REPORT_READ, P.REPORT_EXPORT, P.GEO_READ, P.GROUP_READ},
    )
