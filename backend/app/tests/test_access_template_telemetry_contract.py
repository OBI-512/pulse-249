from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import uuid4

from app.services.access_templates import SNMPRuntimeAccess
from app.tasks import telemetry as telemetry_tasks


class _RowResult:
    def __init__(self, row):
        self._row = row

    def first(self):
        return self._row


class _FakeTelemetrySession:
    def __init__(self, *, device, state, profile, management_ip: str):
        self._row = (device, state, profile)
        self._management_ip = management_ip

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def execute(self, _statement):
        return _RowResult(self._row)

    async def scalar(self, _statement):
        return self._management_ip


def _session_factory(*, device, state, profile, management_ip: str):
    def SessionLocal():
        return _FakeTelemetrySession(
            device=device,
            state=state,
            profile=profile,
            management_ip=management_ip,
        )

    return SessionLocal


def _telemetry_contract_objects():
    device_id = uuid4()
    lease_token = uuid4()
    profile_id = uuid4()
    legacy_reference = "env://TEST_LEGACY_SNMP_COMMUNITY"

    device = SimpleNamespace(id=device_id, credential_reference=legacy_reference)
    state = SimpleNamespace(enabled=True, lease_token=lease_token)
    profile = SimpleNamespace(
        id=profile_id,
        enabled=True,
        interval_seconds=900,
        timeout_seconds=4,
        retries=1,
        metric_definitions=[{"key": "sys_name", "oid": "1.3.6.1.2.1.1.5.0"}],
        max_metrics=16,
    )
    return device, state, profile, lease_token, legacy_reference


def test_effective_snmp_access_template_overrides_legacy_credential_reference(monkeypatch):
    device, state, profile, lease_token, legacy_reference = _telemetry_contract_objects()
    template_runtime = SNMPRuntimeAccess(
        credential={"version": "2c", "community": "TEST-MANAGED-COMMUNITY"},
        port=1161,
        timeout_seconds=8,
        retries=3,
    )

    async def _resolve(_db, *, device_id):
        assert device_id == device.id
        return template_runtime

    monkeypatch.setattr(telemetry_tasks, "resolve_snmp_runtime_access", _resolve)
    SessionLocal = _session_factory(
        device=device,
        state=state,
        profile=profile,
        management_ip="192.0.2.44",
    )

    status, prepared = asyncio.run(
        telemetry_tasks._prepare_device(SessionLocal, device.id, lease_token)
    )

    assert status == "READY"
    assert prepared is not None
    assert prepared["credential_reference"] is None
    assert prepared["credential"] == template_runtime.credential
    assert prepared["snmp_port"] == 1161
    assert prepared["timeout_seconds"] == 8
    assert prepared["retries"] == 3
    assert legacy_reference not in repr(prepared["credential"])


def test_telemetry_keeps_legacy_snmp_reference_fallback_without_effective_template(monkeypatch):
    device, state, profile, lease_token, legacy_reference = _telemetry_contract_objects()

    async def _resolve(_db, *, device_id):
        assert device_id == device.id
        return None

    monkeypatch.setattr(telemetry_tasks, "resolve_snmp_runtime_access", _resolve)
    SessionLocal = _session_factory(
        device=device,
        state=state,
        profile=profile,
        management_ip="192.0.2.45",
    )

    status, prepared = asyncio.run(
        telemetry_tasks._prepare_device(SessionLocal, device.id, lease_token)
    )

    assert status == "READY"
    assert prepared is not None
    assert prepared["credential_reference"] == legacy_reference
    assert prepared["credential"] is None
    assert prepared["snmp_port"] == 161
    assert prepared["timeout_seconds"] == profile.timeout_seconds
    assert prepared["retries"] == profile.retries
