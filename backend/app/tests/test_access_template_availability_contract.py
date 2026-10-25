from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import uuid4

from app.availability import probes as availability_probes
from app.availability.state import ProbeOutcome
from app.services.access_templates import AccessTemplateSecretError, SNMPRuntimeAccess
from app.tasks import availability as availability_tasks


class _FakeSession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


def _session_factory():
    return _FakeSession()


def _target(*, profile: str = "SNMP", credential_reference: str | None = "env://LEGACY_SNMP"):
    return availability_tasks._ProbeTarget(
        availability_id=uuid4(),
        device_id=uuid4(),
        lease_token=uuid4(),
        profile=profile,
        ip_address="192.0.2.61",
        credential_reference=credential_reference,
    )


def _runtime():
    return SimpleNamespace(
        probe_timeout_seconds=3.0,
        probe_retries=2,
        tcp_ports=(22, 80, 443),
    )


def test_effective_snmp_access_template_overrides_legacy_availability_reference(monkeypatch):
    target = _target()
    template_runtime = SNMPRuntimeAccess(
        credential={"version": "2c", "community": "TEST-MANAGED-COMMUNITY"},
        port=1161,
        timeout_seconds=8,
        retries=3,
    )

    async def _resolve(_db, *, device_id):
        assert device_id == target.device_id
        return template_runtime

    monkeypatch.setattr(availability_tasks, "resolve_snmp_runtime_access", _resolve)

    access = asyncio.run(
        availability_tasks._resolve_probe_access(_session_factory, target, _runtime())
    )

    assert access.credential_reference is None
    assert access.credential == template_runtime.credential
    assert access.snmp_port == 1161
    assert access.timeout_seconds == 8
    assert access.retries == 3
    assert "TEST-MANAGED-COMMUNITY" not in repr(access)


def test_availability_keeps_legacy_snmp_reference_without_effective_template(monkeypatch):
    target = _target()

    async def _resolve(_db, *, device_id):
        assert device_id == target.device_id
        return None

    monkeypatch.setattr(availability_tasks, "resolve_snmp_runtime_access", _resolve)

    access = asyncio.run(
        availability_tasks._resolve_probe_access(_session_factory, target, _runtime())
    )

    assert access.credential_reference == "env://LEGACY_SNMP"
    assert access.credential is None
    assert access.snmp_port == 161
    assert access.timeout_seconds == 3.0
    assert access.retries == 2
    assert access.error_code is None


def test_availability_template_resolution_failure_is_indeterminate_not_legacy_fallback(monkeypatch):
    target = _target()

    async def _resolve(_db, *, device_id):
        assert device_id == target.device_id
        raise AccessTemplateSecretError("CONFIGURATION_CONFLICT")

    monkeypatch.setattr(availability_tasks, "resolve_snmp_runtime_access", _resolve)

    access = asyncio.run(
        availability_tasks._resolve_probe_access(_session_factory, target, _runtime())
    )

    assert access.error_code == "CONFIGURATION_CONFLICT"
    assert access.credential_reference is None
    assert access.credential is None


def test_availability_probe_accepts_worker_resolved_snmp_credential(monkeypatch):
    captured = {}

    async def _discover(context):
        captured["context"] = context
        return SimpleNamespace(
            success=True,
            response_time_ms=12.5,
            message="SNMP response received.",
            raw_data={},
        )

    def _legacy_resolver(_reference):
        raise AssertionError("legacy resolver must not run for a managed Access Template")

    monkeypatch.setattr(availability_probes._SNMP, "discover", _discover)
    monkeypatch.setattr(availability_probes, "resolve_snmp_credential", _legacy_resolver)

    observation = asyncio.run(
        availability_probes.probe_availability(
            profile="SNMP",
            ip_address="192.0.2.62",
            timeout_seconds=7,
            retries=0,
            tcp_ports=(22,),
            credential_reference=None,
            credential={"version": "2c", "community": "TEST-MANAGED-COMMUNITY"},
            snmp_port=1161,
        )
    )

    assert observation.outcome is ProbeOutcome.SUCCESS
    assert observation.result_code == "SNMP_REACHABLE"
    context = captured["context"]
    assert context.snmp_version == "2c"
    assert context.snmp_port == 1161
    assert context.timeout_seconds == 7
    assert context.snmp_community == "TEST-MANAGED-COMMUNITY"
