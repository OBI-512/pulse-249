import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.models import AccessTemplate
from app.remote_gateway.ssh_transport import SSHTransportError
from app.services import access_template_testing as testing


class FakeDB:
    def __init__(self):
        self.added = []
        self.scalar_result = None

    def add(self, row):
        self.added.append(row)

    async def flush(self):
        return None

    async def scalar(self, _statement):
        return self.scalar_result


def _template(protocol: str, *, settings=None, variant=None, active=True):
    return AccessTemplate(
        id=uuid4(),
        name=f"Test {protocol}",
        protocol=protocol,
        protocol_variant=variant,
        visibility="PRIVATE",
        owner_user_id=uuid4(),
        is_active=active,
        settings_json=settings or {},
    )


def test_selected_template_is_tested_without_effective_resolution(monkeypatch):
    async def scenario():
        db = FakeDB()
        template = _template("SNMP", variant="V2C")
        actor_id = uuid4()
        device_id = uuid4()

        monkeypatch.setattr(testing, "get_management_ip", AsyncMock(return_value="192.0.2.10"))
        secret_resolver = AsyncMock(return_value={"community": "TOP-SECRET-COMMUNITY"})
        monkeypatch.setattr(testing, "resolved_secrets", secret_resolver)
        probe = AsyncMock(return_value=testing.ProbeOutcome(True, sanitized_message="SNMP probe succeeded."))
        monkeypatch.setattr(testing, "_probe_snmp", probe)

        row = await testing.test_access_template_connection(
            db,
            template=template,
            device_id=device_id,
            tested_by_user_id=actor_id,
        )

        secret_resolver.assert_awaited_once_with(db, template.id)
        probe.assert_awaited_once()
        assert row.template_id == template.id
        assert row.device_id == device_id
        assert row.status == "SUCCESS"
        assert row.failure_code is None
        assert "TOP-SECRET-COMMUNITY" not in (row.sanitized_message or "")
        assert db.added == [row]

    asyncio.run(scenario())


def test_inactive_template_fails_without_resolving_secret_values(monkeypatch):
    async def scenario():
        db = FakeDB()
        template = _template("SSH", active=False)
        secret_resolver = AsyncMock(return_value={"username": "u", "password": "p"})
        monkeypatch.setattr(testing, "get_management_ip", AsyncMock(return_value="192.0.2.11"))
        monkeypatch.setattr(testing, "resolved_secrets", secret_resolver)

        row = await testing.test_access_template_connection(
            db,
            template=template,
            device_id=uuid4(),
            tested_by_user_id=uuid4(),
        )

        secret_resolver.assert_not_awaited()
        assert row.status == "FAILED"
        assert row.failure_code == "PROTOCOL_NOT_SUPPORTED"

    asyncio.run(scenario())


def test_telnet_probe_fails_closed_when_global_gate_is_disabled(monkeypatch):
    async def scenario():
        template = _template("TELNET", settings={"port": 23})
        monkeypatch.setattr(testing.settings, "telnet_access_enabled", False)

        with pytest.raises(testing.AccessTemplateProbeFailure) as exc:
            await testing._probe_telnet(
                template=template,
                management_ip="192.0.2.12",
                secrets={"username": "legacy-user", "password": "legacy-password"},
            )
        assert exc.value.code == "PROTOCOL_NOT_SUPPORTED"
        assert "legacy-password" not in exc.value.message

    asyncio.run(scenario())


def test_ssh_test_requires_device_specific_host_key_pin():
    async def scenario():
        db = FakeDB()
        template = _template("SSH", settings={"port": 22})

        with pytest.raises(testing.AccessTemplateProbeFailure) as exc:
            await testing._probe_ssh(
                db,
                template=template,
                device_id=uuid4(),
                management_ip="192.0.2.13",
                secrets={"username": "operator", "password": "secret-password"},
            )
        assert exc.value.code == "SSH_HOST_KEY_REQUIRED"
        assert "secret-password" not in exc.value.message

    asyncio.run(scenario())


def test_ssh_authentication_rejection_is_reported_precisely(monkeypatch):
    async def scenario():
        db = FakeDB()
        db.scalar_result = SimpleNamespace(ssh_host_key_fingerprint="SHA256:example")
        template = _template(
            "SSH",
            settings={
                "port": 22,
                "timeout_seconds": 9,
                "compatibility_profile": "LEGACY_SSH_RSA_DH1_CBC",
            },
        )
        monkeypatch.setattr(testing, "_tcp_preflight", AsyncMock(return_value=None))
        starter = AsyncMock(side_effect=SSHTransportError("SSH_AUTHENTICATION_FAILED"))
        monkeypatch.setattr(testing, "start_ssh", starter)

        with pytest.raises(testing.AccessTemplateProbeFailure) as exc:
            await testing._probe_ssh(
                db,
                template=template,
                device_id=uuid4(),
                management_ip="192.0.2.14",
                secrets={"username": "operator", "password": "secret-password"},
            )

        assert exc.value.code == "AUTHENTICATION_FAILED"
        assert exc.value.message == "The device rejected the configured SSH credentials."
        assert "secret-password" not in exc.value.message
        assert starter.await_args.kwargs["authentication_timeout_seconds"] == 9

    asyncio.run(scenario())


def test_probe_outcomes_never_need_raw_secret_or_subprocess_output():
    success = testing.ProbeOutcome(True, sanitized_message="Authentication succeeded.")
    failure = testing.ProbeOutcome(False, "AUTHENTICATION_FAILED", "Authentication failed.")
    assert success.failure_code is None
    assert failure.failure_code == "AUTHENTICATION_FAILED"
    assert "stderr" not in (failure.sanitized_message or "").lower()
