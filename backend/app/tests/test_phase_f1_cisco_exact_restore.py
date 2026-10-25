from __future__ import annotations

import asyncio
import json
from pathlib import Path
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.configuration.artifact_leases import (
    ArtifactLease,
    ArtifactLeaseStore,
    ConfigurationArtifactLeaseError,
)
from app.configuration.cisco_ios import (
    CISCO_IOS_ADAPTER,
    CiscoRestoreTarget,
    _wait_for_served_receipt,
)
from app.configuration.contracts import (
    ConfigurationCapability,
    ConfigurationCaptureResult,
    ConfigurationExecutionContext,
    ConfigurationPreMutationError,
    ConfigurationTemplateDefinition,
    ConfigurationTransport,
)
from app.configuration.ssh_cli import ConfigurationSSHError
from app.configuration.templating import ConfigurationTemplateError
from app.settings import settings


BACKEND = Path(__file__).resolve().parents[2]
ROOT = BACKEND.parent


class FakeRedis:
    def __init__(self):
        self.data: dict[str, str] = {}

    async def set(self, key, value, *, ex=None, nx=False, **_kwargs):
        if nx and key in self.data:
            return False
        self.data[str(key)] = str(value)
        return True

    async def get(self, key):
        return self.data.get(str(key))

    async def eval(self, script, _keys, key, source_ip):
        raw = self.data.get(str(key))
        if raw is None:
            return ["MISSING"]
        lease = json.loads(raw)
        if lease["expected_source_ip"] != source_ip:
            return ["SOURCE_MISMATCH"]

        if "served_count" in script:
            reads = int(lease.get("read_count") or 0)
            served = int(lease.get("served_count") or 0)
            maximum = int(lease["max_reads"])
            if (
                maximum < 1
                or reads < 1
                or reads > maximum
                or served < 0
                or served >= reads
                or served >= maximum
            ):
                return ["INVALID"]
            lease["served_count"] = served + 1
            self.data[str(key)] = json.dumps(
                lease, sort_keys=True, separators=(",", ":")
            )
            return ["OK", self.data[str(key)]]

        if int(lease["read_count"]) >= int(lease["max_reads"]):
            self.data.pop(str(key), None)
            return ["READ_LIMIT"]
        lease["read_count"] = int(lease["read_count"]) + 1
        self.data[str(key)] = json.dumps(lease, sort_keys=True, separators=(",", ":"))
        return ["OK", self.data[str(key)]]

    async def delete(self, key):
        self.data.pop(str(key), None)
        return 1


def _definition() -> ConfigurationTemplateDefinition:
    return ConfigurationTemplateDefinition(
        adapter_key="cisco.ios_ssh_cli",
        transport=ConfigurationTransport.SSH_CLI,
        capabilities={
            ConfigurationCapability.CAPTURE,
            ConfigurationCapability.RESTORE,
            ConfigurationCapability.ROLLBACK,
            ConfigurationCapability.PROVISIONAL_COMMIT,
        },
        transport_parameters={
            "prompt_pattern": r"GNS-SECTOR-01#\s*$",
            "capture": {
                "commands": [
                    {"send": "terminal length 0"},
                    {"send": "show running-config"},
                ],
                "start_pattern": r"^Current configuration\s*:\s*\d+\s+bytes\s*$",
                "end_pattern": r"^end\s*$",
                "include_start_line": False,
                "include_end_line": True,
                "restorable": True,
            },
            "restore": {
                "mode": "CISCO_CONFIGURE_REPLACE_HTTP",
                "force": True,
                "confirmation_minutes": 2,
                "revert_on_error": True,
            },
        },
        functions=[],
    )


def _context() -> ConfigurationExecutionContext:
    return ConfigurationExecutionContext(
        device_id=str(uuid4()),
        management_address="192.0.2.4",
        template_version_id=str(uuid4()),
        connection_parameters={
            "template_transport_parameters": _definition().transport_parameters,
        },
    )


def test_cisco_adapter_accepts_only_exact_guarded_restore_contract():
    asyncio.run(CISCO_IOS_ADAPTER.validate_template(_definition()))

    bad = _definition()
    bad.transport_parameters["restore"] = {
        "mode": "COMMAND_STREAM",
        "force": True,
        "confirmation_minutes": 2,
        "revert_on_error": True,
    }
    with pytest.raises(
        ConfigurationTemplateError,
        match="CONFIGURATION_CISCO_RESTORE_MODE_REQUIRED",
    ):
        asyncio.run(CISCO_IOS_ADAPTER.validate_template(bad))

    bad = _definition()
    bad.capabilities.remove(ConfigurationCapability.PROVISIONAL_COMMIT)
    with pytest.raises(
        ConfigurationTemplateError,
        match="CONFIGURATION_CISCO_PROVISIONAL_COMMIT_REQUIRED",
    ):
        asyncio.run(CISCO_IOS_ADAPTER.validate_template(bad))

    bad = _definition()
    bad.transport_parameters["capture"]["restorable"] = False
    with pytest.raises(
        ConfigurationTemplateError,
        match="CONFIGURATION_CISCO_RESTORABLE_CAPTURE_REQUIRED",
    ):
        asyncio.run(CISCO_IOS_ADAPTER.validate_template(bad))

    bad = _definition()
    bad.transport_parameters["restore"]["confirmation_minutes"] = 120
    with pytest.raises(
        ConfigurationTemplateError,
        match="CONFIGURATION_CISCO_CONFIRMATION_TIME_INVALID",
    ):
        asyncio.run(CISCO_IOS_ADAPTER.validate_template(bad))


def test_artifact_lease_is_hashed_source_bound_and_allows_bounded_repeat_reads(monkeypatch):
    monkeypatch.setattr(settings, "configuration_artifact_lease_ttl_seconds", 90)
    monkeypatch.setattr(settings, "configuration_artifact_lease_max_reads", 2)
    fake = FakeRedis()
    store = ArtifactLeaseStore(fake)

    async def scenario():
        issued = await store.issue(
            operation_id=str(uuid4()),
            device_id=str(uuid4()),
            snapshot_id=str(uuid4()),
            template_version_id=str(uuid4()),
            expected_source_ip="192.0.2.4",
            expected_plaintext_sha256="a" * 64,
        )
        assert issued.token not in "\n".join(fake.data.keys())
        assert issued.token not in "\n".join(fake.data.values())
        first = await store.consume(issued.token, source_ip="192.0.2.4")
        second = await store.consume(issued.token, source_ip="192.0.2.4")
        assert first.read_count == 1
        assert second.read_count == 2
        with pytest.raises(
            ConfigurationArtifactLeaseError,
            match="CONFIGURATION_ARTIFACT_LEASE_READ_LIMIT_EXCEEDED",
        ):
            await store.consume(issued.token, source_ip="192.0.2.4")

        other = await store.issue(
            operation_id=str(uuid4()),
            device_id=str(uuid4()),
            snapshot_id=str(uuid4()),
            template_version_id=str(uuid4()),
            expected_source_ip="192.0.2.4",
            expected_plaintext_sha256="b" * 64,
        )
        with pytest.raises(
            ConfigurationArtifactLeaseError,
            match="CONFIGURATION_ARTIFACT_LEASE_SOURCE_MISMATCH",
        ):
            await store.consume(other.token, source_ip="192.0.2.5")
        accepted = await store.consume(other.token, source_ip="192.0.2.4")
        assert accepted.read_count == 1

    asyncio.run(scenario())


def test_artifact_served_receipt_requires_prior_consume_and_is_backward_compatible(monkeypatch):
    monkeypatch.setattr(settings, "configuration_artifact_lease_ttl_seconds", 90)
    monkeypatch.setattr(settings, "configuration_artifact_lease_max_reads", 2)

    legacy = ArtifactLease.from_mapping(
        {
            "operation_id": str(uuid4()),
            "device_id": str(uuid4()),
            "snapshot_id": str(uuid4()),
            "template_version_id": str(uuid4()),
            "expected_source_ip": "192.0.2.4",
            "expected_plaintext_sha256": "e" * 64,
            "read_count": 1,
            "max_reads": 2,
            "expires_at": time.time() + 60,
        }
    )
    assert legacy.served_count == 0

    fake = FakeRedis()
    store = ArtifactLeaseStore(fake)

    async def scenario():
        issued = await store.issue(
            operation_id=str(uuid4()),
            device_id=str(uuid4()),
            snapshot_id=str(uuid4()),
            template_version_id=str(uuid4()),
            expected_source_ip="192.0.2.4",
            expected_plaintext_sha256="f" * 64,
        )

        with pytest.raises(
            ConfigurationArtifactLeaseError,
            match="CONFIGURATION_ARTIFACT_LEASE_SERVE_STATE_INVALID",
        ):
            await store.mark_served(issued.token, source_ip="192.0.2.4")

        first_read = await store.consume(issued.token, source_ip="192.0.2.4")
        assert first_read.read_count == 1
        first_served = await store.mark_served(issued.token, source_ip="192.0.2.4")
        assert first_served.served_count == 1
        assert await store.get_served_count(issued.token, source_ip="192.0.2.4") == 1

        with pytest.raises(
            ConfigurationArtifactLeaseError,
            match="CONFIGURATION_ARTIFACT_LEASE_SOURCE_MISMATCH",
        ):
            await store.get_served_count(issued.token, source_ip="192.0.2.5")

        second_read = await store.consume(issued.token, source_ip="192.0.2.4")
        assert second_read.read_count == 2
        second_served = await store.mark_served(issued.token, source_ip="192.0.2.4")
        assert second_served.served_count == 2

        with pytest.raises(
            ConfigurationArtifactLeaseError,
            match="CONFIGURATION_ARTIFACT_LEASE_SERVE_STATE_INVALID",
        ):
            await store.mark_served(issued.token, source_ip="192.0.2.4")

    asyncio.run(scenario())


def test_cisco_served_receipt_wait_tolerates_short_gateway_observation_delay(monkeypatch):
    observations = [0, 0, 1]
    calls: list[tuple[str, str]] = []

    async def fake_served_count(token, *, source_ip):
        calls.append((token, source_ip))
        return observations.pop(0)

    async def fake_sleep(_seconds):
        return None

    monkeypatch.setattr(
        "app.configuration.cisco_ios.get_artifact_lease_served_count",
        fake_served_count,
    )
    monkeypatch.setattr("app.configuration.cisco_ios.asyncio.sleep", fake_sleep)

    lease = SimpleNamespace(token="delayed-receipt-token", max_reads=4)
    result = asyncio.run(
        _wait_for_served_receipt(
            lease,
            source_ip="192.0.2.4",
            timeout_seconds=1.0,
        )
    )

    assert result == 1
    assert len(calls) == 3
    assert all(source == "192.0.2.4" for _, source in calls)


def test_cisco_restore_stages_http_artifact_locally_then_replaces_confirms_and_cleans(monkeypatch):
    payload = b"version 15.3\nhostname GNS-SECTOR-01\nend\n"
    target = CiscoRestoreTarget(
        operation_id="11111111-2222-3333-4444-555555555555",
        device_id=str(uuid4()),
        snapshot_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        template_version_id=str(uuid4()),
        expected_source_ip="192.0.2.4",
        expected_plaintext_sha256="c" * 64,
    )
    commands: list[str] = []
    revoked: list[str] = []

    class Session:
        prompt_pattern = __import__("re").compile(r"[>#]\s*$")

        async def command(self, command, **_kwargs):
            commands.append(command)
            if command == "show file systems":
                return "flash rw flash:\nhttp rw http:\nGNS-SECTOR-01#"
            return "GNS-SECTOR-01#"

        def close(self):
            pass

    async def fake_session(_context):
        return Session()

    async def fake_target(*_args, **_kwargs):
        return target

    async def fake_issue(_target):
        return SimpleNamespace(token="stage4-local-secret-token", max_reads=4)

    async def fake_wait(_lease, *, source_ip, **_kwargs):
        assert source_ip == "192.0.2.4"
        return 1

    async def fake_revoke(token):
        revoked.append(token)

    async def fake_capture(_context):
        return ConfigurationCaptureResult(
            payload=payload,
            metadata={"transport": "SSH_CLI"},
            restorable=True,
        )

    monkeypatch.setattr(settings, "configuration_artifact_public_base_url", "http://192.0.2.1:8020")
    monkeypatch.setattr("app.configuration.cisco_ios._resolve_active_restore_target", fake_target)
    monkeypatch.setattr("app.configuration.cisco_ios._issue_restore_lease", fake_issue)
    monkeypatch.setattr("app.configuration.cisco_ios._wait_for_served_receipt", fake_wait)
    monkeypatch.setattr("app.configuration.cisco_ios.revoke_artifact_lease", fake_revoke)
    monkeypatch.setattr(CISCO_IOS_ADAPTER, "_session", fake_session)
    monkeypatch.setattr(CISCO_IOS_ADAPTER, "capture", fake_capture)

    result = asyncio.run(CISCO_IOS_ADAPTER.restore(_context(), payload))

    staged = "flash:fttw-stage4p-111111112222-aaaaaaaabbbb.cfg"
    assert commands == [
        "show file systems",
        "show flash:",
        f"delete {staged} /force",
        f"copy http://192.0.2.1:8020/configuration-artifacts/stage4-local-secret-token {staged}",
        f"configure replace {staged} force time 2",
        f"delete {staged} /force",
        "configure confirm",
    ]
    assert result["confirmed"] is True
    assert "stage4-local-secret-token" not in repr(result)
    assert revoked == ["stage4-local-secret-token"]


def test_cisco_restore_without_stage_receipt_never_runs_configure_replace(monkeypatch):
    payload = b"version 15.3\nhostname GNS-SECTOR-01\nend\n"
    target = CiscoRestoreTarget(
        operation_id="11111111-2222-3333-4444-555555555555",
        device_id=str(uuid4()),
        snapshot_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        template_version_id=str(uuid4()),
        expected_source_ip="192.0.2.4",
        expected_plaintext_sha256="9" * 64,
    )
    commands: list[str] = []
    revoked: list[str] = []

    class Session:
        prompt_pattern = __import__("re").compile(r"[>#]\s*$")

        async def command(self, command, **_kwargs):
            commands.append(command)
            if command == "show file systems":
                return "flash rw flash:\nGNS-SECTOR-01#"
            return "GNS-SECTOR-01#"

        def close(self):
            pass

    async def fake_session(_context):
        return Session()

    async def fake_target(*_args, **_kwargs):
        return target

    async def fake_issue(_target):
        return SimpleNamespace(token="stage4-no-receipt-token", max_reads=4)

    async def fake_wait(_lease, *, source_ip, **_kwargs):
        assert source_ip == "192.0.2.4"
        return 0

    async def fake_revoke(token):
        revoked.append(token)

    monkeypatch.setattr(settings, "configuration_artifact_public_base_url", "http://192.0.2.1:8020")
    monkeypatch.setattr("app.configuration.cisco_ios._resolve_active_restore_target", fake_target)
    monkeypatch.setattr("app.configuration.cisco_ios._issue_restore_lease", fake_issue)
    monkeypatch.setattr("app.configuration.cisco_ios._wait_for_served_receipt", fake_wait)
    monkeypatch.setattr("app.configuration.cisco_ios.revoke_artifact_lease", fake_revoke)
    monkeypatch.setattr(CISCO_IOS_ADAPTER, "_session", fake_session)

    with pytest.raises(
        ConfigurationSSHError,
        match="CONFIGURATION_CISCO_ARTIFACT_DELIVERY_UNCONFIRMED",
    ):
        asyncio.run(CISCO_IOS_ADAPTER.restore(_context(), payload))

    assert any(command.startswith("copy http://") for command in commands)
    assert not any(command.startswith("configure replace ") for command in commands)
    assert revoked == ["stage4-no-receipt-token"]


def test_cisco_restore_local_stage_mismatch_reverts_and_cleans(monkeypatch):
    payload = b"version 15.3\nhostname GNS-SECTOR-01\nend\n"
    target = CiscoRestoreTarget(
        operation_id="11111111-2222-3333-4444-555555555555",
        device_id=str(uuid4()),
        snapshot_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        template_version_id=str(uuid4()),
        expected_source_ip="192.0.2.4",
        expected_plaintext_sha256="d" * 64,
    )
    commands: list[str] = []

    class Session:
        prompt_pattern = __import__("re").compile(r"[>#]\s*$")

        async def command(self, command, **_kwargs):
            commands.append(command)
            if command == "show file systems":
                return "flash rw flash:\nGNS-SECTOR-01#"
            return "GNS-SECTOR-01#"

        def close(self):
            pass

    async def fake_session(_context):
        return Session()

    async def fake_target(*_args, **_kwargs):
        return target

    async def fake_issue(_target):
        return SimpleNamespace(token="stage4-mismatch-token", max_reads=4)

    async def fake_wait(_lease, *, source_ip, **_kwargs):
        assert source_ip == "192.0.2.4"
        return 1

    async def fake_revoke(_token):
        return None

    async def mismatched_capture(_context):
        return ConfigurationCaptureResult(
            payload=b"different\nend\n",
            metadata={"transport": "SSH_CLI"},
            restorable=True,
        )

    monkeypatch.setattr(settings, "configuration_artifact_public_base_url", "http://192.0.2.1:8020")
    monkeypatch.setattr("app.configuration.cisco_ios._resolve_active_restore_target", fake_target)
    monkeypatch.setattr("app.configuration.cisco_ios._issue_restore_lease", fake_issue)
    monkeypatch.setattr("app.configuration.cisco_ios._wait_for_served_receipt", fake_wait)
    monkeypatch.setattr("app.configuration.cisco_ios.revoke_artifact_lease", fake_revoke)
    monkeypatch.setattr(CISCO_IOS_ADAPTER, "_session", fake_session)
    monkeypatch.setattr(CISCO_IOS_ADAPTER, "capture", mismatched_capture)

    with pytest.raises(
        ConfigurationSSHError,
        match="CONFIGURATION_CISCO_RESTORE_PRECONFIRM_MISMATCH",
    ):
        asyncio.run(CISCO_IOS_ADAPTER.restore(_context(), payload))

    staged = "flash:fttw-stage4p-111111112222-aaaaaaaabbbb.cfg"
    assert f"configure replace {staged} force time 2" in commands
    assert commands.count(f"delete {staged} /force") >= 2
    assert commands[-1] == "configure revert now"


def test_cisco_local_staging_requires_rw_local_filesystem(monkeypatch):
    class Session:
        prompt_pattern = __import__("re").compile(r"[>#]\s*$")

        async def command(self, command, **_kwargs):
            assert command == "show file systems"
            return "http rw http:\ntftp rw tftp:\nnvram ro nvram:\nGNS-SECTOR-01#"

        def close(self):
            pass

    async def fake_session(_context):
        return Session()

    monkeypatch.setattr(CISCO_IOS_ADAPTER, "_session", fake_session)

    with pytest.raises(
        ConfigurationSSHError,
        match="CONFIGURATION_CISCO_LOCAL_STAGING_FILESYSTEM_REQUIRED",
    ):
        asyncio.run(CISCO_IOS_ADAPTER._select_local_staging_prefix(_context()))

def test_cisco_local_staging_skips_advertised_but_unavailable_flash_and_selects_disk0(monkeypatch):
    commands: list[str] = []

    class Session:
        prompt_pattern = __import__("re").compile(r"[>#]\s*$")

        async def command(self, command, **_kwargs):
            commands.append(command)
            if command == "show file systems":
                return "flash rw flash:\\ndisk rw disk0:\\nGNS-SECTOR-01#"
            if command == "show flash:":
                return "Open device slot0 failed (No such device)\\nGNS-SECTOR-01#"
            if command == "show disk0:":
                return "No files on device\\n66867200 bytes available (0 bytes used)\\nGNS-SECTOR-01#"
            raise AssertionError(command)

        def close(self):
            pass

    async def fake_session(_context):
        return Session()

    monkeypatch.setattr(CISCO_IOS_ADAPTER, "_session", fake_session)

    selected = asyncio.run(CISCO_IOS_ADAPTER._select_local_staging_prefix(_context()))

    assert selected == "disk0:"
    assert commands == ["show file systems", "show flash:", "show disk0:"]


def test_cisco_restore_preflight_stages_locally_requires_served_receipt_cleans_and_revokes(monkeypatch):
    payload = b"version 15.3\nhostname GNS-SECTOR-01\nend\n"
    target = CiscoRestoreTarget(
        operation_id="11111111-2222-3333-4444-555555555555",
        device_id=str(uuid4()),
        snapshot_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        template_version_id=str(uuid4()),
        expected_source_ip="192.0.2.4",
        expected_plaintext_sha256="7" * 64,
    )
    commands: list[str] = []
    revoked: list[str] = []

    class Session:
        prompt_pattern = __import__("re").compile(r"[>#]\s*$")

        async def command(self, command, **_kwargs):
            commands.append(command)
            if command == "show file systems":
                return "flash rw flash:\nhttp rw http:\nGNS-SECTOR-01#"
            return "GNS-SECTOR-01#"

        def close(self):
            pass

    async def fake_session(_context):
        return Session()

    async def fake_target(*_args, **_kwargs):
        return target

    async def fake_issue(_target):
        assert _target == target
        return SimpleNamespace(token="preflight-secret-token", max_reads=4)

    async def fake_wait(_lease, *, source_ip, **_kwargs):
        assert source_ip == "192.0.2.4"
        return 1

    async def fake_revoke(token):
        revoked.append(token)

    monkeypatch.setattr(settings, "configuration_artifact_public_base_url", "http://192.0.2.1:8020")
    monkeypatch.setattr("app.configuration.cisco_ios._resolve_active_restore_target", fake_target)
    monkeypatch.setattr("app.configuration.cisco_ios._issue_restore_lease", fake_issue)
    monkeypatch.setattr("app.configuration.cisco_ios._wait_for_served_receipt", fake_wait)
    monkeypatch.setattr("app.configuration.cisco_ios.revoke_artifact_lease", fake_revoke)
    monkeypatch.setattr(CISCO_IOS_ADAPTER, "_session", fake_session)

    result = asyncio.run(CISCO_IOS_ADAPTER.preflight_restore(_context(), payload))

    staged = "flash:fttw-stage4p-111111112222-aaaaaaaabbbb.cfg"
    assert commands == [
        "show file systems",
        "show flash:",
        f"delete {staged} /force",
        f"copy http://192.0.2.1:8020/configuration-artifacts/preflight-secret-token {staged}",
        f"delete {staged} /force",
    ]
    assert not any("null:" in command for command in commands)
    assert not any(command.startswith("configure replace ") for command in commands)
    assert result["preflight"] == "CISCO_ARTIFACT_FETCH_CONFIRMED"
    assert "preflight-secret-token" not in repr(result)
    assert revoked == ["preflight-secret-token"]

def test_cisco_restore_preflight_without_served_receipt_is_safe_pre_mutation_failure(monkeypatch):
    payload = b"version 15.3\nhostname GNS-SECTOR-01\nend\n"
    target = CiscoRestoreTarget(
        operation_id="11111111-2222-3333-4444-555555555555",
        device_id=str(uuid4()),
        snapshot_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        template_version_id=str(uuid4()),
        expected_source_ip="192.0.2.4",
        expected_plaintext_sha256="8" * 64,
    )
    commands: list[str] = []
    revoked: list[str] = []

    class Session:
        prompt_pattern = __import__("re").compile(r"[>#]\s*$")

        async def command(self, command, **_kwargs):
            commands.append(command)
            if command == "show file systems":
                return "flash rw flash:\nGNS-SECTOR-01#"
            return "GNS-SECTOR-01#"

        def close(self):
            pass

    async def fake_session(_context):
        return Session()

    async def fake_target(*_args, **_kwargs):
        return target

    async def fake_issue(_target):
        return SimpleNamespace(token="preflight-no-receipt-token", max_reads=4)

    async def fake_wait(_lease, *, source_ip, **_kwargs):
        assert source_ip == "192.0.2.4"
        return 0

    async def fake_revoke(token):
        revoked.append(token)

    monkeypatch.setattr(settings, "configuration_artifact_public_base_url", "http://192.0.2.1:8020")
    monkeypatch.setattr("app.configuration.cisco_ios._resolve_active_restore_target", fake_target)
    monkeypatch.setattr("app.configuration.cisco_ios._issue_restore_lease", fake_issue)
    monkeypatch.setattr("app.configuration.cisco_ios._wait_for_served_receipt", fake_wait)
    monkeypatch.setattr("app.configuration.cisco_ios.revoke_artifact_lease", fake_revoke)
    monkeypatch.setattr(CISCO_IOS_ADAPTER, "_session", fake_session)

    with pytest.raises(
        ConfigurationPreMutationError,
        match="CONFIGURATION_CISCO_ARTIFACT_PREFLIGHT_UNCONFIRMED",
    ):
        asyncio.run(CISCO_IOS_ADAPTER.preflight_restore(_context(), payload))

    staged = "flash:fttw-stage4p-111111112222-aaaaaaaabbbb.cfg"
    assert any(command.startswith("copy http://") and command.endswith(staged) for command in commands)
    assert commands.count(f"delete {staged} /force") >= 2
    assert not any("null:" in command for command in commands)
    assert not any(command.startswith("configure replace ") for command in commands)
    assert revoked == ["preflight-no-receipt-token"]

def test_cisco_replace_command_does_not_depend_on_human_success_prose(monkeypatch):
    outputs = [
        "GNS-SECTOR-01#",
        "% Error opening source URL\nGNS-SECTOR-01#",
    ]

    class Session:
        async def command(self, _command, **_kwargs):
            return outputs.pop(0)

        def close(self):
            pass

    async def fake_session(_context):
        return Session()

    monkeypatch.setattr(CISCO_IOS_ADAPTER, "_session", fake_session)

    # The command layer may return only a prompt on an IOS variant/no-op.
    # Overall restore success is still impossible without the served receipt,
    # provisional byte equality, confirm, and confirmed byte equality.
    asyncio.run(
        CISCO_IOS_ADAPTER._run_replace_command(
            _context(),
            url="http://192.0.2.1:8020/configuration-artifacts/redacted",
            confirmation_minutes=2,
        )
    )

    with pytest.raises(
        ConfigurationSSHError,
        match="CONFIGURATION_CISCO_REPLACE_DEVICE_REJECTED",
    ):
        asyncio.run(
            CISCO_IOS_ADAPTER._run_replace_command(
                _context(),
                url="http://192.0.2.1:8020/configuration-artifacts/redacted",
                confirmation_minutes=2,
            )
        )


def test_artifact_gateway_is_isolated_no_store_served_receipt_and_normal_backend_route_contract_unchanged():
    gateway = (BACKEND / "app" / "configuration_artifact_gateway" / "main.py").read_text(
        encoding="utf-8"
    )
    leases = (BACKEND / "app" / "configuration" / "artifact_leases.py").read_text(
        encoding="utf-8"
    )
    registry = (BACKEND / "app" / "configuration" / "registry.py").read_text(
        encoding="utf-8"
    )
    normal_router = (BACKEND / "app" / "api" / "router.py").read_text(encoding="utf-8")

    # These assertions intentionally cover files present in the backend runtime
    # image. Dockerfile/Compose isolation is validated separately by host-side
    # compose/build qualification because those build files are not copied into
    # the backend test image.
    assert 'docs_url=None' in gateway
    assert 'openapi_url=None' in gateway
    assert 'Cache-Control": "no-store"' in gateway
    assert "decrypt_snapshot" in gateway
    assert "_lease_matches_active_operation" in gateway
    assert "await store.mark_served(token, source_ip=effective_source)" in gateway

    route_start = gateway.index('@app.get("/configuration-artifacts/{token}"')
    route = gateway[route_start:]
    payload_index = route.index("payload = await _load_authorized_payload(lease)")
    served_index = route.index("await store.mark_served(token, source_ip=effective_source)")
    success_response_index = route.index("return Response(", served_index)
    assert payload_index < served_index < success_response_index

    assert "served_count" in leases
    assert "get_artifact_lease_served_count" in leases
    assert "CISCO_IOS_ADAPTER" in registry
    assert "configuration_artifact_gateway" not in normal_router
