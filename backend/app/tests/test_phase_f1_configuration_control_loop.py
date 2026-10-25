from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
from pathlib import Path
import stat
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.configuration.artifacts import (
    ConfigurationArtifactError,
    decrypt_snapshot,
    encrypt_snapshot,
)
from app.configuration.contracts import (
    ConfigurationCapability,
    ConfigurationExecutionContext,
    ConfigurationFunctionDefinition,
    ConfigurationTemplateDefinition,
    ConfigurationTransport,
    ParameterValueType,
    TemplateParameterDefinition,
)
from app.configuration.ssh_cli import ConfigurationSSHError, GENERIC_SSH_ADAPTER
from app.configuration.templating import (
    ConfigurationTemplateError,
    definition_sha256,
    render_pattern,
    resolve_parameters,
)
from app.schemas.configuration import public_parameter_summary
from app.services.configuration import _validate_operation_capabilities
from app.settings import settings


BACKEND = Path(__file__).resolve().parents[2]


def _valid_definition(*, name_pattern: str | None = r"[A-Za-z0-9_-]{1,32}"):
    function = ConfigurationFunctionDefinition(
        code="create_vlan",
        name="Create VLAN",
        parameters=[
            TemplateParameterDefinition(
                name="vlan_id",
                label="VLAN ID",
                value_type=ParameterValueType.VLAN_ID,
            ),
            TemplateParameterDefinition(
                name="vlan_name",
                label="VLAN Name",
                value_type=ParameterValueType.STRING,
                pattern=name_pattern,
            ),
        ],
        execution_spec={
            "commands": [
                "configure terminal",
                "vlan {{ vlan_id }}",
                "name {{ vlan_name }}",
                "end",
            ]
        },
        verification_spec={
            "commands": ["show vlan {{ vlan_id }}"],
            "success_pattern": r"VLAN\s+{{ vlan_id }}\s+active",
        },
        required_capabilities={
            ConfigurationCapability.APPLY,
            ConfigurationCapability.VERIFY,
        },
    )
    return ConfigurationTemplateDefinition(
        adapter_key="generic.ssh_cli",
        transport=ConfigurationTransport.SSH_CLI,
        capabilities={
            ConfigurationCapability.CAPTURE,
            ConfigurationCapability.APPLY,
            ConfigurationCapability.VERIFY,
            ConfigurationCapability.RESTORE,
            ConfigurationCapability.ROLLBACK,
        },
        transport_parameters={
            "prompt_pattern": r"[>#]\s*$",
            "capture": {
                "commands": ["show running-config"],
                "start_pattern": r"^FTTW-CONFIG-START$",
                "end_pattern": r"^FTTW-CONFIG-END$",
                "restorable": True,
            },
            "restore": {
                "mode": "COMMAND_STREAM",
                "prefix_commands": ["configure terminal"],
                "suffix_commands": ["end", "write memory"],
            },
            "allow_display_diff": True,
            "display_redaction_patterns": [r"(?i)^snmp-server community"],
        },
        functions=[function],
    )


def _file_upload_definition():
    definition = _valid_definition()
    definition.transport_parameters["restore"] = {
        "mode": "FILE_UPLOAD",
        "transfer_protocol": "SCP_LEGACY",
        "upload_path": "/tmp/fttw-restore.cfg",
        "checksum_algorithm": "MD5",
        "activation": {
            "commands": [
                "cp {{ upload_path }} /tmp/system.cfg",
                "/usr/etc/rc.d/rc.softrestart save",
            ]
        },
        "cleanup": {"commands": ["rm -f {{ upload_path }}"]},
    }
    return definition


def _file_upload_context(definition: ConfigurationTemplateDefinition):
    return ConfigurationExecutionContext(
        device_id=str(uuid4()),
        management_address="192.0.2.10",
        template_version_id=str(uuid4()),
        connection_parameters={
            "username": "fttw-test",
            "password": "test-secret",
            "host_key_fingerprint": "SHA256:abcdefghijklmnopqrstuv",
            "compatibility_profile": "LEGACY_SSH_RSA_DH1_CBC",
            "command_timeout_seconds": 10,
            "template_transport_parameters": definition.transport_parameters,
        },
    )


def test_template_hash_is_deterministic_for_capability_sets():
    first = _valid_definition()
    second = _valid_definition()
    second.capabilities = set(reversed(list(second.capabilities)))
    second.functions[0].required_capabilities = set(
        reversed(list(second.functions[0].required_capabilities))
    )
    assert definition_sha256(first) == definition_sha256(second)


def test_parameter_validation_rejects_lossy_and_non_finite_numbers():
    integer = TemplateParameterDefinition(
        name="count", label="Count", value_type=ParameterValueType.INTEGER
    )
    number = TemplateParameterDefinition(
        name="metric", label="Metric", value_type=ParameterValueType.NUMBER
    )
    with pytest.raises(ConfigurationTemplateError, match="CONFIGURATION_PARAMETER_INTEGER_INVALID"):
        resolve_parameters([integer], {"count": 1.5})
    for value in (math.nan, math.inf, -math.inf):
        with pytest.raises(ConfigurationTemplateError, match="CONFIGURATION_PARAMETER_NUMBER_INVALID"):
            resolve_parameters([number], {"metric": value})


def test_sensitive_parameters_require_exact_env_references_and_public_summary_redacts_name():
    secret = TemplateParameterDefinition(
        name="wifi_key",
        label="WiFi key",
        value_type=ParameterValueType.STRING,
        sensitive=True,
    )
    with pytest.raises(ConfigurationTemplateError, match="CONFIGURATION_SENSITIVE_PARAMETER_REFERENCE_REQUIRED"):
        resolve_parameters([secret], {"wifi_key": "plain-secret"})
    _, summary = resolve_parameters([secret], {"wifi_key": "env://FTTW_DEVICE_WIFI_KEY"})
    assert summary["wifi_key"]["reference"] == "env://FTTW_DEVICE_WIFI_KEY"
    assert public_parameter_summary(summary) == {
        "wifi_key": {"sensitive": True, "configured": True}
    }
    resolved, _ = resolve_parameters(
        [secret],
        {"wifi_key": "env://FTTW_DEVICE_WIFI_KEY"},
        secret_resolver=lambda _reference: "safe-WiFi-key!",
    )
    assert resolved["wifi_key"] == "safe-WiFi-key!"
    with pytest.raises(
        ConfigurationTemplateError,
        match="CONFIGURATION_PARAMETER_CONTROL_CHARACTER_FORBIDDEN",
    ):
        resolve_parameters(
            [secret],
            {"wifi_key": "env://FTTW_DEVICE_WIFI_KEY"},
            secret_resolver=lambda _reference: "safe-key\nreload",
        )


def test_regex_rendering_treats_operator_values_as_literals():
    rendered = render_pattern(r"^interface {{ interface }} up$", {"interface": "Gi0/1.+"})
    assert rendered == r"^interface Gi0/1\.\+ up$"


def test_generic_ssh_template_accepts_guarded_vendor_neutral_definition():
    asyncio.run(GENERIC_SSH_ADAPTER.validate_template(_valid_definition()))


def test_generic_ssh_restorable_capture_requires_explicit_boundaries():
    definition = _valid_definition()
    definition.transport_parameters["capture"].pop("start_pattern")
    with pytest.raises(
        ConfigurationTemplateError,
        match="CONFIGURATION_RESTORABLE_CAPTURE_BOUNDARIES_REQUIRED",
    ):
        asyncio.run(GENERIC_SSH_ADAPTER.validate_template(definition))


def test_generic_ssh_rejects_unknown_transport_fields_and_unconstrained_freeform_cli_values():
    definition = _valid_definition()
    definition.transport_parameters["arbitrary_shell"] = "forbidden"
    with pytest.raises(
        ConfigurationTemplateError,
        match="CONFIGURATION_SSH_TRANSPORT_FIELD_UNSUPPORTED",
    ):
        asyncio.run(GENERIC_SSH_ADAPTER.validate_template(definition))

    definition = _valid_definition(name_pattern=None)
    with pytest.raises(
        ConfigurationTemplateError,
        match="CONFIGURATION_SSH_FREEFORM_PARAMETER_PATTERN_REQUIRED",
    ):
        asyncio.run(GENERIC_SSH_ADAPTER.validate_template(definition))

    definition = _valid_definition()
    definition.functions[0].execution_spec = {"commands": ["password literal-secret"]}
    with pytest.raises(
        ConfigurationTemplateError,
        match="CONFIGURATION_SSH_LITERAL_SECRET_FORBIDDEN",
    ):
        asyncio.run(GENERIC_SSH_ADAPTER.validate_template(definition))

    definition = _valid_definition()
    definition.functions[0].verification_spec = {
        "commands": ["show password literal-secret"],
        "success_pattern": "ok",
    }
    with pytest.raises(
        ConfigurationTemplateError,
        match="CONFIGURATION_SSH_LITERAL_SECRET_FORBIDDEN",
    ):
        asyncio.run(GENERIC_SSH_ADAPTER.validate_template(definition))


def test_generic_ssh_connection_overrides_are_explicit_and_host_key_pinned():
    GENERIC_SSH_ADAPTER.validate_connection_overrides(
        {
            "port": 2222,
            "host_key_fingerprint": "SHA256:abcdefghijklmnopqrstuv",
            "compatibility_profile": "MODERN",
        }
    )
    with pytest.raises(ValueError, match="CONFIGURATION_CONNECTION_OVERRIDE_UNSUPPORTED"):
        GENERIC_SSH_ADAPTER.validate_connection_overrides({"proxy_command": "bad"})
    with pytest.raises(ValueError, match="CONFIGURATION_HOST_KEY_FINGERPRINT_INVALID"):
        GENERIC_SSH_ADAPTER.validate_connection_overrides({"host_key_fingerprint": "MD5:bad"})
    with pytest.raises(ValueError, match="CONFIGURATION_SSH_PORT_INVALID"):
        GENERIC_SSH_ADAPTER.validate_connection_overrides({"port": 70000})


def test_configuration_artifacts_are_aes_gcm_encrypted_integrity_checked_and_restricted(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "data_root", str(tmp_path))
    monkeypatch.setattr(settings, "configuration_artifact_key_reference", "env://FTTW_TEST_CONFIG_KEY")
    monkeypatch.setenv("FTTW_TEST_CONFIG_KEY", "11" * 32)
    device_id = uuid4()
    snapshot_id = uuid4()
    plaintext = b"hostname test\ninterface Gi0/1\n"

    metadata = encrypt_snapshot(
        device_id=device_id,
        snapshot_id=snapshot_id,
        plaintext=plaintext,
    )
    path = tmp_path / "configurations" / metadata["artifact_path"]
    assert path.read_bytes() != plaintext
    assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0
    assert stat.S_IMODE(path.parent.stat().st_mode) & 0o077 == 0
    assert decrypt_snapshot(
        device_id=device_id,
        snapshot_id=snapshot_id,
        artifact_path=str(metadata["artifact_path"]),
        expected_sha256=str(metadata["artifact_sha256"]),
        key_reference=str(metadata["encryption_key_reference"]),
    ) == plaintext

    payload = bytearray(path.read_bytes())
    payload[-1] ^= 0x01
    path.write_bytes(bytes(payload))
    with pytest.raises(ConfigurationArtifactError, match="CONFIGURATION_ARTIFACT_CHECKSUM_MISMATCH"):
        decrypt_snapshot(
            device_id=device_id,
            snapshot_id=snapshot_id,
            artifact_path=str(metadata["artifact_path"]),
            expected_sha256=str(metadata["artifact_sha256"]),
            key_reference=str(metadata["encryption_key_reference"]),
        )


def test_route_contract_advances_to_280_with_17_configuration_operations_and_global_templates():
    contract = json.loads(
        (BACKEND / "scripts" / "ci_route_permission_contract_baseline.json").read_text(
            encoding="utf-8"
        )
    )
    assert contract["route_count"] == 280 == len(contract["routes"])
    rows = [row for row in contract["routes"] if "configuration" in row["path"]]
    assert len(rows) == 17
    template_rows = [
        row for row in rows if row["path"].startswith("/api/configuration-templates")
    ]
    assert len(template_rows) == 6
    assert all(row.get("global_scope") is True for row in template_rows)
    assert {
        row["permission"] for row in rows
    } >= {
        "device.configuration.read",
        "device.configuration.capture",
        "device.configuration.apply",
        "device.configuration.restore",
        "device.configuration.template.read",
        "device.configuration.template.manage",
    }


def test_control_loop_source_contains_durable_backup_reauthorization_idempotency_and_no_adapter_type_switch():
    service = (BACKEND / "app" / "services" / "configuration.py").read_text(encoding="utf-8")
    tasks = (BACKEND / "app" / "tasks" / "configuration.py").read_text(encoding="utf-8")
    assert "CONFIGURATION_IDEMPOTENCY_KEY_REUSED" in service
    assert "request_fingerprint" in service
    router = (BACKEND / "app" / "api" / "routers" / "configuration.py").read_text(encoding="utf-8")
    assert "CONFIGURATION_SNAPSHOT_TEMPLATE_VERSION_MISMATCH" in service
    assert "This commit is intentionally before the first mutating device command" in service
    assert service.count("await _reauthorize(db, operation)") >= 3
    assert "_assert_version_integrity" in service
    assert "definition_sha256(definition) != version.content_sha256" in service
    assert "_execution_target_fingerprint" in service
    assert "CONFIGURATION_EXECUTION_TARGET_CHANGED" in service
    assert "CONFIGURATION_DEVICE_OPERATION_ACTIVE" in service
    assert "CONFIGURATION_QUEUE_EXPIRED" in service
    assert "from app.settings import settings" in service
    assert service.count("await _assert_version_integrity(db, version)") >= 4
    assert "for_update=True" in router
    assert "expires=1800" not in router
    assert "isinstance(adapter, GenericSSHCLIAdapter)" not in service
    assert 'current.status in {"RUNNING", "ROLLING_BACK"}' in tasks
    assert "logger.exception" not in tasks

    version = SimpleNamespace(
        adapter_key="generic.ssh_cli",
        capabilities=[ConfigurationCapability.CAPTURE.value],
    )
    with pytest.raises(
        ConfigurationTemplateError,
        match="CONFIGURATION_TEMPLATE_CAPABILITY_UNAVAILABLE",
    ):
        _validate_operation_capabilities(version, "APPLY")



def test_generic_ssh_file_upload_restore_template_is_vendor_neutral_and_strict():
    asyncio.run(GENERIC_SSH_ADAPTER.validate_template(_file_upload_definition()))

    bad = _file_upload_definition()
    bad.transport_parameters["restore"]["upload_path"] = "/tmp/../etc/passwd"
    with pytest.raises(
        ConfigurationTemplateError,
        match="CONFIGURATION_RESTORE_UPLOAD_PATH_INVALID",
    ):
        asyncio.run(GENERIC_SSH_ADAPTER.validate_template(bad))

    bad = _file_upload_definition()
    bad.transport_parameters["restore"]["transfer_protocol"] = "SFTP"
    with pytest.raises(
        ConfigurationTemplateError,
        match="CONFIGURATION_RESTORE_TRANSFER_PROTOCOL_INVALID",
    ):
        asyncio.run(GENERIC_SSH_ADAPTER.validate_template(bad))

    bad = _file_upload_definition()
    bad.transport_parameters["restore"].pop("cleanup")
    with pytest.raises(
        ConfigurationTemplateError,
        match="CONFIGURATION_RESTORE_CLEANUP_REQUIRED",
    ):
        asyncio.run(GENERIC_SSH_ADAPTER.validate_template(bad))


def test_generic_ssh_file_upload_restore_uploads_snapshot_verifies_before_activation_and_cleans(monkeypatch):
    definition = _file_upload_definition()
    context = _file_upload_context(definition)
    snapshot = b"wireless.1.ssid=OBI-WLAN\nradio.1.txpower=28\n"
    expected_md5 = hashlib.md5(snapshot, usedforsecurity=False).hexdigest()
    uploaded = {}
    calls: list[list[str]] = []

    async def fake_upload(**kwargs):
        uploaded.update(kwargs)

    async def fake_run_spec(_context, spec, values):
        rendered = [
            entry if isinstance(entry, str) else entry["send"]
            for entry in spec["commands"]
        ]
        rendered = [item.replace("{{ upload_path }}", values.get("upload_path", "")) for item in rendered]
        calls.append(rendered)
        if rendered == ["md5sum /tmp/fttw-restore.cfg"]:
            return f"{expected_md5}  /tmp/fttw-restore.cfg\nXM.v5.5.6# "
        return "XM.v5.5.6# "

    monkeypatch.setattr("app.configuration.ssh_cli.upload_file_scp", fake_upload)
    monkeypatch.setattr(GENERIC_SSH_ADAPTER, "_run_spec", fake_run_spec)

    result = asyncio.run(GENERIC_SSH_ADAPTER.restore(context, snapshot))
    assert uploaded["payload"] == snapshot
    assert uploaded["remote_path"] == "/tmp/fttw-restore.cfg"
    assert result["restore_mode"] == "FILE_UPLOAD"
    assert result["checksum_algorithm"] == "MD5"
    assert calls[0] == ["md5sum /tmp/fttw-restore.cfg"]
    assert calls[1] == [
        "cp /tmp/fttw-restore.cfg /tmp/system.cfg",
        "/usr/etc/rc.d/rc.softrestart save",
    ]
    assert calls[2] == ["rm -f /tmp/fttw-restore.cfg"]
    assert not any("wireless.1.ssid=OBI-WLAN" in command for group in calls for command in group)


def test_generic_ssh_file_upload_checksum_mismatch_fails_before_activation_and_still_cleans(monkeypatch):
    definition = _file_upload_definition()
    context = _file_upload_context(definition)
    calls: list[list[str]] = []

    async def fake_upload(**_kwargs):
        return None

    async def fake_run_spec(_context, spec, values):
        rendered = [
            entry if isinstance(entry, str) else entry["send"]
            for entry in spec["commands"]
        ]
        rendered = [item.replace("{{ upload_path }}", values.get("upload_path", "")) for item in rendered]
        calls.append(rendered)
        if rendered[0].startswith("md5sum "):
            return "00000000000000000000000000000000  /tmp/fttw-restore.cfg\n"
        return "XM.v5.5.6# "

    monkeypatch.setattr("app.configuration.ssh_cli.upload_file_scp", fake_upload)
    monkeypatch.setattr(GENERIC_SSH_ADAPTER, "_run_spec", fake_run_spec)

    with pytest.raises(
        ConfigurationSSHError,
        match="CONFIGURATION_RESTORE_UPLOAD_CHECKSUM_MISMATCH",
    ):
        asyncio.run(GENERIC_SSH_ADAPTER.restore(context, b"safe-config\n"))
    assert calls == [
        ["md5sum /tmp/fttw-restore.cfg"],
        ["rm -f /tmp/fttw-restore.cfg"],
    ]


def test_scp_transport_is_pinned_legacy_protocol_and_keeps_password_out_of_argv():
    source = (BACKEND / "app" / "remote_gateway" / "ssh_transport.py").read_text(
        encoding="utf-8"
    )
    assert "async def upload_file_scp(" in source
    assert '"-O"' in source
    assert '"StrictHostKeyChecking=yes"' in source
    assert 'env["SSHPASS"] = password' in source
    assert 'command = ["sshpass", "-e", *command]' in source
    assert "password, *command" not in source


def test_publish_endpoint_refreshes_version_after_commit_before_response_serialization():
    router = (
        BACKEND / "app" / "api" / "routers" / "configuration.py"
    ).read_text(encoding="utf-8")

    block = router.split(
        "async def publish_configuration_template_version(", 1
    )[1].split(
        "async def _scoped_device", 1
    )[0]

    commit_position = block.index("await db.commit()")
    refresh_position = block.index("await db.refresh(version)")
    return_position = block.index("return version")

    assert commit_position < refresh_position < return_position

def test_generic_ssh_reconnect_after_command_contract_is_explicit_bounded_and_vendor_neutral():
    definition = _valid_definition()
    definition.functions[0].execution_spec = {
        "commands": [
            {
                "send": "reload",
                "reconnect_after_command": True,
                "reconnect_timeout_seconds": 30,
            }
        ]
    }
    asyncio.run(GENERIC_SSH_ADAPTER.validate_template(definition))

    file_upload = _file_upload_definition()
    file_upload.transport_parameters["restore"]["activation"]["commands"][1] = {
        "send": "reload",
        "reconnect_after_command": True,
        "reconnect_timeout_seconds": 30,
    }
    asyncio.run(GENERIC_SSH_ADAPTER.validate_template(file_upload))

    bad = _valid_definition()
    bad.functions[0].execution_spec = {
        "commands": [
            {
                "send": "reload",
                "reconnect_after_command": True,
            }
        ]
    }
    with pytest.raises(
        ConfigurationTemplateError,
        match="CONFIGURATION_SSH_RECONNECT_TIMEOUT_REQUIRED",
    ):
        asyncio.run(GENERIC_SSH_ADAPTER.validate_template(bad))

    bad = _valid_definition()
    bad.functions[0].verification_spec = {
        "commands": [
            {
                "send": "show status",
                "reconnect_after_command": True,
                "reconnect_timeout_seconds": 30,
            }
        ],
        "success_pattern": "ok",
    }
    with pytest.raises(
        ConfigurationTemplateError,
        match="CONFIGURATION_SSH_RECONNECT_NOT_ALLOWED",
    ):
        asyncio.run(GENERIC_SSH_ADAPTER.validate_template(bad))


def test_generic_ssh_run_spec_reconnects_after_declared_transport_drop(monkeypatch):
    definition = _file_upload_definition()
    context = _file_upload_context(definition)
    events = []

    class FakeSession:
        def __init__(self, name, disconnect=False):
            self.name = name
            self.disconnect = disconnect

        async def command(self, command, *, expect=None, timeout=None):
            events.append(("command", self.name, command))
            if self.disconnect:
                raise ConfigurationSSHError("CONFIGURATION_SSH_SESSION_ENDED")
            return "PROMPT> "

        def close(self):
            events.append(("close", self.name))

    sessions = [
        FakeSession("initial", disconnect=True),
        FakeSession("reconnected"),
    ]

    async def fake_session(_context):
        events.append(("session", len(sessions)))
        return sessions.pop(0)

    monkeypatch.setattr(GENERIC_SSH_ADAPTER, "_session", fake_session)

    result = asyncio.run(
        GENERIC_SSH_ADAPTER._run_spec(
            context,
            {
                "commands": [
                    {
                        "send": "reload",
                        "reconnect_after_command": True,
                        "reconnect_timeout_seconds": 30,
                    }
                ]
            },
            {},
        )
    )

    assert result == ""
    assert ("command", "initial", "reload") in events
    assert ("close", "initial") in events
    assert ("close", "reconnected") in events
    assert not sessions


def test_generic_ssh_run_spec_does_not_hide_undeclared_disconnect(monkeypatch):
    definition = _file_upload_definition()
    context = _file_upload_context(definition)

    class FakeSession:
        async def command(self, command, *, expect=None, timeout=None):
            raise ConfigurationSSHError("CONFIGURATION_SSH_SESSION_ENDED")

        def close(self):
            pass

    async def fake_session(_context):
        return FakeSession()

    monkeypatch.setattr(GENERIC_SSH_ADAPTER, "_session", fake_session)

    with pytest.raises(
        ConfigurationSSHError,
        match="CONFIGURATION_SSH_SESSION_ENDED",
    ):
        asyncio.run(
            GENERIC_SSH_ADAPTER._run_spec(
                context,
                {"commands": ["show status"]},
                {},
            )
        )

def test_template_version_create_and_update_endpoints_refresh_after_commit_before_response_serialization():
    router = (
        BACKEND / "app" / "api" / "routers" / "configuration.py"
    ).read_text(encoding="utf-8")

    create_block = router.split(
        "async def create_configuration_template_version(", 1
    )[1].split(
        "@template_router.put(", 1
    )[0]

    update_block = router.split(
        "async def update_configuration_template_version(", 1
    )[1].split(
        "@template_router.post(", 1
    )[0]

    for block in (create_block, update_block):
        commit_position = block.index("await db.commit()")
        refresh_position = block.index("await db.refresh(version)")
        return_position = block.index("return version")
        assert commit_position < refresh_position < return_position

def test_generic_ssh_reconnect_delay_is_explicit_bounded_and_consumes_total_window(monkeypatch):
    definition = _valid_definition()
    definition.functions[0].execution_spec = {
        "commands": [
            {
                "send": "reload",
                "reconnect_after_command": True,
                "reconnect_timeout_seconds": 30,
                "reconnect_delay_seconds": 5,
            }
        ]
    }
    asyncio.run(GENERIC_SSH_ADAPTER.validate_template(definition))

    bad = _valid_definition()
    bad.functions[0].execution_spec = {
        "commands": [
            {
                "send": "reload",
                "reconnect_after_command": True,
                "reconnect_timeout_seconds": 30,
                "reconnect_delay_seconds": 30,
            }
        ]
    }
    with pytest.raises(
        ConfigurationTemplateError,
        match="CONFIGURATION_SSH_RECONNECT_DELAY_INVALID",
    ):
        asyncio.run(GENERIC_SSH_ADAPTER.validate_template(bad))

    bad = _valid_definition()
    bad.functions[0].verification_spec = {
        "commands": [
            {
                "send": "show status",
                "reconnect_delay_seconds": 5,
            }
        ],
        "success_pattern": "ok",
    }
    with pytest.raises(ConfigurationTemplateError):
        asyncio.run(GENERIC_SSH_ADAPTER.validate_template(bad))

    context = _file_upload_context(_file_upload_definition())
    events = []

    class FakeSession:
        def __init__(self, name):
            self.name = name

        async def command(self, command, *, expect=None, timeout=None):
            events.append(("command", self.name, command))
            return "PROMPT> "

        def close(self):
            events.append(("close", self.name))

    sessions = [FakeSession("initial"), FakeSession("reconnected")]

    async def fake_session(_context):
        events.append(("session", len(sessions)))
        return sessions.pop(0)

    sleep_calls = []

    async def fake_sleep(seconds):
        sleep_calls.append(seconds)

    monkeypatch.setattr(GENERIC_SSH_ADAPTER, "_session", fake_session)
    monkeypatch.setattr("app.configuration.ssh_cli.asyncio.sleep", fake_sleep)

    result = asyncio.run(
        GENERIC_SSH_ADAPTER._run_spec(
            context,
            {
                "commands": [
                    {
                        "send": "reload",
                        "reconnect_after_command": True,
                        "reconnect_timeout_seconds": 30,
                        "reconnect_delay_seconds": 5,
                    }
                ]
            },
            {},
        )
    )

    assert result == "PROMPT> "
    assert sleep_calls == [5.0]
    assert ("command", "initial", "reload") in events
    assert ("close", "initial") in events
    assert ("close", "reconnected") in events
    assert not sessions
