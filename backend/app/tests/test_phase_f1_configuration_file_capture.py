from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from app.configuration.contracts import (
    ConfigurationCapability,
    ConfigurationExecutionContext,
    ConfigurationTemplateDefinition,
    ConfigurationTransport,
)
from app.configuration.ssh_cli import ConfigurationSSHError, GENERIC_SSH_ADAPTER
from app.configuration.templating import ConfigurationTemplateError


def _definition() -> ConfigurationTemplateDefinition:
    return ConfigurationTemplateDefinition(
        adapter_key="generic.ssh_cli",
        transport=ConfigurationTransport.SSH_CLI,
        capabilities={
            ConfigurationCapability.CAPTURE,
            ConfigurationCapability.RESTORE,
            ConfigurationCapability.ROLLBACK,
        },
        transport_parameters={
            "prompt_pattern": r"[#>]\s*$",
            "capture": {
                "mode": "FILE_DOWNLOAD",
                "transfer_protocol": "SCP_LEGACY",
                "remote_path": "/tmp/system.cfg",
                "restorable": True,
            },
            "restore": {
                "mode": "FILE_UPLOAD",
                "transfer_protocol": "SCP_LEGACY",
                "upload_path": "/tmp/fttw-restore.cfg",
                "checksum_algorithm": "MD5",
                "activation": {"commands": ["cp {{ upload_path }} /tmp/system.cfg"]},
                "cleanup": {"commands": ["rm -f {{ upload_path }}"]},
            },
        },
    )


def _context(definition: ConfigurationTemplateDefinition) -> ConfigurationExecutionContext:
    return ConfigurationExecutionContext(
        device_id=str(uuid4()),
        management_address="192.0.2.20",
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


def test_file_download_capture_template_is_vendor_neutral_and_strict():
    asyncio.run(GENERIC_SSH_ADAPTER.validate_template(_definition()))

    bad = _definition()
    bad.transport_parameters["capture"]["remote_path"] = "/tmp/../etc/passwd"
    with pytest.raises(
        ConfigurationTemplateError,
        match="CONFIGURATION_CAPTURE_REMOTE_PATH_INVALID",
    ):
        asyncio.run(GENERIC_SSH_ADAPTER.validate_template(bad))

    bad = _definition()
    bad.transport_parameters["capture"]["transfer_protocol"] = "SFTP"
    with pytest.raises(
        ConfigurationTemplateError,
        match="CONFIGURATION_CAPTURE_TRANSFER_PROTOCOL_INVALID",
    ):
        asyncio.run(GENERIC_SSH_ADAPTER.validate_template(bad))

    bad = _definition()
    bad.transport_parameters["capture"]["commands"] = ["cat /tmp/system.cfg"]
    with pytest.raises(
        ConfigurationTemplateError,
        match="CONFIGURATION_CAPTURE_MODE_FIELD_CONFLICT",
    ):
        asyncio.run(GENERIC_SSH_ADAPTER.validate_template(bad))


def test_file_download_capture_preserves_exact_bytes(monkeypatch):
    definition = _definition()
    context = _context(definition)
    exact = b"line-1\r\nline-2\x00\xff\n"
    observed = {}

    async def fake_download(**kwargs):
        observed.update(kwargs)
        return exact

    monkeypatch.setattr("app.configuration.ssh_cli.download_file_scp", fake_download)
    result = asyncio.run(GENERIC_SSH_ADAPTER.capture(context))

    assert result.payload == exact
    assert result.restorable is True
    assert result.metadata["capture_mode"] == "FILE_DOWNLOAD"
    assert observed["remote_path"] == "/tmp/system.cfg"
    assert observed["compatibility_profile"] == "LEGACY_SSH_RSA_DH1_CBC"
    assert observed["max_bytes"] > len(exact)


def test_file_download_capture_rejects_empty_payload(monkeypatch):
    definition = _definition()
    context = _context(definition)

    async def fake_download(**_kwargs):
        return b""

    monkeypatch.setattr("app.configuration.ssh_cli.download_file_scp", fake_download)
    with pytest.raises(ConfigurationSSHError, match="CONFIGURATION_CAPTURE_EMPTY"):
        asyncio.run(GENERIC_SSH_ADAPTER.capture(context))


def test_file_upload_restore_runtime_accepts_reconnecting_activation(monkeypatch):
    definition = _definition()
    definition.transport_parameters["restore"]["activation"] = {
        "commands": [
            {
                "send": "/usr/etc/rc.d/rc.softrestart save",
                "reconnect_after_command": True,
                "reconnect_timeout_seconds": 120,
                "reconnect_delay_seconds": 5,
            }
        ]
    }
    asyncio.run(GENERIC_SSH_ADAPTER.validate_template(definition))
    context = _context(definition)
    observed_specs = []

    async def fake_upload(**_kwargs):
        return None

    class FakeSession:
        async def command(self, _command, **_kwargs):
            return "900150983cd24fb0d6963f7d28e17f72  /tmp/fttw-restore.cfg"

        def close(self):
            return None

    async def fake_session(_context):
        return FakeSession()

    async def fake_run_spec(_context, spec, values):
        commands = list(spec.get("commands") or [])
        if commands == ["md5sum /tmp/fttw-restore.cfg"]:
            return "900150983cd24fb0d6963f7d28e17f72  /tmp/fttw-restore.cfg"
        observed_specs.append((spec, values))
        return ""

    monkeypatch.setattr("app.configuration.ssh_cli.upload_file_scp", fake_upload)
    monkeypatch.setattr(GENERIC_SSH_ADAPTER, "_session", fake_session)
    monkeypatch.setattr(GENERIC_SSH_ADAPTER, "_run_spec", fake_run_spec)

    result = asyncio.run(GENERIC_SSH_ADAPTER.restore(context, b"abc"))

    assert result["restore_mode"] == "FILE_UPLOAD"
    assert result["transfer_protocol"] == "SCP_LEGACY"
    assert len(observed_specs) == 2
    activation = observed_specs[0][0]["commands"][0]
    assert activation["reconnect_after_command"] is True
    assert activation["reconnect_timeout_seconds"] == 120
    assert activation["reconnect_delay_seconds"] == 5
