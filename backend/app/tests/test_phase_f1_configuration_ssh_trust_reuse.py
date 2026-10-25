from __future__ import annotations

from pathlib import Path

import pytest

from app.configuration.contracts import ConfigurationExecutionContext
from app.configuration.ssh_cli import ConfigurationSSHError, GenericSSHCLIAdapter


def _context(line):
    return ConfigurationExecutionContext(
        device_id="00000000-0000-0000-0000-000000000001",
        management_address="192.0.2.10",
        template_version_id="00000000-0000-0000-0000-000000000002",
        connection_parameters={
            "username": "operator",
            "password": "redacted",
            "host_key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "compatibility_profile": "LEGACY_SSH_RSA_DH1_CBC",
            "trusted_host_key_line": line,
        },
    )


def test_generic_ssh_connection_forwards_cached_trusted_host_key_line():
    line = "192.0.2.10 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCexample"
    connection = GenericSSHCLIAdapter()._connection(_context(line))
    assert connection["trusted_host_key_line"] == line


def test_generic_ssh_connection_allows_missing_cached_line_for_legacy_fallback():
    connection = GenericSSHCLIAdapter()._connection(_context(None))
    assert connection["trusted_host_key_line"] is None


def test_generic_ssh_connection_rejects_invalid_cached_line_type():
    with pytest.raises(ConfigurationSSHError, match="CONFIGURATION_SSH_TRUSTED_HOST_KEY_INVALID"):
        GenericSSHCLIAdapter()._connection(_context({"bad": "type"}))


def test_configuration_context_reuses_remote_profile_host_key_metadata():
    source = (Path(__file__).resolve().parents[1] / "services" / "configuration.py").read_text(encoding="utf-8")
    assert "SSH_HOST_KEY_LINE_METADATA_KEY" in source
    assert "def _trusted_ssh_host_key_line" in source
    assert source.count('"trusted_host_key_line": _trusted_ssh_host_key_line(profile)') == 2
