import asyncio
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.configuration.contracts import (
    ConfigurationCapability,
    ConfigurationExecutionContext,
    ConfigurationTemplateDefinition,
    ConfigurationTransport,
)
from app.configuration.registry import registry
from app.configuration.telnet_cli import (
    ConfigurationTelnetError,
    GENERIC_TELNET_ADAPTER,
)
from app.configuration.templating import ConfigurationTemplateError
from app.schemas.configuration import DeviceConfigurationBindingWrite
from app.services.access_templates import AccessTemplateSecretError
from app.services.configuration import _classify_failure


def test_registry_exposes_guarded_generic_telnet_adapter():
    adapter = registry.get("generic.telnet_cli")
    assert adapter is GENERIC_TELNET_ADAPTER
    assert adapter.descriptor.transport == ConfigurationTransport.TELNET_CLI
    assert ConfigurationCapability.CAPTURE in adapter.descriptor.capabilities
    assert ConfigurationCapability.APPLY in adapter.descriptor.capabilities
    assert ConfigurationCapability.VERIFY in adapter.descriptor.capabilities
    assert ConfigurationCapability.RESTORE in adapter.descriptor.capabilities


def test_configuration_binding_accepts_access_template_without_reference():
    row = DeviceConfigurationBindingWrite(
        template_version_id=uuid4(),
        credential_source="ACCESS_TEMPLATE",
    )
    assert row.credential_source == "ACCESS_TEMPLATE"
    assert row.credential_reference is None


def test_configuration_binding_rejects_reference_for_access_template():
    with pytest.raises(ValidationError):
        DeviceConfigurationBindingWrite(
            template_version_id=uuid4(),
            credential_source="ACCESS_TEMPLATE",
            credential_reference="env://SHOULD_NOT_BE_USED",
        )


def test_telnet_configuration_live_session_fails_closed_by_default(monkeypatch):
    async def scenario():
        monkeypatch.setattr("app.configuration.telnet_cli.settings.telnet_access_enabled", False)
        context = ConfigurationExecutionContext(
            device_id=str(uuid4()),
            management_address="192.0.2.20",
            template_version_id=str(uuid4()),
            connection_parameters={"username": "legacy-user", "password": "legacy-secret"},
        )
        with pytest.raises(ConfigurationTelnetError) as exc:
            await GENERIC_TELNET_ADAPTER._session(context)
        assert str(exc.value) == "CONFIGURATION_TELNET_DISABLED"
        assert "legacy-secret" not in str(exc.value)

    asyncio.run(scenario())


def test_telnet_template_rejects_file_upload_restore():
    async def scenario():
        definition = ConfigurationTemplateDefinition(
            adapter_key="generic.telnet_cli",
            transport=ConfigurationTransport.TELNET_CLI,
            capabilities={
                ConfigurationCapability.CAPTURE,
                ConfigurationCapability.APPLY,
                ConfigurationCapability.VERIFY,
                ConfigurationCapability.RESTORE,
            },
            transport_parameters={"restore": {"mode": "FILE_UPLOAD"}},
        )
        with pytest.raises(ConfigurationTemplateError) as exc:
            await GENERIC_TELNET_ADAPTER.validate_template(definition)
        assert str(exc.value) == "CONFIGURATION_TELNET_FILE_UPLOAD_UNSUPPORTED"

    asyncio.run(scenario())


def test_access_template_secret_failure_keeps_stable_configuration_code():
    stage, code = _classify_failure(AccessTemplateSecretError("AUTHENTICATION_FAILED"))
    assert stage == "TRANSPORT"
    assert code == "CONFIGURATION_AUTHENTICATION_FAILED"


def test_configuration_fingerprint_uses_encrypted_envelope_hash_not_plaintext_resolution():
    source = (
        Path(__file__).resolve().parents[1] / "services" / "configuration.py"
    ).read_text(encoding="utf-8")
    start = source.index("async def _execution_target_fingerprint")
    end = source.index("\nasync def ", start + 10)
    fingerprint_source = source[start:end]

    assert 'binding.credential_source == "ACCESS_TEMPLATE"' in fingerprint_source
    assert '"encrypted_payload_sha256"' in fingerprint_source
    assert "hashlib.sha256" in fingerprint_source
    assert "resolved_secrets(" not in fingerprint_source
    assert '"secret_state"' in fingerprint_source


def test_access_template_connection_overrides_fail_closed_in_configuration_binding_source():
    source = (
        Path(__file__).resolve().parents[1] / "services" / "configuration.py"
    ).read_text(encoding="utf-8")
    assert "CONFIGURATION_ACCESS_TEMPLATE_OVERRIDE_FORBIDDEN" in source
    assert "CONFIGURATION_HOST_KEY_FINGERPRINT_REQUIRED" in source
    assert "resolve_telnet_runtime_access" in source
    assert "resolve_ssh_runtime_access" in source
