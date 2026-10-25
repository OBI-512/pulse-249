from uuid import uuid4

import pytest

from app.core.exceptions import APIError
from app.models import AccessTemplate
from app.services import access_templates as service


def _validate(*, protocol, variant=None, settings=None, secret_keys=None, active=True):
    return service.validate_template_definition(
        protocol=protocol,
        protocol_variant=variant,
        template_settings=settings or {},
        secret_keys=set(secret_keys or set()),
        is_active=active,
    )


def _snmp_template(*, variant="V2C", settings=None):
    return AccessTemplate(
        id=uuid4(),
        name="Runtime SNMP",
        protocol="SNMP",
        protocol_variant=variant,
        visibility="PRIVATE",
        owner_user_id=uuid4(),
        is_active=True,
        settings_json=settings or {},
    )


def test_encrypted_database_secret_round_trip(monkeypatch):
    key = b"K" * 32
    import base64

    monkeypatch.setenv("FTTW_TEST_ACCESS_TEMPLATE_KEY", base64.b64encode(key).decode("ascii"))
    monkeypatch.setattr(service.settings, "access_template_key_reference", "env://FTTW_TEST_ACCESS_TEMPLATE_KEY")
    template_id = uuid4()
    payload = service.encrypt_secret(template_id=template_id, secret_key="password", plaintext="super-secret")
    assert "super-secret" not in payload
    assert service.decrypt_secret(template_id=template_id, secret_key="password", payload=payload) == "super-secret"


def test_active_ssh_requires_username_and_authentication_material():
    with pytest.raises(APIError) as exc:
        _validate(protocol="SSH", secret_keys={"username"})
    assert exc.value.detail["code"] == "ACCESS_TEMPLATE_INCOMPLETE"


def test_inactive_ssh_may_be_saved_incomplete():
    protocol, variant, settings = _validate(protocol="SSH", active=False)
    assert protocol == "SSH"
    assert variant == "PASSWORD_OR_KEY"
    assert settings["port"] == 22


def test_telnet_defaults_and_requires_credentials_when_active():
    protocol, variant, settings = _validate(
        protocol="TELNET",
        secret_keys={"username", "password"},
    )
    assert protocol == "TELNET"
    assert variant == "PASSWORD"
    assert settings["port"] == 23


def test_snmp_v2c_requires_community():
    with pytest.raises(APIError) as exc:
        _validate(protocol="SNMP", variant="V2C")
    assert exc.value.detail["code"] == "ACCESS_TEMPLATE_INCOMPLETE"


def test_snmp_v3_authpriv_requires_both_auth_and_privacy_secrets():
    with pytest.raises(APIError) as exc:
        _validate(
            protocol="SNMP",
            variant="V3",
            settings={"security_level": "authPriv"},
            secret_keys={"security_name", "auth_secret"},
        )
    assert exc.value.detail["code"] == "ACCESS_TEMPLATE_INCOMPLETE"

    protocol, variant, settings = _validate(
        protocol="SNMP",
        variant="V3",
        settings={"security_level": "authPriv", "auth_protocol": "sha-256", "privacy_protocol": "aes"},
        secret_keys={"security_name", "auth_secret", "privacy_secret"},
    )
    assert protocol == "SNMP"
    assert variant == "V3"
    assert settings["security_level"] == "authPriv"
    assert settings["auth_protocol"] == "SHA-256"
    assert settings["privacy_protocol"] == "AES"


def test_snmp_runtime_mapping_keeps_secrets_in_memory_only():
    template = _snmp_template(
        variant="V3",
        settings={
            "security_level": "authPriv",
            "auth_protocol": "SHA",
            "privacy_protocol": "AES",
            "context_name": "monitoring",
        },
    )
    credential = service.build_snmp_runtime_credential(
        template,
        {
            "security_name": "observer",
            "auth_secret": "AUTH-VALUE",
            "privacy_secret": "PRIV-VALUE",
        },
    )
    assert credential == {
        "version": "3",
        "username": "observer",
        "security_level": "authPriv",
        "context_name": "monitoring",
        "auth_protocol": "SHA",
        "auth_password": "AUTH-VALUE",
        "priv_protocol": "AES",
        "priv_password": "PRIV-VALUE",
    }
    runtime = service.SNMPRuntimeAccess(credential=credential, port=1161, timeout_seconds=7, retries=2)
    assert "AUTH-VALUE" not in repr(runtime)
    assert "PRIV-VALUE" not in repr(runtime)


def test_snmp_runtime_v2c_mapping_and_template_connection_settings():
    template = _snmp_template(variant="V2C", settings={"port": 1161, "timeout_seconds": 8, "retries": 3})
    credential = service.build_snmp_runtime_credential(template, {"community": "COMMUNITY-VALUE"})
    assert credential == {"version": "2c", "community": "COMMUNITY-VALUE"}


def test_secret_looking_settings_are_rejected():
    with pytest.raises(APIError) as exc:
        _validate(
            protocol="SSH",
            settings={"password_hint": "do-not-store"},
            secret_keys={"username", "password"},
        )
    assert exc.value.detail["code"] == "ACCESS_TEMPLATE_SECRET_IN_SETTINGS"
