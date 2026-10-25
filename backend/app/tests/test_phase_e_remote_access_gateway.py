from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.requests import Request

from app.schemas.device import DeviceUpdate
from app.security.authorization import permission_for_request
from app.security.permission_dependencies import expand_permission_codes
from app.security.permissions import Permission as P
from app.remote_gateway.secrets import RemoteAccessSecretError, resolve_secret_reference
from app.remote_gateway.ssh_transport import ssh_compatibility_options
from app.services.remote_access import hash_remote_ticket


def _request(method: str, path: str) -> Request:
    return Request({
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "scheme": "http",
        "query_string": b"",
        "headers": [],
        "client": ("test", 1),
        "server": ("test", 80),
        "route": SimpleNamespace(path=path),
    })


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/devices/{device_id}/remote-access"),
        ("POST", "/api/devices/{device_id}/remote-access/ssh-sessions"),
        ("DELETE", "/api/devices/{device_id}/remote-access/sessions/{session_id}"),
    ],
)
def test_remote_access_routes_require_explicit_ssh_permission(method, path):
    assert permission_for_request(_request(method, path)) == P.DEVICE_REMOTE_ACCESS_SSH


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/devices/{device_id}/remote-access/web"),
        ("POST", "/api/devices/{device_id}/remote-access/web-sessions"),
        ("DELETE", "/api/devices/{device_id}/remote-access/web-sessions/{session_id}"),
    ],
)
def test_web_gui_routes_require_explicit_web_permission(method, path):
    assert permission_for_request(_request(method, path)) == P.DEVICE_REMOTE_ACCESS_WEB


def test_remote_access_permissions_require_device_visibility():
    for permission in (P.DEVICE_REMOTE_ACCESS_SSH, P.DEVICE_REMOTE_ACCESS_WEB):
        expanded = expand_permission_codes([permission])
        assert permission in expanded
        assert P.DEVICE_READ in expanded


def test_device_update_accepts_write_only_remote_access_configuration():
    payload = DeviceUpdate.model_validate({
        "remote_access": {
            "ssh_enabled": True,
            "ssh_port": 2222,
            "ssh_compatibility_profile": "LEGACY_SSH_RSA_DH1_CBC",
            "ssh_username_reference": "env://TEST_SSH_USER",
            "ssh_password_reference": "env://TEST_SSH_PASSWORD",
            "ssh_host_key_fingerprint": "SHA256:abcdefghijklmnopqrstuv",
        }
    })
    assert payload.remote_access is not None
    assert payload.remote_access.ssh_port == 2222
    assert payload.remote_access.ssh_compatibility_profile == "LEGACY_SSH_RSA_DH1_CBC"




def test_device_update_accepts_native_web_gui_proxy_configuration():
    payload = DeviceUpdate.model_validate({
        "remote_access": {
            "web_enabled": True,
            "web_scheme": "HTTPS",
            "web_port": 443,
            "web_tls_mode": "PINNED_CERT",
            "web_tls_pinned_certificate_reference": "env://TEST_DEVICE_WEB_CERT",
        }
    })
    assert payload.remote_access is not None
    assert payload.remote_access.web_scheme == "HTTPS"
    assert payload.remote_access.web_tls_mode == "PINNED_CERT"

def test_legacy_ssh_compatibility_profile_is_fixed_and_does_not_enable_dss():
    options = ssh_compatibility_options("LEGACY_SSH_RSA_DH1_CBC")
    joined = " ".join(options)
    assert "diffie-hellman-group1-sha1" in joined
    assert "HostKeyAlgorithms=+ssh-rsa" in joined
    assert "PubkeyAcceptedAlgorithms=+ssh-rsa" in joined
    assert "Ciphers=+aes128-cbc" in joined
    assert "ssh-dss" not in joined


def test_modern_ssh_profile_does_not_weaken_defaults():
    assert ssh_compatibility_options("MODERN") == []


def test_remote_access_secret_resolution_is_environment_only(monkeypatch):
    monkeypatch.setenv("FTTW_TEST_REMOTE_SECRET", "value")
    assert resolve_secret_reference("env://FTTW_TEST_REMOTE_SECRET") == "value"
    with pytest.raises(RemoteAccessSecretError):
        resolve_secret_reference("vault://somewhere")
    with pytest.raises(RemoteAccessSecretError):
        resolve_secret_reference("env://FTTW_TEST_MISSING")


def test_remote_access_ticket_is_hashed_before_persistence():
    digest = hash_remote_ticket("one-time-ticket")
    assert digest != "one-time-ticket"
    assert len(digest) == 64


def test_remote_access_is_disabled_by_default_in_backend_settings():
    settings_source = (Path(__file__).resolve().parents[1] / "settings.py").read_text(encoding="utf-8")
    assert "remote_access_enabled: bool = False" in settings_source
    assert "remote_access_ticket_ttl_seconds: int = 60" in settings_source
    assert "remote_access_session_max_seconds: int = 1800" in settings_source
    assert "remote_access_idle_timeout_seconds: int = 900" in settings_source


def test_gateway_security_invariants_are_present():
    source = (Path(__file__).resolve().parents[1] / "remote_gateway" / "main.py").read_text(encoding="utf-8")
    transport = (Path(__file__).resolve().parents[1] / "remote_gateway" / "ssh_transport.py").read_text(encoding="utf-8")
    assert "origin not in _allowed_origins()" in source
    assert 'launch.get("type") != "launch"' in source
    assert 'query_params.get("ticket")' not in source
    assert "REMOTE_ACCESS_TICKET_ALREADY_USED" in source
    assert "StrictHostKeyChecking=yes" in transport
    assert "ClearAllForwardings=yes" in transport
    assert "SSH_HOST_KEY_MISMATCH" in transport


def test_fresh_install_migrations_guard_metadata_created_tables():
    versions = Path(__file__).resolve().parents[2] / "migrations" / "versions"
    migration_28 = (versions / "0028_integration_foundation.py").read_text(encoding="utf-8")
    migration_29 = (versions / "0029_remote_access_gateway.py").read_text(encoding="utf-8")
    migration_30 = (versions / "0030_ssh_compat_profile.py").read_text(encoding="utf-8")
    migration_31 = (versions / "0031_operational_sync.py").read_text(encoding="utf-8")
    migration_32 = (versions / "0032_web_gui_proxy.py").read_text(encoding="utf-8")
    assert 'inspector.has_table("integration_connectors")' in migration_28
    assert 'inspector.has_table("device_remote_access_profiles")' in migration_29
    assert '"ssh_compatibility_profile" not in columns' in migration_30
    assert '"manual_degraded_override" not in columns' in migration_31
    assert 'inspector.has_table("device_remote_access_profiles")' in migration_32
    assert '"web_enabled"' in migration_32


def test_remote_access_activity_refreshes_linked_fttw_auth_session_and_keeps_security_limits():
    source = (Path(__file__).resolve().parents[1] / "remote_gateway" / "main.py").read_text(encoding="utf-8")
    assert "auth_session.last_user_activity_at = now" in source
    assert "auth.last_user_activity_at = now" in source
    assert "settings.remote_access_idle_timeout_seconds" in source
    assert "settings.remote_access_session_max_seconds" in source
    assert "AUTH_SESSION_EXPIRED" in source
