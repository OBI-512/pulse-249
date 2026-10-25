from pathlib import Path
from types import SimpleNamespace

from starlette.requests import Request

from app.security.authorization import permission_for_request
from app.security.permission_dependencies import expand_permission_codes
from app.security.permissions import Permission as P


def _request(method: str, path: str) -> Request:
    return Request(
        {
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
        }
    )


def test_access_template_routes_use_explicit_permissions():
    assert permission_for_request(_request("GET", "/api/access-templates")) == P.ACCESS_TEMPLATE_READ
    assert permission_for_request(_request("POST", "/api/access-templates")) == P.ACCESS_TEMPLATE_MANAGE
    assert permission_for_request(_request("PATCH", "/api/access-templates/{template_id}")) == P.ACCESS_TEMPLATE_MANAGE
    assert permission_for_request(_request("POST", "/api/access-templates/{template_id}/test")) == P.ACCESS_TEMPLATE_TEST


def test_ssh_and_telnet_routes_keep_explicit_remote_access_permissions():
    assert permission_for_request(
        _request("POST", "/api/devices/{device_id}/remote-access/ssh-sessions")
    ) == P.DEVICE_REMOTE_ACCESS_SSH
    assert permission_for_request(
        _request("POST", "/api/devices/{device_id}/remote-access/telnet-sessions")
    ) == P.DEVICE_REMOTE_ACCESS_TELNET
    assert permission_for_request(
        _request("DELETE", "/api/devices/{device_id}/remote-access/telnet-sessions/{session_id}")
    ) == P.DEVICE_REMOTE_ACCESS_TELNET


def test_new_permissions_include_required_read_prerequisites():
    telnet = expand_permission_codes([P.DEVICE_REMOTE_ACCESS_TELNET])
    assert P.DEVICE_REMOTE_ACCESS_TELNET in telnet
    assert P.DEVICE_READ in telnet

    manage = expand_permission_codes([P.ACCESS_TEMPLATE_MANAGE])
    assert P.ACCESS_TEMPLATE_MANAGE in manage
    assert P.ACCESS_TEMPLATE_READ in manage

    test = expand_permission_codes([P.ACCESS_TEMPLATE_TEST])
    assert P.ACCESS_TEMPLATE_TEST in test
    assert P.ACCESS_TEMPLATE_READ in test
    assert P.DEVICE_READ in test


def test_telnet_is_disabled_by_default_and_gateway_is_fail_closed():
    app_root = Path(__file__).resolve().parents[1]
    settings_source = (app_root / "settings.py").read_text(encoding="utf-8")
    gateway_source = (app_root / "remote_gateway" / "telnet_gateway.py").read_text(encoding="utf-8")

    assert "telnet_access_enabled: bool = False" in settings_source
    assert "not settings.remote_access_enabled or not settings.telnet_access_enabled" in gateway_source
    assert 'origin not in _allowed_origins()' in gateway_source
    assert 'launch.get("type") != "launch"' in gateway_source
    assert 'query_params.get("ticket")' not in gateway_source
    assert '"insecure_transport": True' in gateway_source


def test_ssh_gateway_preserves_device_pin_and_supports_template_fallback():
    source = (
        Path(__file__).resolve().parents[1] / "remote_gateway" / "main.py"
    ).read_text(encoding="utf-8")

    assert "resolve_ssh_runtime_access" in source
    assert 'credential_source = "ACCESS_TEMPLATE"' in source
    assert 'credential_source = "REMOTE_ACCESS_PROFILE"' in source
    assert "profile.ssh_host_key_fingerprint" in source
    assert "expected_fingerprint=context[\"fingerprint\"]" in source


def test_remote_access_status_is_template_aware_without_resolving_secrets():
    source = (
        Path(__file__).resolve().parents[1] / "api" / "routers" / "devices_remote_access.py"
    ).read_text(encoding="utf-8")

    assert "access_template_ready" in source
    assert 'protocol="SSH"' in source
    assert "status.ready = bool(" in source
    assert "profile.ssh_enabled" in source
    assert "profile.ssh_host_key_fingerprint" in source


def test_ssh_trust_on_first_use_is_explicit_and_revalidated():
    app_root = Path(__file__).resolve().parents[1]
    route_source = (app_root / "api" / "routers" / "devices_remote_access.py").read_text(encoding="utf-8")
    trust_source = (app_root / "services" / "ssh_host_trust.py").read_text(encoding="utf-8")
    schema_source = (app_root / "schemas" / "remote_access.py").read_text(encoding="utf-8")
    model_source = (app_root / "models" / "remote_access.py").read_text(encoding="utf-8")

    # Discovery/trust reuse the existing SSH-session route, preserving the
    # route-permission baseline and the device.remote_access.ssh permission.
    assert 'action == "DISCOVER_HOST_KEY"' in route_source
    assert 'action == "TRUST_HOST_KEY"' in route_source
    assert 'Literal["LAUNCH", "DISCOVER_HOST_KEY", "TRUST_HOST_KEY"]' in schema_source

    # Candidate collection never authenticates and does not persist an
    # accept-new known_hosts file as trusted state.
    assert '"PasswordAuthentication=no"' in trust_source
    assert '"KbdInteractiveAuthentication=no"' in trust_source
    assert '"StrictHostKeyChecking=accept-new"' in trust_source
    assert "TemporaryDirectory" in trust_source

    # Trust requires an exact observed fingerprint and re-discovers before
    # writing. Changed keys require an explicit replacement flag.
    assert "candidate.fingerprint != expected_fingerprint" in trust_source
    assert "SSH_HOST_KEY_CHANGED_DURING_CONFIRMATION" in trust_source
    assert "SSH_HOST_KEY_REPLACE_CONFIRMATION_REQUIRED" in trust_source
    assert "not replace_existing" in trust_source
    assert 'trust_state="MATCH"' in trust_source

    # Access-Template-backed SSH requires only enablement + a per-device pin;
    # reusable credentials are intentionally not duplicated on each device.
    assert '"(ssh_enabled = false) OR ssh_host_key_fingerprint IS NOT NULL"' in model_source


def test_access_template_ssh_test_handles_first_use_trust_without_enabling_web_ssh():
    app_root = Path(__file__).resolve().parents[1]
    router_source = (app_root / "api" / "routers" / "access_templates.py").read_text(encoding="utf-8")
    schema_source = (app_root / "schemas" / "access_templates.py").read_text(encoding="utf-8")
    trust_source = (app_root / "services" / "ssh_host_trust.py").read_text(encoding="utf-8")

    assert "AccessTemplateTestRead | SSHHostKeyActionResponse" in router_source
    assert "discover_device_ssh_host_key" in router_source
    assert "trust_device_ssh_host_key" in router_source
    assert "enable_remote_access=False" in router_source
    assert "trust_host_key: bool = False" in schema_source
    assert "expected_fingerprint" in schema_source
    assert "replace_existing" in schema_source
    assert "enable_remote_access: bool = True" in trust_source
    assert "if enable_remote_access:" in trust_source
