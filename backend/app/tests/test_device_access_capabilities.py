from pathlib import Path
from types import SimpleNamespace

from starlette.requests import Request

from app.security.authorization import permission_for_request
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


def test_unified_capability_route_is_read_only_device_scoped():
    assert permission_for_request(
        _request("GET", "/api/devices/{device_id}/access-capabilities")
    ) == P.DEVICE_READ


def test_capability_route_reuses_existing_remote_access_and_template_guards():
    app_root = Path(__file__).resolve().parents[1]
    source = (app_root / "api" / "routers" / "devices_remote_access.py").read_text(encoding="utf-8")

    assert '"/{device_id}/access-capabilities"' in source
    assert "user_has_permission" in source
    assert "settings.remote_access_enabled" in source
    assert "settings.telnet_access_enabled" in source
    assert "access_template_ready" in source
    assert "profile_is_ready" in source
    assert "web_profile_is_ready" in source
    assert "get_management_ip" in source
    assert "resolved_secrets" not in source


def test_capability_response_is_sanitized_and_contains_no_secret_fields():
    app_root = Path(__file__).resolve().parents[1]
    schema = (app_root / "schemas" / "remote_access.py").read_text(encoding="utf-8")

    start = schema.index("class DeviceAccessCapabilityRead")
    end = schema.index("class SSHSessionActionRequest")
    capability_schema = schema[start:end]
    for forbidden in ("password", "private_key", "username", "ticket", "cookie", "secret"):
        assert forbidden not in capability_schema.lower()

def test_enabled_ssh_visibility_is_separate_from_immediate_readiness():
    app_root = Path(__file__).resolve().parents[1]
    source = (app_root / "api" / "routers" / "devices_remote_access.py").read_text(encoding="utf-8")

    assert "legacy_enabled = bool(profile is not None and profile.ssh_enabled)" in source
    assert "available=legacy_enabled" in source
    assert '"SSH_LEGACY_NOT_READY"' in source
    assert "template_enabled = bool(profile is not None and profile.ssh_enabled)" in source
    assert "available=template_enabled" in source