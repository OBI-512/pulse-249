"""Permission hardening regression coverage for device routes and domain moves."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest
from starlette.requests import Request

from app.api.routers import devices as devices_router
from app.core.audit_context import bind_audit_actor, reset_audit_context
from app.core.exceptions import APIError
from app.security.authorization import permission_for_request
from app.security.permissions import Permission as PermissionCode


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
    ("method", "path", "expected"),
    [
        ("POST", "/api/devices", PermissionCode.DEVICE_CREATE),
        ("POST", "/api/devices/{device_id}/test-accessibility", PermissionCode.DEVICE_READ),
        ("POST", "/api/devices/{device_id}/decommission", PermissionCode.DEVICE_UPDATE),
        ("POST", "/api/devices/{device_id}/reactivate", PermissionCode.DEVICE_UPDATE),
        ("POST", "/api/devices/{device_id}/ips", PermissionCode.DEVICE_UPDATE),
        ("POST", "/api/devices/{device_id}/interfaces", PermissionCode.DEVICE_UPDATE),
        ("PATCH", "/api/devices/{device_id}/ips/{ip_id}", PermissionCode.DEVICE_UPDATE),
        ("DELETE", "/api/devices/{device_id}/ips/{ip_id}", PermissionCode.DEVICE_DELETE),
        ("DELETE", "/api/devices/{device_id}/interfaces/{interface_id}", PermissionCode.DEVICE_DELETE),
    ],
)
def test_device_subresource_permissions_match_operation_semantics(method, path, expected):
    assert permission_for_request(_request(method, path)) == expected


def test_unknown_device_post_subaction_fails_closed_mapping():
    assert permission_for_request(_request("POST", "/api/devices/{device_id}/future-action")) is None


def test_secondary_domain_permission_check_rejects_bound_actor(monkeypatch):
    async def denied(*args, **kwargs):
        return False

    monkeypatch.setattr(devices_router, "user_has_permission", denied)
    token = bind_audit_actor(uuid4(), "permission-hardening-test")
    try:
        with pytest.raises(APIError) as error:
            asyncio.run(devices_router._require_actor_permission_for_change(object(), PermissionCode.PHYSICAL_MOVEMENT_CPE))
        assert error.value.status_code == 403
        assert error.value.detail["code"] == "PERMISSION_DENIED"
    finally:
        reset_audit_context(token)
