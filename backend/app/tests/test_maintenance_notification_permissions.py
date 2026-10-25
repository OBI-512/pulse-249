from starlette.requests import Request

from app.security.authorization import permission_for_request


def _request(method: str, path: str):
    return Request({"type":"http", "method":method, "path":path, "raw_path":path.encode(), "query_string":b"", "headers":[], "scheme":"http", "server":("test",80), "client":("test",1)})


def test_c3_route_permission_map_is_explicit():
    assert permission_for_request(_request("GET", "/api/maintenance-windows")) == "maintenance.read"
    assert permission_for_request(_request("GET", "/api/maintenance-windows/targets")) == "maintenance.read"
    assert permission_for_request(_request("POST", "/api/maintenance-windows")) == "maintenance.manage"
    assert permission_for_request(_request("PUT", "/api/maintenance-windows/x")) == "maintenance.manage"
    assert permission_for_request(_request("POST", "/api/maintenance-windows/x/cancel")) == "maintenance.manage"
    assert permission_for_request(_request("GET", "/api/notifications/policies")) == "notification.read"
    assert permission_for_request(_request("POST", "/api/notifications/policies")) == "notification.manage"
    assert permission_for_request(_request("PATCH", "/api/notifications/policies/x")) == "notification.manage"
    assert permission_for_request(_request("GET", "/api/notifications/deliveries")) == "notification.read"
