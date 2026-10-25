from starlette.requests import Request

from app.security.authorization import permission_for_request


def _request(method: str, path: str):
    return Request({"type":"http", "method":method, "path":path, "raw_path":path.encode(), "query_string":b"", "headers":[], "scheme":"http", "server":("test",80), "client":("test",1)})


def test_alarm_route_permission_map_is_explicit():
    assert permission_for_request(_request("GET", "/api/alarms/page")) == "alarm.read"
    assert permission_for_request(_request("GET", "/api/alarms/x/history")) == "alarm.read"
    assert permission_for_request(_request("GET", "/api/alarms/x/events")) == "alarm.read"
    assert permission_for_request(_request("POST", "/api/alarms/x/acknowledge")) == "alarm.acknowledge"
    assert permission_for_request(_request("PATCH", "/api/alarms/x/owner")) == "alarm.assign"
    assert permission_for_request(_request("POST", "/api/alarms/x/clear")) == "alarm.clear"
