import asyncio
from types import SimpleNamespace

from app.discovery.adapters.http import HTTPDiscoveryAdapter
from app.discovery.adapters.tcp import TCPDiscoveryAdapter
from app.discovery.models import DiscoveryContext


def test_http_adapter_extracts_metadata(monkeypatch):
    class Headers:
        def get(self, key, default=None):
            return {
                "Server": "TestServer/1.0",
                "Content-Type": "text/html",
            }.get(key, default)

    class Response:
        status = 200
        headers = Headers()

        def read(self, size):
            return b"<html><head><title>FTTW Test Device</title></head><body>ok</body></html>"

        def geturl(self):
            return "http://192.0.2.1/"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_urlopen(*args, **kwargs):
        return Response()

    monkeypatch.setattr("app.discovery.adapters.http.urlopen", fake_urlopen)
    monkeypatch.setattr(
        "app.discovery.adapters.http._reverse_dns",
        lambda ip: "test-device.local",
    )

    result = asyncio.run(
        HTTPDiscoveryAdapter().discover(
            DiscoveryContext(ip_address="192.0.2.1", timeout_seconds=1)
        )
    )

    assert result.success is True
    assert result.hostname == "test-device.local"
    assert result.raw_data["server"] == "TestServer/1.0"
    assert result.raw_data["title"] == "FTTW Test Device"
    assert result.raw_data["status_code"] == 200


def test_http_adapter_does_not_send_credentials():
    source = __import__(
        "app.discovery.adapters.http",
        fromlist=["HTTPDiscoveryAdapter"],
    ).__dict__
    assert "credential_reference" not in source["HTTPDiscoveryAdapter"].__dict__


def test_tcp_adapter_reports_open_ports(monkeypatch):
    async def fake_open_connection(host, port):
        class Writer:
            def close(self):
                pass

            async def wait_closed(self):
                pass

        return SimpleNamespace(), Writer()

    monkeypatch.setattr(
        "asyncio.open_connection",
        fake_open_connection,
    )

    result = asyncio.run(
        TCPDiscoveryAdapter().discover(
            DiscoveryContext(
                ip_address="192.0.2.1",
                timeout_seconds=1,
                metadata={"ports": [80, 443]},
            )
        )
    )

    assert result.success is True
    assert result.raw_data["open_ports"] == [80, 443]


def test_tcp_adapter_reports_no_open_ports(monkeypatch):
    async def fake_open_connection(host, port):
        raise OSError("connection refused")

    monkeypatch.setattr(
        "asyncio.open_connection",
        fake_open_connection,
    )

    result = asyncio.run(
        TCPDiscoveryAdapter().discover(
            DiscoveryContext(
                ip_address="192.0.2.1",
                timeout_seconds=1,
                metadata={"ports": [80, 443]},
            )
        )
    )

    assert result.success is False
    assert result.raw_data["open_ports"] == []


def test_http_404_preserves_server_and_title(monkeypatch):
    class Headers:
        def get(self, key, default=None):
            return {
                "Server": "lighttpd/1.4.31",
                "Content-Type": "text/html",
            }.get(key, default)

    from urllib.error import HTTPError

    fake_body = b"<html><head><title>Router Login</title></head><body>Not Found</body></html>"

    class FakeHTTPError(HTTPError):
        def __init__(self):
            super().__init__(
                url="http://192.0.2.1/",
                code=404,
                msg="Not Found",
                hdrs=Headers(),
                fp=None,
            )

        def read(self, size=-1):
            return fake_body

    def fake_urlopen(*args, **kwargs):
        raise FakeHTTPError()

    monkeypatch.setattr("app.discovery.adapters.http.urlopen", fake_urlopen)
    monkeypatch.setattr(
        "app.discovery.adapters.http._reverse_dns",
        lambda ip: None,
    )

    result = asyncio.run(
        HTTPDiscoveryAdapter().discover(
            DiscoveryContext(ip_address="192.0.2.1", timeout_seconds=1)
        )
    )

    assert result.success is True
    assert result.raw_data["status_code"] == 404
    assert result.raw_data["server"] == "lighttpd/1.4.31"
    assert result.raw_data["title"] == "Router Login"


def test_icmp_adapter_reports_missing_ping_cleanly(monkeypatch):
    from app.discovery.adapters.icmp import ICMPDiscoveryAdapter

    monkeypatch.setattr(
        "app.discovery.adapters.icmp.shutil.which",
        lambda name: None,
    )

    result = asyncio.run(
        ICMPDiscoveryAdapter().discover(
            DiscoveryContext(ip_address="192.0.2.1", timeout_seconds=1)
        )
    )

    assert result.success is False
    assert result.raw_data["probe_available"] is False
    assert "ping utility is not installed" in result.message
