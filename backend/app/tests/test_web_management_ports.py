from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.deps import get_db
from app.api.routers import devices_lifecycle
from app.discovery.adapters import http as http_adapter
from app.discovery.adapters.http import HTTPDiscoveryAdapter, HTTPSDiscoveryAdapter
from app.discovery.aggregation import aggregate_discovery_records
from app.discovery.models import DiscoveryContext
from app.main import app
from app.models import AuditLog, City, Device, DeviceIP, DevicePlacement, DeviceType, Location, Network
from app.schemas.batch_discovery import BatchDiscoveryRequest
from app.schemas.discovery import DiscoveryRunRequest
from app.schemas.remote_access import DeviceRemoteAccessUpdate
from app.services.audit import enable_audit_maintenance
from app.services.device_registration import register_domain_device
from app.services.remote_access import web_profile_read
from app.remote_gateway.web_proxy import WebProxyState
from app.settings import settings
from app.web_management import effective_web_port, web_management_url


@pytest.mark.parametrize(
    ("scheme", "configured", "expected_port", "expected_url"),
    [
        ("HTTP", None, 80, "http://192.0.2.10"),
        ("HTTPS", None, 443, "https://192.0.2.10"),
        ("HTTP", 8080, 8080, "http://192.0.2.10:8080"),
        ("HTTPS", 8443, 8443, "https://192.0.2.10:8443"),
        ("HTTP", 1, 1, "http://192.0.2.10:1"),
        ("HTTPS", 65535, 65535, "https://192.0.2.10:65535"),
    ],
)
def test_effective_web_management_ports_and_urls(scheme, configured, expected_port, expected_url):
    assert effective_web_port(scheme, configured) == expected_port
    assert web_management_url(scheme, "192.0.2.10", configured) == expected_url


@pytest.mark.parametrize("port", [0, 65536])
def test_invalid_web_management_ports_are_rejected(port):
    with pytest.raises(ValueError):
        effective_web_port("HTTP", port)
    with pytest.raises(ValidationError):
        DeviceRemoteAccessUpdate(web_port=port)
    with pytest.raises(ValidationError):
        DiscoveryRunRequest(ip_address="192.0.2.10", methods=["HTTP"], http_port=port)
    with pytest.raises(ValidationError):
        BatchDiscoveryRequest(ip_addresses=["192.0.2.10"], methods=["HTTPS"], https_port=port)


def test_null_profile_port_round_trips_with_protocol_default():
    profile = SimpleNamespace(
        web_enabled=True,
        web_scheme="HTTP",
        web_port=None,
        web_tls_mode="SYSTEM",
        web_tls_compat_profile="MODERN",
        web_tls_ca_reference=None,
        web_tls_pinned_certificate_reference=None,
    )
    payload = web_profile_read(profile, uuid4())
    assert payload.web_port is None
    assert payload.effective_web_port == 80


def test_secure_proxy_target_origin_uses_custom_and_default_ports():
    origin = WebProxyState.target_origin.fget
    assert origin is not None
    assert origin(SimpleNamespace(target_scheme="HTTP", target_host="192.0.2.10", target_port=80)) == "http://192.0.2.10"
    assert origin(SimpleNamespace(target_scheme="HTTPS", target_host="192.0.2.10", target_port=443)) == "https://192.0.2.10"
    assert origin(SimpleNamespace(target_scheme="HTTP", target_host="192.0.2.10", target_port=8080)) == "http://192.0.2.10:8080"
    assert origin(SimpleNamespace(target_scheme="HTTPS", target_host="192.0.2.10", target_port=8443)) == "https://192.0.2.10:8443"


@pytest.mark.parametrize(
    ("adapter", "context", "expected"),
    [
        (HTTPDiscoveryAdapter(), DiscoveryContext("192.0.2.10"), "http://192.0.2.10/"),
        (HTTPSDiscoveryAdapter(), DiscoveryContext("192.0.2.10"), "https://192.0.2.10/"),
        (HTTPDiscoveryAdapter(), DiscoveryContext("192.0.2.10", http_port=8080), "http://192.0.2.10:8080/"),
        (HTTPSDiscoveryAdapter(), DiscoveryContext("192.0.2.10", https_port=8443), "https://192.0.2.10:8443/"),
    ],
)
def test_discovery_connects_to_effective_protocol_port(monkeypatch, adapter, context, expected):
    captured = []

    class Response:
        status = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self, _limit):
            return b"<title>Device</title>"

        def geturl(self):
            return captured[-1]

    def fake_urlopen(request, **_kwargs):
        captured.append(request.full_url)
        return Response()

    monkeypatch.setattr(http_adapter, "urlopen", fake_urlopen)
    monkeypatch.setattr(http_adapter, "_reverse_dns", lambda _ip: None)
    result = asyncio.run(adapter.discover(context))
    assert result.success is True
    assert captured == [expected]
    assert result.raw_data["requested_url"] == expected


def test_candidate_evidence_preserves_discovered_management_port():
    aggregate = aggregate_discovery_records([
        SimpleNamespace(
            id=uuid4(),
            ip_address="192.0.2.10",
            discovery_method="HTTP",
            status="DISCOVERED",
            hostname="device.example",
            vendor=None,
            model=None,
            serial_number=None,
            raw_data={
                "port": 8080,
                "requested_url": "http://192.0.2.10:8080/",
                "management_protocol": "HTTP",
            },
        )
    ])
    assert aggregate is not None
    assert aggregate.evidence["HTTP"]["port"] == 8080
    assert aggregate.evidence["HTTP"]["requested_url"] == "http://192.0.2.10:8080/"


def test_web_management_port_persistence_api_round_trip_and_direct_url(monkeypatch):
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        async def override_get_db():
            async with factory() as db:
                yield db

        app.dependency_overrides[get_db] = override_get_db
        ids = {}
        captured_urls: list[str] = []
        try:
            async with factory() as db:
                device_type = await db.scalar(select(DeviceType).where(DeviceType.code == "SWITCH"))
                assert device_type is not None
                marker = uuid4().hex[:10]
                network = Network(name=f"Port Net {marker}", code=f"PN-{marker}", status="ACTIVE")
                db.add(network); await db.flush(); ids["network"] = network.id
                city = City(network_id=network.id, name=f"Port City {marker}", code=f"PC-{marker}", status="ACTIVE")
                db.add(city); await db.flush(); ids["city"] = city.id
                location = Location(city_id=city.id, name=f"Port Location {marker}", code=f"PL-{marker}", status="ACTIVE")
                db.add(location); await db.flush(); ids["location"] = location.id
                registration = await register_domain_device(
                    db,
                    device_type_id=device_type.id,
                    display_name=f"Port Device {marker}",
                    management_ip=f"198.18.{uuid4().int % 200 + 1}.{uuid4().int % 200 + 1}",
                    location_id=location.id,
                    sector_id=None,
                    parent_device_id=None,
                    lifecycle_state="ACTIVE",
                    operational_state="UP",
                    metadata={},
                    ip_source="TEST",
                )
                ids["device"] = registration.device.id
                await db.commit()

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                blank = await client.patch(
                    f"/api/devices/{ids['device']}",
                    json={"remote_access": {"web_enabled": True, "web_scheme": "HTTP", "web_port": None, "web_tls_mode": "SYSTEM", "web_tls_compat_profile": "MODERN"}},
                )
                assert blank.status_code == 200, blank.text
                status = await client.get(f"/api/devices/{ids['device']}/remote-access/web")
                assert status.status_code == 200, status.text
                assert status.json()["web_port"] is None
                assert status.json()["effective_web_port"] == 80

                custom = await client.patch(
                    f"/api/devices/{ids['device']}",
                    json={"remote_access": {"web_enabled": True, "web_scheme": "HTTPS", "web_port": 8443, "web_tls_mode": "SYSTEM", "web_tls_compat_profile": "MODERN"}},
                )
                assert custom.status_code == 200, custom.text
                status = await client.get(f"/api/devices/{ids['device']}/remote-access/web")
                assert status.json()["web_port"] == 8443
                assert status.json()["effective_web_port"] == 8443

                class FakeResponse:
                    status_code = 200

                class FakeClient:
                    async def __aenter__(self): return self
                    async def __aexit__(self, *_): return False
                    async def get(self, url):
                        captured_urls.append(url)
                        return FakeResponse()

                monkeypatch.setattr(devices_lifecycle.httpx, "AsyncClient", lambda **_kwargs: FakeClient())
                direct = await client.post(f"/api/devices/{ids['device']}/test-accessibility")
                assert direct.status_code == 200, direct.text
                assert direct.json()["url"].endswith(":8443")
                assert captured_urls == [direct.json()["url"]]
        finally:
            app.dependency_overrides.pop(get_db, None)
            async with factory() as db:
                await enable_audit_maintenance(db)
                if ids.get("device"):
                    await db.execute(delete(AuditLog).where(AuditLog.entity_id == ids["device"]))
                    await db.execute(delete(DeviceIP).where(DeviceIP.device_id == ids["device"]))
                    await db.execute(delete(DevicePlacement).where(DevicePlacement.device_id == ids["device"]))
                    await db.execute(delete(Device).where(Device.id == ids["device"]))
                if ids.get("location"): await db.execute(delete(Location).where(Location.id == ids["location"]))
                if ids.get("city"): await db.execute(delete(City).where(City.id == ids["city"]))
                if ids.get("network"): await db.execute(delete(Network).where(Network.id == ids["network"]))
                await db.commit()
            await engine.dispose()

    asyncio.run(scenario())
