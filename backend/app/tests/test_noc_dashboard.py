from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.models import Alarm, City, Device, DeviceAvailability, DeviceGroup, DevicePlacement, DeviceType, Location, Network, OperationalEvent
from app.security.resource_scope import EffectiveResourceScope
from app.services.dashboard import authorized_overview_device_categories, build_operations_dashboard
from app.settings import settings as app_settings


def _factory():
    engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
    return engine, async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


def _scope(*, network_ids=()):
    return EffectiveResourceScope(
        user_id=uuid4(),
        global_access=not network_ids,
        network_ids=frozenset(network_ids),
        city_ids=frozenset(),
        location_ids=frozenset(),
        sector_ids=frozenset(),
        group_ids=frozenset(),
    )


def test_noc_dashboard_uses_authoritative_availability_alarm_and_geography_state():
    async def scenario():
        engine, SessionLocal = _factory()
        try:
            async with SessionLocal() as db:
                tx = await db.begin()
                try:
                    marker = uuid4().hex[:8]
                    device_type = await db.scalar(select(DeviceType).where(DeviceType.code == "OTHER"))
                    assert device_type is not None
                    network = Network(name=f"C4 Network {marker}", code=f"C4N-{marker}")
                    db.add(network); await db.flush()
                    city = City(network_id=network.id, name=f"C4 City {marker}", code=f"C4C-{marker}")
                    db.add(city); await db.flush()
                    location = Location(city_id=city.id, name=f"C4 Location {marker}", code=f"C4L-{marker}", metadata_={})
                    db.add(location); await db.flush()
                    online = Device(
                        device_type_id=device_type.id, display_name=f"C4 Online {marker}",
                        lifecycle_state="ACTIVE", operational_state="DOWN", metadata_={},
                    )
                    offline = Device(
                        device_type_id=device_type.id, display_name=f"C4 Offline {marker}",
                        lifecycle_state="ACTIVE", operational_state="UP", metadata_={},
                    )
                    db.add_all([online, offline]); await db.flush()
                    for device in (online, offline):
                        db.add(DevicePlacement(
                            device_id=device.id, network_id=network.id, city_id=city.id,
                            location_id=location.id, metadata_={},
                        ))
                    now = datetime.now(timezone.utc)
                    db.add_all([
                        DeviceAvailability(device_id=online.id, status="ONLINE", profile="ICMP", enabled=True, next_check_at=now),
                        DeviceAvailability(device_id=offline.id, status="OFFLINE", profile="ICMP", enabled=True, next_check_at=now),
                    ])
                    event = OperationalEvent(
                        device_id=offline.id, event_type="DEVICE_AVAILABILITY_OFFLINE", severity="MAJOR",
                        correlation_key=f"c4:{marker}:offline", occurred_at=now,
                        summary=f"{offline.display_name} is offline.", metadata_={},
                    )
                    db.add(event); await db.flush()
                    db.add(Alarm(
                        device_id=offline.id, alarm_type="DEVICE_AVAILABILITY_OFFLINE",
                        correlation_key=f"c4:{marker}:alarm", severity="MAJOR", state="ACTIVE",
                        summary="offline", first_raised_at=now, last_raised_at=now,
                        occurrence_count=1, last_event_id=event.id,
                    ))
                    await db.flush()

                    snapshot = await build_operations_dashboard(db, scope=_scope(network_ids=(network.id,)), include_alarms=True)
                    # Manual operational_state values are deliberately opposite;
                    # C4 must use C1 server-authoritative availability instead.
                    assert snapshot.availability.total >= 2
                    assert snapshot.availability.online >= 1
                    assert snapshot.availability.offline >= 1
                    assert snapshot.alarms is not None and snapshot.alarms.major >= 1
                    assert any(row.key == device_type.code and row.offline >= 1 for row in snapshot.by_device_type)
                    assert any(row.key == str(network.id) and row.offline >= 1 for row in snapshot.by_network)
                    assert any(row.key == str(location.id) and row.offline >= 1 for row in snapshot.top_locations)
                    assert any(row.device_id == str(offline.id) for row in snapshot.recent_outages)
                finally:
                    await tx.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_noc_dashboard_respects_existing_network_scope_and_hides_alarm_data_without_alarm_permission():
    async def scenario():
        engine, SessionLocal = _factory()
        try:
            async with SessionLocal() as db:
                tx = await db.begin()
                try:
                    marker = uuid4().hex[:8]
                    device_type = await db.scalar(select(DeviceType).where(DeviceType.code == "OTHER"))
                    assert device_type is not None
                    networks = [Network(name=f"C4 Scope {index} {marker}", code=f"C4S{index}-{marker}") for index in (1, 2)]
                    db.add_all(networks); await db.flush()
                    devices = []
                    now = datetime.now(timezone.utc)
                    for index, network in enumerate(networks, 1):
                        city = City(network_id=network.id, name=f"C4 City {index} {marker}", code=f"C4C{index}-{marker}")
                        db.add(city); await db.flush()
                        location = Location(city_id=city.id, name=f"C4 Loc {index} {marker}", code=f"C4L{index}-{marker}", metadata_={})
                        db.add(location); await db.flush()
                        device = Device(device_type_id=device_type.id, display_name=f"C4 Device {index} {marker}", lifecycle_state="ACTIVE", operational_state="UNKNOWN", metadata_={})
                        db.add(device); await db.flush()
                        db.add(DevicePlacement(device_id=device.id, network_id=network.id, city_id=city.id, location_id=location.id, metadata_={}))
                        db.add(DeviceAvailability(device_id=device.id, status="ONLINE" if index == 1 else "OFFLINE", profile="ICMP", enabled=True, next_check_at=now))
                        devices.append(device)
                    await db.flush()

                    snapshot = await build_operations_dashboard(db, scope=_scope(network_ids=(networks[0].id,)), include_alarms=False)
                    assert snapshot.availability.total == 1
                    assert snapshot.availability.online == 1
                    assert snapshot.availability.offline == 0
                    assert snapshot.alarms is None
                    assert snapshot.recent_outages == []
                    assert [row.key for row in snapshot.by_network] == [str(networks[0].id)]
                finally:
                    await tx.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())



def test_permission_aware_overview_categories_come_from_effective_authorization_not_counts():
    async def scenario():
        engine, SessionLocal = _factory()
        try:
            async with SessionLocal() as db:
                tx = await db.begin()
                try:
                    marker = uuid4().hex[:8]
                    ap_group = DeviceGroup(
                        name=f"ENH4 AP {marker}", code=f"ENH4-AP-{marker}",
                        group_kind="CUSTOM", membership_mode="DYNAMIC",
                        scope_type="GLOBAL", device_scope="ACCESS_POINT", metadata_={},
                    )
                    cpe_group = DeviceGroup(
                        name=f"ENH4 CPE {marker}", code=f"ENH4-CPE-{marker}",
                        group_kind="CUSTOM", membership_mode="DYNAMIC",
                        scope_type="GLOBAL", device_scope="CPE", metadata_={},
                    )
                    any_group = DeviceGroup(
                        name=f"ENH4 ANY {marker}", code=f"ENH4-ANY-{marker}",
                        group_kind="CUSTOM", membership_mode="DYNAMIC",
                        scope_type="GLOBAL", device_scope="ANY", metadata_={},
                    )
                    db.add_all([ap_group, cpe_group, any_group]); await db.flush()

                    base = dict(
                        user_id=uuid4(), global_access=False, network_ids=frozenset(),
                        city_ids=frozenset(), location_ids=frozenset(), sector_ids=frozenset(),
                    )
                    ap_only = EffectiveResourceScope(**base, group_ids=frozenset({ap_group.id}))
                    cpe_ap = EffectiveResourceScope(**base, group_ids=frozenset({ap_group.id, cpe_group.id}))
                    any_group_scope = EffectiveResourceScope(**base, group_ids=frozenset({any_group.id}))
                    geographic = EffectiveResourceScope(
                        **{**base, "network_ids": frozenset({uuid4()})}, group_ids=frozenset()
                    )

                    # No observed device counts are consulted for these decisions.
                    assert await authorized_overview_device_categories(db, ap_only) == ["ACCESS_POINT"]
                    assert await authorized_overview_device_categories(db, cpe_ap) == ["ACCESS_POINT", "CPE"]
                    assert await authorized_overview_device_categories(db, any_group_scope) == ["ACCESS_POINT", "CPE", "SECTOR"]
                    assert await authorized_overview_device_categories(db, geographic) == ["ACCESS_POINT", "CPE", "SECTOR"]
                finally:
                    await tx.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())

def test_noc_dashboard_route_contract_is_device_read_and_worker_heartbeat_is_scheduled():
    from app.celery_app.config import celery_app
    from app.security.authorization import permission_for_request
    from starlette.requests import Request
    from types import SimpleNamespace

    request = Request({
        "type":"http", "http_version":"1.1", "method":"GET", "scheme":"http",
        "path":"/api/operations-dashboard", "raw_path":b"/api/operations-dashboard",
        "query_string":b"", "headers":[], "client":("test",0), "server":("test",80),
        "route":SimpleNamespace(path="/api/operations-dashboard"),
    })
    assert permission_for_request(request) == "device.read"
    heartbeat = celery_app.conf.beat_schedule["availability-worker-heartbeat"]
    assert heartbeat["task"] == "fttw.availability.worker_heartbeat"
    assert heartbeat["schedule"] <= 15.0
