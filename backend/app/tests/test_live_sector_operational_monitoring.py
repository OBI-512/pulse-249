from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import uuid4

from sqlalchemy import select

from app.api.routers import topology as topology_module
from app.api.routers.topology import _effective_live_state, get_location_topology_devices, get_sector_live_topology
from app.db.session import AsyncSessionLocal, engine
from app.models import City, Device, DeviceIP, DeviceType, Location, Network, Sector
from app.services.device_domain import create_domain_placement
from app.services.onboarding import ProbeResult


def test_live_state_semantics_are_explicit():
    up_device = SimpleNamespace(operational_state="UP")
    degraded_device = SimpleNamespace(operational_state="DEGRADED")
    reachable = ProbeResult("192.0.2.10", True, 8.1, "ICMP", "Device responded to ICMP.")
    unreachable = ProbeResult("192.0.2.10", False, 1000.0, "ICMP", "No ICMP response.")
    failed = ProbeResult("192.0.2.10", False, None, "ICMP", "Probe failed: ping unavailable")

    assert _effective_live_state(up_device, "192.0.2.10", reachable) == ("UP", "ICMP_REACHABLE")
    assert _effective_live_state(degraded_device, "192.0.2.10", reachable) == (
        "DEGRADED",
        "ICMP_REACHABLE_MANUAL_DEGRADED",
    )
    assert _effective_live_state(up_device, "192.0.2.10", unreachable) == ("DOWN", "ICMP_UNREACHABLE")
    assert _effective_live_state(up_device, None, None) == ("UNKNOWN", "NO_MANAGEMENT_IP")
    assert _effective_live_state(up_device, "192.0.2.10", failed) == ("UNKNOWN", "PROBE_ERROR")


def test_live_sector_topology_uses_icmp_without_overwriting_stored_state(monkeypatch):
    async def scenario():
        await engine.dispose()
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                marker = uuid4().hex[:10]
                network = Network(name=f"Reachability Network {marker}", code=f"LR-N-{marker}")
                db.add(network)
                await db.flush()
                city = City(network_id=network.id, name=f"Reachability City {marker}", code=f"LR-C-{marker}")
                db.add(city)
                await db.flush()
                location = Location(city_id=city.id, name=f"Reachability Location {marker}", code=f"LR-L-{marker}", metadata_={})
                db.add(location)
                await db.flush()
                sector = Sector(
                    location_id=location.id,
                    name=f"Reachability Sector {marker}",
                    code=f"LR-S-{marker}",
                    sequence_number=1,
                    role="CUSTOMER_ACCESS",
                    metadata_={},
                )
                db.add(sector)
                await db.flush()

                rows = (
                    await db.scalars(
                        select(DeviceType).where(DeviceType.code.in_(["SECTOR", "CPE", "ACCESS_POINT"]))
                    )
                ).all()
                types = {row.code: row for row in rows}

                sector_device = Device(
                    device_type_id=types["SECTOR"].id,
                    display_name=f"Reachable Sector {marker}",
                    lifecycle_state="REGISTERED",
                    operational_state="UNKNOWN",
                    metadata_={},
                )
                cpe = Device(
                    device_type_id=types["CPE"].id,
                    display_name=f"Degraded CPE {marker}",
                    lifecycle_state="REGISTERED",
                    operational_state="DEGRADED",
                    metadata_={},
                )
                ap = Device(
                    device_type_id=types["ACCESS_POINT"].id,
                    display_name=f"Offline AP {marker}",
                    lifecycle_state="REGISTERED",
                    operational_state="UP",
                    metadata_={},
                )
                db.add_all([sector_device, cpe, ap])
                await db.flush()

                await create_domain_placement(db, sector_device, "SECTOR", location_id=None, sector_id=sector.id, parent_device_id=None)
                await db.flush()
                await create_domain_placement(db, cpe, "CPE", location_id=None, sector_id=None, parent_device_id=sector_device.id)
                await db.flush()
                await create_domain_placement(db, ap, "ACCESS_POINT", location_id=None, sector_id=None, parent_device_id=cpe.id)
                await db.flush()

                ips = {
                    sector_device.id: "192.0.2.10",
                    cpe.id: "192.0.2.11",
                    ap.id: "192.0.2.12",
                }
                for device_id, address in ips.items():
                    db.add(DeviceIP(
                        device_id=device_id,
                        ip_address=address,
                        address_family=4,
                        is_management=True,
                        is_primary=True,
                        source="TEST",
                    ))
                await db.flush()

                async def fake_probe(address: str, timeout_seconds: float = 1.0) -> ProbeResult:
                    assert timeout_seconds == topology_module.LIVE_PROBE_TIMEOUT_SECONDS
                    if address == "192.0.2.12":
                        return ProbeResult(address, False, 1000.0, "ICMP", "No ICMP response.")
                    return ProbeResult(address, True, 4.5, "ICMP", "Device responded to ICMP.")

                monkeypatch.setattr(topology_module, "probe_icmp", fake_probe)
                result = await get_sector_live_topology(sector.id, db)
                root = result.sector.devices[0]
                assert root.live_state == "UP"
                assert root.live_state_source == "ICMP_REACHABLE"
                assert root.live_response_time_ms == 4.5
                assert root.live_checked_at is not None
                assert root.operational_state == "UNKNOWN"

                cpe_node = root.children[0]
                assert cpe_node.live_state == "DEGRADED"
                assert cpe_node.operational_state == "DEGRADED"

                ap_node = cpe_node.children[0]
                assert ap_node.live_state == "DOWN"
                assert ap_node.operational_state == "UP"

                # Live reachability is intentionally observational. It must not
                # rewrite the manually managed operational-state field.
                assert (await db.get(Device, sector_device.id)).operational_state == "UNKNOWN"
                assert (await db.get(Device, cpe.id)).operational_state == "DEGRADED"
                assert (await db.get(Device, ap.id)).operational_state == "UP"
            finally:
                await transaction.rollback()
        await engine.dispose()

    asyncio.run(scenario())



def test_location_view_returns_only_direct_physical_infrastructure_and_preserves_tree_contract(monkeypatch):
    async def scenario():
        await engine.dispose()
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                marker = uuid4().hex[:10]
                network = Network(name=f"Location View Network {marker}", code=f"LV-N-{marker}")
                db.add(network)
                await db.flush()
                city = City(network_id=network.id, name=f"Location View City {marker}", code=f"LV-C-{marker}")
                db.add(city)
                await db.flush()
                location = Location(city_id=city.id, name=f"Location View Site {marker}", code=f"LV-L-{marker}", metadata_={})
                db.add(location)
                await db.flush()

                customer_sector = Sector(
                    location_id=location.id,
                    name=f"Customer Sector {marker}",
                    code=f"LV-CS-{marker}",
                    sequence_number=1,
                    role="CUSTOMER_ACCESS",
                    metadata_={},
                )
                backhaul_sector = Sector(
                    location_id=location.id,
                    name=f"Backhaul Sector {marker}",
                    code=f"LV-BS-{marker}",
                    sequence_number=2,
                    role="BACKHAUL",
                    metadata_={},
                )
                db.add_all([customer_sector, backhaul_sector])
                await db.flush()

                rows = (
                    await db.scalars(
                        select(DeviceType).where(DeviceType.code.in_(["ROUTER", "SECTOR", "CPE", "ACCESS_POINT"]))
                    )
                ).all()
                types = {row.code: row for row in rows}
                assert {"ROUTER", "SECTOR", "CPE", "ACCESS_POINT"}.issubset(types)

                router = Device(device_type_id=types["ROUTER"].id, display_name=f"Site Router {marker}", lifecycle_state="REGISTERED", operational_state="UP", metadata_={})
                customer_sector_device = Device(device_type_id=types["SECTOR"].id, display_name=f"Customer Sector Device {marker}", lifecycle_state="REGISTERED", operational_state="UP", metadata_={})
                backhaul_sector_device = Device(device_type_id=types["SECTOR"].id, display_name=f"Backhaul Sector Device {marker}", lifecycle_state="REGISTERED", operational_state="UP", metadata_={})
                cpe = Device(device_type_id=types["CPE"].id, display_name=f"Downstream CPE {marker}", lifecycle_state="REGISTERED", operational_state="UP", metadata_={})
                ap = Device(device_type_id=types["ACCESS_POINT"].id, display_name=f"Downstream AP {marker}", lifecycle_state="REGISTERED", operational_state="UP", metadata_={})
                db.add_all([router, customer_sector_device, backhaul_sector_device, cpe, ap])
                await db.flush()

                await create_domain_placement(db, router, "ROUTER", location_id=location.id, sector_id=None, parent_device_id=None)
                await create_domain_placement(db, customer_sector_device, "SECTOR", location_id=None, sector_id=customer_sector.id, parent_device_id=None)
                await create_domain_placement(db, backhaul_sector_device, "SECTOR", location_id=None, sector_id=backhaul_sector.id, parent_device_id=None)
                await create_domain_placement(db, cpe, "CPE", location_id=None, sector_id=None, parent_device_id=customer_sector_device.id)
                await create_domain_placement(db, ap, "ACCESS_POINT", location_id=None, sector_id=None, parent_device_id=cpe.id)
                await db.flush()

                for index, device in enumerate([router, customer_sector_device, backhaul_sector_device, cpe, ap], start=20):
                    db.add(DeviceIP(device_id=device.id, ip_address=f"192.0.2.{index}", address_family=4, is_management=True, is_primary=True, source="TEST"))
                await db.flush()

                async def fake_probe(address: str, timeout_seconds: float = 1.0) -> ProbeResult:
                    return ProbeResult(address, True, 3.2, "ICMP", "Device responded to ICMP.")

                monkeypatch.setattr(topology_module, "probe_icmp", fake_probe)

                legacy_rows = await get_location_topology_devices(location.id, live=False, db=db)
                assert [row.id for row in legacy_rows] == [router.id]
                assert legacy_rows[0].live_state is None

                live_rows = await get_location_topology_devices(location.id, live=True, db=db)
                live_ids = {row.id for row in live_rows}
                assert live_ids == {router.id, customer_sector_device.id, backhaul_sector_device.id}
                assert cpe.id not in live_ids
                assert ap.id not in live_ids
                assert all(row.live_state == "UP" for row in live_rows)
                assert all(row.children == [] for row in live_rows)
            finally:
                await transaction.rollback()
        await engine.dispose()

    asyncio.run(scenario())
