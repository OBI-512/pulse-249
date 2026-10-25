
import asyncio
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.db.session import AsyncSessionLocal, engine
from app.models import Device, DeviceGroup, DeviceGroupMembership, DeviceType, Location, City, Network, Sector
from app.services.device_domain import create_domain_placement
from app.services.topology_lazy import TopologyQuery, filter_options, hierarchy_children


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(engine.dispose())
        yield loop
    finally:
        loop.run_until_complete(engine.dispose())
        loop.close()


async def _type(db, code: str) -> DeviceType:
    row = await db.scalar(select(DeviceType).where(DeviceType.code == code))
    if row is not None:
        return row
    row = DeviceType(name=f"Phase 24 Fix {code}", code=code, is_active=True)
    db.add(row)
    await db.flush()
    return row


async def _device(db, device_type: DeviceType, name: str) -> Device:
    row = Device(
        device_type_id=device_type.id,
        display_name=name,
        lifecycle_state="ACTIVE",
        operational_state="UP",
    )
    db.add(row)
    await db.flush()
    return row


async def _fixture(db):
    network = Network(name=f"P24 Fix Network {uuid4()}", code=f"P24F-N-{uuid4().hex[:8]}")
    db.add(network)
    await db.flush()
    city = City(network_id=network.id, name=f"P24 Fix City {uuid4()}", code=f"P24F-C-{uuid4().hex[:8]}")
    db.add(city)
    await db.flush()
    location = Location(city_id=city.id, name=f"P24 Fix Location {uuid4()}", code=f"P24F-L-{uuid4().hex[:8]}")
    db.add(location)
    await db.flush()
    sector = Sector(
        location_id=location.id,
        name=f"P24 Fix Sector {uuid4()}",
        code=f"P24F-S-{uuid4().hex[:8]}",
        role="CUSTOMER_ACCESS",
    )
    db.add(sector)
    await db.flush()

    sector_type = await _type(db, "SECTOR")
    cpe_type = await _type(db, "CPE")
    ap_type = await _type(db, "ACCESS_POINT")

    sector_device = await _device(db, sector_type, f"P24 Fix Physical {uuid4()}")
    await create_domain_placement(
        db, sector_device, "SECTOR",
        location_id=location.id, sector_id=sector.id, parent_device_id=None,
    )
    cpe = await _device(db, cpe_type, f"P24 Fix CPE {uuid4()}")
    await create_domain_placement(
        db, cpe, "CPE",
        location_id=None, sector_id=None, parent_device_id=sector_device.id,
    )
    ap = await _device(db, ap_type, f"P24 Fix AP {uuid4()}")
    await create_domain_placement(
        db, ap, "ACCESS_POINT",
        location_id=None, sector_id=None, parent_device_id=cpe.id,
    )
    await db.flush()
    return network, city, location, sector, sector_device, cpe, ap


def test_dynamic_any_group_exposes_cpes_in_group_filter(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                network, _, _, _, _, cpe, _ = await _fixture(db)
                group = DeviceGroup(
                    name=f"P24 Fix All Devices {uuid4()}",
                    code=f"P24F-G-{uuid4().hex[:8]}",
                    scope_type="GLOBAL",
                    device_scope="ANY",
                    group_kind="CUSTOM",
                    membership_mode="DYNAMIC",
                )
                db.add(group)
                await db.flush()

                options = await filter_options(
                    db,
                    TopologyQuery(source_type="group", source_id=group.id, network_ids=(network.id,)),
                    kind="cpe",
                    search="",
                    page=1,
                    page_size=50,
                )
                assert cpe.id in {item.id for item in options.items}
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_ap_group_exposes_structural_parent_cpe_and_cpe_filter_keeps_group_ap(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                _, city, location, sector, sector_device, cpe, ap = await _fixture(db)
                group = DeviceGroup(
                    name=f"P24 Fix AP Group {uuid4()}",
                    code=f"P24F-AP-{uuid4().hex[:8]}",
                    scope_type="GLOBAL",
                    device_scope="ANY",
                    group_kind="CUSTOM",
                    membership_mode="MANUAL",
                )
                db.add(group)
                await db.flush()
                db.add(DeviceGroupMembership(group_id=group.id, device_id=ap.id))
                await db.flush()

                options = await filter_options(
                    db,
                    TopologyQuery(source_type="group", source_id=group.id),
                    kind="cpe",
                    search="",
                    page=1,
                    page_size=50,
                )
                assert [item.id for item in options.items] == [cpe.id]

                query = TopologyQuery(
                    source_type="group",
                    source_id=group.id,
                    cpe_ids=(cpe.id,),
                )
                roots = await hierarchy_children(db, query, node_kind="root", node_id=None)
                assert len(roots) == 1
                cities = await hierarchy_children(db, query, node_kind="network", node_id=roots[0].id)
                assert [node.id for node in cities] == [city.id]
                locations = await hierarchy_children(db, query, node_kind="city", node_id=city.id)
                assert [node.id for node in locations] == [location.id]
                sectors = await hierarchy_children(db, query, node_kind="location", node_id=location.id)
                assert [node.id for node in sectors] == [sector.id]
                physical = await hierarchy_children(db, query, node_kind="sector", node_id=sector.id)
                assert [node.id for node in physical] == [sector_device.id]
                cpes = await hierarchy_children(db, query, node_kind="sector_device", node_id=sector_device.id)
                assert [node.id for node in cpes] == [cpe.id]
                assert cpes[0].context_only is True
                aps = await hierarchy_children(db, query, node_kind="cpe", node_id=cpe.id)
                assert [node.id for node in aps] == [ap.id]
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())
