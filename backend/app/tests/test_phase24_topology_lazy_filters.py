import asyncio
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.db.session import AsyncSessionLocal, engine
from app.models import City, Device, DeviceGroup, DeviceGroupMembership, DeviceType, Location, Network, Sector
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
    row = DeviceType(name=f"Phase 24 {code}", code=code, is_active=True)
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
    network = Network(name=f"Phase 24 Network {uuid4()}", code=f"P24-N-{uuid4().hex[:8]}")
    db.add(network)
    await db.flush()
    city = City(network_id=network.id, name=f"Phase 24 City {uuid4()}", code=f"P24-C-{uuid4().hex[:8]}")
    db.add(city)
    await db.flush()
    location_a = Location(city_id=city.id, name=f"Phase 24 Location A {uuid4()}", code=f"P24-LA-{uuid4().hex[:8]}")
    location_b = Location(city_id=city.id, name=f"Phase 24 Location B {uuid4()}", code=f"P24-LB-{uuid4().hex[:8]}")
    db.add_all([location_a, location_b])
    await db.flush()
    sector_a = Sector(location_id=location_a.id, name=f"Phase 24 Sector A {uuid4()}", code=f"P24-SA-{uuid4().hex[:8]}", role="CUSTOMER_ACCESS")
    sector_b = Sector(location_id=location_b.id, name=f"Phase 24 Sector B {uuid4()}", code=f"P24-SB-{uuid4().hex[:8]}", role="CUSTOMER_ACCESS")
    db.add_all([sector_a, sector_b])
    await db.flush()

    sector_type = await _type(db, "SECTOR")
    cpe_type = await _type(db, "CPE")
    ap_type = await _type(db, "ACCESS_POINT")
    switch_type = await _type(db, "SWITCH")

    independent_switch = await _device(db, switch_type, f"Phase 24 Switch {uuid4()}")
    await create_domain_placement(db, independent_switch, "SWITCH", location_id=location_a.id, sector_id=None, parent_device_id=None)

    sector_device_a = await _device(db, sector_type, f"Phase 24 Physical A {uuid4()}")
    await create_domain_placement(db, sector_device_a, "SECTOR", location_id=location_a.id, sector_id=sector_a.id, parent_device_id=None)
    cpe_a = await _device(db, cpe_type, f"Phase 24 CPE A {uuid4()}")
    await create_domain_placement(db, cpe_a, "CPE", location_id=None, sector_id=None, parent_device_id=sector_device_a.id)
    ap_a = await _device(db, ap_type, f"Phase 24 AP A {uuid4()}")
    await create_domain_placement(db, ap_a, "ACCESS_POINT", location_id=None, sector_id=None, parent_device_id=cpe_a.id)

    sector_device_b = await _device(db, sector_type, f"Phase 24 Physical B {uuid4()}")
    await create_domain_placement(db, sector_device_b, "SECTOR", location_id=location_b.id, sector_id=sector_b.id, parent_device_id=None)
    cpe_b = await _device(db, cpe_type, f"Phase 24 CPE B {uuid4()}")
    await create_domain_placement(db, cpe_b, "CPE", location_id=None, sector_id=None, parent_device_id=sector_device_b.id)
    ap_b = await _device(db, ap_type, f"Phase 24 AP B {uuid4()}")
    await create_domain_placement(db, ap_b, "ACCESS_POINT", location_id=None, sector_id=None, parent_device_id=cpe_b.id)
    await db.flush()

    return {
        "network": network,
        "city": city,
        "location_a": location_a,
        "location_b": location_b,
        "sector_a": sector_a,
        "sector_b": sector_b,
        "sector_device_a": sector_device_a,
        "sector_device_b": sector_device_b,
        "cpe_a": cpe_a,
        "cpe_b": cpe_b,
        "ap_a": ap_a,
        "ap_b": ap_b,
        "independent_switch": independent_switch,
    }


def test_network_topology_filters_cascade_and_cpe_filter_keeps_ap_descendant(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _fixture(db)
                query = TopologyQuery(
                    source_type="network",
                    source_id=ctx["network"].id,
                    location_ids=(ctx["location_a"].id,),
                )
                sectors = await filter_options(db, query, kind="sector", search="", page=1, page_size=50)
                assert [item.id for item in sectors.items] == [ctx["sector_a"].id]

                cpe_query = TopologyQuery(
                    source_type="network",
                    source_id=ctx["network"].id,
                    location_ids=(ctx["location_a"].id,),
                    sector_ids=(ctx["sector_a"].id,),
                )
                cpes = await filter_options(db, cpe_query, kind="cpe", search="", page=1, page_size=50)
                assert [item.id for item in cpes.items] == [ctx["cpe_a"].id]

                sector_only = TopologyQuery(
                    source_type="network",
                    source_id=ctx["network"].id,
                    sector_ids=(ctx["sector_a"].id,),
                )
                sector_only_children = await hierarchy_children(
                    db, sector_only, node_kind="location", node_id=ctx["location_a"].id
                )
                assert [(node.kind, node.id) for node in sector_only_children] == [("sector", ctx["sector_a"].id)]

                path = TopologyQuery(
                    source_type="network",
                    source_id=ctx["network"].id,
                    cpe_ids=(ctx["cpe_a"].id,),
                )
                roots = await hierarchy_children(db, path, node_kind="root", node_id=None)
                assert [node.id for node in roots] == [ctx["city"].id]
                locations = await hierarchy_children(db, path, node_kind="city", node_id=ctx["city"].id)
                assert [node.id for node in locations] == [ctx["location_a"].id]
                sectors_in_path = await hierarchy_children(db, path, node_kind="location", node_id=ctx["location_a"].id)
                assert [node.id for node in sectors_in_path] == [ctx["sector_a"].id]
                sector_devices = await hierarchy_children(db, path, node_kind="sector", node_id=ctx["sector_a"].id)
                assert [node.id for node in sector_devices] == [ctx["sector_device_a"].id]
                cpe_nodes = await hierarchy_children(db, path, node_kind="sector_device", node_id=ctx["sector_device_a"].id)
                assert [node.id for node in cpe_nodes] == [ctx["cpe_a"].id]
                ap_nodes = await hierarchy_children(db, path, node_kind="cpe", node_id=ctx["cpe_a"].id)
                assert [node.id for node in ap_nodes] == [ctx["ap_a"].id]
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_group_lazy_topology_keeps_only_effective_members_and_structural_ancestors(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _fixture(db)
                group = DeviceGroup(
                    name=f"Phase 24 AP Group {uuid4()}",
                    code=f"P24-G-{uuid4().hex[:8]}",
                    scope_type="GLOBAL",
                    device_scope="ANY",
                    group_kind="CUSTOM",
                    membership_mode="MANUAL",
                )
                db.add(group)
                await db.flush()
                db.add(DeviceGroupMembership(group_id=group.id, device_id=ctx["ap_a"].id))
                await db.flush()

                query = TopologyQuery(source_type="group", source_id=group.id)
                ap_options = await filter_options(db, query, kind="access_point", search="", page=1, page_size=50)
                assert [item.id for item in ap_options.items] == [ctx["ap_a"].id]
                cpe_options = await filter_options(db, query, kind="cpe", search="", page=1, page_size=50)
                assert [item.id for item in cpe_options.items] == [ctx["cpe_a"].id]

                filtered = TopologyQuery(source_type="group", source_id=group.id, access_point_ids=(ctx["ap_a"].id,))
                networks = await hierarchy_children(db, filtered, node_kind="root", node_id=None)
                assert [node.id for node in networks] == [ctx["network"].id]
                cities = await hierarchy_children(db, filtered, node_kind="network", node_id=ctx["network"].id)
                assert [node.id for node in cities] == [ctx["city"].id]
                locations = await hierarchy_children(db, filtered, node_kind="city", node_id=ctx["city"].id)
                assert [node.id for node in locations] == [ctx["location_a"].id]
                sectors = await hierarchy_children(db, filtered, node_kind="location", node_id=ctx["location_a"].id)
                assert [node.id for node in sectors] == [ctx["sector_a"].id]
                sector_device = (await hierarchy_children(db, filtered, node_kind="sector", node_id=ctx["sector_a"].id))[0]
                assert sector_device.id == ctx["sector_device_a"].id
                assert sector_device.context_only is True
                cpe = (await hierarchy_children(db, filtered, node_kind="sector_device", node_id=sector_device.id))[0]
                assert cpe.id == ctx["cpe_a"].id
                assert cpe.context_only is True
                ap = (await hierarchy_children(db, filtered, node_kind="cpe", node_id=cpe.id))[0]
                assert ap.id == ctx["ap_a"].id
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_keyword_matching_physical_sector_name_prunes_sibling_sector(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _fixture(db)
                query = TopologyQuery(
                    source_type="network",
                    source_id=ctx["network"].id,
                    keyword=ctx["sector_device_a"].display_name,
                )
                locations = await hierarchy_children(db, query, node_kind="city", node_id=ctx["city"].id)
                assert [node.id for node in locations] == [ctx["location_a"].id]
                sectors = await hierarchy_children(db, query, node_kind="location", node_id=ctx["location_a"].id)
                assert [node.id for node in sectors] == [ctx["sector_a"].id]
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())
