import asyncio
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.api.routers.customers import customer_filter_options, list_customer_page
from app.api.routers.devices_inventory import list_device_inventory_page, list_device_management_page, list_device_management_vlan_options
from app.api.routers.geo import list_cities_page, list_locations_page, list_sectors_page
from app.db.session import AsyncSessionLocal, engine
from app.models import City, Customer, Device, DeviceType, Location, Network, Sector
from app.services.customer_services import create_customer_service
from app.services.device_domain import create_domain_placement
from app.services.topology_query_filters import filter_options as topology_filter_options
from app.services.topology_query_models import TopologyQuery
from app.services.topology_query_scope import resolve_path_scope


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()
    loop.run_until_complete(engine.dispose())
    try:
        yield loop
    finally:
        loop.run_until_complete(engine.dispose())
        loop.close()


async def _type(db, code: str) -> DeviceType:
    row = await db.scalar(select(DeviceType).where(DeviceType.code == code))
    if row is None:
        row = DeviceType(name=f"Filter {code}", code=code)
        db.add(row)
        await db.flush()
    return row


async def _device(db, dtype: DeviceType, label: str) -> Device:
    row = Device(device_type_id=dtype.id, display_name=label, hostname=f"vf-{uuid4().hex[:12]}")
    db.add(row)
    await db.flush()
    return row


async def _available_service_vlans(db, count=2):
    used = set((await db.scalars(select(City.service_vlan_id).where(City.service_vlan_id.is_not(None)))).all())
    values = [value for value in range(2, 4095) if value not in used]
    if len(values) < count:
        pytest.skip("Not enough unallocated S-VLANs for isolated filter regression test.")
    return values[:count]


async def _branch(db, network: Network, *, s_vlan: int, marker: str, c_vlan: int):
    city = City(network_id=network.id, name=f"Filter City {marker}", code=f"FC-{marker}", service_vlan_id=s_vlan)
    db.add(city); await db.flush()
    location = Location(city_id=city.id, name=f"Filter Location {marker}", code=f"FL-{marker}")
    db.add(location); await db.flush()
    sector = Sector(location_id=location.id, name=f"Filter Sector {marker}", code=f"FS-{marker}", customer_vlan_start=100, customer_vlan_end=199)
    db.add(sector); await db.flush()

    sector_type = await _type(db, "SECTOR")
    cpe_type = await _type(db, "CPE")
    ap_type = await _type(db, "ACCESS_POINT")
    sector_device = await _device(db, sector_type, f"Filter Sector Device {marker}")
    await create_domain_placement(db, sector_device, "SECTOR", location_id=None, sector_id=sector.id, parent_device_id=None)
    cpe = await _device(db, cpe_type, f"Filter CPE {marker}")
    await create_domain_placement(db, cpe, "CPE", location_id=None, sector_id=None, parent_device_id=sector_device.id)
    ap = await _device(db, ap_type, f"Filter AP {marker}")
    await create_domain_placement(db, ap, "ACCESS_POINT", location_id=None, sector_id=None, parent_device_id=cpe.id)
    customer = Customer(customer_code=f"FILTER-{marker}", name=f"Filter Customer {marker}")
    db.add(customer); await db.flush()
    await create_customer_service(
        db,
        customer_id=customer.id,
        service_code=f"FILTER-SVC-{marker}",
        status="ACTIVE",
        access_point_device_id=ap.id,
        router_device_id=None,
        customer_vlan_id=c_vlan,
        require_customer_vlan=True,
        metadata={},
    )
    return city, location, sector, sector_device, cpe, ap, customer


def test_vlan_filters_follow_documented_scope_without_changing_topology(event_loop):
    async def run_test():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                s1, s2 = await _available_service_vlans(db, 2)
                marker = uuid4().hex[:7]
                network = Network(name=f"Filter Network {marker}", code=f"FN-{marker}")
                db.add(network); await db.flush()
                b1 = await _branch(db, network, s_vlan=s1, marker=f"{marker}A", c_vlan=110)
                b2 = await _branch(db, network, s_vlan=s2, marker=f"{marker}B", c_vlan=110)
                city1, location1, sector1, sector_device1, cpe1, ap1, customer1 = b1
                city2, _, _, _, cpe2, ap2, customer2 = b2

                cities = await list_cities_page(
                    db=db, search=None, network_id=network.id, service_vlan_id=s1, status_filter=None,
                    sort_by="name", sort_direction="asc", page=1, page_size=50, actor=None,
                )
                assert {row.id for row in cities.items} == {city1.id}

                locations = await list_locations_page(
                    db=db, search=None, network_id=network.id, city_id=None, service_vlan_id=s1,
                    customer_vlan_id=110, status_filter=None, sort_by="name", sort_direction="asc",
                    page=1, page_size=50, actor=None,
                )
                assert {row.id for row in locations.items} == {location1.id}

                sectors = await list_sectors_page(
                    db=db, search=None, network_id=network.id, city_id=None, location_id=None,
                    service_vlan_id=s1, customer_vlan_id=150, role=None, status_filter=None, bound=None,
                    sort_by="name", sort_direction="asc", page=1, page_size=50, actor=None,
                )
                assert {row.id for row in sectors.items} == {sector1.id}

                customers = await list_customer_page(
                    search=None, customer_name=None, service_code=None, sector_id=None,
                    service_vlan_id=s1, customer_vlan_id=110, status_filter=None,
                    sort_by="name", sort_direction="asc", page=1, page_size=50, db=db, actor=None,
                )
                assert {row.id for row in customers.items} == {customer1.id}

                sorted_customers = await list_customer_page(
                    search=None, customer_name=None, service_code=None, sector_id=None,
                    service_vlan_id=None, customer_vlan_id=110, status_filter=None,
                    sort_by="service_vlan_id", sort_direction="asc", page=1, page_size=500, db=db, actor=None,
                )
                sorted_customer_ids = [row.id for row in sorted_customers.items]
                assert sorted_customer_ids.index(customer1.id) < sorted_customer_ids.index(customer2.id)

                customer_s_options = await customer_filter_options(
                    kind="service-vlan", search=None, selected_id=None, customer_name=None,
                    service_code=None, sector_id=None, service_vlan_id=None, customer_vlan_id=110,
                    network_id=network.id, page=1, page_size=50, db=db, actor=None,
                )
                assert {item.id for item in customer_s_options.items} == {str(s1), str(s2)}

                customer_c_options = await customer_filter_options(
                    kind="customer-vlan", search=None, selected_id=None, customer_name=None,
                    service_code=None, sector_id=None, service_vlan_id=s1, customer_vlan_id=None,
                    network_id=network.id, page=1, page_size=50, db=db, actor=None,
                )
                assert {item.id for item in customer_c_options.items} == {"110"}

                device_s_options = await list_device_management_vlan_options(
                    kind="service", network_id=network.id, city_id=None, location_id=None,
                    physical_sector_device_id=None, group_id=None, device_type_id=None,
                    lifecycle_state=None, operational_state=None, service_vlan_id=None,
                    customer_vlan_id=110, management_search=None, search=None, page=1, page_size=50,
                    db=db, actor=None,
                )
                assert {item.id for item in device_s_options.items} == {str(s1), str(s2)}

                device_c_options = await list_device_management_vlan_options(
                    kind="customer", network_id=network.id, city_id=None, location_id=None,
                    physical_sector_device_id=None, group_id=None, device_type_id=None,
                    lifecycle_state=None, operational_state=None, service_vlan_id=s1,
                    customer_vlan_id=None, management_search=None, search=None, page=1, page_size=100,
                    db=db, actor=None,
                )
                device_c_ids = {item.id for item in device_c_options.items}
                assert {"110", "150"}.issubset(device_c_ids)

                topology_s_options = await topology_filter_options(
                    db, TopologyQuery(source_type="network", source_id=network.id, customer_vlan_ids=(110,)),
                    kind="service_vlan", search="", page=1, page_size=50,
                )
                assert {str(item.id) for item in topology_s_options.items} == {str(s1), str(s2)}

                topology_c_options = await topology_filter_options(
                    db, TopologyQuery(source_type="network", source_id=network.id, service_vlan_ids=(s1,)),
                    kind="customer_vlan", search="", page=1, page_size=50,
                )
                assert {str(item.id) for item in topology_c_options.items} == {"110"}

                devices = await list_device_management_page(
                    db=db, network_id=network.id, city_id=None, location_id=None,
                    physical_sector_device_id=None, group_id=None, device_id=None, device_type_id=None,
                    service_vlan_id=s1, customer_vlan_id=150, sector_role=None,
                    available_for_ap_parent=False, ap_child_device_id=None, exclude_decommissioned=False,
                    lifecycle_state=None, operational_state=None, search=None, sort_by="display_name",
                    sort_direction="asc", page=1, page_size=50, actor=None,
                )
                assert sector_device1.id in {row.id for row in devices.items}
                assert all(row.id not in {cpe1.id, ap1.id, cpe2.id, ap2.id} for row in devices.items)


                inventory_sector = await list_device_inventory_page(
                    db=db, device_type_id=None, operational_state=None, lifecycle_state=None,
                    vendor=None, management_protocol=None, search=None, sort_by="customer_vlan_id",
                    sort_direction="asc", page=1, page_size=50, actor=None,
                    service_vlan_id=s1, customer_vlan_id=150,
                )
                assert {row.id for row in inventory_sector.items} == {sector_device1.id}
                assert inventory_sector.items[0].service_vlan_id == s1
                assert inventory_sector.items[0].customer_vlan_display == "100-199"

                inventory_service = await list_device_inventory_page(
                    db=db, device_type_id=None, operational_state=None, lifecycle_state=None,
                    vendor=None, management_protocol=None, search=None, sort_by="service_vlan_id",
                    sort_direction="asc", page=1, page_size=50, actor=None,
                    service_vlan_id=s1, customer_vlan_id=110,
                )
                inventory_by_id = {row.id: row for row in inventory_service.items}
                assert {sector_device1.id, cpe1.id, ap1.id} <= set(inventory_by_id)
                assert inventory_by_id[cpe1.id].customer_vlan_display == "110"
                assert inventory_by_id[ap1.id].customer_vlan_display == "110"
                assert all(row.service_vlan_id == s1 for row in inventory_service.items)

                # The same C-VLAN may exist in multiple cities. With only C-VLAN
                # selected, both paths remain eligible. Adding S-VLAN narrows to
                # the City that owns that outer VLAN.
                _, _, c_scope = await resolve_path_scope(db, TopologyQuery(
                    source_type="network", source_id=network.id, customer_vlan_ids=(110,),
                ))
                assert {city1.id, city2.id}.issubset(c_scope.city_ids)
                assert {cpe1.id, cpe2.id}.issubset(c_scope.target_cpe_ids)
                assert {ap1.id, ap2.id}.issubset(c_scope.target_ap_ids)

                _, _, sc_scope = await resolve_path_scope(db, TopologyQuery(
                    source_type="network", source_id=network.id,
                    service_vlan_ids=(s1,), customer_vlan_ids=(110,),
                ))
                assert sc_scope.city_ids == {city1.id}
                assert cpe1.id in sc_scope.target_cpe_ids and cpe2.id not in sc_scope.target_cpe_ids
                assert ap1.id in sc_scope.target_ap_ids and ap2.id not in sc_scope.target_ap_ids
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(run_test())
