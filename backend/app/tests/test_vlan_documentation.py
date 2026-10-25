import asyncio
from uuid import uuid4

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import select

from app.api.routers.geo import _ensure_service_vlan_available, _validate_sector_vlan_range
from app.db.session import AsyncSessionLocal, engine
from app.models import City, Customer, Device, DeviceType, Location, Network, Sector
from app.schemas.geo import CityCreate, SectorCreate
from app.services.customer_services import CustomerServiceValidationError, create_customer_service
from app.services.device_domain import create_domain_placement


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
        row = DeviceType(name=f"VLAN {code}", code=code)
        db.add(row)
        await db.flush()
    return row


async def _device(db, device_type: DeviceType, label: str) -> Device:
    row = Device(
        device_type_id=device_type.id,
        display_name=label,
        hostname=f"vlan-{uuid4().hex[:16]}",
        vendor="Integration-Test",
        model="TEST",
    )
    db.add(row)
    await db.flush()
    return row


async def _available_service_vlans(db, count: int = 2) -> list[int]:
    used = set((await db.scalars(select(City.service_vlan_id).where(City.service_vlan_id.is_not(None)))).all())
    available = [value for value in range(2, 4095) if value not in used]
    if len(available) < count:
        pytest.skip("Not enough unallocated Service VLAN IDs for isolated VLAN regression test.")
    return available[:count]


async def _geography(db, *, s_vlan: int, c_start: int, c_end: int):
    network = Network(name=f"VLAN Network {uuid4()}", code=f"VLAN-NET-{uuid4().hex[:8]}")
    db.add(network)
    await db.flush()
    city = City(
        network_id=network.id,
        name=f"VLAN City {uuid4()}",
        code=f"VLAN-CITY-{uuid4().hex[:8]}",
        service_vlan_id=s_vlan,
    )
    db.add(city)
    await db.flush()
    location = Location(city_id=city.id, name=f"VLAN Location {uuid4()}", code=f"VLAN-LOC-{uuid4().hex[:8]}")
    db.add(location)
    await db.flush()
    sector = Sector(
        location_id=location.id,
        name=f"VLAN Sector {uuid4()}",
        code=f"VLAN-SEC-{uuid4().hex[:8]}",
        customer_vlan_start=c_start,
        customer_vlan_end=c_end,
    )
    db.add(sector)
    await db.flush()

    sector_type = await _type(db, "SECTOR")
    sector_device = await _device(db, sector_type, f"VLAN Sector Device {uuid4()}")
    await create_domain_placement(
        db,
        sector_device,
        "SECTOR",
        location_id=None,
        sector_id=sector.id,
        parent_device_id=None,
    )
    return city, location, sector, sector_device


async def _customer_endpoint(db, sector_device: Device):
    customer = Customer(customer_code=f"VLAN-CUST-{uuid4().hex[:8]}", name=f"VLAN Customer {uuid4()}")
    db.add(customer)
    await db.flush()
    cpe_type = await _type(db, "CPE")
    ap_type = await _type(db, "ACCESS_POINT")
    cpe = await _device(db, cpe_type, f"VLAN CPE {uuid4()}")
    await create_domain_placement(db, cpe, "CPE", location_id=None, sector_id=None, parent_device_id=sector_device.id)
    ap = await _device(db, ap_type, f"VLAN AP {uuid4()}")
    await create_domain_placement(db, ap, "ACCESS_POINT", location_id=None, sector_id=None, parent_device_id=cpe.id)
    return customer, cpe, ap


def test_vlan_input_contracts():
    assert CityCreate(name="City", code="CITY", service_vlan_id=2).service_vlan_id == 2
    assert CityCreate(name="City", code="CITY", service_vlan_id=4094).service_vlan_id == 4094
    with pytest.raises(ValidationError):
        CityCreate(name="City", code="CITY", service_vlan_id=1)
    with pytest.raises(ValidationError):
        SectorCreate(name="Sector", code="SEC", customer_vlan_start=100, customer_vlan_end=None)
    with pytest.raises(ValidationError):
        SectorCreate(name="Sector", code="SEC", customer_vlan_start=200, customer_vlan_end=100)


def test_vlan_city_scope_and_allocation_rules(event_loop):
    async def run_test():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                s_vlan1, s_vlan2 = await _available_service_vlans(db, 2)
                city1, location1, sector1, sector_device1 = await _geography(db, s_vlan=s_vlan1, c_start=100, c_end=199)

                with pytest.raises(HTTPException) as duplicate_s_vlan:
                    await _ensure_service_vlan_available(db, s_vlan1)
                assert duplicate_s_vlan.value.status_code == 409

                with pytest.raises(HTTPException) as overlapping_range:
                    await _validate_sector_vlan_range(
                        db,
                        location_id=location1.id,
                        vlan_start=150,
                        vlan_end=250,
                    )
                assert overlapping_range.value.status_code == 409
                assert overlapping_range.value.detail["code"] == "CUSTOMER_VLAN_RANGE_OVERLAP"

                customer1, _, ap1 = await _customer_endpoint(db, sector_device1)
                service1 = await create_customer_service(
                    db,
                    customer_id=customer1.id,
                    service_code=f"VLAN-SVC-{uuid4().hex[:8]}",
                    status="ACTIVE",
                    access_point_device_id=ap1.id,
                    router_device_id=None,
                    customer_vlan_id=110,
                    require_customer_vlan=True,
                    metadata={},
                )
                assert service1.sector_id == sector1.id
                assert service1.customer_vlan_id == 110
                assert city1.service_vlan_id == s_vlan1

                customer2, _, ap2 = await _customer_endpoint(db, sector_device1)
                with pytest.raises(CustomerServiceValidationError) as duplicate_c_vlan:
                    await create_customer_service(
                        db,
                        customer_id=customer2.id,
                        service_code=f"VLAN-SVC-{uuid4().hex[:8]}",
                        status="ACTIVE",
                        access_point_device_id=ap2.id,
                        router_device_id=None,
                        customer_vlan_id=110,
                        require_customer_vlan=True,
                        metadata={},
                    )
                assert duplicate_c_vlan.value.code == "CUSTOMER_VLAN_IN_USE_IN_CITY"

                with pytest.raises(CustomerServiceValidationError) as outside_range:
                    await create_customer_service(
                        db,
                        customer_id=customer2.id,
                        service_code=f"VLAN-SVC-{uuid4().hex[:8]}",
                        status="ACTIVE",
                        access_point_device_id=ap2.id,
                        router_device_id=None,
                        customer_vlan_id=250,
                        require_customer_vlan=True,
                        metadata={},
                    )
                assert outside_range.value.code == "CUSTOMER_VLAN_OUTSIDE_SECTOR_RANGE"

                _, _, sector2, sector_device2 = await _geography(db, s_vlan=s_vlan2, c_start=100, c_end=199)
                customer3, _, ap3 = await _customer_endpoint(db, sector_device2)
                service3 = await create_customer_service(
                    db,
                    customer_id=customer3.id,
                    service_code=f"VLAN-SVC-{uuid4().hex[:8]}",
                    status="ACTIVE",
                    access_point_device_id=ap3.id,
                    router_device_id=None,
                    customer_vlan_id=110,
                    require_customer_vlan=True,
                    metadata={},
                )
                assert service3.sector_id == sector2.id
                assert service3.customer_vlan_id == 110
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(run_test())

