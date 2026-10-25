import asyncio
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.db.session import AsyncSessionLocal, engine
from app.models import (
    City,
    Customer,
    Device,
    DeviceHierarchyLink,
    DeviceRelationship,
    DeviceType,
    Location,
    Network,
    Sector,
)
from app.services.customer_services import (
    CustomerServiceValidationError,
    create_customer_service,
)
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
    device_type = await db.scalar(select(DeviceType).where(DeviceType.code == code))
    if device_type is None:
        device_type = DeviceType(name=f"Phase 1 {code}", code=code)
        db.add(device_type)
        await db.flush()
    return device_type


async def _device(db, device_type: DeviceType, label: str) -> Device:
    device = Device(
        device_type_id=device_type.id,
        display_name=label,
        hostname=f"p1-{uuid4().hex[:16]}",
        vendor="Integration-Test",
        model="TEST",
    )
    db.add(device)
    await db.flush()
    return device


async def _service_context(db):
    network = Network(name=f"Phase 1 Network {uuid4()}", code=f"P1-NET-{uuid4().hex[:10]}")
    db.add(network)
    await db.flush()
    city = City(network_id=network.id, name=f"Phase 1 City {uuid4()}", code=f"P1-CITY-{uuid4().hex[:10]}")
    db.add(city)
    await db.flush()
    location = Location(city_id=city.id, name=f"Phase 1 Location {uuid4()}", code=f"P1-LOC-{uuid4().hex[:10]}")
    db.add(location)
    await db.flush()
    sector = Sector(location_id=location.id, name=f"Phase 1 Sector {uuid4()}", code=f"P1-SEC-{uuid4().hex[:10]}")
    customer = Customer(customer_code=f"P1-CUST-{uuid4().hex[:10]}", name="Phase 1 Customer")
    db.add_all([sector, customer])
    await db.flush()

    sector_type, cpe_type, ap_type, router_type = [
        await _type(db, code) for code in ("SECTOR", "CPE", "ACCESS_POINT", "ROUTER")
    ]
    sector_device = await _device(db, sector_type, f"Phase 1 Sector Device {uuid4()}")
    await create_domain_placement(db, sector_device, "SECTOR", location_id=None, sector_id=sector.id, parent_device_id=None)
    cpe = await _device(db, cpe_type, f"Phase 1 CPE {uuid4()}")
    await create_domain_placement(db, cpe, "CPE", location_id=None, sector_id=None, parent_device_id=sector_device.id)
    access_point = await _device(db, ap_type, f"Phase 1 AP {uuid4()}")
    await create_domain_placement(db, access_point, "ACCESS_POINT", location_id=None, sector_id=None, parent_device_id=cpe.id)
    router = await _device(db, router_type, f"Phase 1 Router {uuid4()}")
    await create_domain_placement(db, router, "ROUTER", location_id=location.id, sector_id=None, parent_device_id=None)
    return customer, sector, sector_device, cpe, access_point, router, cpe_type


def test_customer_service_uses_hierarchy_links_not_connectivity(event_loop):
    async def run_test():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                customer, sector, _, cpe, access_point, router, _ = await _service_context(db)
                service = await create_customer_service(
                    db,
                    customer_id=customer.id,
                    sector_id=sector.id,
                    service_code=f"P1-SVC-{uuid4().hex[:10]}",
                    status="ACTIVE",
                    cpe_device_id=cpe.id,
                    access_point_device_id=access_point.id,
                    router_device_id=router.id,
                    metadata={},
                )
                assert service.cpe_device_id == cpe.id
                assert service.access_point_device_id == access_point.id
                assert await db.scalar(select(DeviceHierarchyLink).where(DeviceHierarchyLink.child_device_id == cpe.id))
                assert (await db.execute(select(DeviceRelationship))).scalars().all() == []
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(run_test())


def test_customer_service_rejects_access_point_from_another_cpe(event_loop):
    async def run_test():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                customer, sector, sector_device, _, access_point, _, cpe_type = await _service_context(db)
                other_cpe = await _device(db, cpe_type, f"Phase 1 Other CPE {uuid4()}")
                await create_domain_placement(db, other_cpe, "CPE", location_id=None, sector_id=None, parent_device_id=sector_device.id)
                with pytest.raises(CustomerServiceValidationError) as error:
                    await create_customer_service(
                        db,
                        customer_id=customer.id,
                        sector_id=sector.id,
                        service_code=f"P1-SVC-{uuid4().hex[:10]}",
                        status="ACTIVE",
                        cpe_device_id=other_cpe.id,
                        access_point_device_id=access_point.id,
                        router_device_id=None,
                        metadata={},
                    )
                assert error.value.code == "CPE_AP_MISMATCH"
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(run_test())
