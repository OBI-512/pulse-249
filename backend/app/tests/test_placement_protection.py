import asyncio
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.db.session import AsyncSessionLocal, engine
from app.models import (
    City,
    Device,
    DevicePlacement,
    DeviceType,
    Location,
    Network,
    Sector,
)
from app.services.placements import (
    PlacementValidationError,
    update_device_placement,
)


@pytest.fixture(scope="module")
def event_loop():
    """
    Use one asyncio event loop for the entire test module.

    SQLAlchemy's asyncpg connection pool binds connections to the event loop
    in which they were created. Repeated asyncio.run() calls create different
    loops and can therefore cause:

        Future attached to a different loop

    A single shared loop avoids that problem.
    """

    loop = asyncio.new_event_loop()

    try:
        # Dispose any connections that may have been created by previous
        # tests using another event loop.
        loop.run_until_complete(engine.dispose())

        yield loop

    finally:
        # Dispose all pooled asyncpg connections before closing the loop.
        loop.run_until_complete(engine.dispose())
        loop.close()


def test_valid_physical_reassignment_succeeds(event_loop):
    async def run_test():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()

            try:
                # ---------------------------------------------------------
                # 1. Create two networks
                # ---------------------------------------------------------

                network_a = Network(
                    name=f"Placement Network A {uuid4()}",
                    code=f"PL-NET-A-{uuid4().hex[:10]}",
                )

                network_b = Network(
                    name=f"Placement Network B {uuid4()}",
                    code=f"PL-NET-B-{uuid4().hex[:10]}",
                )

                db.add_all(
                    [
                        network_a,
                        network_b,
                    ]
                )

                await db.flush()

                # ---------------------------------------------------------
                # 2. Create cities
                # ---------------------------------------------------------

                city_a = City(
                    network_id=network_a.id,
                    name=f"Placement City A {uuid4()}",
                    code=f"PL-CITY-A-{uuid4().hex[:10]}",
                )

                city_b = City(
                    network_id=network_b.id,
                    name=f"Placement City B {uuid4()}",
                    code=f"PL-CITY-B-{uuid4().hex[:10]}",
                )

                db.add_all(
                    [
                        city_a,
                        city_b,
                    ]
                )

                await db.flush()

                # ---------------------------------------------------------
                # 3. Create locations
                # ---------------------------------------------------------

                location_a = Location(
                    city_id=city_a.id,
                    name=f"Placement Location A {uuid4()}",
                    code=f"PL-LOC-A-{uuid4().hex[:10]}",
                )

                location_b = Location(
                    city_id=city_b.id,
                    name=f"Placement Location B {uuid4()}",
                    code=f"PL-LOC-B-{uuid4().hex[:10]}",
                )

                db.add_all(
                    [
                        location_a,
                        location_b,
                    ]
                )

                await db.flush()

                # ---------------------------------------------------------
                # 4. Create sectors
                # ---------------------------------------------------------

                sector_a = Sector(
                    location_id=location_a.id,
                    name=f"Placement Sector A {uuid4()}",
                    code=f"PL-SEC-A-{uuid4().hex[:10]}",
                )

                sector_b = Sector(
                    location_id=location_b.id,
                    name=f"Placement Sector B {uuid4()}",
                    code=f"PL-SEC-B-{uuid4().hex[:10]}",
                )

                db.add_all(
                    [
                        sector_a,
                        sector_b,
                    ]
                )

                await db.flush()

                # ---------------------------------------------------------
                # 5. Create device type
                # ---------------------------------------------------------

                device_type = await db.scalar(
                    select(DeviceType).where(DeviceType.code == "SWITCH")
                )
                assert device_type is not None

                # ---------------------------------------------------------
                # 6. Create device
                # ---------------------------------------------------------

                device = Device(
                    device_type_id=device_type.id,
                    display_name=f"Placement Device {uuid4()}",
                    hostname=f"placement-device-{uuid4().hex[:10]}",
                    vendor="Integration-Test",
                    model="TEST",
                )

                db.add(device)

                await db.flush()

                # ---------------------------------------------------------
                # 7. Create initial physical placement
                # ---------------------------------------------------------

                placement = DevicePlacement(
                    device_id=device.id,
                    network_id=network_a.id,
                    city_id=city_a.id,
                    location_id=location_a.id,
                    sector_id=sector_a.id,
                )

                db.add(placement)

                await db.flush()

                # ---------------------------------------------------------
                # 8. Perform valid physical reassignment
                # ---------------------------------------------------------

                updated = await update_device_placement(
                    db,
                    device.id,
                    {
                        "network_id": network_b.id,
                        "city_id": city_b.id,
                        "location_id": location_b.id,
                        "sector_id": sector_b.id,
                    },
                )

                assert updated.network_id == network_b.id
                assert updated.city_id == city_b.id
                assert updated.location_id == location_b.id
                assert updated.sector_id == sector_b.id

            finally:
                await transaction.rollback()

    event_loop.run_until_complete(run_test())


def test_invalid_city_network_combination_is_rejected(event_loop):
    async def run_test():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()

            try:
                # ---------------------------------------------------------
                # 1. Create two networks
                # ---------------------------------------------------------

                network_a = Network(
                    name=f"Invalid Network A {uuid4()}",
                    code=f"INV-NET-A-{uuid4().hex[:10]}",
                )

                network_b = Network(
                    name=f"Invalid Network B {uuid4()}",
                    code=f"INV-NET-B-{uuid4().hex[:10]}",
                )

                db.add_all(
                    [
                        network_a,
                        network_b,
                    ]
                )

                await db.flush()

                # ---------------------------------------------------------
                # 2. City belongs to Network A
                # ---------------------------------------------------------

                city = City(
                    network_id=network_a.id,
                    name=f"Invalid City {uuid4()}",
                    code=f"INV-CITY-{uuid4().hex[:10]}",
                )

                db.add(city)

                await db.flush()

                # ---------------------------------------------------------
                # 3. Location belongs to City
                # ---------------------------------------------------------

                location = Location(
                    city_id=city.id,
                    name=f"Invalid Location {uuid4()}",
                    code=f"INV-LOC-{uuid4().hex[:10]}",
                )

                db.add(location)

                await db.flush()

                # ---------------------------------------------------------
                # 4. Create device type
                # ---------------------------------------------------------

                device_type = await db.scalar(
                    select(DeviceType).where(DeviceType.code == "SWITCH")
                )
                assert device_type is not None

                # ---------------------------------------------------------
                # 5. Create device
                # ---------------------------------------------------------

                device = Device(
                    device_type_id=device_type.id,
                    display_name=f"Invalid Device {uuid4()}",
                    hostname=f"invalid-device-{uuid4().hex[:10]}",
                    vendor="Integration-Test",
                    model="TEST",
                )

                db.add(device)

                await db.flush()

                # ---------------------------------------------------------
                # 6. Create valid initial placement
                # ---------------------------------------------------------

                placement = DevicePlacement(
                    device_id=device.id,
                    network_id=network_a.id,
                    city_id=city.id,
                    location_id=location.id,
                )

                db.add(placement)

                await db.flush()

                # ---------------------------------------------------------
                # 7. Attempt invalid reassignment
                #
                # City belongs to Network A, but the requested network
                # is Network B.
                # ---------------------------------------------------------

                with pytest.raises(
                    PlacementValidationError
                ) as exc_info:
                    await update_device_placement(
                        db,
                        device.id,
                        {
                            "network_id": network_b.id,
                        },
                    )

                assert exc_info.value.code == "CITY_NETWORK_MISMATCH"

            finally:
                await transaction.rollback()

    event_loop.run_until_complete(run_test())


def test_invalid_location_city_combination_is_rejected(event_loop):
    async def run_test():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()

            try:
                # ---------------------------------------------------------
                # 1. Create network
                # ---------------------------------------------------------

                network = Network(
                    name=f"Location Network {uuid4()}",
                    code=f"LOC-NET-{uuid4().hex[:10]}",
                )

                db.add(network)

                await db.flush()

                # ---------------------------------------------------------
                # 2. Create two cities under the same network
                # ---------------------------------------------------------

                city_a = City(
                    network_id=network.id,
                    name=f"Location City A {uuid4()}",
                    code=f"LOC-CITY-A-{uuid4().hex[:10]}",
                )

                city_b = City(
                    network_id=network.id,
                    name=f"Location City B {uuid4()}",
                    code=f"LOC-CITY-B-{uuid4().hex[:10]}",
                )

                db.add_all(
                    [
                        city_a,
                        city_b,
                    ]
                )

                await db.flush()

                # ---------------------------------------------------------
                # 3. Location belongs to City A
                # ---------------------------------------------------------

                location_a = Location(
                    city_id=city_a.id,
                    name=f"Location A {uuid4()}",
                    code=f"LOC-A-{uuid4().hex[:10]}",
                )

                db.add(location_a)

                await db.flush()

                # ---------------------------------------------------------
                # 4. Create device type
                # ---------------------------------------------------------

                device_type = await db.scalar(
                    select(DeviceType).where(DeviceType.code == "SWITCH")
                )
                assert device_type is not None

                # ---------------------------------------------------------
                # 5. Create device
                # ---------------------------------------------------------

                device = Device(
                    device_type_id=device_type.id,
                    display_name=f"Location Device {uuid4()}",
                    hostname=f"location-device-{uuid4().hex[:10]}",
                    vendor="Integration-Test",
                    model="TEST",
                )

                db.add(device)

                await db.flush()

                # ---------------------------------------------------------
                # 6. Create valid initial placement
                # ---------------------------------------------------------

                placement = DevicePlacement(
                    device_id=device.id,
                    network_id=network.id,
                    city_id=city_a.id,
                    location_id=location_a.id,
                )

                db.add(placement)

                await db.flush()

                # ---------------------------------------------------------
                # 7. Attempt invalid city reassignment
                #
                # Location A belongs to City A, but the requested city
                # is City B.
                # ---------------------------------------------------------

                with pytest.raises(
                    PlacementValidationError
                ) as exc_info:
                    await update_device_placement(
                        db,
                        device.id,
                        {
                            "city_id": city_b.id,
                        },
                    )

                assert exc_info.value.code == "LOCATION_CITY_MISMATCH"

            finally:
                await transaction.rollback()

    event_loop.run_until_complete(run_test())


def test_invalid_sector_location_combination_is_rejected(event_loop):
    async def run_test():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()

            try:
                # ---------------------------------------------------------
                # 1. Create network
                # ---------------------------------------------------------

                network = Network(
                    name=f"Sector Network {uuid4()}",
                    code=f"SEC-NET-{uuid4().hex[:10]}",
                )

                db.add(network)

                await db.flush()

                # ---------------------------------------------------------
                # 2. Create city
                # ---------------------------------------------------------

                city = City(
                    network_id=network.id,
                    name=f"Sector City {uuid4()}",
                    code=f"SEC-CITY-{uuid4().hex[:10]}",
                )

                db.add(city)

                await db.flush()

                # ---------------------------------------------------------
                # 3. Create two locations
                # ---------------------------------------------------------

                location_a = Location(
                    city_id=city.id,
                    name=f"Sector Location A {uuid4()}",
                    code=f"SEC-LOC-A-{uuid4().hex[:10]}",
                )

                location_b = Location(
                    city_id=city.id,
                    name=f"Sector Location B {uuid4()}",
                    code=f"SEC-LOC-B-{uuid4().hex[:10]}",
                )

                db.add_all(
                    [
                        location_a,
                        location_b,
                    ]
                )

                await db.flush()

                # ---------------------------------------------------------
                # 4. Sector belongs to Location B
                # ---------------------------------------------------------

                sector_b = Sector(
                    location_id=location_b.id,
                    name=f"Sector B {uuid4()}",
                    code=f"SEC-B-{uuid4().hex[:10]}",
                )

                db.add(sector_b)

                await db.flush()

                # ---------------------------------------------------------
                # 5. Create device type
                # ---------------------------------------------------------

                device_type = await db.scalar(
                    select(DeviceType).where(DeviceType.code == "SWITCH")
                )
                assert device_type is not None

                # ---------------------------------------------------------
                # 6. Create device
                # ---------------------------------------------------------

                device = Device(
                    device_type_id=device_type.id,
                    display_name=f"Sector Device {uuid4()}",
                    hostname=f"sector-device-{uuid4().hex[:10]}",
                    vendor="Integration-Test",
                    model="TEST",
                )

                db.add(device)

                await db.flush()

                # ---------------------------------------------------------
                # 7. Create valid initial placement at Location A
                # ---------------------------------------------------------

                placement = DevicePlacement(
                    device_id=device.id,
                    network_id=network.id,
                    city_id=city.id,
                    location_id=location_a.id,
                    sector_id=None,
                )

                db.add(placement)

                await db.flush()

                # ---------------------------------------------------------
                # 8. Attempt to assign a Sector belonging to Location B
                #    while remaining at Location A.
                # ---------------------------------------------------------

                with pytest.raises(
                    PlacementValidationError
                ) as exc_info:
                    await update_device_placement(
                        db,
                        device.id,
                        {
                            "sector_id": sector_b.id,
                        },
                    )

                assert exc_info.value.code == "SECTOR_LOCATION_MISMATCH"

            finally:
                await transaction.rollback()

    event_loop.run_until_complete(run_test())
