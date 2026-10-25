import asyncio
from uuid import UUID, uuid4

import httpx
from sqlalchemy import delete, select

from app.db.session import AsyncSessionLocal, engine
from app.main import app
from app.models import (
    City,
    Device,
    DevicePlacement,
    DeviceType,
    Location,
    Network,
    Sector,
)


async def create_test_physical_hierarchy():
    """
    Create an isolated physical hierarchy for API-level testing.

    The records are committed because the FastAPI request uses a separate
    SQLAlchemy session and therefore must be able to see the test data.

    The caller is responsible for cleanup.
    """

    async with AsyncSessionLocal() as db:
        transaction = await db.begin()

        try:
            # -------------------------------------------------------------
            # Networks
            # -------------------------------------------------------------

            network_a = Network(
                name=f"API Placement Network A {uuid4()}",
                code=f"API-NET-A-{uuid4().hex[:10]}",
            )

            network_b = Network(
                name=f"API Placement Network B {uuid4()}",
                code=f"API-NET-B-{uuid4().hex[:10]}",
            )

            db.add_all(
                [
                    network_a,
                    network_b,
                ]
            )

            await db.flush()

            # -------------------------------------------------------------
            # Cities
            # -------------------------------------------------------------

            city_a = City(
                network_id=network_a.id,
                name=f"API Placement City A {uuid4()}",
                code=f"API-CITY-A-{uuid4().hex[:10]}",
            )

            city_b = City(
                network_id=network_b.id,
                name=f"API Placement City B {uuid4()}",
                code=f"API-CITY-B-{uuid4().hex[:10]}",
            )

            db.add_all(
                [
                    city_a,
                    city_b,
                ]
            )

            await db.flush()

            # -------------------------------------------------------------
            # Locations
            # -------------------------------------------------------------

            location_a = Location(
                city_id=city_a.id,
                name=f"API Placement Location A {uuid4()}",
                code=f"API-LOC-A-{uuid4().hex[:10]}",
            )

            location_b = Location(
                city_id=city_b.id,
                name=f"API Placement Location B {uuid4()}",
                code=f"API-LOC-B-{uuid4().hex[:10]}",
            )

            db.add_all(
                [
                    location_a,
                    location_b,
                ]
            )

            await db.flush()

            # -------------------------------------------------------------
            # Sectors
            # -------------------------------------------------------------

            sector_a = Sector(
                location_id=location_a.id,
                name=f"API Placement Sector A {uuid4()}",
                code=f"API-SEC-A-{uuid4().hex[:10]}",
            )

            sector_b = Sector(
                location_id=location_b.id,
                name=f"API Placement Sector B {uuid4()}",
                code=f"API-SEC-B-{uuid4().hex[:10]}",
            )

            db.add_all(
                [
                    sector_a,
                    sector_b,
                ]
            )

            await db.flush()

            # -------------------------------------------------------------
            # Device type
            # -------------------------------------------------------------

            device_type = await db.scalar(
                select(DeviceType).where(DeviceType.code == "SWITCH")
            )
            assert device_type is not None

            # -------------------------------------------------------------
            # Device
            # -------------------------------------------------------------

            device = Device(
                device_type_id=device_type.id,
                display_name=f"API Placement Device {uuid4()}",
                hostname=f"api-placement-device-{uuid4().hex[:10]}",
                vendor="Integration-Test",
                model="TEST",
            )

            db.add(device)

            await db.flush()

            # -------------------------------------------------------------
            # Initial placement
            # -------------------------------------------------------------

            placement = DevicePlacement(
                device_id=device.id,
                network_id=network_a.id,
                city_id=city_a.id,
                location_id=location_a.id,
                sector_id=sector_a.id,
            )

            db.add(placement)

            await db.flush()

            ids = {
                "device_id": device.id,
                "device_type_id": device_type.id,
                "network_a_id": network_a.id,
                "network_b_id": network_b.id,
                "city_a_id": city_a.id,
                "city_b_id": city_b.id,
                "location_a_id": location_a.id,
                "location_b_id": location_b.id,
                "sector_a_id": sector_a.id,
                "sector_b_id": sector_b.id,
            }

            await db.commit()

            return ids

        except Exception:
            await transaction.rollback()
            raise


async def read_placement(device_id: UUID):
    """
    Read the current placement using a fresh async SQLAlchemy session.

    This runs on the same event loop as the caller.
    """

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(DevicePlacement).where(
                DevicePlacement.device_id == device_id
            )
        )

        placement = result.scalar_one()

        return {
            "network_id": placement.network_id,
            "city_id": placement.city_id,
            "location_id": placement.location_id,
            "sector_id": placement.sector_id,
            "metadata": dict(placement.metadata_),
        }


async def cleanup_test_data(ids: dict):
    """
    Remove all records created by the API integration test.
    """

    async with AsyncSessionLocal() as db:
        transaction = await db.begin()

        try:
            # -------------------------------------------------------------
            # Device placement
            # -------------------------------------------------------------

            await db.execute(
                delete(DevicePlacement).where(
                    DevicePlacement.device_id == ids["device_id"]
                )
            )

            # -------------------------------------------------------------
            # Device
            # -------------------------------------------------------------

            await db.execute(
                delete(Device).where(
                    Device.id == ids["device_id"]
                )
            )

            # -------------------------------------------------------------
            # Sectors
            # -------------------------------------------------------------

            await db.execute(
                delete(Sector).where(
                    Sector.id.in_(
                        [
                            ids["sector_a_id"],
                            ids["sector_b_id"],
                        ]
                    )
                )
            )

            # -------------------------------------------------------------
            # Locations
            # -------------------------------------------------------------

            await db.execute(
                delete(Location).where(
                    Location.id.in_(
                        [
                            ids["location_a_id"],
                            ids["location_b_id"],
                        ]
                    )
                )
            )

            # -------------------------------------------------------------
            # Cities
            # -------------------------------------------------------------

            await db.execute(
                delete(City).where(
                    City.id.in_(
                        [
                            ids["city_a_id"],
                            ids["city_b_id"],
                        ]
                    )
                )
            )

            # -------------------------------------------------------------
            # Networks
            # -------------------------------------------------------------

            await db.execute(
                delete(Network).where(
                    Network.id.in_(
                        [
                            ids["network_a_id"],
                            ids["network_b_id"],
                        ]
                    )
                )
            )

            await db.commit()

        except Exception:
            await transaction.rollback()
            raise


async def api_client():
    """
    Create an HTTPX async client using the FastAPI application directly.

    Unlike TestClient, this does not create a second AnyIO event loop.
    The API request therefore runs on the same asyncio event loop as the
    database setup and verification.
    """

    transport = httpx.ASGITransport(app=app)

    return httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
    )


def test_invalid_physical_reassignment_is_rejected_by_api():
    """
    Verify that the FastAPI endpoint rejects an invalid physical hierarchy.

    Scenario:

        Network A
          └── City A
               └── Location A

        Network B
          └── City B
               └── Location B

    The device starts at:

        Network A / City A / Location A / Sector A

    We then request only:

        network_id = Network B

    while leaving City A and Location A unchanged.

    The service must reject this because City A belongs to Network A.

    The existing PostgreSQL placement must remain unchanged.
    """

    async def run_test():
        ids = None

        try:
            # Ensure the SQLAlchemy pool starts cleanly on this event loop.
            await engine.dispose()

            ids = await create_test_physical_hierarchy()

            original = await read_placement(
                ids["device_id"]
            )

            async with await api_client() as client:
                response = await client.patch(
                    f"/api/devices/{ids['device_id']}/placement",
                    json={
                        "network_id": str(ids["network_b_id"]),
                    },
                )

            assert response.status_code == 400

            body = response.json()

            assert body["detail"]["code"] == "CITY_NETWORK_MISMATCH"

            # ---------------------------------------------------------
            # Critical assertion:
            #
            # The invalid request must not modify PostgreSQL state.
            # ---------------------------------------------------------

            after = await read_placement(
                ids["device_id"]
            )

            assert after == original

        finally:
            if ids is not None:
                await cleanup_test_data(ids)

            await engine.dispose()

    asyncio.run(run_test())


def test_valid_physical_reassignment_succeeds_through_api():
    """
    Verify that a valid physical reassignment succeeds through FastAPI.

    Target hierarchy:

        Network B
          └── City B
               └── Location B
                    └── Sector B
    """

    async def run_test():
        ids = None

        try:
            # Ensure the SQLAlchemy pool starts cleanly on this event loop.
            await engine.dispose()

            ids = await create_test_physical_hierarchy()

            async with await api_client() as client:
                response = await client.patch(
                    f"/api/devices/{ids['device_id']}/placement",
                    json={
                        "network_id": str(ids["network_b_id"]),
                        "city_id": str(ids["city_b_id"]),
                        "location_id": str(ids["location_b_id"]),
                        "sector_id": str(ids["sector_b_id"]),
                    },
                )

            assert response.status_code == 200

            body = response.json()

            assert body["device_id"] == str(
                ids["device_id"]
            )

            assert body["network_id"] == str(
                ids["network_b_id"]
            )

            assert body["city_id"] == str(
                ids["city_b_id"]
            )

            assert body["location_id"] == str(
                ids["location_b_id"]
            )

            assert body["sector_id"] == str(
                ids["sector_b_id"]
            )

            # ---------------------------------------------------------
            # Verify actual PostgreSQL state.
            # ---------------------------------------------------------

            placement = await read_placement(
                ids["device_id"]
            )

            assert placement["network_id"] == ids["network_b_id"]
            assert placement["city_id"] == ids["city_b_id"]
            assert placement["location_id"] == ids["location_b_id"]
            assert placement["sector_id"] == ids["sector_b_id"]

        finally:
            if ids is not None:
                await cleanup_test_data(ids)

            await engine.dispose()

    asyncio.run(run_test())
