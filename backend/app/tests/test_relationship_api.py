import asyncio
from uuid import UUID, uuid4

import httpx
from sqlalchemy import delete, select

from app.db.session import AsyncSessionLocal, engine
from app.main import app
from app.models import Device, DeviceRelationship, DeviceType


async def create_test_devices():
    """
    Create three isolated devices for API relationship testing.

    The records are committed because the FastAPI endpoint uses its own
    database session.
    """

    async with AsyncSessionLocal() as db:
        transaction = await db.begin()

        try:
            device_type = await db.scalar(
                select(DeviceType).where(DeviceType.code == "SWITCH")
            )
            assert device_type is not None

            device_a = Device(
                device_type_id=device_type.id,
                display_name=f"API Relationship Device A {uuid4()}",
                hostname=f"api-rel-a-{uuid4().hex[:10]}",
                vendor="Integration-Test",
                model="TEST",
            )

            device_b = Device(
                device_type_id=device_type.id,
                display_name=f"API Relationship Device B {uuid4()}",
                hostname=f"api-rel-b-{uuid4().hex[:10]}",
                vendor="Integration-Test",
                model="TEST",
            )

            device_c = Device(
                device_type_id=device_type.id,
                display_name=f"API Relationship Device C {uuid4()}",
                hostname=f"api-rel-c-{uuid4().hex[:10]}",
                vendor="Integration-Test",
                model="TEST",
            )

            db.add_all(
                [
                    device_a,
                    device_b,
                    device_c,
                ]
            )

            await db.flush()

            ids = {
                "device_type_id": device_type.id,
                "device_a_id": device_a.id,
                "device_b_id": device_b.id,
                "device_c_id": device_c.id,
            }

            await db.commit()

            return ids

        except Exception:
            await transaction.rollback()
            raise


async def count_relationships():
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(DeviceRelationship)
        )

        return len(result.scalars().all())


async def get_relationships_for_device(device_id: UUID):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(DeviceRelationship).where(
                (DeviceRelationship.source_device_id == device_id)
                | (DeviceRelationship.target_device_id == device_id)
            )
        )

        return result.scalars().all()


async def cleanup_test_data(ids):
    """
    Remove all records created by the API tests.
    """

    async with AsyncSessionLocal() as db:
        transaction = await db.begin()

        try:
            device_ids = [
                ids["device_a_id"],
                ids["device_b_id"],
                ids["device_c_id"],
            ]

            await db.execute(
                delete(DeviceRelationship).where(
                    (DeviceRelationship.source_device_id.in_(device_ids))
                    | (DeviceRelationship.target_device_id.in_(device_ids))
                )
            )

            await db.execute(
                delete(Device).where(
                    Device.id.in_(device_ids)
                )
            )

            await db.commit()

        except Exception:
            await transaction.rollback()
            raise


async def api_client():
    """
    Create an HTTPX async client using the FastAPI ASGI application.

    This keeps API execution on the same asyncio event loop as the
    database operations and avoids the asyncpg/TestClient event-loop
    problem encountered previously.
    """

    transport = httpx.ASGITransport(app=app)

    return httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
    )


def test_valid_relationship_is_created_through_api():
    async def run_test():
        ids = None

        try:
            await engine.dispose()

            ids = await create_test_devices()

            async with await api_client() as client:
                response = await client.post(
                    "/api/device-relationships",
                    json={
                        "source_device_id": str(ids["device_a_id"]),
                        "target_device_id": str(ids["device_b_id"]),
                        "relationship_type": "PHYSICAL_LINK",
                        "direction": "DIRECTED",
                        "metadata": {},
                    },
                )

            assert response.status_code == 201

            body = response.json()

            assert body["source_device_id"] == str(
                ids["device_a_id"]
            )

            assert body["target_device_id"] == str(
                ids["device_b_id"]
            )

            assert body["relationship_type"] == "PHYSICAL_LINK"
            assert body["direction"] == "DIRECTED"
            assert body["metadata"] == {}

            relationships = await get_relationships_for_device(
                ids["device_a_id"]
            )

            assert len(relationships) == 1

            relationship = relationships[0]

            assert relationship.source_device_id == ids["device_a_id"]
            assert relationship.target_device_id == ids["device_b_id"]

        finally:
            if ids is not None:
                await cleanup_test_data(ids)

            await engine.dispose()

    asyncio.run(run_test())


def test_self_relationship_is_rejected_by_api():
    async def run_test():
        ids = None

        try:
            await engine.dispose()

            ids = await create_test_devices()

            async with await api_client() as client:
                response = await client.post(
                    "/api/device-relationships",
                    json={
                        "source_device_id": str(ids["device_a_id"]),
                        "target_device_id": str(ids["device_a_id"]),
                        "relationship_type": "PHYSICAL_LINK",
                        "direction": "DIRECTED",
                        "metadata": {},
                    },
                )

            assert response.status_code == 409

            body = response.json()

            assert body["detail"]["code"] == "SELF_RELATIONSHIP"

            relationships = await get_relationships_for_device(
                ids["device_a_id"]
            )

            assert len(relationships) == 0

        finally:
            if ids is not None:
                await cleanup_test_data(ids)

            await engine.dispose()

    asyncio.run(run_test())


def test_exact_duplicate_relationship_is_rejected_by_api():
    async def run_test():
        ids = None

        try:
            await engine.dispose()

            ids = await create_test_devices()

            payload = {
                "source_device_id": str(ids["device_a_id"]),
                "target_device_id": str(ids["device_b_id"]),
                "relationship_type": "PHYSICAL_LINK",
                "direction": "DIRECTED",
                "metadata": {},
            }

            async with await api_client() as client:
                first_response = await client.post(
                    "/api/device-relationships",
                    json=payload,
                )

                assert first_response.status_code == 201

                second_response = await client.post(
                    "/api/device-relationships",
                    json=payload,
                )

            assert second_response.status_code == 409

            body = second_response.json()

            assert body["detail"]["code"] == "RELATIONSHIP_CONFLICT"

            relationships = await get_relationships_for_device(
                ids["device_a_id"]
            )

            assert len(relationships) == 1

        finally:
            if ids is not None:
                await cleanup_test_data(ids)

            await engine.dispose()

    asyncio.run(run_test())


def test_reverse_relationship_is_rejected_by_api():
    async def run_test():
        ids = None

        try:
            await engine.dispose()

            ids = await create_test_devices()

            first_payload = {
                "source_device_id": str(ids["device_a_id"]),
                "target_device_id": str(ids["device_b_id"]),
                "relationship_type": "PHYSICAL_LINK",
                "direction": "DIRECTED",
                "metadata": {},
            }

            reverse_payload = {
                "source_device_id": str(ids["device_b_id"]),
                "target_device_id": str(ids["device_a_id"]),
                "relationship_type": "PHYSICAL_LINK",
                "direction": "DIRECTED",
                "metadata": {},
            }

            async with await api_client() as client:
                first_response = await client.post(
                    "/api/device-relationships",
                    json=first_payload,
                )

                assert first_response.status_code == 201

                reverse_response = await client.post(
                    "/api/device-relationships",
                    json=reverse_payload,
                )

            assert reverse_response.status_code == 409

            body = reverse_response.json()

            assert body["detail"]["code"] == "RELATIONSHIP_CONFLICT"

            relationships_a = await get_relationships_for_device(
                ids["device_a_id"]
            )

            relationships_b = await get_relationships_for_device(
                ids["device_b_id"]
            )

            assert len(relationships_a) == 1
            assert len(relationships_b) == 1

        finally:
            if ids is not None:
                await cleanup_test_data(ids)

            await engine.dispose()

    asyncio.run(run_test())


def test_reverse_undirected_relationship_is_rejected_by_api():
    async def run_test():
        ids = None

        try:
            await engine.dispose()

            ids = await create_test_devices()

            first_payload = {
                "source_device_id": str(ids["device_a_id"]),
                "target_device_id": str(ids["device_b_id"]),
                "relationship_type": "PHYSICAL_LINK",
                "direction": "UNDIRECTED",
                "metadata": {},
            }

            reverse_payload = {
                "source_device_id": str(ids["device_b_id"]),
                "target_device_id": str(ids["device_a_id"]),
                "relationship_type": "PHYSICAL_LINK",
                "direction": "UNDIRECTED",
                "metadata": {},
            }

            async with await api_client() as client:
                first_response = await client.post(
                    "/api/device-relationships",
                    json=first_payload,
                )

                assert first_response.status_code == 201

                reverse_response = await client.post(
                    "/api/device-relationships",
                    json=reverse_payload,
                )

            assert reverse_response.status_code == 409

            body = reverse_response.json()

            assert body["detail"]["code"] == "RELATIONSHIP_CONFLICT"

            relationships = await get_relationships_for_device(
                ids["device_a_id"]
            )

            assert len(relationships) == 1

        finally:
            if ids is not None:
                await cleanup_test_data(ids)

            await engine.dispose()

    asyncio.run(run_test())


def test_invalid_direction_is_rejected_by_api():
    async def run_test():
        ids = None

        try:
            await engine.dispose()

            ids = await create_test_devices()

            async with await api_client() as client:
                response = await client.post(
                    "/api/device-relationships",
                    json={
                        "source_device_id": str(ids["device_a_id"]),
                        "target_device_id": str(ids["device_b_id"]),
                        "relationship_type": "PHYSICAL_LINK",
                        "direction": "INVALID",
                        "metadata": {},
                    },
                )

            assert response.status_code == 422

            body = response.json()

            assert "detail" in body

            relationships = await get_relationships_for_device(
                ids["device_a_id"]
            )

            assert len(relationships) == 0

        finally:
            if ids is not None:
                await cleanup_test_data(ids)

            await engine.dispose()

    asyncio.run(run_test())


def test_relationship_creation_does_not_create_unrelated_edges():
    async def run_test():
        ids = None

        try:
            await engine.dispose()

            ids = await create_test_devices()

            async with await api_client() as client:
                response = await client.post(
                    "/api/device-relationships",
                    json={
                        "source_device_id": str(ids["device_a_id"]),
                        "target_device_id": str(ids["device_b_id"]),
                        "relationship_type": "PHYSICAL_LINK",
                        "direction": "DIRECTED",
                        "metadata": {},
                    },
                )

            assert response.status_code == 201

            a_relationships = await get_relationships_for_device(
                ids["device_a_id"]
            )

            b_relationships = await get_relationships_for_device(
                ids["device_b_id"]
            )

            c_relationships = await get_relationships_for_device(
                ids["device_c_id"]
            )

            assert len(a_relationships) == 1
            assert len(b_relationships) == 1
            assert len(c_relationships) == 0

            assert (
                a_relationships[0].source_device_id
                == ids["device_a_id"]
            )

            assert (
                a_relationships[0].target_device_id
                == ids["device_b_id"]
            )

        finally:
            if ids is not None:
                await cleanup_test_data(ids)

            await engine.dispose()

    asyncio.run(run_test())
