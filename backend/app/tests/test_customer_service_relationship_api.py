import asyncio
from uuid import uuid4

import httpx
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.api.deps import get_db
from app.main import app
from app.models import Customer
from app.settings import settings


async def _run_test(test_coroutine):
    engine = create_async_engine(
        settings.database_url,
        poolclass=NullPool,
    )

    session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async def override_get_db():
        async with session_factory() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db

    try:
        await test_coroutine(session_factory)
    finally:
        app.dependency_overrides.pop(get_db, None)
        await engine.dispose()


async def api_request(method: str, url: str, **kwargs):
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as client:
        return await client.request(
            method,
            url,
            **kwargs,
        )


async def create_test_customer(session_factory) -> Customer:
    async with session_factory() as db:
        customer = Customer(
            customer_code=f"S7-CUSTOMER-{uuid4().hex[:10]}",
            name="Customer-service API test customer",
            metadata_={},
        )
        db.add(customer)
        await db.commit()
        await db.refresh(customer)
        return customer


async def cleanup_test_customer(session_factory, customer_id) -> None:
    async with session_factory() as db:
        customer = await db.get(Customer, customer_id)
        if customer is not None:
            await db.delete(customer)
            await db.commit()


def test_customer_service_api_rejects_customer_id_mismatch():
    async def run_test(_session_factory):
        response = await api_request(
            "POST",
            f"/api/customers/{uuid4()}/services",
            json={
                "customer_id": str(uuid4()),
                "service_code": f"S7-API-{uuid4().hex[:10]}",
                "status": "ACTIVE",
                "access_point_device_id": str(uuid4()),
                "router_device_id": None,
                "metadata": {},
            },
        )

        assert response.status_code == 400

        body = response.json()

        assert body["detail"]["code"] == "CUSTOMER_ID_MISMATCH"

    asyncio.run(_run_test(run_test))


def test_customer_service_api_rejects_independent_cpe_or_sector_inputs():
    async def run_test(_session_factory):
        customer_id = uuid4()
        response = await api_request(
            "POST",
            f"/api/customers/{customer_id}/services",
            json={
                "customer_id": str(customer_id),
                "sector_id": str(uuid4()),
                "cpe_device_id": str(uuid4()),
                "service_code": f"S7-API-{uuid4().hex[:10]}",
                "status": "ACTIVE",
                "access_point_device_id": str(uuid4()),
                "router_device_id": None,
                "metadata": {},
            },
        )
        assert response.status_code == 422

    asyncio.run(_run_test(run_test))

def test_customer_service_api_rejects_nonexistent_customer():
    async def run_test(_session_factory):
        customer_id = uuid4()

        response = await api_request(
            "POST",
            f"/api/customers/{customer_id}/services",
            json={
                "customer_id": str(customer_id),
                "service_code": f"S7-API-{uuid4().hex[:10]}",
                "status": "ACTIVE",
                "access_point_device_id": str(uuid4()),
                "router_device_id": None,
                "metadata": {},
            },
        )

        assert response.status_code == 404

        body = response.json()

        assert body["detail"]["code"] == "CUSTOMER_NOT_FOUND"

    asyncio.run(_run_test(run_test))


def test_customer_service_create_schema_is_access_point_only():
    from app.schemas.customer import ServiceCreate

    assert "access_point_device_id" in ServiceCreate.model_fields
    assert "cpe_device_id" not in ServiceCreate.model_fields
    assert "sector_id" not in ServiceCreate.model_fields


def test_customer_service_topology_endpoint_rejects_unknown_service():
    async def run_test(_session_factory):
        service_id = uuid4()

        response = await api_request(
            "GET",
            f"/api/customers/services/{service_id}/topology",
        )

        assert response.status_code == 404

        body = response.json()

        assert body["detail"]["code"] == "RESOURCE_NOT_FOUND"

    asyncio.run(_run_test(run_test))
