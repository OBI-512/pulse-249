import asyncio
from unittest.mock import patch
from uuid import uuid4

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.main import app
from app.api.deps import get_db
from app.models import DeviceCandidate, DeviceIP
from app.discovery.models import DiscoveryResult
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


async def _unique_candidate_ip(session_factory):
    async with session_factory() as db:
        while True:
            target_ip = (
                f"198.18.{uuid4().int % 250 + 1}.{uuid4().int % 250 + 1}"
            )

            existing_candidate = await db.scalar(
                select(DeviceCandidate).where(
                    DeviceCandidate.ip_address == target_ip
                )
            )

            if existing_candidate is not None:
                continue

            existing_ip = await db.scalar(
                select(DeviceIP).where(
                    DeviceIP.ip_address == target_ip
                )
            )

            if existing_ip is None:
                return target_ip


def _successful_icmp_result(ip_address: str) -> DiscoveryResult:
    return DiscoveryResult(
        success=True,
        method="ICMP",
        ip_address=ip_address,
        vendor=None,
        model=None,
        hostname=None,
        serial_number=None,
        management_protocol="ICMP",
        response_time_ms=1.0,
        message="Mock ICMP response received.",
        raw_data={
            "probe_available": True,
        },
    )


class MockICMPAdapter:
    async def discover(self, context):
        return _successful_icmp_result(context.ip_address)


def test_single_discovery_generates_candidate():

    async def run_test(session_factory):
        target_ip = await _unique_candidate_ip(session_factory)

        with patch(
            "app.api.routers.discovery.registry.get",
            return_value=MockICMPAdapter(),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                response = await client.post(
                    "/api/discovery/run",
                    json={
                        "ip_address": target_ip,
                        "methods": ["ICMP"],
                        "timeout_seconds": 3,
                    },
                )

        assert response.status_code == 200

        body = response.json()

        assert body["status"] == "COMPLETED"
        assert body["results"]
        assert body["results"][0]["ip_address"] == target_ip
        assert body["results"][0]["status"] == "DISCOVERED"

        async with session_factory() as db:
            candidate = await db.scalar(
                select(DeviceCandidate).where(
                    DeviceCandidate.ip_address == target_ip
                )
            )

            assert candidate is not None
            assert candidate.ip_address == target_ip
            assert candidate.state == "NEW"

    asyncio.run(_run_test(run_test))


def test_single_discovery_does_not_register_device():

    async def run_test(session_factory):
        target_ip = await _unique_candidate_ip(session_factory)

        with patch(
            "app.api.routers.discovery.registry.get",
            return_value=MockICMPAdapter(),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                response = await client.post(
                    "/api/discovery/run",
                    json={
                        "ip_address": target_ip,
                        "methods": ["ICMP"],
                        "timeout_seconds": 3,
                    },
                )

        assert response.status_code == 200

        async with session_factory() as db:
            candidate = await db.scalar(
                select(DeviceCandidate).where(
                    DeviceCandidate.ip_address == target_ip
                )
            )

            assert candidate is not None
            assert candidate.state == "NEW"

            device_ip = await db.scalar(
                select(DeviceIP).where(
                    DeviceIP.ip_address == target_ip
                )
            )

            assert device_ip is None

    asyncio.run(_run_test(run_test))
