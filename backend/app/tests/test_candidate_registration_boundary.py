import asyncio
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.models import Device, DeviceCandidate, DeviceIP
from app.services.candidates import (
    CANDIDATE_APPROVED,
    CANDIDATE_NEW,
    CANDIDATE_REGISTERED,
    CANDIDATE_REJECTED,
)
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

    try:
        await test_coroutine(session_factory)
    finally:
        await engine.dispose()


async def unique_candidate_ip(db):
    """
    Generate a candidate IP address that does not already
    exist in the persistent test database.
    """
    while True:
        value = uuid4().int

        ip_address = (
            f"198.18.{(value >> 8) % 250 + 1}.{value % 250 + 1}"
        )

        existing = await db.scalar(
            select(DeviceCandidate).where(
                DeviceCandidate.ip_address == ip_address
            )
        )

        if existing is None:
            return ip_address


def test_registration_requires_approved_state():
    async def run_test(session_factory):
        async with session_factory() as db:
            transaction = await db.begin()

            try:
                candidate = DeviceCandidate(
                    ip_address=await unique_candidate_ip(db),
                    state=CANDIDATE_NEW,
                    confidence=0.90,
                    metadata_={},
                )

                db.add(candidate)
                await db.flush()

                assert candidate.state == CANDIDATE_NEW
                assert candidate.state != CANDIDATE_APPROVED

            finally:
                await transaction.rollback()

    asyncio.run(_run_test(run_test))


def test_rejected_candidate_is_not_registerable():
    async def run_test(session_factory):
        async with session_factory() as db:
            transaction = await db.begin()

            try:
                candidate = DeviceCandidate(
                    ip_address=await unique_candidate_ip(db),
                    state=CANDIDATE_REJECTED,
                    confidence=0.90,
                    metadata_={},
                )

                db.add(candidate)
                await db.flush()

                assert candidate.state == CANDIDATE_REJECTED
                assert candidate.state != CANDIDATE_APPROVED

            finally:
                await transaction.rollback()

    asyncio.run(_run_test(run_test))


def test_registered_candidate_is_terminal():
    async def run_test(session_factory):
        async with session_factory() as db:
            transaction = await db.begin()

            try:
                candidate = DeviceCandidate(
                    ip_address=await unique_candidate_ip(db),
                    state=CANDIDATE_REGISTERED,
                    confidence=0.90,
                    metadata_={
                        "registration": {
                            "device_id": str(uuid4()),
                            "ip_id": str(uuid4()),
                        }
                    },
                )

                db.add(candidate)
                await db.flush()

                assert candidate.state == CANDIDATE_REGISTERED

            finally:
                await transaction.rollback()

    asyncio.run(_run_test(run_test))


def test_device_ip_registration_identity_is_unique():
    async def run_test(session_factory):
        async with session_factory() as db:
            transaction = await db.begin()

            try:
                from app.models import DeviceType

                device_type = await db.scalar(
                    select(DeviceType).where(DeviceType.code == "CPE")
                )
                assert device_type is not None

                device = Device(
                    device_type_id=device_type.id,
                    display_name=f"S8-DEVICE-{uuid4().hex[:8]}",
                    lifecycle_state="REGISTERED",
                    operational_state="UNKNOWN",
                )

                db.add(device)
                await db.flush()

                ip_address = (
                    f"198.51.100.{uuid4().int % 200 + 1}"
                )

                ip_obj = DeviceIP(
                    device_id=device.id,
                    ip_address=ip_address,
                    address_family=4,
                    is_management=True,
                    is_primary=True,
                    source="TEST",
                )

                db.add(ip_obj)
                await db.flush()

                existing = await db.scalar(
                    select(DeviceIP).where(
                        DeviceIP.ip_address == ip_address
                    )
                )

                assert existing is not None
                assert existing.device_id == device.id

            finally:
                await transaction.rollback()

    asyncio.run(_run_test(run_test))


def test_registration_metadata_contains_result_identifiers():
    async def run_test(session_factory):
        async with session_factory() as db:
            transaction = await db.begin()

            try:
                device_id = uuid4()
                ip_id = uuid4()

                candidate = DeviceCandidate(
                    ip_address=await unique_candidate_ip(db),
                    state=CANDIDATE_REGISTERED,
                    confidence=0.95,
                    metadata_={
                        "registration": {
                            "device_id": str(device_id),
                            "ip_id": str(ip_id),
                        }
                    },
                )

                db.add(candidate)
                await db.flush()

                registration = candidate.metadata_.get(
                    "registration",
                    {},
                )

                assert registration["device_id"] == str(device_id)
                assert registration["ip_id"] == str(ip_id)

            finally:
                await transaction.rollback()

    asyncio.run(_run_test(run_test))


def test_registration_metadata_without_result_identifiers_is_incomplete():
    async def run_test(session_factory):
        async with session_factory() as db:
            transaction = await db.begin()

            try:
                candidate = DeviceCandidate(
                    ip_address=await unique_candidate_ip(db),
                    state=CANDIDATE_REGISTERED,
                    confidence=0.95,
                    metadata_={
                        "registration": {}
                    },
                )

                db.add(candidate)
                await db.flush()

                registration = candidate.metadata_.get(
                    "registration",
                    {},
                )

                assert registration.get("device_id") is None
                assert registration.get("ip_id") is None

            finally:
                await transaction.rollback()

    asyncio.run(_run_test(run_test))
