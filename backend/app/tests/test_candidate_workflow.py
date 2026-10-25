from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.db.session import AsyncSessionLocal
from app.models import Device, DeviceCandidate, DeviceIP, DiscoveryJob, DiscoveryResult
from app.services.candidates import (
    CANDIDATE_APPROVED,
    CANDIDATE_NEW,
    CANDIDATE_REGISTERED,
    CANDIDATE_REJECTED,
    can_transition,
)
from app.settings import settings


def test_candidate_state_machine():
    assert can_transition(CANDIDATE_NEW, CANDIDATE_APPROVED)
    assert can_transition(CANDIDATE_NEW, CANDIDATE_REJECTED)
    assert can_transition(CANDIDATE_REJECTED, CANDIDATE_NEW)
    assert can_transition(CANDIDATE_APPROVED, CANDIDATE_REJECTED)
    assert not can_transition(CANDIDATE_REGISTERED, CANDIDATE_NEW)
    assert not can_transition(CANDIDATE_REGISTERED, CANDIDATE_APPROVED)
    assert not can_transition(CANDIDATE_REGISTERED, CANDIDATE_REJECTED)


def test_terminal_state_is_not_reopenable():
    assert not can_transition(
        CANDIDATE_REGISTERED,
        CANDIDATE_REGISTERED,
    )


def test_candidate_review_supports_topology_assignment_but_not_customer_assignment():
    from pydantic import ValidationError
    from app.schemas.candidates import CandidateApprove, CandidateUpdate

    payload = CandidateUpdate(
        suggested_device_type_id=uuid4(),
        display_name_suggestion="CPE-001",
        network_id=uuid4(),
        city_id=uuid4(),
        location_id=uuid4(),
        sector_id=uuid4(),
        relationship_target_device_id=uuid4(),
        relationship_type="CONNECTED_TO",
        relationship_direction="DIRECTED",
    )
    assert payload.relationship_type == "CONNECTED_TO"
    from app.schemas.candidates import CandidateRead
    assert "customer_id" not in CandidateRead.model_fields
    assert "customer_id" not in CandidateUpdate.model_fields

    approved = CandidateApprove(
        suggested_device_type_id=uuid4(),
        display_name="CPE-001",
        network_id=payload.network_id,
        city_id=payload.city_id,
        location_id=payload.location_id,
        sector_id=payload.sector_id,
    )
    assert approved.display_name == "CPE-001"
    assert "customer_id" not in CandidateApprove.model_fields

    try:
        CandidateUpdate(customer_id=uuid4())
    except ValidationError:
        pass
    else:
        raise AssertionError("Candidate Review must reject direct customer assignment")


async def _run_db_test(test_coroutine):
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


def _run(coro):
    import asyncio

    asyncio.run(coro)


async def _create_discovery_result(
    db,
    *,
    ip_address,
    method,
    vendor=None,
    model=None,
    hostname=None,
    serial_number=None,
):
    job = DiscoveryJob(
        id=uuid4(),
        scope_type="TEST",
        scope_value=ip_address,
        status="COMPLETED",
        metadata_={},
    )

    db.add(job)
    await db.flush()

    result = DiscoveryResult(
        id=uuid4(),
        discovery_job_id=job.id,
        ip_address=ip_address,
        status="DISCOVERED",
        discovery_method=method,
        vendor=vendor,
        model=model,
        hostname=hostname,
        serial_number=serial_number,
        raw_data={},
    )

    db.add(result)
    await db.flush()

    return result


def test_candidate_enrichment_updates_only_discovery_fields():
    from app.services.candidates import generate_candidate

    async def scenario(session_factory):
        async with session_factory() as db:
            transaction = await db.begin()

            try:
                result = await _create_discovery_result(
                    db,
                    ip_address=f"198.18.100.{uuid4().int % 200 + 1}",
                    method="ICMP",
                    vendor="Vendor-A",
                    model="Model-A",
                    hostname="device-a",
                    serial_number="SERIAL-A",
                )

                candidate = await generate_candidate(db, result)

                assert candidate is not None
                assert candidate.state == CANDIDATE_NEW
                assert candidate.vendor == "Vendor-A"
                assert candidate.model == "Model-A"
                assert candidate.hostname == "device-a"
                assert candidate.serial_number == "SERIAL-A"

                original_confidence = candidate.confidence

                result2 = await _create_discovery_result(
                    db,
                    ip_address=result.ip_address,
                    method="SNMP",
                    vendor="Vendor-B",
                    model="Model-B",
                    hostname="device-b",
                    serial_number="SERIAL-B",
                )

                enriched = await generate_candidate(db, result2)

                assert enriched.id == candidate.id
                assert enriched.state == CANDIDATE_NEW
                assert enriched.vendor == "Vendor-B"
                assert enriched.model == "Model-B"
                assert enriched.hostname == "device-b"
                assert enriched.serial_number == "SERIAL-B"
                assert enriched.confidence >= original_confidence

                await transaction.rollback()

            except Exception:
                await transaction.rollback()
                raise

    _run(_run_db_test(scenario))


def test_registered_candidate_is_not_enriched_by_discovery():
    from app.services.candidates import generate_candidate

    async def scenario(session_factory):
        async with session_factory() as db:
            transaction = await db.begin()

            try:
                ip_address = f"198.18.101.{uuid4().int % 200 + 1}"

                candidate = DeviceCandidate(
                    id=uuid4(),
                    ip_address=ip_address,
                    state=CANDIDATE_REGISTERED,
                    confidence=0.95,
                    vendor="Original-Vendor",
                    model="Original-Model",
                    hostname="original-host",
                    serial_number="ORIGINAL-SERIAL",
                    metadata_={
                        "registration": {
                            "device_id": "registered-device",
                            "ip_id": "registered-ip",
                        }
                    },
                )

                db.add(candidate)
                await db.flush()

                result = await _create_discovery_result(
                    db,
                    ip_address=ip_address,
                    method="SNMP",
                    vendor="New-Vendor",
                    model="New-Model",
                    hostname="new-host",
                    serial_number="NEW-SERIAL",
                )

                returned = await generate_candidate(db, result)

                assert returned.id == candidate.id
                assert returned.state == CANDIDATE_REGISTERED
                assert returned.vendor == "Original-Vendor"
                assert returned.model == "Original-Model"
                assert returned.hostname == "original-host"
                assert returned.serial_number == "ORIGINAL-SERIAL"
                assert returned.metadata_["registration"]["device_id"] == "registered-device"
                assert returned.metadata_["registration"]["ip_id"] == "registered-ip"

                await transaction.rollback()

            except Exception:
                await transaction.rollback()
                raise

    _run(_run_db_test(scenario))


def test_discovery_does_not_create_duplicate_candidate_for_same_ip():
    from app.services.candidates import generate_candidate

    async def scenario(session_factory):
        async with session_factory() as db:
            transaction = await db.begin()

            try:
                ip_address = f"198.18.102.{uuid4().int % 200 + 1}"

                result1 = await _create_discovery_result(
                    db,
                    ip_address=ip_address,
                    method="ICMP",
                    vendor="Vendor-A",
                )

                first = await generate_candidate(db, result1)

                result2 = await _create_discovery_result(
                    db,
                    ip_address=ip_address,
                    method="HTTP",
                    vendor="Vendor-B",
                )

                second = await generate_candidate(db, result2)

                assert first.id == second.id

                candidates = (
                    await db.execute(
                        select(DeviceCandidate).where(
                            DeviceCandidate.ip_address == ip_address
                        )
                    )
                ).scalars().all()

                assert len(candidates) == 1

                await transaction.rollback()

            except Exception:
                await transaction.rollback()
                raise

    _run(_run_db_test(scenario))
