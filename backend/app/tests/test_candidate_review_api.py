import asyncio
from uuid import uuid4

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.api.deps import get_db
from app.main import app
from app.models import (
    AuditLog,
    City,
    Device,
    DeviceCandidate,
    DeviceType,
    Location,
    Network,
    Sector,
)
from app.settings import settings
from app.services.audit import enable_audit_maintenance
from app.services.candidates import (
    CANDIDATE_APPROVED,
    CANDIDATE_NEW,
    CANDIDATE_REGISTERED,
    CANDIDATE_REJECTED,
)


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


async def _unique_ip(db):
    while True:
        value = uuid4().int
        ip = f"198.19.{(value >> 8) % 250 + 1}.{value % 250 + 1}"

        existing = await db.scalar(
            select(DeviceCandidate).where(
                DeviceCandidate.ip_address == ip
            )
        )

        if existing is None:
            return ip


async def _create_candidate(
    db,
    *,
    state=CANDIDATE_NEW,
):
    candidate = DeviceCandidate(
        ip_address=await _unique_ip(db),
        state=state,
        confidence=0.95,
        metadata_={},
    )

    db.add(candidate)
    await db.flush()

    return candidate


async def _create_device_type(db):
    device_type = await db.scalar(
        select(DeviceType).where(DeviceType.code == "SWITCH")
    )
    assert device_type is not None
    return device_type

async def _create_review_hierarchy(db):
    network = Network(
        name=f"Review Network {uuid4()}",
        code=f"REVIEW-NET-{uuid4().hex[:10]}",
    )

    db.add(network)
    await db.flush()

    city = City(
        network_id=network.id,
        name=f"Review City {uuid4()}",
        code=f"REVIEW-CITY-{uuid4().hex[:10]}",
    )

    db.add(city)
    await db.flush()

    location = Location(
        city_id=city.id,
        name=f"Review Location {uuid4()}",
        code=f"REVIEW-LOC-{uuid4().hex[:10]}",
    )

    db.add(location)
    await db.flush()

    sector = Sector(
        location_id=location.id,
        name=f"Review Sector {uuid4()}",
        code=f"REVIEW-SEC-{uuid4().hex[:10]}",
    )

    db.add(sector)
    await db.flush()

    target_device_type = await _create_device_type(db)

    target_device = Device(
        device_type_id=target_device_type.id,
        display_name=f"Review Target Device {uuid4()}",
        hostname=f"review-target-{uuid4().hex[:10]}",
        vendor="Integration-Test",
        model="TARGET",
    )

    db.add(target_device)
    await db.flush()

    return {
        "network_id": network.id,
        "city_id": city.id,
        "location_id": location.id,
        "sector_id": sector.id,
        "target_device_id": target_device.id,
        "target_device_type_id": target_device_type.id,
    }


def test_candidate_update_persists_review_data_and_audit():
    async def run_test(session_factory):
        async with session_factory() as db:
            candidate = await _create_candidate(db)
            candidate_id = candidate.id
            await db.commit()

        device_type = None

        try:
            async with session_factory() as db:
                device_type = await _create_device_type(db)
                await db.commit()

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                response = await client.patch(
                    f"/api/device-candidates/{candidate_id}",
                    json={
                        "suggested_device_type_id": str(device_type.id),
                        "display_name_suggestion": "CPE-REVIEW-001",
                        "review_note": "Reviewed during Phase 6.2.",
                    },
                )

            assert response.status_code == 200

            body = response.json()

            assert body["id"] == str(candidate_id)
            assert body["suggested_device_type_id"] == str(
                device_type.id
            )
            assert body["display_name_suggestion"] == "CPE-REVIEW-001"
            assert body["review_note"] == "Reviewed during Phase 6.2."

            async with session_factory() as db:
                audit = await db.scalar(
                    select(AuditLog)
                    .where(
                        AuditLog.entity_type == "DeviceCandidate",
                        AuditLog.entity_id == candidate_id,
                        AuditLog.action == "CANDIDATE_UPDATED",
                    )
                    .order_by(AuditLog.occurred_at.desc())
                )

                assert audit is not None
                assert audit.result == "SUCCESS"
                assert audit.request_id is not None
                assert audit.source_ip is not None

        finally:
            async with session_factory() as db:
                await db.execute(
                    __import__("sqlalchemy").delete(DeviceCandidate).where(
                        DeviceCandidate.id == candidate_id
                    )
                )
                await db.commit()


    asyncio.run(_run_test(run_test))


def test_candidate_approve_persists_review_assignment_and_audit():
    async def run_test(session_factory):
        async with session_factory() as db:
            candidate = await _create_candidate(db)
            candidate_id = candidate.id

            device_type = await _create_device_type(db)
            location = await db.scalar(select(Location).order_by(Location.id))
            assert location is not None
            city = await db.get(City, location.city_id)
            assert city is not None
            network = await db.get(Network, city.network_id)
            assert network is not None
            placement = {
                "network_id": str(network.id),
                "city_id": str(city.id),
                "location_id": str(location.id),
            }

            await db.commit()

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                response = await client.post(
                    f"/api/device-candidates/{candidate_id}/approve",
                    json={
                        "suggested_device_type_id": str(device_type.id),
                        "display_name": "SWITCH-APPROVED-001",
                        "review_note": "Approved for registration.",
                        **placement,
                    },
                )

            assert response.status_code == 200

            body = response.json()

            assert body["state"] == CANDIDATE_APPROVED
            assert body["suggested_device_type_id"] == str(
                device_type.id
            )
            assert body["display_name_suggestion"] == "SWITCH-APPROVED-001"
            assert body["review_note"] == "Approved for registration."

            async with session_factory() as db:
                audit = await db.scalar(
                    select(AuditLog)
                    .where(
                        AuditLog.entity_type == "DeviceCandidate",
                        AuditLog.entity_id == candidate_id,
                        AuditLog.action == "CANDIDATE_APPROVED",
                    )
                    .order_by(AuditLog.occurred_at.desc())
                )

                assert audit is not None
                assert audit.result == "SUCCESS"
                assert audit.request_id is not None
                assert audit.source_ip is not None

        finally:
            async with session_factory() as db:
                await enable_audit_maintenance(db)
                await db.execute(
                    __import__("sqlalchemy").delete(AuditLog).where(
                        AuditLog.entity_type == "DeviceCandidate",
                        AuditLog.entity_id == candidate_id,
                    )
                )
                await db.execute(
                    __import__("sqlalchemy").delete(DeviceCandidate).where(
                        DeviceCandidate.id == candidate_id
                    )
                )
                await db.commit()

    asyncio.run(_run_test(run_test))


def test_candidate_reject_and_reopen_follow_workflow():
    async def run_test(session_factory):
        async with session_factory() as db:
            candidate = await _create_candidate(db)
            candidate_id = candidate.id
            await db.commit()

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                rejected = await client.post(
                    f"/api/device-candidates/{candidate_id}/reject",
                    json={
                        "review_note": "Rejected during review.",
                    },
                )

                assert rejected.status_code == 200
                assert rejected.json()["state"] == CANDIDATE_REJECTED

                reopened = await client.post(
                    f"/api/device-candidates/{candidate_id}/reopen"
                )

                assert reopened.status_code == 200
                assert reopened.json()["state"] == CANDIDATE_NEW

            async with session_factory() as db:
                audits = (
                    await db.execute(
                        select(AuditLog)
                        .where(
                            AuditLog.entity_type == "DeviceCandidate",
                            AuditLog.entity_id == candidate_id,
                        )
                        .order_by(AuditLog.occurred_at)
                    )
                ).scalars().all()

                actions = [row.action for row in audits]

                assert "CANDIDATE_REJECTED" in actions
                assert "CANDIDATE_REOPENED" in actions
                rejected_audit = next(
                    row for row in audits if row.action == "CANDIDATE_REJECTED"
                )
                assert rejected_audit.result == "SUCCESS"
                assert rejected_audit.request_id is not None
                assert rejected_audit.source_ip is not None

        finally:
            async with session_factory() as db:
                await enable_audit_maintenance(db)
                await db.execute(
                    __import__("sqlalchemy").delete(AuditLog).where(
                        AuditLog.entity_type == "DeviceCandidate",
                        AuditLog.entity_id == candidate_id,
                    )
                )
                await db.execute(
                    __import__("sqlalchemy").delete(DeviceCandidate).where(
                        DeviceCandidate.id == candidate_id
                    )
                )
                await db.commit()

    asyncio.run(_run_test(run_test))


def test_registered_candidate_is_immutable():
    async def run_test(session_factory):
        async with session_factory() as db:
            candidate = await _create_candidate(
                db,
                state=CANDIDATE_REGISTERED,
            )
            candidate_id = candidate.id
            await db.commit()

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                response = await client.patch(
                    f"/api/device-candidates/{candidate_id}",
                    json={
                        "display_name_suggestion": "SHOULD-NOT-CHANGE",
                    },
                )

            assert response.status_code == 409
            assert response.json()["detail"]["code"] == (
                "CANDIDATE_REGISTERED"
            )

        finally:
            async with session_factory() as db:
                await db.execute(
                    __import__("sqlalchemy").delete(DeviceCandidate).where(
                        DeviceCandidate.id == candidate_id
                    )
                )
                await db.commit()

    asyncio.run(_run_test(run_test))


def test_registered_candidate_cannot_be_approved_or_rejected():
    async def run_test(session_factory):
        async with session_factory() as db:
            candidate = await _create_candidate(
                db,
                state=CANDIDATE_REGISTERED,
            )
            candidate_id = candidate.id

            device_type = await _create_device_type(db)

            await db.commit()

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                approve = await client.post(
                    f"/api/device-candidates/{candidate_id}/approve",
                    json={
                        "suggested_device_type_id": str(device_type.id),
                        "display_name": "INVALID-APPROVAL",
                    },
                )

                reject = await client.post(
                    f"/api/device-candidates/{candidate_id}/reject",
                    json={
                        "review_note": "INVALID-REJECTION",
                    },
                )

            assert approve.status_code == 409
            assert approve.json()["detail"]["code"] == (
                "INVALID_CANDIDATE_TRANSITION"
            )

            assert reject.status_code == 409
            assert reject.json()["detail"]["code"] == (
                "INVALID_CANDIDATE_TRANSITION"
            )

        finally:
            async with session_factory() as db:
                await enable_audit_maintenance(db)
                await db.execute(
                    __import__("sqlalchemy").delete(AuditLog).where(
                        AuditLog.entity_type == "DeviceCandidate",
                        AuditLog.entity_id == candidate_id,
                    )
                )
                await db.execute(
                    __import__("sqlalchemy").delete(DeviceCandidate).where(
                        DeviceCandidate.id == candidate_id
                    )
                )
                await db.commit()

    asyncio.run(_run_test(run_test))




def test_candidate_queue_filters_and_search_include_device_type_and_name():
    async def run_test(session_factory):
        marker = uuid4().hex[:10]
        async with session_factory() as db:
            cpe_type = await db.scalar(select(DeviceType).where(DeviceType.code == "CPE"))
            switch_type = await db.scalar(select(DeviceType).where(DeviceType.code == "SWITCH"))
            assert cpe_type is not None and switch_type is not None
            first = DeviceCandidate(
                ip_address=await _unique_ip(db),
                state=CANDIDATE_APPROVED,
                confidence=0.8,
                suggested_device_type_id=cpe_type.id,
                display_name_suggestion=f"Queue CPE {marker}",
                hostname=f"queue-cpe-{marker}",
                metadata_={},
            )
            second = DeviceCandidate(
                ip_address=await _unique_ip(db),
                state=CANDIDATE_APPROVED,
                confidence=0.8,
                suggested_device_type_id=switch_type.id,
                display_name_suggestion=f"Queue Switch {marker}",
                hostname=f"queue-switch-{marker}",
                metadata_={},
            )
            db.add_all([first, second])
            await db.commit()
            ids = [first.id, second.id]

        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                by_type = await client.get(
                    "/api/device-candidates",
                    params={"device_type_id": str(cpe_type.id), "search": marker, "limit": 50},
                )
                assert by_type.status_code == 200, by_type.text
                assert by_type.json()["count"] == 1
                assert by_type.json()["items"][0]["display_name_suggestion"] == f"Queue CPE {marker}"

                by_type_name = await client.get(
                    "/api/device-candidates",
                    params={"search": "CPE", "device_type_id": str(cpe_type.id), "limit": 50},
                )
                assert by_type_name.status_code == 200, by_type_name.text
                assert any(item["id"] == str(first.id) for item in by_type_name.json()["items"])
        finally:
            async with session_factory() as db:
                await db.execute(__import__("sqlalchemy").delete(DeviceCandidate).where(DeviceCandidate.id.in_(ids)))
                await db.commit()

    asyncio.run(_run_test(run_test))
