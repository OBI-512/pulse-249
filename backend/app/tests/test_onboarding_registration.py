from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import delete, select

from app.api.routers.candidates import register_candidate as register_reviewed_candidate
from app.api.routers.devices import create_device
from app.api.routers.onboarding import create_candidate, register_candidate
from app.db.session import AsyncSessionLocal, engine
from app.models import (
    AuditLog,
    City,
    Device,
    DeviceCandidate,
    DeviceHierarchyLink,
    DeviceIP,
    DevicePlacement,
    DeviceType,
    Location,
    Network,
    Sector,
)
from app.schemas.device import DeviceCreate
from app.schemas.onboarding import OnboardingCandidateCreate, OnboardingRegisterRequest
from app.services.device_registration import register_domain_device
from app.services.audit import enable_audit_maintenance


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(engine.dispose())
        yield loop
    finally:
        loop.run_until_complete(engine.dispose())
        loop.close()


def _ip(second_octet: int) -> str:
    token = uuid4().int
    return f"198.{second_octet}.{(token >> 8) % 250 + 1}.{token % 250 + 1}"


async def _type(db, code: str) -> DeviceType:
    device_type = await db.scalar(select(DeviceType).where(DeviceType.code == code))
    assert device_type is not None
    return device_type


async def _context(db):
    network = Network(
        name=f"Onboarding Network {uuid4()}",
        code=f"ONB-N-{uuid4().hex[:10]}",
    )
    db.add(network)
    await db.flush()
    city = City(
        network_id=network.id,
        name=f"Onboarding City {uuid4()}",
        code=f"ONB-C-{uuid4().hex[:10]}",
    )
    db.add(city)
    await db.flush()
    location = Location(
        city_id=city.id,
        name=f"Onboarding Location {uuid4()}",
        code=f"ONB-L-{uuid4().hex[:10]}",
        metadata_={},
    )
    db.add(location)
    await db.flush()
    sector = Sector(
        location_id=location.id,
        name=f"Onboarding Sector {uuid4()}",
        code=f"ONB-S-{uuid4().hex[:10]}",
        role="CUSTOMER_ACCESS",
        metadata_={},
    )
    db.add(sector)
    await db.flush()
    return network, city, location, sector


async def _register_base_device(
    db,
    *,
    code: str,
    name: str,
    location_id=None,
    sector_id=None,
    parent_device_id=None,
):
    device_type = await _type(db, code)
    result = await register_domain_device(
        db,
        device_type_id=device_type.id,
        display_name=name,
        management_ip=_ip(20),
        location_id=location_id,
        sector_id=sector_id,
        parent_device_id=parent_device_id,
        ip_source="TEST",
    )
    await db.flush()
    return result.device


async def _run_in_rollback(db, scenario):
    transaction = await db.begin()
    original_commit = db.commit

    async def flush_without_commit():
        await db.flush()

    db.commit = flush_without_commit  # type: ignore[method-assign]
    try:
        await scenario()
    finally:
        db.commit = original_commit  # type: ignore[method-assign]
        if transaction.is_active:
            await transaction.rollback()


def test_onboarding_cpe_with_bound_sector_registers_authoritative_link(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            async def assertions():
                _, _, location, sector = await _context(db)
                sector_device = await _register_base_device(
                    db,
                    code="SECTOR",
                    name=f"Onboarding parent {uuid4()}",
                    sector_id=sector.id,
                )
                cpe_type = await _type(db, "CPE")
                candidate = await create_candidate(
                    OnboardingCandidateCreate(
                        ip_address=_ip(21),
                        device_type_id=cpe_type.id,
                        display_name=f"Onboarding CPE {uuid4()}",
                        sector_id=sector.id,
                    ),
                    db,
                )
                assert candidate.state == "APPROVED"
                assert candidate.parent_device_id == sector_device.id

                result = await register_candidate(
                    OnboardingRegisterRequest(candidate_id=candidate.id),
                    db,
                )
                link = await db.scalar(
                    select(DeviceHierarchyLink).where(
                        DeviceHierarchyLink.child_device_id == result.device_id
                    )
                )
                placement = await db.scalar(
                    select(DevicePlacement).where(
                        DevicePlacement.device_id == result.device_id
                    )
                )
                assert link is not None
                assert link.parent_device_id == sector_device.id
                assert link.relationship_type == "SECTOR_CPE"
                assert placement is not None
                assert placement.location_id == location.id
                assert placement.sector_id == sector.id
                audits = list(
                    (
                        await db.scalars(
                            select(AuditLog)
                            .where(
                                AuditLog.entity_type == "DeviceCandidate",
                                AuditLog.entity_id == candidate.id,
                                AuditLog.action.in_(
                                    ["CANDIDATE_APPROVED", "CANDIDATE_REGISTERED"]
                                ),
                            )
                            .order_by(AuditLog.occurred_at, AuditLog.id)
                        )
                    ).all()
                )
                assert [audit.action for audit in audits] == [
                    "CANDIDATE_APPROVED",
                    "CANDIDATE_REGISTERED",
                ]
                registered_audit = audits[-1]
                assert registered_audit.result == "SUCCESS"
                assert registered_audit.after_summary["registration_source"] == "ONBOARDING"
                assert registered_audit.after_summary["device_id"] == str(result.device_id)

            await _run_in_rollback(db, assertions)

    event_loop.run_until_complete(scenario())


def test_onboarding_cpe_without_valid_sector_parent_is_rejected(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            async def assertions():
                cpe_type = await _type(db, "CPE")
                with pytest.raises(HTTPException) as missing:
                    await create_candidate(
                        OnboardingCandidateCreate(
                            ip_address=_ip(22),
                            device_type_id=cpe_type.id,
                            display_name=f"Invalid onboarding CPE {uuid4()}",
                        ),
                        db,
                    )
                assert missing.value.status_code == 422
                assert missing.value.detail["code"] == "PARENT_DEVICE_REQUIRED"

                with pytest.raises(HTTPException) as unknown:
                    await create_candidate(
                        OnboardingCandidateCreate(
                            ip_address=_ip(23),
                            device_type_id=cpe_type.id,
                            display_name=f"Unknown-sector onboarding CPE {uuid4()}",
                            sector_id=uuid4(),
                        ),
                        db,
                    )
                assert unknown.value.status_code == 404
                assert unknown.value.detail["code"] == "SECTOR_NOT_FOUND"

            await _run_in_rollback(db, assertions)

    event_loop.run_until_complete(scenario())


def test_onboarding_access_point_requires_and_uses_valid_cpe(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            async def assertions():
                _, _, _, sector = await _context(db)
                sector_device = await _register_base_device(
                    db,
                    code="SECTOR",
                    name=f"AP sector parent {uuid4()}",
                    sector_id=sector.id,
                )
                cpe = await _register_base_device(
                    db,
                    code="CPE",
                    name=f"AP CPE parent {uuid4()}",
                    parent_device_id=sector_device.id,
                )
                ap_type = await _type(db, "ACCESS_POINT")

                with pytest.raises(HTTPException) as missing:
                    await create_candidate(
                        OnboardingCandidateCreate(
                            ip_address=_ip(24),
                            device_type_id=ap_type.id,
                            display_name=f"Missing-parent AP {uuid4()}",
                        ),
                        db,
                    )
                assert missing.value.status_code == 422
                assert missing.value.detail["code"] == "PARENT_DEVICE_REQUIRED"

                candidate = await create_candidate(
                    OnboardingCandidateCreate(
                        ip_address=_ip(25),
                        device_type_id=ap_type.id,
                        display_name=f"Valid onboarding AP {uuid4()}",
                        parent_device_id=cpe.id,
                    ),
                    db,
                )
                result = await register_candidate(
                    OnboardingRegisterRequest(candidate_id=candidate.id),
                    db,
                )
                link = await db.scalar(
                    select(DeviceHierarchyLink).where(
                        DeviceHierarchyLink.child_device_id == result.device_id
                    )
                )
                assert link is not None
                assert link.parent_device_id == cpe.id
                assert link.relationship_type == "CPE_ACCESS_POINT"

            await _run_in_rollback(db, assertions)

    event_loop.run_until_complete(scenario())


def test_onboarding_sector_device_binds_existing_sector(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            async def assertions():
                _, _, _, sector = await _context(db)
                sector_type = await _type(db, "SECTOR")
                candidate = await create_candidate(
                    OnboardingCandidateCreate(
                        ip_address=_ip(26),
                        device_type_id=sector_type.id,
                        display_name=f"Onboarding sector device {uuid4()}",
                        sector_id=sector.id,
                    ),
                    db,
                )
                result = await register_candidate(
                    OnboardingRegisterRequest(candidate_id=candidate.id),
                    db,
                )
                await db.refresh(sector)
                assert sector.sector_device_id == result.device_id

            await _run_in_rollback(db, assertions)

    event_loop.run_until_complete(scenario())


def test_onboarding_rejects_inactive_unknown_type_and_duplicate_management_ip(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            async def assertions():
                _, _, location, _ = await _context(db)
                switch_type = await _type(db, "SWITCH")
                switch_type.is_active = False
                await db.flush()
                with pytest.raises(HTTPException) as inactive:
                    await create_candidate(
                        OnboardingCandidateCreate(
                            ip_address=_ip(27),
                            device_type_id=switch_type.id,
                            display_name=f"Inactive type {uuid4()}",
                            location_id=location.id,
                        ),
                        db,
                    )
                assert inactive.value.status_code == 422
                assert inactive.value.detail["code"] == "UNSUPPORTED_DEVICE_TYPE"

                with pytest.raises(HTTPException) as unknown:
                    await create_candidate(
                        OnboardingCandidateCreate(
                            ip_address=_ip(28),
                            device_type_id=uuid4(),
                            display_name=f"Unknown type {uuid4()}",
                            location_id=location.id,
                        ),
                        db,
                    )
                assert unknown.value.status_code == 422
                assert unknown.value.detail["code"] == "UNSUPPORTED_DEVICE_TYPE"

                switch_type.is_active = True
                duplicate_ip = _ip(29)
                await register_domain_device(
                    db,
                    device_type_id=switch_type.id,
                    display_name=f"Duplicate source {uuid4()}",
                    management_ip=duplicate_ip,
                    location_id=location.id,
                    sector_id=None,
                    parent_device_id=None,
                    ip_source="TEST",
                )
                await db.flush()
                with pytest.raises(HTTPException) as duplicate:
                    await create_candidate(
                        OnboardingCandidateCreate(
                            ip_address=duplicate_ip,
                            device_type_id=switch_type.id,
                            display_name=f"Duplicate onboarding {uuid4()}",
                            location_id=location.id,
                        ),
                        db,
                    )
                assert duplicate.value.status_code == 409
                assert duplicate.value.detail["code"] == "IP_ALREADY_REGISTERED"

            await _run_in_rollback(db, assertions)

    event_loop.run_until_complete(scenario())


def test_onboarding_candidate_survives_session_restart(event_loop):
    async def scenario():
        candidate_id = None
        network_id = city_id = location_id = None
        async with AsyncSessionLocal() as db:
            network, city, location, _ = await _context(db)
            switch_type = await _type(db, "SWITCH")
            candidate = await create_candidate(
                OnboardingCandidateCreate(
                    ip_address=_ip(30),
                    device_type_id=switch_type.id,
                    display_name=f"Persistent onboarding {uuid4()}",
                    location_id=location.id,
                ),
                db,
            )
            candidate_id = candidate.id
            network_id, city_id, location_id = network.id, city.id, location.id

        try:
            async with AsyncSessionLocal() as restarted_db:
                persisted = await restarted_db.get(DeviceCandidate, candidate_id)
                assert persisted is not None
                assert persisted.state == "APPROVED"
                assert persisted.metadata_["source"] == "ONBOARDING"
        finally:
            async with AsyncSessionLocal() as cleanup_db:
                await enable_audit_maintenance(cleanup_db)
                await cleanup_db.execute(
                    delete(AuditLog).where(
                        AuditLog.entity_type == "DeviceCandidate",
                        AuditLog.entity_id == candidate_id,
                    )
                )
                await cleanup_db.execute(
                    delete(DeviceCandidate).where(DeviceCandidate.id == candidate_id)
                )
                await cleanup_db.execute(delete(Sector).where(Sector.location_id == location_id))
                await cleanup_db.execute(delete(Location).where(Location.id == location_id))
                await cleanup_db.execute(delete(City).where(City.id == city_id))
                await cleanup_db.execute(delete(Network).where(Network.id == network_id))
                await cleanup_db.commit()

    event_loop.run_until_complete(scenario())


def test_direct_candidate_and_onboarding_registration_have_domain_parity(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            async def assertions():
                network, city, location, _ = await _context(db)
                switch_type = await _type(db, "SWITCH")

                direct = await create_device(
                    DeviceCreate(
                        device_type_id=switch_type.id,
                        display_name=f"Direct parity {uuid4()}",
                        management_ip=_ip(31),
                        location_id=location.id,
                    ),
                    db,
                )

                reviewed = DeviceCandidate(
                    ip_address=_ip(32),
                    state="APPROVED",
                    confidence=1.0,
                    suggested_device_type_id=switch_type.id,
                    display_name_suggestion=f"Candidate parity {uuid4()}",
                    network_id=network.id,
                    city_id=city.id,
                    location_id=location.id,
                    metadata_={},
                )
                db.add(reviewed)
                await db.flush()
                reviewed_result = await register_reviewed_candidate(reviewed.id, db)

                onboarding = await create_candidate(
                    OnboardingCandidateCreate(
                        ip_address=_ip(33),
                        device_type_id=switch_type.id,
                        display_name=f"Onboarding parity {uuid4()}",
                        location_id=location.id,
                    ),
                    db,
                )
                onboarding_result = await register_candidate(
                    OnboardingRegisterRequest(candidate_id=onboarding.id),
                    db,
                )

                device_ids = {
                    direct.id,
                    reviewed_result.device_id,
                    onboarding_result.device_id,
                }
                placements = (
                    await db.scalars(
                        select(DevicePlacement).where(
                            DevicePlacement.device_id.in_(device_ids)
                        )
                    )
                ).all()
                management_ips = (
                    await db.scalars(
                        select(DeviceIP).where(DeviceIP.device_id.in_(device_ids))
                    )
                ).all()
                devices = (
                    await db.scalars(select(Device).where(Device.id.in_(device_ids)))
                ).all()

                assert len(devices) == 3
                assert len(placements) == 3
                assert len(management_ips) == 3
                assert {placement.location_id for placement in placements} == {location.id}
                assert all(ip.is_management and ip.is_primary for ip in management_ips)

            await _run_in_rollback(db, assertions)

    event_loop.run_until_complete(scenario())
