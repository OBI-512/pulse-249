from __future__ import annotations

import asyncio
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select

from app.api.routers.candidates import approve_candidate
from app.api.routers.devices import list_device_management
from app.db.session import AsyncSessionLocal, engine
from app.models import (
    City,
    Customer,
    DeviceCandidate,
    DeviceGroup,
    DeviceGroupMembership,
    DeviceType,
    Location,
    Network,
    Sector,
)
from app.schemas.candidates import CandidateApprove
from app.services.device_registration import register_domain_device


def _ip() -> str:
    token = uuid4().int
    return f"198.51.{(token >> 8) % 250 + 1}.{token % 250 + 1}"


async def _type(db, code: str) -> DeviceType:
    row = await db.scalar(select(DeviceType).where(DeviceType.code == code))
    assert row is not None
    return row


async def _geo(db):
    marker = uuid4().hex[:10]
    network = Network(name=f"Target Network {marker}", code=f"TN-{marker}")
    db.add(network)
    await db.flush()
    city = City(network_id=network.id, name=f"Target City {marker}", code=f"TC-{marker}")
    db.add(city)
    await db.flush()
    location = Location(city_id=city.id, name=f"Target Location {marker}", code=f"TL-{marker}", metadata_={})
    db.add(location)
    await db.flush()
    sector = Sector(location_id=location.id, name=f"Target Sector {marker}", code=f"TS-{marker}", role="CUSTOMER_ACCESS", metadata_={})
    db.add(sector)
    await db.flush()
    return network, city, location, sector


async def _without_commit(db, scenario):
    transaction = await db.begin()
    original_commit = db.commit

    async def flush_only():
        await db.flush()

    db.commit = flush_only  # type: ignore[method-assign]
    try:
        await scenario()
    finally:
        db.commit = original_commit  # type: ignore[method-assign]
        if transaction.is_active:
            await transaction.rollback()


def test_candidate_cpe_review_derives_parent_relationship_without_customer_assignment():
    async def scenario():
        await engine.dispose()
        async with AsyncSessionLocal() as db:
            async def assertions():
                _, _, _, sector = await _geo(db)
                sector_type = await _type(db, "SECTOR")
                cpe_type = await _type(db, "CPE")
                parent = (await register_domain_device(
                    db,
                    device_type_id=sector_type.id,
                    display_name=f"Review parent {uuid4()}",
                    management_ip=_ip(),
                    location_id=None,
                    sector_id=sector.id,
                    parent_device_id=None,
                    ip_source="TEST",
                )).device
                candidate = DeviceCandidate(ip_address=_ip(), state="NEW", confidence=0.9, metadata_={})
                db.add(candidate)
                await db.flush()

                approved = await approve_candidate(
                    candidate.id,
                    CandidateApprove(
                        suggested_device_type_id=cpe_type.id,
                        display_name="Reviewed CPE",
                        relationship_target_device_id=parent.id,
                    ),
                    db,
                )
                assert approved.network_id is None
                assert approved.city_id is None
                assert approved.location_id is None
                assert approved.sector_id is None
                assert approved.relationship_target_device_id == parent.id
                assert approved.relationship_type == "SECTOR_CPE"
                assert approved.relationship_direction == "DIRECTED"

            await _without_commit(db, assertions)
        await engine.dispose()

    asyncio.run(scenario())


def test_device_management_endpoint_exposes_physical_sector_for_cpe_and_ap_and_filters_it():
    async def scenario():
        await engine.dispose()
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                network, city, location, logical_sector = await _geo(db)
                sector_type = await _type(db, "SECTOR")
                cpe_type = await _type(db, "CPE")
                ap_type = await _type(db, "ACCESS_POINT")
                physical_sector = (await register_domain_device(
                    db,
                    device_type_id=sector_type.id,
                    display_name=f"Physical Sector {uuid4()}",
                    management_ip=_ip(),
                    location_id=None,
                    sector_id=logical_sector.id,
                    parent_device_id=None,
                    ip_source="TEST",
                )).device
                cpe = (await register_domain_device(
                    db,
                    device_type_id=cpe_type.id,
                    display_name=f"Managed CPE {uuid4()}",
                    management_ip=_ip(),
                    location_id=None,
                    sector_id=None,
                    parent_device_id=physical_sector.id,
                    ip_source="TEST",
                )).device
                ap = (await register_domain_device(
                    db,
                    device_type_id=ap_type.id,
                    display_name=f"Managed AP {uuid4()}",
                    management_ip=_ip(),
                    location_id=None,
                    sector_id=None,
                    parent_device_id=cpe.id,
                    ip_source="TEST",
                )).device
                group = DeviceGroup(
                    name=f"Managed Group {uuid4()}",
                    code=f"MG-{uuid4().hex[:10]}",
                    scope_type="GLOBAL",
                    device_scope="ANY",
                    metadata_={},
                )
                db.add(group)
                await db.flush()
                db.add(DeviceGroupMembership(device_id=cpe.id, group_id=group.id))
                await db.flush()

                cpe_rows = await list_device_management(
                    db=db,
                    network_id=network.id,
                    city_id=city.id,
                    location_id=location.id,
                    physical_sector_device_id=physical_sector.id,
                    group_id=group.id,
                    device_type_id=cpe_type.id,
                    lifecycle_state=None,
                    operational_state=None,
                    search="Managed CPE",
                    limit=500,
                    offset=0,
                )
                assert len(cpe_rows) == 1
                cpe_row = cpe_rows[0]
                assert cpe_row.id == cpe.id
                assert cpe_row.network_id == network.id and cpe_row.network_name == network.name
                assert cpe_row.city_id == city.id and cpe_row.city_name == city.name
                assert cpe_row.location_id == location.id and cpe_row.location_name == location.name
                assert cpe_row.physical_sector_device_id == physical_sector.id
                assert cpe_row.physical_sector_device_name == physical_sector.display_name

                ap_rows = await list_device_management(
                    db=db,
                    network_id=network.id,
                    city_id=city.id,
                    location_id=location.id,
                    physical_sector_device_id=physical_sector.id,
                    group_id=None,
                    device_type_id=ap_type.id,
                    lifecycle_state=None,
                    operational_state=None,
                    search="Managed AP",
                    limit=500,
                    offset=0,
                )
                assert len(ap_rows) == 1
                ap_row = ap_rows[0]
                assert ap_row.id == ap.id
                assert ap_row.parent_device_id == cpe.id
                assert ap_row.physical_sector_device_id == physical_sector.id
                assert ap_row.physical_sector_device_name == physical_sector.display_name
            finally:
                await transaction.rollback()
        await engine.dispose()

    asyncio.run(scenario())


def test_frontend_targeted_workflow_contracts_are_present():
    root = Path("/app")
    candidate = (root / "app" / "tests").exists() and Path("/app/../app")
    # The Docker test image uses /app as repository backend root, with frontend
    # not copied into the backend image. Source-package validation runs this
    # assertion only when frontend is available in a full repository checkout.
    candidates = [Path("/frontend/src/pages/CandidatePage.tsx"), Path("/app/frontend/src/pages/CandidatePage.tsx"), Path("../frontend/src/pages/CandidatePage.tsx")]
    candidate_path = next((path.resolve() for path in candidates if path.exists()), None)
    if candidate_path is None:
        return
    source = candidate_path.read_text(encoding="utf-8")
    assert "Parent SECTOR device" in source
    assert "Parent CPE" in source
    assert "Relationship type" not in source
    assert "Relationship direction" not in source
    management = candidate_path.parents[1] / "components" / "device" / "DeviceManagementPanel.tsx"
    feedback = candidate_path.parents[1] / "components" / "common" / "FeedbackSystem.tsx"
    assert management.exists() and feedback.exists()
    management_source = management.read_text(encoding="utf-8")
    for label in ("All networks", "All cities", "All locations", "All physical sectors", "All groups", "Move selected to Recycle Bin"):
        assert label in management_source
    assert "Physical movement" not in management_source
    assert "Destination location" not in management_source
    assert "Decommission selected devices" not in management_source
    assert "Physical Sector" in management_source
