"""Focused Phase 1 integration tests for the authoritative device hierarchy."""

import asyncio
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.db.session import AsyncSessionLocal, engine
from app.models import City, Customer, Device, DeviceCandidate, DeviceGroup, DeviceHierarchyLink, DeviceType, Location, Network, Sector
from app.api.routers.candidates import register_candidate
from app.api.routers.devices import update_device
from app.schemas.device import DeviceUpdate
from app.services.customer_services import CustomerServiceValidationError, create_customer_service
from app.services.device_domain import create_domain_placement
from app.services.groups import validate_membership
from app.services.hierarchy import resolve_effective_hierarchy
from app.api.routers.topology import get_network_topology


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(engine.dispose())
        yield loop
    finally:
        loop.run_until_complete(engine.dispose())
        loop.close()


async def _type(db, code: str) -> DeviceType:
    existing = await db.scalar(select(DeviceType).where(DeviceType.code == code))
    if existing is not None:
        return existing
    obj = DeviceType(name=f"Phase 1 {code}", code=code, is_active=True)
    db.add(obj)
    await db.flush()
    return obj


async def _context(db):
    network = Network(name=f"Phase 1 Network {uuid4()}", code=f"P1-N-{uuid4().hex[:10]}")
    db.add(network)
    await db.flush()
    city = City(network_id=network.id, name=f"Phase 1 City {uuid4()}", code=f"P1-C-{uuid4().hex[:10]}")
    db.add(city)
    await db.flush()
    location = Location(city_id=city.id, name=f"Phase 1 Location {uuid4()}", code=f"P1-L-{uuid4().hex[:10]}")
    db.add(location)
    await db.flush()
    sector = Sector(location_id=location.id, name=f"Phase 1 Sector {uuid4()}", code=f"P1-S-{uuid4().hex[:10]}")
    other_sector = Sector(location_id=location.id, name=f"Phase 1 Other Sector {uuid4()}", code=f"P1-O-{uuid4().hex[:10]}")
    db.add_all([sector, other_sector])
    await db.flush()
    return network, city, location, sector, other_sector


async def _device(db, device_type: DeviceType, name: str) -> Device:
    device = Device(device_type_id=device_type.id, display_name=name, lifecycle_state="ACTIVE", operational_state="UP")
    db.add(device)
    await db.flush()
    return device


def test_sector_cpe_access_point_chain_is_authoritative(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                network, city, location, sector, _ = await _context(db)
                sector_type, cpe_type, ap_type, switch_type = [
                    await _type(db, code) for code in ("SECTOR", "CPE", "ACCESS_POINT", "SWITCH")
                ]
                sector_device = await _device(db, sector_type, f"P1 Sector Device {uuid4()}")
                await create_domain_placement(db, sector_device, "SECTOR", location_id=None, sector_id=sector.id, parent_device_id=None)

                cpe = await _device(db, cpe_type, f"P1 CPE {uuid4()}")
                await create_domain_placement(db, cpe, "CPE", location_id=None, sector_id=None, parent_device_id=sector_device.id)
                cpe_context = await resolve_effective_hierarchy(db, cpe)
                assert (cpe_context.network_id, cpe_context.city_id, cpe_context.location_id, cpe_context.sector_id) == (network.id, city.id, location.id, sector.id)

                access_point = await _device(db, ap_type, f"P1 AP {uuid4()}")
                await create_domain_placement(db, access_point, "ACCESS_POINT", location_id=None, sector_id=None, parent_device_id=cpe.id)
                assert (await resolve_effective_hierarchy(db, access_point)).sector_id == sector.id

                invalid_cpe = await _device(db, cpe_type, f"P1 Invalid CPE {uuid4()}")
                switch = await _device(db, switch_type, f"P1 Switch {uuid4()}")
                await create_domain_placement(db, switch, "SWITCH", location_id=location.id, sector_id=None, parent_device_id=None)
                with pytest.raises(HTTPException) as invalid_parent:
                    await create_domain_placement(db, invalid_cpe, "CPE", location_id=None, sector_id=None, parent_device_id=switch.id)
                assert invalid_parent.value.detail["code"] == "INVALID_PARENT_DEVICE_TYPE"
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_second_ap_customer_service_and_group_scope_use_authoritative_chain(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                _, _, location, sector, other_sector = await _context(db)
                sector_type, cpe_type, ap_type = [await _type(db, code) for code in ("SECTOR", "CPE", "ACCESS_POINT")]
                sector_device = await _device(db, sector_type, f"P1 Sector Device {uuid4()}")
                await create_domain_placement(db, sector_device, "SECTOR", location_id=location.id, sector_id=sector.id, parent_device_id=None)
                cpe = await _device(db, cpe_type, f"P1 CPE {uuid4()}")
                await create_domain_placement(db, cpe, "CPE", location_id=None, sector_id=None, parent_device_id=sector_device.id)
                access_point = await _device(db, ap_type, f"P1 AP {uuid4()}")
                await create_domain_placement(db, access_point, "ACCESS_POINT", location_id=None, sector_id=None, parent_device_id=cpe.id)

                second_ap = await _device(db, ap_type, f"P1 AP 2 {uuid4()}")
                with pytest.raises(HTTPException) as second_ap_error:
                    await create_domain_placement(db, second_ap, "ACCESS_POINT", location_id=None, sector_id=None, parent_device_id=cpe.id)
                assert second_ap_error.value.detail["code"] == "CPE_ALREADY_HAS_ACCESS_POINT"

                customer = Customer(customer_code=f"P1-CUST-{uuid4().hex[:10]}", name="Phase 1 Customer")
                db.add(customer)
                await db.flush()
                service = await create_customer_service(
                    db,
                    customer_id=customer.id,
                    sector_id=sector.id,
                    service_code=f"P1-SVC-{uuid4().hex[:10]}",
                    status="ACTIVE",
                    cpe_device_id=cpe.id,
                    access_point_device_id=access_point.id,
                    router_device_id=None,
                    metadata={},
                )
                assert service.sector_id == sector.id
                with pytest.raises(CustomerServiceValidationError) as mismatch:
                    await create_customer_service(
                        db,
                        customer_id=customer.id,
                        sector_id=other_sector.id,
                        service_code=f"P1-BAD-{uuid4().hex[:10]}",
                        status="ACTIVE",
                        cpe_device_id=cpe.id,
                        access_point_device_id=access_point.id,
                        router_device_id=None,
                        metadata={},
                    )
                assert mismatch.value.code == "CPE_SECTOR_MISMATCH"

                # Deliberately stale compatibility data cannot move the CPE
                # into another sector for scoped group validation.
                cpe_placement = await db.scalar(select_from_placement(cpe.id))
                cpe_placement.sector_id = other_sector.id
                group = DeviceGroup(
                    name=f"P1 Sector Group {uuid4()}",
                    code=f"P1-GRP-{uuid4().hex[:10]}",
                    scope_type="SECTOR",
                    sector_id=sector.id,
                    device_scope="CPE",
                )
                db.add(group)
                await db.flush()
                resolved_device, resolved_group = await validate_membership(db, cpe.id, group.id)
                assert resolved_device.id == cpe.id
                assert resolved_group.id == group.id
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_network_topology_uses_links_when_child_placements_are_absent(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                network, _, location, sector, _ = await _context(db)
                sector_type, cpe_type, ap_type = [await _type(db, code) for code in ("SECTOR", "CPE", "ACCESS_POINT")]
                sector_device = await _device(db, sector_type, f"P1 Sector Device {uuid4()}")
                await create_domain_placement(db, sector_device, "SECTOR", location_id=location.id, sector_id=sector.id, parent_device_id=None)
                cpe = await _device(db, cpe_type, f"P1 CPE {uuid4()}")
                await create_domain_placement(db, cpe, "CPE", location_id=None, sector_id=None, parent_device_id=sector_device.id)
                access_point = await _device(db, ap_type, f"P1 AP {uuid4()}")
                await create_domain_placement(db, access_point, "ACCESS_POINT", location_id=None, sector_id=None, parent_device_id=cpe.id)
                await db.flush()

                cpe_placement = await db.scalar(select_from_placement(cpe.id))
                ap_placement = await db.scalar(select_from_placement(access_point.id))
                await db.delete(cpe_placement)
                await db.delete(ap_placement)
                await db.flush()

                topology = await get_network_topology(network.id, db)
                topology_sector = next(
                    item
                    for city in topology.cities
                    for topology_location in city.locations
                    for item in topology_location.sectors
                    if item.id == sector.id
                )
                root = next(item for item in topology_sector.devices if item.id == sector_device.id)
                assert root.children[0].id == cpe.id
                assert root.children[0].children[0].id == access_point.id
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_candidate_cpe_and_ap_registration_use_domain_hierarchy(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            original_commit = db.commit

            async def flush_without_committing():
                await db.flush()

            try:
                _, _, location, sector, _ = await _context(db)
                sector_type, cpe_type, ap_type = [await _type(db, code) for code in ("SECTOR", "CPE", "ACCESS_POINT")]
                sector_device = await _device(db, sector_type, f"P1 Sector Device {uuid4()}")
                await create_domain_placement(db, sector_device, "SECTOR", location_id=location.id, sector_id=sector.id, parent_device_id=None)

                cpe_candidate = DeviceCandidate(
                    ip_address=f"198.18.{uuid4().int % 254 + 1}.{uuid4().int % 254 + 1}",
                    state="APPROVED",
                    confidence=1.0,
                    suggested_device_type_id=cpe_type.id,
                    display_name_suggestion=f"P1 Candidate CPE {uuid4()}",
                    relationship_target_device_id=sector_device.id,
                    relationship_type="SECTOR_CPE",
                    metadata_={},
                )
                db.add(cpe_candidate)
                await db.flush()
                db.commit = flush_without_committing  # type: ignore[method-assign]
                cpe_registration = await register_candidate(cpe_candidate.id, db)
                cpe = await db.get(Device, cpe_registration.device_id)
                assert (await resolve_effective_hierarchy(db, cpe)).sector_id == sector.id

                ap_candidate = DeviceCandidate(
                    ip_address=f"198.19.{uuid4().int % 254 + 1}.{uuid4().int % 254 + 1}",
                    state="APPROVED",
                    confidence=1.0,
                    suggested_device_type_id=ap_type.id,
                    display_name_suggestion=f"P1 Candidate AP {uuid4()}",
                    relationship_target_device_id=cpe.id,
                    relationship_type="CPE_ACCESS_POINT",
                    metadata_={},
                )
                db.add(ap_candidate)
                await db.flush()
                ap_registration = await register_candidate(ap_candidate.id, db)
                link = await db.scalar(
                    select(DeviceHierarchyLink).where(DeviceHierarchyLink.child_device_id == ap_registration.device_id)
                )
                assert link.relationship_type == "CPE_ACCESS_POINT"
            finally:
                db.commit = original_commit  # type: ignore[method-assign]
                await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_device_type_change_is_rejected_for_hierarchy_participants(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                _, _, location, sector, _ = await _context(db)
                sector_type, switch_type = [await _type(db, code) for code in ("SECTOR", "SWITCH")]
                sector_device = await _device(db, sector_type, f"P1 Sector Device {uuid4()}")
                await create_domain_placement(db, sector_device, "SECTOR", location_id=location.id, sector_id=sector.id, parent_device_id=None)
                with pytest.raises(HTTPException) as protected:
                    await update_device(
                        sector_device.id,
                        DeviceUpdate(device_type_id=switch_type.id),
                        db,
                    )
                assert protected.value.status_code == 409
                assert protected.value.detail["code"] == "DEVICE_TYPE_CHANGE_RELATIONSHIP_PROTECTED"
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())


def select_from_placement(device_id):
    from app.models import DevicePlacement

    return select(DevicePlacement).where(DevicePlacement.device_id == device_id)
