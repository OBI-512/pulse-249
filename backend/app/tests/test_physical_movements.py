"""Regression coverage for transactional, authoritative physical movements."""

import asyncio
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.api.routers.movements import move_sector
from app.api.routers.topology import get_network_topology
from app.db.session import AsyncSessionLocal, engine
from app.models import (
    City,
    Customer,
    CustomerService,
    Device,
    DeviceGroup,
    DeviceGroupMembership,
    DeviceHierarchyLink,
    DevicePlacement,
    DeviceType,
    Location,
    Network,
    Sector,
)
from app.schemas.movement import SectorMove
from app.schemas.placement import DevicePlacementUpdate
from app.services.customer_services import create_customer_service
from app.services.device_domain import create_domain_placement
from app.services.groups import validate_membership
from app.services.hierarchy import resolve_effective_hierarchy
from app.services.movement import (
    MovementValidationError,
    move_cpe_to_sector,
    move_sector_to_location,
    reassign_access_point,
)
from app.services.placements import PlacementValidationError, update_device_placement


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()
    loop.run_until_complete(engine.dispose())
    try:
        yield loop
    finally:
        loop.run_until_complete(engine.dispose())
        loop.close()


async def _type(db, code: str) -> DeviceType:
    result = await db.scalar(select(DeviceType).where(DeviceType.code == code))
    assert result is not None
    return result


async def _device(db, device_type: DeviceType, label: str) -> Device:
    device = Device(
        device_type_id=device_type.id,
        display_name=label,
        hostname=label.lower(),
        lifecycle_state="ACTIVE",
        operational_state="UP",
        metadata_={},
    )
    db.add(device)
    await db.flush()
    return device


async def _context(db):
    suffix = uuid4().hex[:8]
    network = Network(name=f"Movement Network {suffix}", code=f"MOVE-NET-{suffix}")
    db.add(network)
    await db.flush()
    city = City(network_id=network.id, name=f"Movement City {suffix}", code=f"MOVE-CITY-{suffix}")
    db.add(city)
    await db.flush()
    source_location = Location(
        city_id=city.id,
        name="Movement Source",
        code=f"MOVE-SRC-{suffix}",
        metadata_={},
    )
    destination_location = Location(
        city_id=city.id,
        name="Movement Destination",
        code=f"MOVE-DST-{suffix}",
        metadata_={},
    )
    db.add_all([source_location, destination_location])
    await db.flush()

    source_sector = Sector(
        location_id=source_location.id,
        name="Legacy Source Sector",
        code=f"LEGACY-SRC-{suffix}",
        sequence_number=1,
        role="CUSTOMER_ACCESS",
        metadata_={},
    )
    destination_sector = Sector(
        location_id=destination_location.id,
        name=f"Movement Destination Sector 1",
        code=f"{destination_location.code}-SECTOR-01",
        sequence_number=1,
        role="CUSTOMER_ACCESS",
        metadata_={},
    )
    backhaul_sector = Sector(
        location_id=destination_location.id,
        name="Movement Backhaul",
        code=f"MOVE-BH-{suffix}",
        sequence_number=10,
        role="BACKHAUL",
        metadata_={},
    )
    db.add_all([source_sector, destination_sector, backhaul_sector])
    await db.flush()

    sector_type = await _type(db, "SECTOR")
    source_device = await _device(db, sector_type, source_sector.code)
    destination_device = await _device(db, sector_type, destination_sector.code)
    backhaul_device = await _device(db, sector_type, backhaul_sector.code)
    await create_domain_placement(
        db, source_device, "SECTOR", location_id=None, sector_id=source_sector.id, parent_device_id=None
    )
    await create_domain_placement(
        db, destination_device, "SECTOR", location_id=None, sector_id=destination_sector.id, parent_device_id=None
    )
    await create_domain_placement(
        db, backhaul_device, "SECTOR", location_id=None, sector_id=backhaul_sector.id, parent_device_id=None
    )
    await db.flush()
    return {
        "network": network,
        "city": city,
        "source_location": source_location,
        "destination_location": destination_location,
        "source_sector": source_sector,
        "destination_sector": destination_sector,
        "backhaul_sector": backhaul_sector,
        "source_device": source_device,
        "destination_device": destination_device,
        "backhaul_device": backhaul_device,
    }


async def _cpe(db, parent_sector_device: Device, label: str, *, with_ap: bool = True):
    cpe = await _device(db, await _type(db, "CPE"), label)
    await create_domain_placement(
        db, cpe, "CPE", location_id=None, sector_id=None, parent_device_id=parent_sector_device.id
    )
    access_point = None
    if with_ap:
        access_point = await _device(db, await _type(db, "ACCESS_POINT"), f"{label}-AP")
        await create_domain_placement(
            db,
            access_point,
            "ACCESS_POINT",
            location_id=None,
            sector_id=None,
            parent_device_id=cpe.id,
        )
    await db.flush()
    return cpe, access_point


async def _customer_service(db, sector: Sector, cpe: Device, access_point: Device) -> CustomerService:
    customer = Customer(
        customer_code=f"MOVE-CUSTOMER-{uuid4().hex[:10]}",
        name="Movement customer",
        metadata_={},
    )
    db.add(customer)
    await db.flush()
    return await create_customer_service(
        db,
        customer_id=customer.id,
        sector_id=sector.id,
        service_code=f"MOVE-SERVICE-{uuid4().hex[:10]}",
        status="ACTIVE",
        cpe_device_id=cpe.id,
        access_point_device_id=access_point.id,
        router_device_id=None,
        metadata={},
    )


def test_empty_sector_moves_and_recalculates_naming_and_device_placement(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _context(db)
                moved = await move_sector_to_location(
                    db,
                    sector_id=ctx["source_sector"].id,
                    destination_location_id=ctx["destination_location"].id,
                )
                assert moved.location_id == ctx["destination_location"].id
                assert moved.sequence_number == 11
                assert moved.code == f"{ctx['destination_location'].code}-SECTOR-11"
                assert moved.name == f"{ctx['destination_location'].name} Sector 11"
                placement = await db.scalar(
                    select(DevicePlacement).where(DevicePlacement.device_id == ctx["source_device"].id)
                )
                assert placement.location_id == ctx["destination_location"].id
                assert placement.sector_id == moved.id
                assert ctx["source_device"].id == moved.sector_device_id
                assert ctx["source_device"].display_name == moved.code
                assert ctx["source_device"].hostname == moved.code.lower()
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_sector_with_one_cpe_cannot_move(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _context(db)
                await _cpe(db, ctx["source_device"], "MOVE-ONE")
                with pytest.raises(MovementValidationError) as error:
                    await move_sector_to_location(
                        db,
                        sector_id=ctx["source_sector"].id,
                        destination_location_id=ctx["destination_location"].id,
                    )
                assert error.value.code == "SECTOR_HAS_ATTACHED_CPES"
                assert error.value.status_code == 409
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_sector_with_multiple_cpes_cannot_move(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _context(db)
                await _cpe(db, ctx["source_device"], "MOVE-MULTI-1")
                await _cpe(db, ctx["source_device"], "MOVE-MULTI-2")
                with pytest.raises(MovementValidationError) as error:
                    await move_sector_to_location(
                        db,
                        sector_id=ctx["source_sector"].id,
                        destination_location_id=ctx["destination_location"].id,
                    )
                assert error.value.code == "SECTOR_HAS_ATTACHED_CPES"
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_failed_sector_move_has_no_partial_changes(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _context(db)
                await _cpe(db, ctx["source_device"], "MOVE-PARTIAL")
                old_code = ctx["source_sector"].code
                old_name = ctx["source_sector"].name
                old_placement = await db.scalar(
                    select(DevicePlacement).where(DevicePlacement.device_id == ctx["source_device"].id)
                )
                with pytest.raises(MovementValidationError):
                    await move_sector_to_location(
                        db,
                        sector_id=ctx["source_sector"].id,
                        destination_location_id=ctx["destination_location"].id,
                    )
                assert ctx["source_sector"].location_id == ctx["source_location"].id
                assert ctx["source_sector"].code == old_code
                assert ctx["source_sector"].name == old_name
                assert old_placement.location_id == ctx["source_location"].id
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_sector_destination_naming_collision_is_rejected(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _context(db)
                with pytest.raises(MovementValidationError) as error:
                    await move_sector_to_location(
                        db,
                        sector_id=ctx["source_sector"].id,
                        destination_location_id=ctx["destination_location"].id,
                        sequence_number=1,
                    )
                assert error.value.code in {"SECTOR_NAMING_CONFLICT", "SECTOR_SEQUENCE_CONFLICT"}
                assert ctx["source_sector"].location_id == ctx["source_location"].id
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_sector_move_api_returns_409_for_attached_cpes(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _context(db)
                await _cpe(db, ctx["source_device"], "MOVE-API")
                with pytest.raises(HTTPException) as error:
                    await move_sector(
                        ctx["source_sector"].id,
                        SectorMove(destination_location_id=ctx["destination_location"].id),
                        db,
                    )
                assert error.value.status_code == 409
                assert error.value.detail["code"] == "SECTOR_HAS_ATTACHED_CPES"
            finally:
                await db.rollback()
                if transaction.is_active:
                    await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_cpe_moves_between_customer_access_sectors_and_keeps_ap_and_service_consistent(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _context(db)
                cpe, ap = await _cpe(db, ctx["source_device"], "MOVE-CPE")
                service = await _customer_service(db, ctx["source_sector"], cpe, ap)
                await move_cpe_to_sector(
                    db,
                    cpe_device_id=cpe.id,
                    destination_sector_device_id=ctx["destination_device"].id,
                )
                cpe_link = await db.scalar(
                    select(DeviceHierarchyLink).where(DeviceHierarchyLink.child_device_id == cpe.id)
                )
                ap_link = await db.scalar(
                    select(DeviceHierarchyLink).where(DeviceHierarchyLink.child_device_id == ap.id)
                )
                assert cpe_link.parent_device_id == ctx["destination_device"].id
                assert ap_link.parent_device_id == cpe.id
                assert (await resolve_effective_hierarchy(db, cpe)).sector_id == ctx["destination_sector"].id
                assert (await resolve_effective_hierarchy(db, ap)).sector_id == ctx["destination_sector"].id
                assert service.sector_id == ctx["destination_sector"].id
                cpe_placement = await db.scalar(select(DevicePlacement).where(DevicePlacement.device_id == cpe.id))
                ap_placement = await db.scalar(select(DevicePlacement).where(DevicePlacement.device_id == ap.id))
                assert cpe_placement.location_id == ctx["destination_location"].id
                assert ap_placement.location_id == ctx["destination_location"].id
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_cpe_move_to_backhaul_sector_is_rejected(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _context(db)
                cpe, _ = await _cpe(db, ctx["source_device"], "MOVE-BACKHAUL")
                with pytest.raises(MovementValidationError) as error:
                    await move_cpe_to_sector(
                        db,
                        cpe_device_id=cpe.id,
                        destination_sector_device_id=ctx["backhaul_device"].id,
                    )
                assert error.value.code == "BACKHAUL_SECTOR_NOT_CUSTOMER_SERVING"
                assert (await resolve_effective_hierarchy(db, cpe)).sector_id == ctx["source_sector"].id
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_access_point_reassignment_succeeds_and_synchronizes_customer_service(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _context(db)
                source_cpe, ap = await _cpe(db, ctx["source_device"], "MOVE-AP-SOURCE")
                destination_cpe, _ = await _cpe(db, ctx["destination_device"], "MOVE-AP-DEST", with_ap=False)
                service = await _customer_service(db, ctx["source_sector"], source_cpe, ap)
                moved = await reassign_access_point(
                    db,
                    access_point_device_id=ap.id,
                    destination_cpe_device_id=destination_cpe.id,
                )
                link = await db.scalar(
                    select(DeviceHierarchyLink).where(DeviceHierarchyLink.child_device_id == moved.id)
                )
                assert link.parent_device_id == destination_cpe.id
                assert service.cpe_device_id == destination_cpe.id
                assert service.sector_id == ctx["destination_sector"].id
                assert (await resolve_effective_hierarchy(db, moved)).sector_id == ctx["destination_sector"].id
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_access_point_reassignment_to_cpe_with_existing_ap_is_rejected(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _context(db)
                _, source_ap = await _cpe(db, ctx["source_device"], "MOVE-AP-CONFLICT-SOURCE")
                destination_cpe, destination_ap = await _cpe(db, ctx["destination_device"], "MOVE-AP-CONFLICT-DEST")
                with pytest.raises(MovementValidationError) as error:
                    await reassign_access_point(
                        db,
                        access_point_device_id=source_ap.id,
                        destination_cpe_device_id=destination_cpe.id,
                    )
                assert error.value.code == "CPE_ALREADY_HAS_ACCESS_POINT"
                link = await db.scalar(
                    select(DeviceHierarchyLink).where(DeviceHierarchyLink.child_device_id == source_ap.id)
                )
                assert link.parent_device_id != destination_cpe.id
                assert destination_ap is not None
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_direct_cpe_and_access_point_placement_moves_remain_rejected(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _context(db)
                cpe, ap = await _cpe(db, ctx["source_device"], "MOVE-DIRECT")
                for device in (cpe, ap):
                    with pytest.raises(PlacementValidationError) as error:
                        await update_device_placement(
                            db,
                            device.id,
                            {"location_id": ctx["destination_location"].id},
                        )
                    assert error.value.code == "HIERARCHY_MANAGED_PARENT"
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_network_topology_reflects_sector_move(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _context(db)
                await move_sector_to_location(
                    db,
                    sector_id=ctx["source_sector"].id,
                    destination_location_id=ctx["destination_location"].id,
                )
                topology = await get_network_topology(ctx["network"].id, db)
                source = next(location for city in topology.cities for location in city.locations if location.id == ctx["source_location"].id)
                destination = next(location for city in topology.cities for location in city.locations if location.id == ctx["destination_location"].id)
                assert ctx["source_sector"].id not in {sector.id for sector in source.sectors}
                assert ctx["source_sector"].id in {sector.id for sector in destination.sectors}
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_network_topology_reflects_cpe_move(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _context(db)
                cpe, ap = await _cpe(db, ctx["source_device"], "MOVE-TOPOLOGY")
                await move_cpe_to_sector(
                    db,
                    cpe_device_id=cpe.id,
                    destination_sector_device_id=ctx["destination_device"].id,
                )
                topology = await get_network_topology(ctx["network"].id, db)
                destination_sector = next(
                    sector
                    for city in topology.cities
                    for location in city.locations
                    for sector in location.sectors
                    if sector.id == ctx["destination_sector"].id
                )
                root = next(device for device in destination_sector.devices if device.id == ctx["destination_device"].id)
                assert root.children[0].id == cpe.id
                assert root.children[0].children[0].id == ap.id
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_scoped_groups_are_reconciled_and_global_groups_are_preserved_after_cpe_move(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _context(db)
                cpe, ap = await _cpe(db, ctx["source_device"], "MOVE-GROUPS")
                scoped = DeviceGroup(
                    name=f"Move scoped {uuid4()}",
                    code=f"MOVE-SCOPED-{uuid4().hex[:8]}",
                    scope_type="SECTOR",
                    sector_id=ctx["source_sector"].id,
                    device_scope="CPE",
                    metadata_={},
                )
                global_group = DeviceGroup(
                    name=f"Move global {uuid4()}",
                    code=f"MOVE-GLOBAL-{uuid4().hex[:8]}",
                    scope_type="GLOBAL",
                    device_scope="CPE",
                    metadata_={},
                )
                db.add_all([scoped, global_group])
                await db.flush()
                await validate_membership(db, cpe.id, scoped.id)
                await validate_membership(db, cpe.id, global_group.id)
                db.add_all([
                    DeviceGroupMembership(device_id=cpe.id, group_id=scoped.id),
                    DeviceGroupMembership(device_id=cpe.id, group_id=global_group.id),
                ])
                await db.flush()
                await move_cpe_to_sector(
                    db,
                    cpe_device_id=cpe.id,
                    destination_sector_device_id=ctx["destination_device"].id,
                )
                memberships = (
                    await db.scalars(
                        select(DeviceGroupMembership).where(DeviceGroupMembership.device_id == cpe.id)
                    )
                ).all()
                assert {membership.group_id for membership in memberships} == {global_group.id}
                assert ap is not None
            finally:
                await transaction.rollback()

    event_loop.run_until_complete(scenario())
