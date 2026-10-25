"""Phase 3A regression coverage for authoritative sector-role transitions."""

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException, Request
from sqlalchemy import delete, func, or_, select

from app.api.routers.geo import change_sector_role, update_sector
from app.db.session import AsyncSessionLocal, engine
from app.models import (
    City,
    Customer,
    CustomerService,
    Device,
    DeviceHierarchyLink,
    DevicePlacement,
    DeviceType,
    Location,
    Network,
    Sector,
)
from app.schemas.domain import SectorRole
from app.schemas.geo import SectorRoleTransition, SectorUpdate
from app.security.authorization import permission_for_request
from app.services.customer_services import create_customer_service
from app.services.device_domain import create_domain_placement
from app.services.sector_roles import (
    SectorRoleTransitionError,
    transition_sector_role,
)


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
    device_type = await db.scalar(select(DeviceType).where(DeviceType.code == code))
    assert device_type is not None
    return device_type


async def _device(db, type_code: str, label: str) -> Device:
    device = Device(
        device_type_id=(await _type(db, type_code)).id,
        display_name=label,
        hostname=label.lower(),
        lifecycle_state="ACTIVE",
        operational_state="UP",
        metadata_={},
    )
    db.add(device)
    await db.flush()
    return device


async def _context(db, *, role: str = "CUSTOMER_ACCESS") -> dict[str, object]:
    suffix = uuid4().hex[:10]
    network = Network(
        name=f"Role transition network {suffix}",
        code=f"ROLE-NET-{suffix}",
    )
    db.add(network)
    await db.flush()
    city = City(
        network_id=network.id,
        name=f"Role transition city {suffix}",
        code=f"ROLE-CITY-{suffix}",
    )
    db.add(city)
    await db.flush()
    location = Location(
        city_id=city.id,
        name=f"Role transition location {suffix}",
        code=f"ROLE-LOC-{suffix}",
        metadata_={},
    )
    db.add(location)
    await db.flush()
    sector = Sector(
        location_id=location.id,
        name=f"Role transition sector {suffix}",
        code=f"ROLE-SEC-{suffix}",
        role=role,
        metadata_={},
    )
    db.add(sector)
    await db.flush()
    sector_device = await _device(db, "SECTOR", f"ROLE-SECTOR-DEVICE-{suffix}")
    await create_domain_placement(
        db,
        sector_device,
        "SECTOR",
        location_id=None,
        sector_id=sector.id,
        parent_device_id=None,
    )
    await db.flush()
    return {
        "network": network,
        "city": city,
        "location": location,
        "sector": sector,
        "sector_device": sector_device,
    }


async def _cpe(db, sector_device: Device, label: str, *, with_ap: bool = False):
    cpe = await _device(db, "CPE", label)
    await create_domain_placement(
        db,
        cpe,
        "CPE",
        location_id=None,
        sector_id=None,
        parent_device_id=sector_device.id,
    )
    access_point = None
    if with_ap:
        access_point = await _device(db, "ACCESS_POINT", f"{label}-AP")
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


async def _active_service(
    db,
    *,
    sector: Sector,
    cpe: Device,
    access_point: Device,
) -> CustomerService:
    suffix = uuid4().hex[:10]
    customer = Customer(
        customer_code=f"ROLE-CUSTOMER-{suffix}",
        name=f"Role transition customer {suffix}",
        metadata_={},
    )
    db.add(customer)
    await db.flush()
    return await create_customer_service(
        db,
        customer_id=customer.id,
        sector_id=sector.id,
        service_code=f"ROLE-SERVICE-{suffix}",
        status="ACTIVE",
        cpe_device_id=cpe.id,
        access_point_device_id=access_point.id,
        router_device_id=None,
        metadata={},
    )


def test_role_transition_endpoint_requires_geo_update_permission():
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/sectors/example/role-transition",
            "query_string": b"",
            "headers": [],
            "route": SimpleNamespace(path="/api/sectors/{sector_id}/role-transition"),
        }
    )
    assert permission_for_request(request) == "geo.update"


def test_empty_customer_access_sector_can_transition_to_backhaul(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _context(db)
                sector = await transition_sector_role(
                    db,
                    sector_id=ctx["sector"].id,
                    target_role=SectorRole.BACKHAUL,
                )
                assert sector.role == "BACKHAUL"
                assert transaction.is_active, "the domain service must not commit"
            finally:
                if transaction.is_active:
                    await transaction.rollback()

    event_loop.run_until_complete(scenario())


@pytest.mark.parametrize("cpe_count", [1, 2])
def test_customer_access_sector_with_cpes_cannot_transition_to_backhaul(
    event_loop,
    cpe_count,
):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _context(db)
                cpes = []
                for index in range(cpe_count):
                    cpe, _ = await _cpe(
                        db,
                        ctx["sector_device"],
                        f"ROLE-CPE-{uuid4().hex[:8]}-{index}",
                    )
                    cpes.append(cpe)

                with pytest.raises(SectorRoleTransitionError) as error:
                    await transition_sector_role(
                        db,
                        sector_id=ctx["sector"].id,
                        target_role=SectorRole.BACKHAUL,
                    )

                assert error.value.status_code == 409
                assert error.value.code == "SECTOR_HAS_CUSTOMER_DEPENDENCIES"
                assert ctx["sector"].role == "CUSTOMER_ACCESS"
                attached_count = await db.scalar(
                    select(func.count(DeviceHierarchyLink.id)).where(
                        DeviceHierarchyLink.parent_device_id == ctx["sector_device"].id,
                        DeviceHierarchyLink.relationship_type == "SECTOR_CPE",
                    )
                )
                assert attached_count == cpe_count
                assert all(cpe.id is not None for cpe in cpes)
            finally:
                if transaction.is_active:
                    await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_sector_with_active_customer_service_cannot_transition_to_backhaul(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _context(db)
                cpe, access_point = await _cpe(
                    db,
                    ctx["sector_device"],
                    f"ROLE-SERVICE-CPE-{uuid4().hex[:8]}",
                    with_ap=True,
                )
                service = await _active_service(
                    db,
                    sector=ctx["sector"],
                    cpe=cpe,
                    access_point=access_point,
                )

                with pytest.raises(SectorRoleTransitionError) as error:
                    await transition_sector_role(
                        db,
                        sector_id=ctx["sector"].id,
                        target_role=SectorRole.BACKHAUL,
                    )

                assert error.value.code == "SECTOR_HAS_CUSTOMER_DEPENDENCIES"
                assert service.status == "ACTIVE"
                assert service.sector_id == ctx["sector"].id
                assert ctx["sector"].role == "CUSTOMER_ACCESS"
            finally:
                if transaction.is_active:
                    await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_failed_patch_transition_is_atomic_and_uses_stable_http_error(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _context(db)
                await _cpe(
                    db,
                    ctx["sector_device"],
                    f"ROLE-ATOMIC-CPE-{uuid4().hex[:8]}",
                )
                original_name = ctx["sector"].name

                with pytest.raises(HTTPException) as error:
                    await update_sector(
                        ctx["sector"].id,
                        SectorUpdate(
                            name="must not be applied",
                            role=SectorRole.BACKHAUL,
                        ),
                        db,
                    )

                assert error.value.status_code == 409
                assert error.value.detail == {
                    "code": "SECTOR_HAS_CUSTOMER_DEPENDENCIES",
                    "message": "Move or remove all attached CPEs and active customer services before changing this sector to BACKHAUL.",
                }
                assert ctx["sector"].name == original_name
                assert ctx["sector"].role == "CUSTOMER_ACCESS"
                link_count = await db.scalar(
                    select(func.count(DeviceHierarchyLink.id)).where(
                        DeviceHierarchyLink.parent_device_id == ctx["sector_device"].id
                    )
                )
                assert link_count == 1
            finally:
                if transaction.is_active:
                    await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_backhaul_sector_can_transition_to_customer_access(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _context(db, role="BACKHAUL")
                sector = await transition_sector_role(
                    db,
                    sector_id=ctx["sector"].id,
                    target_role=SectorRole.CUSTOMER_ACCESS,
                )
                assert sector.role == "CUSTOMER_ACCESS"
            finally:
                if transaction.is_active:
                    await transaction.rollback()

    event_loop.run_until_complete(scenario())


def test_dedicated_endpoint_returns_stable_conflict(event_loop):
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                ctx = await _context(db)
                await _cpe(
                    db,
                    ctx["sector_device"],
                    f"ROLE-ENDPOINT-CPE-{uuid4().hex[:8]}",
                )
                with pytest.raises(HTTPException) as error:
                    await change_sector_role(
                        ctx["sector"].id,
                        SectorRoleTransition(role=SectorRole.BACKHAUL),
                        db,
                    )
                assert error.value.status_code == 409
                assert error.value.detail["code"] == "SECTOR_HAS_CUSTOMER_DEPENDENCIES"
                assert ctx["sector"].role == "CUSTOMER_ACCESS"
            finally:
                if transaction.is_active:
                    await transaction.rollback()

    event_loop.run_until_complete(scenario())


async def _cleanup_committed_concurrency_context(ids: dict[str, object]) -> None:
    device_ids = [ids["sector_device_id"], ids["cpe_id"]]
    async with AsyncSessionLocal() as db:
        await db.execute(
            delete(DeviceHierarchyLink).where(
                or_(
                    DeviceHierarchyLink.child_device_id.in_(device_ids),
                    DeviceHierarchyLink.parent_device_id.in_(device_ids),
                )
            )
        )
        await db.execute(delete(DevicePlacement).where(DevicePlacement.device_id.in_(device_ids)))
        await db.execute(delete(CustomerService).where(CustomerService.sector_id == ids["sector_id"]))
        await db.execute(delete(Sector).where(Sector.id == ids["sector_id"]))
        await db.execute(delete(Device).where(Device.id.in_(device_ids)))
        await db.execute(delete(Location).where(Location.id == ids["location_id"]))
        await db.execute(delete(City).where(City.id == ids["city_id"]))
        await db.execute(delete(Network).where(Network.id == ids["network_id"]))
        await db.commit()


def test_concurrent_cpe_creation_waits_for_transition_and_cannot_enter_backhaul(event_loop):
    async def scenario():
        ids = None
        async with AsyncSessionLocal() as setup_db:
            ctx = await _context(setup_db)
            unplaced_cpe = await _device(
                setup_db,
                "CPE",
                f"ROLE-RACE-CPE-{uuid4().hex[:8]}",
            )
            ids = {
                "network_id": ctx["network"].id,
                "city_id": ctx["city"].id,
                "location_id": ctx["location"].id,
                "sector_id": ctx["sector"].id,
                "sector_device_id": ctx["sector_device"].id,
                "cpe_id": unplaced_cpe.id,
            }
            await setup_db.commit()

        transition_db = AsyncSessionLocal()
        registration_db = AsyncSessionLocal()
        registration_task = None
        try:
            await transition_db.begin()
            sector = await transition_sector_role(
                transition_db,
                sector_id=ids["sector_id"],
                target_role=SectorRole.BACKHAUL,
            )
            assert sector.role == "BACKHAUL"

            cpe = await registration_db.get(Device, ids["cpe_id"])
            registration_task = asyncio.create_task(
                create_domain_placement(
                    registration_db,
                    cpe,
                    "CPE",
                    location_id=None,
                    sector_id=None,
                    parent_device_id=ids["sector_device_id"],
                )
            )
            done, _ = await asyncio.wait({registration_task}, timeout=0.2)
            assert registration_task not in done, "CPE registration must wait on the sector row lock"

            await transition_db.commit()
            with pytest.raises(HTTPException) as error:
                await registration_task
            assert error.value.detail["code"] == "BACKHAUL_SECTOR_NOT_CUSTOMER_SERVING"
            assert await registration_db.scalar(
                select(func.count(DeviceHierarchyLink.id)).where(
                    DeviceHierarchyLink.child_device_id == ids["cpe_id"]
                )
            ) == 0
        finally:
            if registration_task is not None and not registration_task.done():
                registration_task.cancel()
                await asyncio.gather(registration_task, return_exceptions=True)
            if transition_db.in_transaction():
                await transition_db.rollback()
            if registration_db.in_transaction():
                await registration_db.rollback()
            await transition_db.close()
            await registration_db.close()
            if ids is not None:
                await _cleanup_committed_concurrency_context(ids)

    event_loop.run_until_complete(scenario())
