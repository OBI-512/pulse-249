from __future__ import annotations

import asyncio
from uuid import uuid4

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.deps import get_db
from app.main import app
from app.models import (
    AuditLog,
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
from app.settings import settings


async def _run_isolated(scenario) -> None:
    """Run an API scenario in an outer transaction that is always rolled back."""

    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    async with engine.connect() as connection:
        outer_transaction = await connection.begin()
        session_factory = async_sessionmaker(
            bind=connection,
            class_=AsyncSession,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        )

        async def override_get_db():
            async with session_factory() as db:
                yield db

        previous = app.dependency_overrides.get(get_db)
        app.dependency_overrides[get_db] = override_get_db
        try:
            await scenario(session_factory)
        finally:
            if previous is None:
                app.dependency_overrides.pop(get_db, None)
            else:
                app.dependency_overrides[get_db] = previous
            await outer_transaction.rollback()
    await engine.dispose()


async def _request_delete(device_id, *, confirmed: bool = False):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as client:
        suffix = "?confirmed=true" if confirmed else ""
        return await client.delete(f"/api/devices/{device_id}{suffix}")


async def _request_customer_delete(customer_id, *, confirmed: bool = False):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as client:
        suffix = "?confirmed=true" if confirmed else ""
        return await client.delete(f"/api/customers/{customer_id}{suffix}")


async def _type(db: AsyncSession, code: str) -> DeviceType:
    device_type = await db.scalar(select(DeviceType).where(DeviceType.code == code))
    assert device_type is not None
    return device_type


async def _device(db: AsyncSession, code: str) -> Device:
    device_type = await _type(db, code)
    device = Device(
        device_type_id=device_type.id,
        display_name=f"DELETE-{code}-{uuid4().hex[:10]}",
        lifecycle_state="DECOMMISSIONED",
        operational_state="UNKNOWN",
        metadata_={},
    )
    db.add(device)
    await db.flush()
    return device


async def _location(db: AsyncSession) -> tuple[Network, City, Location]:
    suffix = uuid4().hex[:10]
    network = Network(
        name=f"Delete Network {suffix}",
        code=f"DEL-N-{suffix}",
        status="ACTIVE",
    )
    db.add(network)
    await db.flush()
    city = City(
        network_id=network.id,
        name=f"Delete City {suffix}",
        code=f"DEL-C-{suffix}",
        status="ACTIVE",
    )
    db.add(city)
    await db.flush()
    location = Location(
        city_id=city.id,
        name=f"Delete Location {suffix}",
        code=f"DEL-L-{suffix}",
        status="ACTIVE",
        metadata_={},
    )
    db.add(location)
    await db.flush()
    return network, city, location


async def _bound_sector_device(
    db: AsyncSession,
) -> tuple[Network, City, Location, Sector, Device]:
    network, city, location = await _location(db)
    sector_device = await _device(db, "SECTOR")
    sector = Sector(
        location_id=location.id,
        name=f"Delete Sector {uuid4().hex[:10]}",
        code=f"DEL-S-{uuid4().hex[:10]}",
        status="ACTIVE",
        role="CUSTOMER_ACCESS",
        sector_device_id=sector_device.id,
        metadata_={},
    )
    db.add(sector)
    await db.flush()
    return network, city, location, sector, sector_device


async def _customer_hierarchy(db: AsyncSession):
    network, city, location, sector, sector_device = await _bound_sector_device(db)
    cpe = await _device(db, "CPE")
    access_point = await _device(db, "ACCESS_POINT")
    cpe_link = DeviceHierarchyLink(
        parent_device_id=sector_device.id,
        child_device_id=cpe.id,
        relationship_type="SECTOR_CPE",
    )
    ap_link = DeviceHierarchyLink(
        parent_device_id=cpe.id,
        child_device_id=access_point.id,
        relationship_type="CPE_ACCESS_POINT",
    )
    db.add_all([cpe_link, ap_link])
    await db.flush()
    return {
        "network": network,
        "city": city,
        "location": location,
        "sector": sector,
        "sector_device": sector_device,
        "cpe": cpe,
        "access_point": access_point,
        "cpe_link": cpe_link,
        "ap_link": ap_link,
    }


async def _add_customer_service(db: AsyncSession, hierarchy) -> CustomerService:
    customer = Customer(
        customer_code=f"DEL-CUST-{uuid4().hex[:10]}",
        name="Device deletion protection customer",
        status="ACTIVE",
        metadata_={},
    )
    db.add(customer)
    await db.flush()
    service = CustomerService(
        customer_id=customer.id,
        sector_id=hierarchy["sector"].id,
        service_code=f"DEL-SVC-{uuid4().hex[:10]}",
        status="ACTIVE",
        cpe_device_id=hierarchy["cpe"].id,
        access_point_device_id=hierarchy["access_point"].id,
        metadata_={},
    )
    db.add(service)
    await db.flush()
    return service


async def _assert_no_recycle_audit(db: AsyncSession, device_id) -> None:
    audit_id = await db.scalar(
        select(AuditLog.id).where(
            AuditLog.action == "DEVICE_RECYCLED",
            AuditLog.entity_id == device_id,
        )
    )
    assert audit_id is None


def test_bound_sector_device_delete_is_rejected_and_binding_is_preserved():
    async def scenario(session_factory):
        async with session_factory() as db:
            _, _, _, sector, sector_device = await _bound_sector_device(db)
            sector_id = sector.id
            device_id = sector_device.id
            await db.commit()

        response = await _request_delete(device_id)
        assert response.status_code == 409
        assert response.json()["detail"]["code"] == "SECTOR_DEVICE_IS_BOUND"

        async with session_factory() as db:
            assert await db.get(Device, device_id) is not None
            preserved_sector = await db.get(Sector, sector_id)
            assert preserved_sector is not None
            assert preserved_sector.sector_device_id == device_id
            await _assert_no_recycle_audit(db, device_id)

    asyncio.run(_run_isolated(scenario))


def test_sector_device_with_cpe_delete_is_rejected_and_all_rows_survive():
    async def scenario(session_factory):
        async with session_factory() as db:
            hierarchy = await _customer_hierarchy(db)
            parent_id = hierarchy["sector_device"].id
            cpe_id = hierarchy["cpe"].id
            link_id = hierarchy["cpe_link"].id
            await db.commit()

        response = await _request_delete(parent_id)
        assert response.status_code == 409
        assert response.json()["detail"]["code"] == "DEVICE_HAS_HIERARCHY_DEPENDENCIES"

        async with session_factory() as db:
            assert await db.get(Device, parent_id) is not None
            assert await db.get(Device, cpe_id) is not None
            assert await db.get(DeviceHierarchyLink, link_id) is not None
            await _assert_no_recycle_audit(db, parent_id)

    asyncio.run(_run_isolated(scenario))


def test_cpe_with_access_point_delete_cannot_create_an_orphan():
    async def scenario(session_factory):
        async with session_factory() as db:
            hierarchy = await _customer_hierarchy(db)
            cpe_id = hierarchy["cpe"].id
            access_point_id = hierarchy["access_point"].id
            link_id = hierarchy["ap_link"].id
            await db.commit()

        response = await _request_delete(cpe_id)
        assert response.status_code == 409
        assert response.json()["detail"]["code"] == "DEVICE_HAS_HIERARCHY_DEPENDENCIES"

        async with session_factory() as db:
            assert await db.get(Device, cpe_id) is not None
            assert await db.get(Device, access_point_id) is not None
            link = await db.get(DeviceHierarchyLink, link_id)
            assert link is not None
            assert link.parent_device_id == cpe_id
            assert link.child_device_id == access_point_id
            await _assert_no_recycle_audit(db, cpe_id)

    asyncio.run(_run_isolated(scenario))


def test_cpe_with_active_customer_service_delete_is_rejected():
    async def scenario(session_factory):
        async with session_factory() as db:
            hierarchy = await _customer_hierarchy(db)
            service = await _add_customer_service(db, hierarchy)
            cpe_id = hierarchy["cpe"].id
            service_id = service.id
            ap_link_id = hierarchy["ap_link"].id
            await db.commit()

        response = await _request_delete(cpe_id)
        assert response.status_code == 409
        assert response.json()["detail"]["code"] == "DEVICE_HAS_CUSTOMER_SERVICE_DEPENDENCIES"

        async with session_factory() as db:
            assert await db.get(Device, cpe_id) is not None
            assert await db.get(CustomerService, service_id) is not None
            assert await db.get(DeviceHierarchyLink, ap_link_id) is not None
            await _assert_no_recycle_audit(db, cpe_id)

    asyncio.run(_run_isolated(scenario))


def test_access_point_with_active_customer_service_recycles_customer_and_service_as_one_confirmed_bundle():
    async def scenario(session_factory):
        async with session_factory() as db:
            hierarchy = await _customer_hierarchy(db)
            service = await _add_customer_service(db, hierarchy)
            access_point_id = hierarchy["access_point"].id
            cpe_id = hierarchy["cpe"].id
            customer_id = service.customer_id
            service_id = service.id
            ap_link_id = hierarchy["ap_link"].id
            await db.commit()

        response = await _request_delete(access_point_id)
        assert response.status_code == 409
        assert response.json()["detail"]["code"] == "RECYCLE_CONFIRMATION_REQUIRED"

        response = await _request_delete(access_point_id, confirmed=True)
        assert response.status_code == 204

        async with session_factory() as db:
            assert await db.get(Device, access_point_id) is None
            assert await db.get(CustomerService, service_id) is None
            assert await db.get(Customer, customer_id) is None
            assert await db.get(DeviceHierarchyLink, ap_link_id) is None
            assert await db.get(Device, cpe_id) is not None

            hidden_ap = await db.scalar(
                select(Device)
                .where(Device.id == access_point_id)
                .execution_options(include_recycled=True)
            )
            hidden_service = await db.scalar(
                select(CustomerService)
                .where(CustomerService.id == service_id)
                .execution_options(include_recycled=True)
            )
            hidden_customer = await db.scalar(
                select(Customer)
                .where(Customer.id == customer_id)
                .execution_options(include_recycled=True)
            )
            hidden_link = await db.scalar(
                select(DeviceHierarchyLink)
                .where(DeviceHierarchyLink.id == ap_link_id)
                .execution_options(include_recycled=True)
            )
            assert hidden_ap is not None
            assert hidden_service is not None
            assert hidden_customer is not None
            assert hidden_link is not None
            assert hidden_service.deletion_batch_id == hidden_ap.deletion_batch_id
            assert hidden_customer.deletion_batch_id == hidden_ap.deletion_batch_id
            assert hidden_link.deletion_batch_id == hidden_ap.deletion_batch_id

    asyncio.run(_run_isolated(scenario))


def test_customer_delete_recycles_its_service_without_recycling_access_equipment():
    async def scenario(session_factory):
        async with session_factory() as db:
            hierarchy = await _customer_hierarchy(db)
            service = await _add_customer_service(db, hierarchy)
            customer_id = service.customer_id
            service_id = service.id
            cpe_id = hierarchy["cpe"].id
            access_point_id = hierarchy["access_point"].id
            await db.commit()

        response = await _request_customer_delete(customer_id)
        assert response.status_code == 409
        assert response.json()["detail"]["code"] == "RECYCLE_CONFIRMATION_REQUIRED"

        response = await _request_customer_delete(customer_id, confirmed=True)
        assert response.status_code == 204

        async with session_factory() as db:
            assert await db.get(Customer, customer_id) is None
            assert await db.get(CustomerService, service_id) is None
            assert await db.get(Device, cpe_id) is not None
            assert await db.get(Device, access_point_id) is not None

            hidden_customer = await db.scalar(
                select(Customer)
                .where(Customer.id == customer_id)
                .execution_options(include_recycled=True)
            )
            hidden_service = await db.scalar(
                select(CustomerService)
                .where(CustomerService.id == service_id)
                .execution_options(include_recycled=True)
            )
            assert hidden_customer is not None
            assert hidden_service is not None
            assert hidden_service.deletion_batch_id == hidden_customer.deletion_batch_id

    asyncio.run(_run_isolated(scenario))


def test_unrelated_decommissioned_switch_remains_deletable():
    async def scenario(session_factory):
        async with session_factory() as db:
            network, city, location = await _location(db)
            switch = await _device(db, "SWITCH")
            placement = DevicePlacement(
                device_id=switch.id,
                network_id=network.id,
                city_id=city.id,
                location_id=location.id,
                sector_id=None,
                metadata_={"placement_mode": "INDEPENDENT"},
            )
            db.add(placement)
            await db.flush()
            switch_id = switch.id
            placement_id = placement.id
            await db.commit()

        response = await _request_delete(switch_id)
        assert response.status_code == 204

        async with session_factory() as db:
            assert await db.get(Device, switch_id) is None
            assert await db.get(DevicePlacement, placement_id) is None
            audit_id = await db.scalar(
                select(AuditLog.id).where(
                    AuditLog.action == "DEVICE_RECYCLED",
                    AuditLog.entity_id == switch_id,
                )
            )
            assert audit_id is not None

    asyncio.run(_run_isolated(scenario))
