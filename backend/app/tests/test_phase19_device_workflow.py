import asyncio
from uuid import uuid4

from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.deps import get_db
from app.main import app
from app.models import AuditLog, City, Device, DeviceIP, DevicePlacement, DeviceType, Location, Network
from app.schemas.device import DeviceUpdate
from app.settings import settings
from app.services.audit import enable_audit_maintenance
from app.services.device_registration import register_domain_device


def test_device_update_accepts_authoritative_assignment_fields():
    payload = DeviceUpdate(location_id=uuid4(), sector_id=None, parent_device_id=None)
    assert payload.location_id is not None
    assert payload.sector_id is None
    assert payload.parent_device_id is None


def test_decommissioned_location_device_can_be_reactivated_when_hierarchy_is_valid():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        async def override_get_db():
            async with factory() as db:
                yield db

        app.dependency_overrides[get_db] = override_get_db
        ids = {}
        try:
            async with factory() as db:
                switch_type = await db.scalar(select(DeviceType).where(DeviceType.code == "SWITCH"))
                assert switch_type is not None
                marker = uuid4().hex[:10]
                network = Network(name=f"Reactivate Net {marker}", code=f"RNET-{marker}", status="ACTIVE")
                db.add(network); await db.flush(); ids["network"] = network.id
                city = City(network_id=network.id, name=f"Reactivate City {marker}", code=f"RCITY-{marker}", status="ACTIVE")
                db.add(city); await db.flush(); ids["city"] = city.id
                location = Location(city_id=city.id, name=f"Reactivate Location {marker}", code=f"RLOC-{marker}", status="ACTIVE")
                db.add(location); await db.flush(); ids["location"] = location.id
                registration = await register_domain_device(
                    db,
                    device_type_id=switch_type.id,
                    display_name=f"Reactivate Switch {marker}",
                    management_ip=f"198.18.{uuid4().int % 200 + 1}.{uuid4().int % 200 + 1}",
                    location_id=location.id,
                    sector_id=None,
                    parent_device_id=None,
                    lifecycle_state="ACTIVE",
                    operational_state="UP",
                    metadata={},
                    ip_source="TEST",
                )
                ids["device"] = registration.device.id
                await db.commit()

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                decommission = await client.post(f"/api/devices/{ids['device']}/decommission")
                assert decommission.status_code == 200, decommission.text
                assert decommission.json()["lifecycle_state"] == "DECOMMISSIONED"

                reactivate = await client.post(f"/api/devices/{ids['device']}/reactivate")
                assert reactivate.status_code == 200, reactivate.text
                assert reactivate.json()["lifecycle_state"] == "ACTIVE"
                assert reactivate.json()["operational_state"] == "UNKNOWN"
        finally:
            app.dependency_overrides.pop(get_db, None)
            async with factory() as db:
                await enable_audit_maintenance(db)
                if ids.get("device"):
                    await db.execute(delete(AuditLog).where(AuditLog.entity_id == ids["device"]))
                    await db.execute(delete(DeviceIP).where(DeviceIP.device_id == ids["device"]))
                    await db.execute(delete(DevicePlacement).where(DevicePlacement.device_id == ids["device"]))
                    await db.execute(delete(Device).where(Device.id == ids["device"]))
                if ids.get("location"): await db.execute(delete(Location).where(Location.id == ids["location"]))
                if ids.get("city"): await db.execute(delete(City).where(City.id == ids["city"]))
                if ids.get("network"): await db.execute(delete(Network).where(Network.id == ids["network"]))
                await db.commit()
            await engine.dispose()

    asyncio.run(scenario())
