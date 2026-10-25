from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from app.api.routers.admin import list_security_options
from app.api.routers.topology import get_sector_live_topology
from app.db.session import AsyncSessionLocal, engine
from app.models import City, Device, DeviceType, Location, Network, Permission, Sector, User, UserPermission
from app.schemas.admin import UserCreate, UserUpdate
from app.services.device_domain import create_domain_placement


def test_user_payload_accepts_only_one_role_assignment():
    with pytest.raises(ValidationError):
        UserCreate(
            username="two-role-user",
            password="Strong-Test-Password!",
            role_codes=["viewer", "operator"],
        )
    with pytest.raises(ValidationError):
        UserUpdate(role_codes=["viewer", "operator"])
    assert UserCreate(
        username="one-role-user",
        password="Strong-Test-Password!",
        role_codes=["viewer"],
    ).role_codes == ["viewer"]



def test_security_options_endpoint_source_returns_roles_and_permissions_for_user_manager():
    async def scenario():
        await engine.dispose()
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                marker = uuid4().hex[:10]
                read_permission = await db.scalar(select(Permission).where(Permission.code == "user.read"))
                assert read_permission is not None
                actor = User(
                    external_subject=f"targeted-ui:{marker}",
                    username=f"targeted-ui-{marker}",
                    display_name="Targeted UI Test",
                    is_active=True,
                    metadata_={},
                )
                db.add(actor)
                await db.flush()
                db.add(UserPermission(user_id=actor.id, permission_id=read_permission.id))
                await db.flush()

                result = await list_security_options(actor=actor, db=db)
                role_codes = {row.code for row in result.roles}
                permission_codes = {row.code for row in result.permissions}
                assert "administrator" in role_codes
                assert "viewer" in role_codes
                assert "user.read" in permission_codes
                assert "device.read" in permission_codes
            finally:
                await transaction.rollback()
        await engine.dispose()

    asyncio.run(scenario())

def test_live_sector_topology_returns_sector_cpe_ap_tree_with_type_codes():
    async def scenario():
        await engine.dispose()
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()
            try:
                marker = uuid4().hex[:10]
                network = Network(name=f"Live Network {marker}", code=f"LIVE-N-{marker}")
                db.add(network)
                await db.flush()
                city = City(network_id=network.id, name=f"Live City {marker}", code=f"LIVE-C-{marker}")
                db.add(city)
                await db.flush()
                location = Location(city_id=city.id, name=f"Live Location {marker}", code=f"LIVE-L-{marker}", metadata_={})
                db.add(location)
                await db.flush()
                sector = Sector(
                    location_id=location.id,
                    name=f"Live Sector {marker}",
                    code=f"LIVE-S-{marker}",
                    sequence_number=1,
                    role="CUSTOMER_ACCESS",
                    metadata_={},
                )
                db.add(sector)
                await db.flush()

                rows = (await db.scalars(select(DeviceType).where(DeviceType.code.in_(["SECTOR", "CPE", "ACCESS_POINT"])))).all()
                types = {row.code: row for row in rows}
                assert set(types) == {"SECTOR", "CPE", "ACCESS_POINT"}

                def new_device(code: str, label: str, operational: str) -> Device:
                    return Device(
                        device_type_id=types[code].id,
                        display_name=f"{label} {marker}",
                        hostname=f"{label.lower()}-{marker}",
                        lifecycle_state="REGISTERED",
                        operational_state=operational,
                        metadata_={},
                    )

                sector_device = new_device("SECTOR", "LIVE-SECTOR", "UP")
                cpe = new_device("CPE", "LIVE-CPE", "DEGRADED")
                ap = new_device("ACCESS_POINT", "LIVE-AP", "DOWN")
                db.add_all([sector_device, cpe, ap])
                await db.flush()

                await create_domain_placement(db, sector_device, "SECTOR", location_id=None, sector_id=sector.id, parent_device_id=None)
                await db.flush()
                await create_domain_placement(db, cpe, "CPE", location_id=None, sector_id=None, parent_device_id=sector_device.id)
                await db.flush()
                await create_domain_placement(db, ap, "ACCESS_POINT", location_id=None, sector_id=None, parent_device_id=cpe.id)
                await db.flush()

                result = await get_sector_live_topology(sector.id, db)
                assert result.network.id == network.id
                assert result.city.id == city.id
                assert result.location.id == location.id
                assert result.sector.id == sector.id
                assert len(result.sector.devices) == 1
                root = result.sector.devices[0]
                assert root.device_type_code == "SECTOR"
                assert root.operational_state == "UP"
                assert len(root.children) == 1
                assert root.children[0].device_type_code == "CPE"
                assert root.children[0].operational_state == "DEGRADED"
                assert root.children[0].children[0].device_type_code == "ACCESS_POINT"
                assert root.children[0].children[0].operational_state == "DOWN"
            finally:
                await transaction.rollback()
        await engine.dispose()

    asyncio.run(scenario())
