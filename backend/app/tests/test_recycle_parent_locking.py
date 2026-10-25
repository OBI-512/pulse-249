"""Real PostgreSQL races proving active-parent locks serialize with recycle."""

from __future__ import annotations

import asyncio
from uuid import uuid4

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.models import (
    City,
    Device,
    DeviceHierarchyLink,
    DeviceIP,
    DevicePlacement,
    DeviceType,
    Location,
    Network,
    Sector,
)
from app.services.device_domain import create_domain_placement
from app.services.device_registration import register_domain_device
from app.services.movement import move_sector_to_location
from app.services.recycle_bin import RecycleBinError, recycle_entity
from app.settings import settings


def _run(coroutine):
    asyncio.run(coroutine)


async def _recycle_in_separate_transaction(
    factory,
    *,
    started: asyncio.Event,
    entity_type: str,
    entity_id,
    confirmed: bool = False,
):
    async with factory() as db:
        started.set()
        try:
            await recycle_entity(
                db,
                entity_type=entity_type,
                entity_id=entity_id,
                actor_user_id=None,
                confirmed=confirmed,
            )
            await db.commit()
            return None
        except RecycleBinError as exc:
            await db.rollback()
            return exc


async def _cleanup_geography(factory, ids):
    async with factory() as db:
        await db.execute(
            delete(DeviceHierarchyLink).where(
                DeviceHierarchyLink.parent_device_id.in_(ids["device_ids"])
                | DeviceHierarchyLink.child_device_id.in_(ids["device_ids"])
            )
        )
        await db.execute(
            delete(DevicePlacement).where(
                DevicePlacement.device_id.in_(ids["device_ids"])
            )
        )
        await db.execute(
            delete(DeviceIP).where(DeviceIP.device_id.in_(ids["device_ids"]))
        )
        if ids.get("sector_id"):
            await db.execute(delete(Sector).where(Sector.id == ids["sector_id"]))
        await db.execute(delete(Device).where(Device.id.in_(ids["device_ids"])))
        await db.execute(delete(Location).where(Location.id == ids["location_id"]))
        await db.execute(delete(City).where(City.id == ids["city_id"]))
        await db.execute(delete(Network).where(Network.id == ids["network_id"]))
        await db.commit()


def test_independent_placement_and_location_recycle_serialize_without_orphan():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        ids = {"device_ids": []}
        try:
            suffix = uuid4().hex[:10]
            async with factory() as setup:
                network = Network(name=f"Lock Network {suffix}", code=f"LKN-{suffix}")
                setup.add(network)
                await setup.flush()
                city = City(
                    network_id=network.id,
                    name=f"Lock City {suffix}",
                    code=f"LKC-{suffix}",
                )
                setup.add(city)
                await setup.flush()
                location = Location(
                    city_id=city.id,
                    name=f"Lock Location {suffix}",
                    code=f"LKL-{suffix}",
                    metadata_={},
                )
                setup.add(location)
                switch_type = await setup.scalar(
                    select(DeviceType).where(DeviceType.code == "SWITCH")
                )
                assert switch_type is not None
                device = Device(
                    device_type_id=switch_type.id,
                    display_name=f"Lock Switch {suffix}",
                    lifecycle_state="REGISTERED",
                    operational_state="UNKNOWN",
                    metadata_={},
                )
                setup.add(device)
                await setup.commit()
                ids.update(
                    network_id=network.id,
                    city_id=city.id,
                    location_id=location.id,
                    device_ids=[device.id],
                )

            async with factory() as placement_tx:
                device = await placement_tx.scalar(
                    select(Device).where(Device.id == ids["device_ids"][0])
                )
                assert device is not None
                await create_domain_placement(
                    placement_tx,
                    device,
                    "SWITCH",
                    location_id=ids["location_id"],
                    parent_device_id=None,
                )
                await placement_tx.flush()

                started = asyncio.Event()
                recycle_task = asyncio.create_task(
                    _recycle_in_separate_transaction(
                        factory,
                        started=started,
                        entity_type="LOCATION",
                        entity_id=ids["location_id"],
                    )
                )
                await started.wait()
                await asyncio.sleep(0.15)
                assert not recycle_task.done(), "recycle did not wait for the placement parent lock"
                await placement_tx.commit()

            error = await asyncio.wait_for(recycle_task, timeout=5)
            assert error is not None
            assert error.code == "RECYCLE_DEPENDENCIES_PRESENT"
            assert any(
                conflict["code"] == "LOCATION_HAS_PLACED_DEVICES"
                for conflict in error.conflicts
            )

            async with factory() as verify:
                assert await verify.scalar(
                    select(Location.id).where(Location.id == ids["location_id"])
                ) == ids["location_id"]
                assert await verify.scalar(
                    select(DevicePlacement.id).where(
                        DevicePlacement.device_id == ids["device_ids"][0]
                    )
                ) is not None
        finally:
            if ids.get("network_id"):
                await _cleanup_geography(factory, ids)
            await engine.dispose()

    _run(scenario())


def test_cpe_registration_and_sector_recycle_serialize_without_orphan():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        ids = {"device_ids": []}
        try:
            suffix = uuid4().hex[:10]
            async with factory() as setup:
                network = Network(name=f"Reg Lock Network {suffix}", code=f"RLN-{suffix}")
                setup.add(network)
                await setup.flush()
                city = City(network_id=network.id, name=f"Reg Lock City {suffix}", code=f"RLC-{suffix}")
                setup.add(city)
                await setup.flush()
                location = Location(
                    city_id=city.id,
                    name=f"Reg Lock Location {suffix}",
                    code=f"RLL-{suffix}",
                    metadata_={},
                )
                setup.add(location)
                await setup.flush()
                sector_type = await setup.scalar(select(DeviceType).where(DeviceType.code == "SECTOR"))
                cpe_type = await setup.scalar(select(DeviceType).where(DeviceType.code == "CPE"))
                assert sector_type is not None and cpe_type is not None
                sector_device = Device(
                    device_type_id=sector_type.id,
                    display_name=f"Reg Lock Sector Device {suffix}",
                    lifecycle_state="REGISTERED",
                    operational_state="UNKNOWN",
                    metadata_={},
                )
                setup.add(sector_device)
                await setup.flush()
                sector = Sector(
                    location_id=location.id,
                    name=f"Reg Lock Sector {suffix}",
                    code=f"RLS-{suffix}",
                    role="CUSTOMER_ACCESS",
                    sector_device_id=sector_device.id,
                    metadata_={},
                )
                setup.add(sector)
                setup.add(
                    DevicePlacement(
                        device_id=sector_device.id,
                        network_id=network.id,
                        city_id=city.id,
                        location_id=location.id,
                        sector_id=sector.id,
                        metadata_={"placement_mode": "DERIVED"},
                    )
                )
                await setup.commit()
                ids.update(
                    network_id=network.id,
                    city_id=city.id,
                    location_id=location.id,
                    sector_id=sector.id,
                    sector_device_id=sector_device.id,
                    cpe_type_id=cpe_type.id,
                    device_ids=[sector_device.id],
                )

            async with factory() as registration_tx:
                result = await register_domain_device(
                    registration_tx,
                    device_type_id=ids["cpe_type_id"],
                    display_name=f"Concurrent CPE {suffix}",
                    management_ip=f"fd00::{suffix[:4]}:{suffix[4:8]}",
                    location_id=None,
                    sector_id=None,
                    parent_device_id=ids["sector_device_id"],
                    ip_source="CONCURRENCY_TEST",
                )
                await registration_tx.flush()
                ids["device_ids"].append(result.device.id)

                started = asyncio.Event()
                recycle_task = asyncio.create_task(
                    _recycle_in_separate_transaction(
                        factory,
                        started=started,
                        entity_type="SECTOR",
                        entity_id=ids["sector_id"],
                        confirmed=True,
                    )
                )
                await started.wait()
                await asyncio.sleep(0.15)
                assert not recycle_task.done(), "recycle did not wait for registration locks"
                await registration_tx.commit()

            error = await asyncio.wait_for(recycle_task, timeout=5)
            assert error is not None
            assert error.code == "RECYCLE_DEPENDENCIES_PRESENT"
            assert any(
                conflict["code"] == "SECTOR_HAS_CPE_DEPENDENCIES"
                for conflict in error.conflicts
            )

            async with factory() as verify:
                assert await verify.scalar(
                    select(Sector.id).where(Sector.id == ids["sector_id"])
                ) == ids["sector_id"]
                assert await verify.scalar(
                    select(DeviceHierarchyLink.id).where(
                        DeviceHierarchyLink.child_device_id == ids["device_ids"][1]
                    )
                ) is not None
        finally:
            if ids.get("network_id"):
                await _cleanup_geography(factory, ids)
            await engine.dispose()

    _run(scenario())


def test_sector_movement_and_destination_location_recycle_serialize_without_orphan():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        ids = {}
        try:
            suffix = uuid4().hex[:10]
            async with factory() as setup:
                network = Network(name=f"Move Lock Network {suffix}", code=f"MLN-{suffix}")
                setup.add(network)
                await setup.flush()
                city = City(
                    network_id=network.id,
                    name=f"Move Lock City {suffix}",
                    code=f"MLC-{suffix}",
                )
                setup.add(city)
                await setup.flush()
                source = Location(
                    city_id=city.id,
                    name=f"Move Lock Source {suffix}",
                    code=f"MLS-{suffix}",
                    metadata_={},
                )
                destination = Location(
                    city_id=city.id,
                    name=f"Move Lock Destination {suffix}",
                    code=f"MLD-{suffix}",
                    metadata_={},
                )
                setup.add_all([source, destination])
                await setup.flush()
                sector = Sector(
                    location_id=source.id,
                    name=f"Move Lock Sector {suffix}",
                    code=f"MLSE-{suffix}",
                    sequence_number=1,
                    role="CUSTOMER_ACCESS",
                    metadata_={},
                )
                setup.add(sector)
                await setup.commit()
                ids.update(
                    network_id=network.id,
                    city_id=city.id,
                    source_location_id=source.id,
                    destination_location_id=destination.id,
                    sector_id=sector.id,
                )

            async with factory() as movement_tx:
                moved = await move_sector_to_location(
                    movement_tx,
                    sector_id=ids["sector_id"],
                    destination_location_id=ids["destination_location_id"],
                )
                await movement_tx.flush()
                assert moved.location_id == ids["destination_location_id"]

                started = asyncio.Event()
                recycle_task = asyncio.create_task(
                    _recycle_in_separate_transaction(
                        factory,
                        started=started,
                        entity_type="LOCATION",
                        entity_id=ids["destination_location_id"],
                    )
                )
                await started.wait()
                await asyncio.sleep(0.15)
                assert not recycle_task.done(), "recycle did not wait for the movement destination lock"
                await movement_tx.commit()

            error = await asyncio.wait_for(recycle_task, timeout=5)
            assert error is not None
            assert error.code == "RECYCLE_DEPENDENCIES_PRESENT"
            assert any(
                conflict["code"] == "LOCATION_HAS_SECTORS"
                for conflict in error.conflicts
            )

            async with factory() as verify:
                assert await verify.scalar(
                    select(Location.id).where(
                        Location.id == ids["destination_location_id"]
                    )
                ) == ids["destination_location_id"]
                assert await verify.scalar(
                    select(Sector.location_id).where(Sector.id == ids["sector_id"])
                ) == ids["destination_location_id"]
        finally:
            if ids.get("network_id"):
                async with factory() as cleanup:
                    await cleanup.execute(delete(Sector).where(Sector.id == ids["sector_id"]))
                    await cleanup.execute(
                        delete(Location).where(
                            Location.id.in_(
                                [
                                    ids["source_location_id"],
                                    ids["destination_location_id"],
                                ]
                            )
                        )
                    )
                    await cleanup.execute(delete(City).where(City.id == ids["city_id"]))
                    await cleanup.execute(delete(Network).where(Network.id == ids["network_id"]))
                    await cleanup.commit()
            await engine.dispose()

    _run(scenario())
