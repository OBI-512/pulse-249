from __future__ import annotations

import asyncio
from uuid import UUID, uuid4

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

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
    RecycleBinBatch,
    RecycleBinItem,
    Sector,
)
from app.services.recycle_bin import (
    RecycleBinError,
    purge_recycle_batch,
    recycle_entity,
    restore_recycle_batch,
)
from app.services.audit import enable_audit_maintenance
from app.services.sector_roles import SectorRoleTransitionError, transition_sector_role
from app.settings import settings


async def _cleanup(
    factory,
    *,
    batch_ids: list[UUID],
    audit_entity_ids: list[UUID],
    candidate_ids: list[UUID] = [],
    hierarchy_ids: list[UUID] = [],
    placement_ids: list[UUID] = [],
    ip_ids: list[UUID] = [],
    sector_ids: list[UUID] = [],
    device_ids: list[UUID] = [],
    city_ids: list[UUID] = [],
    location_ids: list[UUID] = [],
    network_ids: list[UUID] = [],
) -> None:
    """Remove only UUIDs created by a committed two-connection test."""

    async with factory() as db:
        if candidate_ids:
            await db.execute(delete(DeviceCandidate).where(DeviceCandidate.id.in_(candidate_ids)))
        if hierarchy_ids:
            await db.execute(delete(DeviceHierarchyLink).where(DeviceHierarchyLink.id.in_(hierarchy_ids)))
        if placement_ids:
            await db.execute(delete(DevicePlacement).where(DevicePlacement.id.in_(placement_ids)))
        if ip_ids:
            await db.execute(delete(DeviceIP).where(DeviceIP.id.in_(ip_ids)))
        if sector_ids:
            await db.execute(delete(Sector).where(Sector.id.in_(sector_ids)))
        if device_ids:
            await db.execute(delete(Device).where(Device.id.in_(device_ids)))
        if location_ids:
            await db.execute(delete(Location).where(Location.id.in_(location_ids)))
        if city_ids:
            await db.execute(delete(City).where(City.id.in_(city_ids)))
        if network_ids:
            await db.execute(delete(Network).where(Network.id.in_(network_ids)))
        if batch_ids:
            await db.execute(delete(RecycleBinItem).where(RecycleBinItem.batch_id.in_(batch_ids)))
            await db.execute(delete(RecycleBinBatch).where(RecycleBinBatch.id.in_(batch_ids)))
        if audit_entity_ids:
            await enable_audit_maintenance(db)
            await db.execute(delete(AuditLog).where(AuditLog.entity_id.in_(audit_entity_ids)))
        await db.commit()


def test_parent_recycle_waits_for_child_restore_then_observes_dependency():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        marker = uuid4().hex[:12]
        network_id = city_id = batch_id = None
        try:
            async with factory() as db:
                network = Network(
                    name=f"Concurrent parent {marker}",
                    code=f"CON-P-{marker}",
                    status="ACTIVE",
                )
                db.add(network)
                await db.flush()
                city = City(
                    network_id=network.id,
                    name=f"Concurrent child {marker}",
                    code=f"CON-C-{marker}",
                    status="ACTIVE",
                )
                db.add(city)
                await db.flush()
                batch = await recycle_entity(
                    db,
                    entity_type="CITY",
                    entity_id=city.id,
                    actor_user_id=None,
                )
                network_id, city_id, batch_id = network.id, city.id, batch.id
                await db.commit()

            async with factory() as restoring, factory() as deleting:
                await restore_recycle_batch(
                    restoring,
                    batch_id=batch_id,
                    actor_user_id=None,
                )

                async def try_parent_recycle():
                    try:
                        await recycle_entity(
                            deleting,
                            entity_type="NETWORK",
                            entity_id=network_id,
                            actor_user_id=None,
                        )
                        await deleting.commit()
                        return None
                    except Exception as exc:
                        await deleting.rollback()
                        return exc

                pending = asyncio.create_task(try_parent_recycle())
                await asyncio.sleep(0.2)
                assert not pending.done(), "parent recycle did not wait for restore's parent lock"
                await restoring.commit()
                result = await asyncio.wait_for(pending, timeout=5)
                assert isinstance(result, RecycleBinError)
                assert result.code == "RECYCLE_DEPENDENCIES_PRESENT"
                assert any(conflict["code"] == "NETWORK_HAS_CITIES" for conflict in result.conflicts)
        finally:
            if all(value is not None for value in (network_id, city_id, batch_id)):
                await _cleanup(
                    factory,
                    batch_ids=[batch_id],
                    audit_entity_ids=[city_id, network_id],
                    city_ids=[city_id],
                    network_ids=[network_id],
                )
            await engine.dispose()

    asyncio.run(scenario())


def test_candidate_fk_update_before_purge_lock_is_observed_detached_and_preserved():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        ids: dict[str, UUID] = {}
        try:
            async with factory() as setup:
                marker = uuid4().hex[:12]
                switch_type = await setup.scalar(
                    select(DeviceType).where(DeviceType.code == "SWITCH")
                )
                assert switch_type is not None
                device = Device(
                    device_type_id=switch_type.id,
                    display_name=f"Candidate purge race {marker}",
                    lifecycle_state="DECOMMISSIONED",
                    operational_state="UNKNOWN",
                    metadata_={},
                )
                setup.add(device)
                await setup.flush()
                management_ip = DeviceIP(
                    device_id=device.id,
                    ip_address=f"fd98::{marker}",
                    address_family=6,
                    is_management=True,
                    is_primary=True,
                    source="CONCURRENCY_TEST",
                )
                setup.add(management_ip)
                await setup.flush()
                batch = await recycle_entity(
                    setup,
                    entity_type="DEVICE",
                    entity_id=device.id,
                    actor_user_id=None,
                )
                ids = {
                    "device": device.id,
                    "ip": management_ip.id,
                    "batch": batch.id,
                }
                await setup.commit()

            async with factory() as candidate_tx, factory() as purge_tx:
                candidate = DeviceCandidate(
                    ip_address=f"fd99::{uuid4().hex[:12]}",
                    state="DUPLICATE",
                    confidence=1.0,
                    duplicate_device_id=ids["device"],
                    metadata_={},
                )
                candidate_tx.add(candidate)
                await candidate_tx.flush()
                ids["candidate"] = candidate.id

                async def try_purge():
                    try:
                        await purge_recycle_batch(
                            purge_tx,
                            batch_id=ids["batch"],
                            actor_user_id=None,
                            enforce_retention=False,
                        )
                        await purge_tx.commit()
                        return None
                    except Exception as exc:
                        await purge_tx.rollback()
                        return exc

                pending = asyncio.create_task(try_purge())
                await asyncio.sleep(0.2)
                assert not pending.done(), "purge did not wait for the candidate FK parent lock"
                await candidate_tx.commit()

                result = await asyncio.wait_for(pending, timeout=5)
                assert result is None

            async with factory() as verify:
                retained = await verify.get(DeviceCandidate, ids["candidate"])
                assert retained is not None
                assert retained.duplicate_device_id is None
                hidden_device = await verify.scalar(
                    select(Device)
                    .where(Device.id == ids["device"])
                    .execution_options(include_recycled=True)
                )
                assert hidden_device is None
                assert await verify.get(RecycleBinBatch, ids["batch"]) is None
        finally:
            if ids:
                await _cleanup(
                    factory,
                    batch_ids=[ids["batch"]],
                    audit_entity_ids=[ids["device"]],
                    candidate_ids=[ids["candidate"]] if ids.get("candidate") else [],
                    ip_ids=[ids["ip"]],
                    device_ids=[ids["device"]],
                )
            await engine.dispose()

    asyncio.run(scenario())

def test_cpe_restore_serializes_with_sector_role_transition():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        ids: dict[str, UUID] = {}
        try:
            async with factory() as db:
                marker = uuid4().hex[:12]
                network = Network(name=f"Role lock {marker}", code=f"RLN-{marker}", status="ACTIVE")
                db.add(network)
                await db.flush()
                city = City(
                    network_id=network.id,
                    name=f"Role lock city {marker}",
                    code=f"RLC-{marker}",
                    status="ACTIVE",
                )
                db.add(city)
                await db.flush()
                location = Location(
                    city_id=city.id,
                    name=f"Role lock location {marker}",
                    code=f"RLL-{marker}",
                    status="ACTIVE",
                    metadata_={},
                )
                db.add(location)
                await db.flush()
                sector_type = await db.scalar(select(DeviceType).where(DeviceType.code == "SECTOR"))
                cpe_type = await db.scalar(select(DeviceType).where(DeviceType.code == "CPE"))
                assert sector_type is not None and cpe_type is not None
                sector_device = Device(
                    device_type_id=sector_type.id,
                    display_name=f"Role lock sector {marker}",
                    lifecycle_state="REGISTERED",
                    operational_state="UNKNOWN",
                    metadata_={},
                )
                cpe = Device(
                    device_type_id=cpe_type.id,
                    display_name=f"Role lock CPE {marker}",
                    lifecycle_state="DECOMMISSIONED",
                    operational_state="UNKNOWN",
                    metadata_={},
                )
                db.add_all([sector_device, cpe])
                await db.flush()
                sector = Sector(
                    location_id=location.id,
                    name=f"Role lock sector {marker}",
                    code=f"RLS-{marker}",
                    status="ACTIVE",
                    role="CUSTOMER_ACCESS",
                    sector_device_id=sector_device.id,
                    metadata_={},
                )
                db.add(sector)
                await db.flush()
                sector_ip = DeviceIP(
                    device_id=sector_device.id,
                    ip_address=f"fd10::{marker}",
                    address_family=6,
                    is_management=True,
                    is_primary=True,
                    source="MANUAL",
                )
                cpe_ip = DeviceIP(
                    device_id=cpe.id,
                    ip_address=f"fd11::{marker}",
                    address_family=6,
                    is_management=True,
                    is_primary=True,
                    source="MANUAL",
                )
                sector_placement = DevicePlacement(
                    device_id=sector_device.id,
                    network_id=network.id,
                    city_id=city.id,
                    location_id=location.id,
                    sector_id=sector.id,
                    metadata_={"placement_mode": "DERIVED", "derived_from": "SECTOR"},
                )
                cpe_placement = DevicePlacement(
                    device_id=cpe.id,
                    network_id=network.id,
                    city_id=city.id,
                    location_id=location.id,
                    sector_id=sector.id,
                    metadata_={"placement_mode": "DERIVED", "derived_from": "SECTOR_CPE"},
                )
                cpe_link = DeviceHierarchyLink(
                    parent_device_id=sector_device.id,
                    child_device_id=cpe.id,
                    relationship_type="SECTOR_CPE",
                )
                db.add_all([sector_ip, cpe_ip, sector_placement, cpe_placement, cpe_link])
                await db.flush()
                batch = await recycle_entity(
                    db,
                    entity_type="DEVICE",
                    entity_id=cpe.id,
                    actor_user_id=None,
                )
                ids = {
                    "network": network.id,
                    "city": city.id,
                    "location": location.id,
                    "sector_device": sector_device.id,
                    "cpe": cpe.id,
                    "sector": sector.id,
                    "sector_ip": sector_ip.id,
                    "cpe_ip": cpe_ip.id,
                    "sector_placement": sector_placement.id,
                    "cpe_placement": cpe_placement.id,
                    "cpe_link": cpe_link.id,
                    "batch": batch.id,
                }
                await db.commit()

            async with factory() as restoring, factory() as transitioning:
                await restore_recycle_batch(
                    restoring,
                    batch_id=ids["batch"],
                    actor_user_id=None,
                )

                async def try_role_transition():
                    try:
                        await transition_sector_role(
                            transitioning,
                            sector_id=ids["sector"],
                            target_role="BACKHAUL",
                        )
                        await transitioning.commit()
                        return None
                    except Exception as exc:
                        await transitioning.rollback()
                        return exc

                pending = asyncio.create_task(try_role_transition())
                await asyncio.sleep(0.2)
                assert not pending.done(), "role transition did not wait for restore's Sector lock"
                await restoring.commit()
                result = await asyncio.wait_for(pending, timeout=5)
                assert isinstance(result, SectorRoleTransitionError)
                assert result.code == "SECTOR_HAS_CUSTOMER_DEPENDENCIES"
        finally:
            if ids:
                await _cleanup(
                    factory,
                    batch_ids=[ids["batch"]],
                    audit_entity_ids=[ids["cpe"], ids["sector"]],
                    hierarchy_ids=[ids["cpe_link"]],
                    placement_ids=[ids["cpe_placement"], ids["sector_placement"]],
                    ip_ids=[ids["cpe_ip"], ids["sector_ip"]],
                    sector_ids=[ids["sector"]],
                    device_ids=[ids["cpe"], ids["sector_device"]],
                    location_ids=[ids["location"]],
                    city_ids=[ids["city"]],
                    network_ids=[ids["network"]],
                )
            await engine.dispose()

    asyncio.run(scenario())
