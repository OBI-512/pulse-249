from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.models import (
    AuditLog,
    City,
    Customer,
    CustomerService,
    Device,
    DeviceCandidate,
    DeviceGroup,
    DeviceGroupMembership,
    DeviceHierarchyLink,
    DeviceIP,
    DeviceInterface,
    DevicePlacement,
    DeviceRelationship,
    DeviceType,
    Location,
    Network,
    RecycleBinBatch,
    RecycleBinItem,
    Sector,
)
from app.services.crud import get_or_404
from app.services.recycle_bin import (
    PURGE_FAILED,
    RECYCLED,
    RESTORED,
    RecycleBinError,
    purge_due_batches,
    purge_recycle_batch,
    recycle_entity,
    restore_recycle_batch,
    _recycle_audit_action,
)
from app.services.sector_roles import SectorRoleTransitionError, transition_sector_role
from app.services.device_ips import apply_ip_flags
from app.settings import settings


async def _run_isolated(scenario) -> None:
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    async with engine.connect() as connection:
        transaction = await connection.begin()
        factory = async_sessionmaker(
            bind=connection,
            class_=AsyncSession,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        )
        try:
            await scenario(factory)
        finally:
            await transaction.rollback()
    await engine.dispose()


async def _type(db: AsyncSession, code: str) -> DeviceType:
    row = await db.scalar(select(DeviceType).where(DeviceType.code == code))
    assert row is not None
    return row


async def _geo(db: AsyncSession) -> tuple[Network, City, Location]:
    marker = uuid4().hex[:12]
    network = Network(name=f"Recycle Network {marker}", code=f"RCN-{marker}", status="ACTIVE")
    db.add(network)
    await db.flush()
    city = City(
        network_id=network.id,
        name=f"Recycle City {marker}",
        code=f"RCC-{marker}",
        status="ACTIVE",
    )
    db.add(city)
    await db.flush()
    location = Location(
        city_id=city.id,
        name=f"Recycle Location {marker}",
        code=f"RCL-{marker}",
        status="ACTIVE",
        metadata_={},
    )
    db.add(location)
    await db.flush()
    return network, city, location


async def _device(
    db: AsyncSession,
    code: str,
    *,
    lifecycle_state: str = "DECOMMISSIONED",
    management_ip: str | None = None,
) -> tuple[Device, DeviceIP]:
    device_type = await _type(db, code)
    marker = uuid4().hex[:12]
    device = Device(
        device_type_id=device_type.id,
        display_name=f"Recycle {code} {marker}",
        hostname=f"recycle-{marker}",
        lifecycle_state=lifecycle_state,
        operational_state="UNKNOWN",
        metadata_={},
    )
    db.add(device)
    await db.flush()
    ip = DeviceIP(
        device_id=device.id,
        ip_address=management_ip or f"fd00::{marker}",
        address_family=6,
        is_management=True,
        is_primary=True,
        source="MANUAL",
    )
    db.add(ip)
    await db.flush()
    return device, ip


async def _place(
    db: AsyncSession,
    device: Device,
    network: Network,
    city: City,
    location: Location,
    sector: Sector | None = None,
    *,
    derived_from: str | None = None,
) -> DevicePlacement:
    metadata = {"placement_mode": "INDEPENDENT"}
    if derived_from:
        metadata = {"placement_mode": "DERIVED", "derived_from": derived_from}
    placement = DevicePlacement(
        device_id=device.id,
        network_id=network.id,
        city_id=city.id,
        location_id=location.id,
        sector_id=sector.id if sector else None,
        metadata_=metadata,
    )
    db.add(placement)
    await db.flush()
    return placement


async def _sector_hierarchy(db: AsyncSession, *, with_ap: bool = False) -> dict[str, object]:
    network, city, location = await _geo(db)
    sector_device, sector_ip = await _device(db, "SECTOR", lifecycle_state="REGISTERED")
    sector = Sector(
        location_id=location.id,
        name=f"Recycle Sector {uuid4().hex[:12]}",
        code=f"RCS-{uuid4().hex[:12]}",
        status="ACTIVE",
        role="CUSTOMER_ACCESS",
        sector_device_id=sector_device.id,
        metadata_={},
    )
    db.add(sector)
    await db.flush()
    await _place(db, sector_device, network, city, location, sector, derived_from="SECTOR")

    cpe, cpe_ip = await _device(db, "CPE")
    cpe_link = DeviceHierarchyLink(
        parent_device_id=sector_device.id,
        child_device_id=cpe.id,
        relationship_type="SECTOR_CPE",
    )
    db.add(cpe_link)
    await db.flush()
    await _place(db, cpe, network, city, location, sector, derived_from="SECTOR_CPE")
    result: dict[str, object] = {
        "network": network,
        "city": city,
        "location": location,
        "sector_device": sector_device,
        "sector_ip": sector_ip,
        "sector": sector,
        "cpe": cpe,
        "cpe_ip": cpe_ip,
        "cpe_link": cpe_link,
    }
    if with_ap:
        ap, ap_ip = await _device(db, "ACCESS_POINT")
        ap_link = DeviceHierarchyLink(
            parent_device_id=cpe.id,
            child_device_id=ap.id,
            relationship_type="CPE_ACCESS_POINT",
        )
        db.add(ap_link)
        await db.flush()
        await _place(db, ap, network, city, location, sector, derived_from="CPE_ACCESS_POINT")
        result.update(ap=ap, ap_ip=ap_ip, ap_link=ap_link)
    return result


async def _including_recycled(db: AsyncSession, model, object_id):
    return await db.scalar(
        select(model)
        .where(model.id == object_id)
        .execution_options(include_recycled=True)
    )


def test_recycle_retention_active_filter_same_session_restore_and_audits():
    async def scenario(factory):
        async with factory() as db:
            marker = uuid4().hex[:12]
            network = Network(name=f"Retention {marker}", code=f"RET-{marker}", status="ACTIVE")
            db.add(network)
            await db.flush()
            network_id = network.id
            timestamp = datetime(2030, 1, 2, 3, 4, tzinfo=timezone.utc)

            batch = await recycle_entity(
                db,
                entity_type="NETWORK",
                entity_id=network_id,
                actor_user_id=None,
                now=timestamp,
            )
            assert batch.purge_after == timestamp + timedelta(days=30)
            assert await db.scalar(select(Network).where(Network.id == network_id)) is None
            with pytest.raises(HTTPException) as missing:
                await get_or_404(db, Network, network_id)
            assert missing.value.status_code == 404
            hidden = await _including_recycled(db, Network, network_id)
            assert hidden is not None
            assert hidden.deleted_at == timestamp
            assert hidden.deletion_batch_id == batch.id
            assert await db.scalar(
                select(AuditLog.id).where(
                    AuditLog.action == "NETWORK_RECYCLED",
                    AuditLog.entity_id == network_id,
                )
            ) is not None

            restored = await restore_recycle_batch(
                db,
                batch_id=batch.id,
                actor_user_id=None,
                now=timestamp + timedelta(hours=1),
            )
            assert restored.status == RESTORED
            active = await db.scalar(select(Network).where(Network.id == network_id))
            assert active is not None
            assert active.deleted_at is None and active.deletion_batch_id is None
            assert await db.scalar(
                select(AuditLog.id).where(
                    AuditLog.action == "NETWORK_RESTORED",
                    AuditLog.entity_id == network_id,
                )
            ) is not None

    asyncio.run(_run_isolated(scenario))


def test_restore_identity_collision_is_structured_and_atomic():
    async def scenario(factory):
        async with factory() as db:
            marker = uuid4().hex[:12]
            original = Network(name="Original", code=f"COL-{marker}", status="ACTIVE")
            db.add(original)
            await db.flush()
            batch = await recycle_entity(
                db, entity_type="NETWORK", entity_id=original.id, actor_user_id=None
            )
            replacement = Network(name="Replacement", code=original.code, status="ACTIVE")
            db.add(replacement)
            await db.flush()

            with pytest.raises(RecycleBinError) as conflict:
                await restore_recycle_batch(db, batch_id=batch.id, actor_user_id=None)
            assert conflict.value.code == "RECYCLE_RESTORE_IDENTITY_CONFLICT"
            assert conflict.value.conflicts
            hidden = await _including_recycled(db, Network, original.id)
            assert hidden.deleted_at is not None and hidden.deletion_batch_id == batch.id
            assert (await db.get(RecycleBinBatch, batch.id)).status == RECYCLED
            assert await db.scalar(select(Network).where(Network.id == replacement.id)) is not None

    asyncio.run(_run_isolated(scenario))


def test_device_restore_rejects_reused_management_ip_and_rolls_back_bundle():
    async def scenario(factory):
        async with factory() as db:
            network, city, location = await _geo(db)
            reused_ip = f"fd00::{uuid4().hex[:12]}"
            original, original_ip = await _device(db, "SWITCH", management_ip=reused_ip)
            placement = await _place(db, original, network, city, location)
            batch = await recycle_entity(
                db, entity_type="DEVICE", entity_id=original.id, actor_user_id=None
            )
            replacement, _ = await _device(db, "SWITCH")
            db.add(
                DeviceIP(
                    device_id=replacement.id,
                    ip_address=reused_ip,
                    address_family=6,
                    is_management=False,
                    is_primary=False,
                    source="MANUAL",
                )
            )
            await db.flush()

            with pytest.raises(RecycleBinError) as conflict:
                await restore_recycle_batch(db, batch_id=batch.id, actor_user_id=None)
            assert conflict.value.code == "RECYCLE_RESTORE_IP_ADDRESS_CONFLICT"
            assert conflict.value.conflicts
            for model, object_id in (
                (Device, original.id),
                (DeviceIP, original_ip.id),
                (DevicePlacement, placement.id),
            ):
                row = await _including_recycled(db, model, object_id)
                assert row.deleted_at is not None and row.deletion_batch_id == batch.id
            assert (await db.get(RecycleBinBatch, batch.id)).status == RECYCLED

    asyncio.run(_run_isolated(scenario))


def test_restore_rejects_missing_parent_and_missing_management_ip():
    async def scenario(factory):
        async with factory() as db:
            marker = uuid4().hex[:12]
            network = Network(name="Hidden parent", code=f"HP-{marker}", status="ACTIVE")
            db.add(network)
            await db.flush()
            await recycle_entity(db, entity_type="NETWORK", entity_id=network.id, actor_user_id=None)
            city = City(network_id=network.id, name="Legacy child", code=f"HC-{marker}", status="ACTIVE")
            db.add(city)
            await db.flush()
            city_batch = await recycle_entity(db, entity_type="CITY", entity_id=city.id, actor_user_id=None)
            with pytest.raises(RecycleBinError) as missing_parent:
                await restore_recycle_batch(db, batch_id=city_batch.id, actor_user_id=None)
            assert missing_parent.value.code == "RECYCLE_RESTORE_PARENT_MISSING"
            assert missing_parent.value.conflicts

            network2, city2, location2 = await _geo(db)
            switch, ip = await _device(db, "SWITCH")
            await _place(db, switch, network2, city2, location2)
            device_batch = await recycle_entity(
                db, entity_type="DEVICE", entity_id=switch.id, actor_user_id=None
            )
            # Keep the database invariant valid while simulating a malformed
            # historical recycle bundle: the row is no longer primary before
            # it loses management status.
            ip.is_primary = False
            ip.is_management = False
            await db.flush()
            with pytest.raises(RecycleBinError) as missing_ip:
                await restore_recycle_batch(db, batch_id=device_batch.id, actor_user_id=None)
            assert missing_ip.value.code == "RECYCLE_RESTORE_MANAGEMENT_IP_REQUIRED"
            assert missing_ip.value.conflicts

    asyncio.run(_run_isolated(scenario))


def test_cpe_and_access_point_restore_detect_hierarchy_and_ap_slot_conflicts():
    async def scenario(factory):
        async with factory() as db:
            hierarchy = await _sector_hierarchy(db)
            cpe: Device = hierarchy["cpe"]
            cpe_batch = await recycle_entity(
                db, entity_type="DEVICE", entity_id=cpe.id, actor_user_id=None
            )
            other = await _sector_hierarchy(db)
            db.add(
                DeviceHierarchyLink(
                    parent_device_id=other["sector_device"].id,
                    child_device_id=cpe.id,
                    relationship_type="SECTOR_CPE",
                )
            )
            await db.flush()
            with pytest.raises(RecycleBinError) as hierarchy_conflict:
                await restore_recycle_batch(db, batch_id=cpe_batch.id, actor_user_id=None)
            assert hierarchy_conflict.value.code == "RECYCLE_RESTORE_HIERARCHY_CONFLICT"
            assert hierarchy_conflict.value.conflicts

        # A separate savepoint scenario avoids the intentionally conflicting
        # CPE row affecting the access-point slot case.
        async with factory() as db:
            hierarchy = await _sector_hierarchy(db, with_ap=True)
            ap: Device = hierarchy["ap"]
            ap_batch = await recycle_entity(
                db, entity_type="DEVICE", entity_id=ap.id, actor_user_id=None
            )
            replacement, _ = await _device(db, "ACCESS_POINT", lifecycle_state="REGISTERED")
            db.add(
                DeviceHierarchyLink(
                    parent_device_id=hierarchy["cpe"].id,
                    child_device_id=replacement.id,
                    relationship_type="CPE_ACCESS_POINT",
                )
            )
            await db.flush()
            with pytest.raises(RecycleBinError) as ap_conflict:
                await restore_recycle_batch(db, batch_id=ap_batch.id, actor_user_id=None)
            assert ap_conflict.value.code == "RECYCLE_RESTORE_AP_SLOT_CONFLICT"
            assert ap_conflict.value.conflicts

    asyncio.run(_run_isolated(scenario))


def test_customer_service_and_group_restore_revalidate_current_domain():
    async def scenario(factory):
        async with factory() as db:
            hierarchy = await _sector_hierarchy(db, with_ap=True)
            customer = Customer(
                customer_code=f"RCCUST-{uuid4().hex[:12]}",
                name="Recycle Customer",
                status="ACTIVE",
                metadata_={},
            )
            db.add(customer)
            await db.flush()
            service = CustomerService(
                customer_id=customer.id,
                sector_id=hierarchy["sector"].id,
                service_code=f"RCSV-{uuid4().hex[:12]}",
                status="ACTIVE",
                cpe_device_id=hierarchy["cpe"].id,
                access_point_device_id=hierarchy["ap"].id,
                metadata_={},
            )
            db.add(service)
            await db.flush()
            service_batch = await recycle_entity(
                db,
                entity_type="CUSTOMER_SERVICE",
                entity_id=service.id,
                actor_user_id=None,
            )
            replacement = CustomerService(
                customer_id=customer.id,
                sector_id=hierarchy["sector"].id,
                service_code=f"RCSV2-{uuid4().hex[:12]}",
                status="ACTIVE",
                cpe_device_id=hierarchy["cpe"].id,
                access_point_device_id=hierarchy["ap"].id,
                metadata_={},
            )
            db.add(replacement)
            await db.flush()
            with pytest.raises(RecycleBinError) as service_conflict:
                await restore_recycle_batch(db, batch_id=service_batch.id, actor_user_id=None)
            assert service_conflict.value.code == "RECYCLE_RESTORE_CUSTOMER_SERVICE_CONFLICT"
            assert service_conflict.value.conflicts

        async with factory() as db:
            network, city, location = await _geo(db)
            switch, _ = await _device(db, "SWITCH", lifecycle_state="REGISTERED")
            await _place(db, switch, network, city, location)
            old_group = DeviceGroup(
                name=f"Old group {uuid4().hex[:12]}",
                code=f"OLD-{uuid4().hex[:12]}",
                scope_type="LOCATION",
                location_id=location.id,
                device_scope="ANY",
                metadata_={},
            )
            db.add(old_group)
            await db.flush()
            membership = DeviceGroupMembership(device_id=switch.id, group_id=old_group.id)
            db.add(membership)
            await db.flush()
            group_batch = await recycle_entity(
                db, entity_type="DEVICE_GROUP", entity_id=old_group.id, actor_user_id=None
            )
            old_group_id = old_group.id
            old_membership_id = membership.id
            new_group = DeviceGroup(
                name=f"New group {uuid4().hex[:12]}",
                code=f"NEW-{uuid4().hex[:12]}",
                scope_type="LOCATION",
                location_id=location.id,
                device_scope="ANY",
                metadata_={},
            )
            db.add(new_group)
            await db.flush()
            db.add(DeviceGroupMembership(device_id=switch.id, group_id=new_group.id))
            await db.flush()
            with pytest.raises(RecycleBinError) as group_conflict:
                await restore_recycle_batch(db, batch_id=group_batch.id, actor_user_id=None)
            assert group_conflict.value.code == "RECYCLE_RESTORE_VALIDATION_FAILED"
            assert group_conflict.value.conflicts
            hidden_group = await _including_recycled(db, DeviceGroup, old_group_id)
            hidden_membership = await _including_recycled(db, DeviceGroupMembership, old_membership_id)
            assert hidden_group.deleted_at is not None
            assert hidden_membership.deleted_at is not None

    asyncio.run(_run_isolated(scenario))


def test_explicit_bundle_purge_retention_reverse_order_and_audit():
    async def scenario(factory):
        async with factory() as db:
            network, city, location = await _geo(db)
            switch, ip = await _device(db, "SWITCH")
            placement = await _place(db, switch, network, city, location)
            timestamp = datetime(2001, 1, 1, tzinfo=timezone.utc)
            batch = await recycle_entity(
                db,
                entity_type="DEVICE",
                entity_id=switch.id,
                actor_user_id=None,
                now=timestamp,
            )
            with pytest.raises(RecycleBinError) as retained:
                await purge_recycle_batch(
                    db,
                    batch_id=batch.id,
                    actor_user_id=None,
                    now=timestamp + timedelta(days=29),
                )
            assert retained.value.code == "RECYCLE_RETENTION_NOT_EXPIRED"

            await purge_recycle_batch(
                db,
                batch_id=batch.id,
                actor_user_id=None,
                now=timestamp + timedelta(days=1),
                enforce_retention=False,
            )
            for model, object_id in (
                (Device, switch.id),
                (DeviceIP, ip.id),
                (DevicePlacement, placement.id),
            ):
                assert await _including_recycled(db, model, object_id) is None
            assert await db.get(RecycleBinBatch, batch.id) is None
            assert await db.scalar(
                select(AuditLog.id).where(
                    AuditLog.action == "DEVICE_PURGED",
                    AuditLog.entity_id == switch.id,
                )
            ) is not None

    asyncio.run(_run_isolated(scenario))


def test_automatic_purge_isolates_failure_and_records_stable_diagnostics():
    async def scenario(factory):
        async with factory() as db:
            timestamp = datetime(2002, 1, 1, tzinfo=timezone.utc)
            ok = Network(name="Due success", code=f"DUE-OK-{uuid4().hex[:10]}", status="ACTIVE")
            blocked = Network(name="Due blocked", code=f"DUE-B-{uuid4().hex[:10]}", status="ACTIVE")
            db.add_all([ok, blocked])
            await db.flush()
            ok_batch = await recycle_entity(
                db, entity_type="NETWORK", entity_id=ok.id, actor_user_id=None, now=timestamp
            )
            blocked_batch = await recycle_entity(
                db, entity_type="NETWORK", entity_id=blocked.id, actor_user_id=None, now=timestamp
            )
            # Simulate a legacy/concurrent dependency that deterministic purge
            # must detect instead of allowing the FK to make the decision.
            db.add(
                City(
                    network_id=blocked.id,
                    name="Late dependency",
                    code=f"LATE-{uuid4().hex[:10]}",
                    status="ACTIVE",
                )
            )
            await db.flush()
            summary = await purge_due_batches(
                db,
                now=timestamp + timedelta(days=31),
                limit=10,
            )
            assert summary.considered == 2
            assert summary.purged == 1
            assert summary.failed == 1
            assert summary.batch_ids == [ok_batch.id]
            assert await db.get(RecycleBinBatch, ok_batch.id) is None
            failed_batch = await db.get(RecycleBinBatch, blocked_batch.id)
            assert failed_batch.status == PURGE_FAILED
            assert failed_batch.last_error_code == "RECYCLE_PURGE_DEPENDENCY_CONFLICT"
            assert failed_batch.last_error_message == "Permanent purge would affect dependencies outside this batch."
            assert "sql" not in failed_batch.last_error_message.lower()
            failed_audit = await db.scalar(
                select(AuditLog).where(
                    AuditLog.action == "RECYCLE_PURGE_FAILED",
                    AuditLog.entity_id == blocked.id,
                )
            )
            assert failed_audit is not None
            assert failed_audit.result == "FAILURE"
            assert failed_audit.metadata_["error_code"] == "RECYCLE_PURGE_DEPENDENCY_CONFLICT"

    asyncio.run(_run_isolated(scenario))


def test_group_recycle_audit_actions_use_the_public_group_prefix():
    assert _recycle_audit_action("DEVICE_GROUP", "RECYCLED") == "GROUP_RECYCLED"
    assert _recycle_audit_action("DEVICE_GROUP", "RESTORED") == "GROUP_RESTORED"
    assert _recycle_audit_action("DEVICE_GROUP", "PURGED") == "GROUP_PURGED"
    assert _recycle_audit_action("DEVICE", "RECYCLED") == "DEVICE_RECYCLED"


def test_sector_bound_device_bundle_restores_and_purges_as_one_pg_unit():
    async def scenario(factory):
        async with factory() as db:
            hierarchy = await _sector_hierarchy(db)
            sector: Sector = hierarchy["sector"]
            sector_device: Device = hierarchy["sector_device"]
            # Remove the CPE branch so the Sector is eligible as specified.
            await db.delete(hierarchy["cpe_link"])
            cpe_placement = await db.scalar(
                select(DevicePlacement).where(DevicePlacement.device_id == hierarchy["cpe"].id)
            )
            await db.delete(cpe_placement)
            await db.delete(hierarchy["cpe_ip"])
            await db.flush()
            await db.delete(hierarchy["cpe"])
            await db.flush()
            sector_placement = await db.scalar(
                select(DevicePlacement).where(DevicePlacement.device_id == sector_device.id)
            )
            first = await recycle_entity(
                db,
                entity_type="SECTOR",
                entity_id=sector.id,
                actor_user_id=None,
                confirmed=True,
            )
            first_items = list(
                (
                    await db.scalars(
                        select(RecycleBinItem).where(RecycleBinItem.batch_id == first.id)
                    )
                ).all()
            )
            assert {item.entity_type for item in first_items} == {
                "SECTOR",
                "DEVICE",
                "DEVICE_IP",
                "DEVICE_PLACEMENT",
            }
            orders = {item.entity_type: item.purge_order for item in first_items}
            assert orders["DEVICE_PLACEMENT"] < orders["SECTOR"] < orders["DEVICE"]
            assert orders["DEVICE_IP"] < orders["SECTOR"]
            assert await db.scalar(select(Sector).where(Sector.id == sector.id)) is None
            assert await db.scalar(select(Device).where(Device.id == sector_device.id)) is None

            await restore_recycle_batch(db, batch_id=first.id, actor_user_id=None)
            restored_sector = await db.scalar(select(Sector).where(Sector.id == sector.id))
            assert restored_sector is not None
            assert restored_sector.sector_device_id == sector_device.id
            assert await db.scalar(select(DeviceIP).where(DeviceIP.id == hierarchy["sector_ip"].id)) is not None
            assert await db.scalar(select(DevicePlacement).where(DevicePlacement.id == sector_placement.id)) is not None

            second = await recycle_entity(
                db,
                entity_type="SECTOR",
                entity_id=sector.id,
                actor_user_id=None,
                confirmed=True,
            )
            await purge_recycle_batch(
                db,
                batch_id=second.id,
                actor_user_id=None,
                enforce_retention=False,
            )
            for model, object_id in (
                (Sector, sector.id),
                (Device, sector_device.id),
                (DeviceIP, hierarchy["sector_ip"].id),
                (DevicePlacement, sector_placement.id),
            ):
                assert await _including_recycled(db, model, object_id) is None

    asyncio.run(_run_isolated(scenario))


def test_independent_device_full_bundle_restores_then_purges_components_first():
    async def scenario(factory):
        async with factory() as db:
            network, city, location = await _geo(db)
            root, root_ip = await _device(db, "SWITCH")
            target, _ = await _device(db, "ROUTER", lifecycle_state="REGISTERED")
            placement = await _place(db, root, network, city, location)
            interface = DeviceInterface(
                device_id=root.id,
                interface_name="ether1",
                interface_index=1,
                mac_address="020000000001",
                operational_status="UP",
                administrative_status="UP",
                metadata_={},
            )
            relationship = DeviceRelationship(
                source_device_id=root.id,
                target_device_id=target.id,
                relationship_type="UPLINK",
                direction="DIRECTED",
                metadata_={},
            )
            group = DeviceGroup(
                name=f"Bundle group {uuid4().hex[:12]}",
                code=f"BND-{uuid4().hex[:12]}",
                scope_type="GLOBAL",
                device_scope="ANY",
                metadata_={},
            )
            db.add_all([interface, relationship, group])
            await db.flush()
            membership = DeviceGroupMembership(device_id=root.id, group_id=group.id)
            db.add(membership)
            await db.flush()

            first = await recycle_entity(
                db,
                entity_type="DEVICE",
                entity_id=root.id,
                actor_user_id=None,
            )
            item_types = set(
                await db.scalars(
                    select(RecycleBinItem.entity_type).where(RecycleBinItem.batch_id == first.id)
                )
            )
            assert item_types == {
                "DEVICE",
                "DEVICE_IP",
                "DEVICE_INTERFACE",
                "DEVICE_PLACEMENT",
                "DEVICE_RELATIONSHIP",
                "DEVICE_GROUP_MEMBERSHIP",
            }
            await restore_recycle_batch(db, batch_id=first.id, actor_user_id=None)
            for model, object_id in (
                (Device, root.id),
                (DeviceIP, root_ip.id),
                (DeviceInterface, interface.id),
                (DevicePlacement, placement.id),
                (DeviceRelationship, relationship.id),
                (DeviceGroupMembership, membership.id),
            ):
                assert await db.scalar(select(model).where(model.id == object_id)) is not None

            second = await recycle_entity(
                db,
                entity_type="DEVICE",
                entity_id=root.id,
                actor_user_id=None,
            )
            await purge_recycle_batch(
                db,
                batch_id=second.id,
                actor_user_id=None,
                enforce_retention=False,
            )
            for model, object_id in (
                (Device, root.id),
                (DeviceIP, root_ip.id),
                (DeviceInterface, interface.id),
                (DevicePlacement, placement.id),
                (DeviceRelationship, relationship.id),
                (DeviceGroupMembership, membership.id),
            ):
                assert await _including_recycled(db, model, object_id) is None
            assert await db.scalar(select(Device).where(Device.id == target.id)) is not None
            assert await db.scalar(select(DeviceGroup).where(DeviceGroup.id == group.id)) is not None

    asyncio.run(_run_isolated(scenario))


def test_customer_service_and_group_successful_restore_paths():
    async def scenario(factory):
        async with factory() as db:
            hierarchy = await _sector_hierarchy(db, with_ap=True)
            customer = Customer(
                customer_code=f"OK-CUST-{uuid4().hex[:12]}",
                name="Successful restore customer",
                status="ACTIVE",
                metadata_={},
            )
            db.add(customer)
            await db.flush()
            service = CustomerService(
                customer_id=customer.id,
                sector_id=hierarchy["sector"].id,
                service_code=f"OK-SVC-{uuid4().hex[:12]}",
                status="ACTIVE",
                cpe_device_id=hierarchy["cpe"].id,
                access_point_device_id=hierarchy["ap"].id,
                metadata_={},
            )
            db.add(service)
            await db.flush()
            batch = await recycle_entity(
                db,
                entity_type="CUSTOMER_SERVICE",
                entity_id=service.id,
                actor_user_id=None,
            )
            await restore_recycle_batch(db, batch_id=batch.id, actor_user_id=None)
            restored = await db.scalar(select(CustomerService).where(CustomerService.id == service.id))
            assert restored is not None
            assert restored.cpe_device_id == hierarchy["cpe"].id
            assert restored.access_point_device_id == hierarchy["ap"].id

        async with factory() as db:
            network, city, location = await _geo(db)
            switch, _ = await _device(db, "SWITCH", lifecycle_state="REGISTERED")
            await _place(db, switch, network, city, location)
            group = DeviceGroup(
                name=f"Restore group {uuid4().hex[:12]}",
                code=f"RST-{uuid4().hex[:12]}",
                scope_type="LOCATION",
                location_id=location.id,
                device_scope="ANY",
                metadata_={},
            )
            db.add(group)
            await db.flush()
            membership = DeviceGroupMembership(device_id=switch.id, group_id=group.id)
            db.add(membership)
            await db.flush()
            batch = await recycle_entity(
                db,
                entity_type="DEVICE_GROUP",
                entity_id=group.id,
                actor_user_id=None,
            )
            await restore_recycle_batch(db, batch_id=batch.id, actor_user_id=None)
            assert await db.scalar(select(DeviceGroup).where(DeviceGroup.id == group.id)) is not None
            assert await db.scalar(
                select(DeviceGroupMembership).where(DeviceGroupMembership.id == membership.id)
            ) is not None

    asyncio.run(_run_isolated(scenario))


def test_purge_detaches_candidate_device_live_references_and_preserves_history():
    async def scenario(factory):
        async with factory() as db:
            device, device_ip = await _device(db, "SWITCH")
            candidates = [
                DeviceCandidate(
                    ip_address=f"fdff::{uuid4().hex[:12]}",
                    state="DUPLICATE",
                    confidence=1.0,
                    duplicate_device_id=device.id,
                    metadata_={},
                ),
                DeviceCandidate(
                    ip_address=f"fdff::{uuid4().hex[:12]}",
                    state="APPROVED",
                    confidence=1.0,
                    relationship_target_device_id=device.id,
                    metadata_={},
                ),
                DeviceCandidate(
                    ip_address=f"fdff::{uuid4().hex[:12]}",
                    state="REGISTERED",
                    confidence=1.0,
                    metadata_={
                        "registration": {
                            "device_id": str(device.id),
                            "ip_id": str(device_ip.id),
                        }
                    },
                ),
            ]
            db.add_all(candidates)
            await db.flush()
            candidate_ids = [candidate.id for candidate in candidates]

            batch = await recycle_entity(
                db,
                entity_type="DEVICE",
                entity_id=device.id,
                actor_user_id=None,
            )
            await purge_recycle_batch(
                db,
                batch_id=batch.id,
                actor_user_id=None,
                enforce_retention=False,
            )

            retained = list(
                (
                    await db.scalars(
                        select(DeviceCandidate).where(DeviceCandidate.id.in_(candidate_ids))
                    )
                ).all()
            )
            assert len(retained) == 3
            retained_by_id = {candidate.id: candidate for candidate in retained}
            assert retained_by_id[candidates[0].id].duplicate_device_id is None
            assert retained_by_id[candidates[1].id].relationship_target_device_id is None
            registration = retained_by_id[candidates[2].id].metadata_["registration"]
            assert registration["device_id"] == str(device.id)
            assert registration["ip_id"] == str(device_ip.id)
            assert await _including_recycled(db, Device, device.id) is None
            assert await _including_recycled(db, DeviceIP, device_ip.id) is None
            assert await db.get(RecycleBinBatch, batch.id) is None

    asyncio.run(_run_isolated(scenario))

def test_purge_preserves_registered_ip_metadata_history_without_blocking_purge():
    async def scenario(factory):
        async with factory() as db:
            device, registered_ip = await _device(db, "SWITCH", lifecycle_state="REGISTERED")
            replacement_ip = DeviceIP(
                device_id=device.id,
                ip_address=f"fdfd::{uuid4().hex[:12]}",
                address_family=6,
                is_management=True,
                is_primary=False,
                source="MANUAL",
            )
            db.add(replacement_ip)
            await db.flush()
            await apply_ip_flags(
                db,
                device_id=device.id,
                target=replacement_ip,
                is_management=True,
                is_primary=True,
            )
            await db.flush()
            candidate = DeviceCandidate(
                ip_address=f"fdfc::{uuid4().hex[:12]}",
                state="REGISTERED",
                confidence=1.0,
                metadata_={
                    "registration": {
                        "device_id": str(device.id),
                        "ip_id": str(registered_ip.id),
                    }
                },
            )
            db.add(candidate)
            await db.flush()

            batch = await recycle_entity(
                db,
                entity_type="DEVICE_IP",
                entity_id=registered_ip.id,
                actor_user_id=None,
            )
            await purge_recycle_batch(
                db,
                batch_id=batch.id,
                actor_user_id=None,
                enforce_retention=False,
            )

            retained = await db.get(DeviceCandidate, candidate.id)
            assert retained is not None
            assert retained.metadata_["registration"]["device_id"] == str(device.id)
            assert retained.metadata_["registration"]["ip_id"] == str(registered_ip.id)
            assert await _including_recycled(db, DeviceIP, registered_ip.id) is None
            assert await db.scalar(
                select(DeviceIP).where(DeviceIP.id == replacement_ip.id)
            ) is not None
            assert await db.get(RecycleBinBatch, batch.id) is None

    asyncio.run(_run_isolated(scenario))

def test_purge_detaches_candidate_geography_and_customer_live_references():
    async def scenario(factory):
        async with factory() as db:
            marker = uuid4().hex[:12]
            network_root = Network(
                name=f"Candidate network {marker}",
                code=f"CAN-N-{marker}",
                status="ACTIVE",
            )
            city_parent_network = Network(
                name=f"City parent {marker}",
                code=f"CAN-CN-{marker}",
                status="ACTIVE",
            )
            location_parent_network = Network(
                name=f"Location parent network {marker}",
                code=f"CAN-LN-{marker}",
                status="ACTIVE",
            )
            sector_parent_network = Network(
                name=f"Sector parent network {marker}",
                code=f"CAN-SN-{marker}",
                status="ACTIVE",
            )
            db.add_all(
                [
                    network_root,
                    city_parent_network,
                    location_parent_network,
                    sector_parent_network,
                ]
            )
            await db.flush()

            city_root = City(
                network_id=city_parent_network.id,
                name=f"Candidate city {marker}",
                code=f"CAN-C-{marker}",
                status="ACTIVE",
            )
            location_parent_city = City(
                network_id=location_parent_network.id,
                name=f"Location parent city {marker}",
                code=f"CAN-LC-{marker}",
                status="ACTIVE",
            )
            sector_parent_city = City(
                network_id=sector_parent_network.id,
                name=f"Sector parent city {marker}",
                code=f"CAN-SC-{marker}",
                status="ACTIVE",
            )
            db.add_all([city_root, location_parent_city, sector_parent_city])
            await db.flush()

            location_root = Location(
                city_id=location_parent_city.id,
                name=f"Candidate location {marker}",
                code=f"CAN-L-{marker}",
                status="ACTIVE",
                metadata_={},
            )
            sector_parent_location = Location(
                city_id=sector_parent_city.id,
                name=f"Sector parent location {marker}",
                code=f"CAN-SL-{marker}",
                status="ACTIVE",
                metadata_={},
            )
            db.add_all([location_root, sector_parent_location])
            await db.flush()

            sector_root = Sector(
                location_id=sector_parent_location.id,
                name=f"Candidate sector {marker}",
                code=f"CAN-S-{marker}",
                status="ACTIVE",
                role="CUSTOMER_ACCESS",
                metadata_={},
            )
            customer_root = Customer(
                customer_code=f"CAN-CUST-{marker}",
                name=f"Candidate customer {marker}",
                status="ACTIVE",
                metadata_={},
            )
            db.add_all([sector_root, customer_root])
            await db.flush()

            roots = [
                ("NETWORK", Network, network_root, "network_id"),
                ("CITY", City, city_root, "city_id"),
                ("LOCATION", Location, location_root, "location_id"),
                ("SECTOR", Sector, sector_root, "sector_id"),
                ("CUSTOMER", Customer, customer_root, "customer_id"),
            ]
            candidates: list[tuple[DeviceCandidate, str, object]] = []
            for entity_type, model, root, field in roots:
                candidate = DeviceCandidate(
                    ip_address=f"fdfe::{uuid4().hex[:12]}",
                    state="APPROVED",
                    confidence=1.0,
                    metadata_={},
                    **{field: root.id},
                )
                db.add(candidate)
                await db.flush()
                candidates.append((candidate, field, root))

                batch = await recycle_entity(
                    db,
                    entity_type=entity_type,
                    entity_id=root.id,
                    actor_user_id=None,
                )
                await purge_recycle_batch(
                    db,
                    batch_id=batch.id,
                    actor_user_id=None,
                    enforce_retention=False,
                )

                retained = await db.get(DeviceCandidate, candidate.id)
                assert retained is not None
                assert getattr(retained, field) is None
                assert await _including_recycled(db, model, root.id) is None
                assert await db.get(RecycleBinBatch, batch.id) is None

            for candidate, field, _root in candidates:
                retained = await db.get(DeviceCandidate, candidate.id)
                assert retained is not None
                assert getattr(retained, field) is None

    asyncio.run(_run_isolated(scenario))

