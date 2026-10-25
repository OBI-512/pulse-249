"""Recoverable mutations serialize with recycle and never revive tombstones."""

from __future__ import annotations

import asyncio
import inspect
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.routers import customers, devices, geo, groups, networks
from app.models import Device, DeviceGroup, DeviceGroupMembership, DeviceType, Network
from app.schemas.network import NetworkUpdate
from app.services import groups as group_services
from app.services import movement as movement_service
from app.security import scope_queries
from app.services.groups import remove_membership
from app.services.recycle_bin import purge_recycle_batch, recycle_entity
from app.settings import settings


def _run(coroutine):
    asyncio.run(coroutine)


def test_all_recoverable_patch_roots_use_active_for_update_loads():
    for mutation in (
        networks.update_network,
        geo.update_city,
        geo.update_location,
        geo.update_sector,
        customers.update_customer,
        customers.update_service,
        groups.update_group,
        devices.update_device,
        devices.update_device_status,
        devices.decommission_device,
    ):
        source = inspect.getsource(mutation)
        assert (
            "get_active_for_update_or_404" in source
            or ("for_update=True" in source and "require_" in source)
        ), mutation.__name__

    scoped_lock_source = inspect.getsource(scope_queries)
    assert "with_for_update()" in scoped_lock_source
    assert "populate_existing=True" in scoped_lock_source

    for mutation in (
        devices.update_device_ip,
        devices.delete_device_ip,
        devices.update_device_interface,
        devices.delete_device_interface,
    ):
        source = inspect.getsource(mutation)
        assert (
            "get_active_for_update_or_404" in source
            or ("require_device" in source and "for_update=True" in source)
        ), mutation.__name__
        assert ".with_for_update()" in source, mutation.__name__
        assert "populate_existing=True" in source, mutation.__name__


def test_membership_and_customer_service_movement_paths_use_locked_reloads():
    for mutation in (
        group_services.move_membership,
        group_services.remove_membership,
        group_services.reconcile_physical_move_memberships,
    ):
        assert "_lock_membership_state" in inspect.getsource(mutation), mutation.__name__

    for mutation in (
        movement_service.move_cpe_to_sector,
        movement_service.reassign_access_point,
    ):
        source = inspect.getsource(mutation)
        assert "select(CustomerService)" in source, mutation.__name__
        assert ".with_for_update()" in source, mutation.__name__
        assert "populate_existing=True" in source, mutation.__name__


def test_network_patch_waits_for_recycle_then_returns_not_found():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        batch_id = None
        network_id = None
        try:
            suffix = uuid4().hex[:10]
            async with factory() as setup:
                network = Network(
                    name=f"Patch Lock Network {suffix}",
                    code=f"PLN-{suffix}",
                )
                setup.add(network)
                await setup.commit()
                network_id = network.id

            async with factory() as recycle_db:
                batch = await recycle_entity(
                    recycle_db,
                    entity_type="NETWORK",
                    entity_id=network_id,
                    actor_user_id=None,
                )
                batch_id = batch.id
                await recycle_db.flush()

                async def patch_network():
                    async with factory() as patch_db:
                        try:
                            await networks.update_network(
                                network_id,
                                NetworkUpdate(name="must not revive"),
                                patch_db,
                            )
                        except HTTPException as exc:
                            await patch_db.rollback()
                            return exc
                        raise AssertionError("PATCH unexpectedly mutated a recycled Network")

                patch_task = asyncio.create_task(patch_network())
                await asyncio.sleep(0.15)
                assert not patch_task.done(), "PATCH did not wait for the recycle root lock"
                await recycle_db.commit()

            error = await asyncio.wait_for(patch_task, timeout=5)
            assert error.status_code == 404
            assert error.detail["code"] == "RESOURCE_NOT_FOUND"

            async with factory() as verify:
                active = await verify.scalar(
                    select(Network).where(Network.id == network_id)
                )
                assert active is None
                hidden_name = await verify.scalar(
                    select(Network.name)
                    .where(Network.id == network_id)
                    .execution_options(include_recycled=True)
                )
                assert hidden_name != "must not revive"
        finally:
            if batch_id is not None:
                async with factory() as cleanup:
                    await purge_recycle_batch(
                        cleanup,
                        batch_id=batch_id,
                        actor_user_id=None,
                        enforce_retention=False,
                    )
                    await cleanup.commit()
            await engine.dispose()

    _run(scenario())


def test_membership_remove_waits_for_group_recycle_and_preserves_bundle_item():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        batch_id = None
        device_id = None
        membership_id = None
        try:
            suffix = uuid4().hex[:10]
            async with factory() as setup:
                device_type = await setup.scalar(
                    select(DeviceType).where(DeviceType.code == "SWITCH")
                )
                assert device_type is not None
                device = Device(
                    device_type_id=device_type.id,
                    display_name=f"Membership Lock Device {suffix}",
                    lifecycle_state="REGISTERED",
                    operational_state="UNKNOWN",
                    metadata_={},
                )
                group = DeviceGroup(
                    name=f"Membership Lock Group {suffix}",
                    code=f"MLG-{suffix}",
                    scope_type="GLOBAL",
                    device_scope="ANY",
                    metadata_={},
                )
                setup.add_all([device, group])
                await setup.flush()
                membership = DeviceGroupMembership(
                    device_id=device.id,
                    group_id=group.id,
                )
                setup.add(membership)
                await setup.commit()
                device_id = device.id
                group_id = group.id
                membership_id = membership.id

            async with factory() as recycle_db:
                batch = await recycle_entity(
                    recycle_db,
                    entity_type="DEVICE_GROUP",
                    entity_id=group_id,
                    actor_user_id=None,
                )
                batch_id = batch.id
                await recycle_db.flush()

                async def detach_membership():
                    async with factory() as detach_db:
                        try:
                            await remove_membership(detach_db, device_id, group_id)
                        except ValueError as exc:
                            await detach_db.rollback()
                            return str(exc)
                        await detach_db.commit()
                        return None

                detach_task = asyncio.create_task(detach_membership())
                await asyncio.sleep(0.15)
                assert not detach_task.done(), "membership removal did not wait for group recycle"
                await recycle_db.commit()

            assert await asyncio.wait_for(detach_task, timeout=5) == "MEMBERSHIP_NOT_FOUND"
            async with factory() as verify:
                hidden = await verify.scalar(
                    select(DeviceGroupMembership)
                    .where(DeviceGroupMembership.id == membership_id)
                    .execution_options(include_recycled=True)
                )
                assert hidden is not None
                assert hidden.deletion_batch_id == batch_id
        finally:
            if batch_id is not None:
                async with factory() as cleanup:
                    await purge_recycle_batch(
                        cleanup,
                        batch_id=batch_id,
                        actor_user_id=None,
                        enforce_retention=False,
                    )
                    if device_id is not None:
                        await cleanup.execute(delete(Device).where(Device.id == device_id))
                    await cleanup.commit()
            await engine.dispose()

    _run(scenario())
