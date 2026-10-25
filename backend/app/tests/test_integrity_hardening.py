"""Focused Stage F integrity checks against PostgreSQL constraints/services."""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.models import Device, DeviceGroup, DeviceGroupMembership, DeviceIP, DeviceType
from app.schemas.group import DeviceGroupUpdate, DeviceScope
from app.services.device_ips import apply_ip_flags, ensure_ip_recycle_permitted
from app.api.routers.groups import update_group
from app.settings import settings


async def _isolated(scenario) -> None:
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


async def _switch(db: AsyncSession) -> Device:
    kind = await db.scalar(select(DeviceType).where(DeviceType.code == "SWITCH"))
    assert kind is not None
    row = Device(
        device_type_id=kind.id,
        display_name=f"Stage F switch {uuid4().hex}",
        lifecycle_state="REGISTERED",
        operational_state="UNKNOWN",
        metadata_={},
    )
    db.add(row)
    await db.flush()
    return row


def test_primary_ip_promotion_is_constraint_safe_and_protects_required_ip_state():
    async def scenario(factory):
        async with factory() as db:
            device = await _switch(db)
            first = DeviceIP(
                device_id=device.id, ip_address=f"198.51.100.{uuid4().int % 200 + 1}",
                address_family=4, is_management=True, is_primary=True,
            )
            second = DeviceIP(
                device_id=device.id, ip_address=f"2001:db8::{uuid4().hex[:8]}",
                address_family=6, is_management=True, is_primary=False,
            )
            db.add_all((first, second))
            await db.flush()

            # This exercises the two-phase demote/promote sequence while the
            # PostgreSQL partial unique index is live.
            await apply_ip_flags(
                db, device_id=device.id, target=second,
                is_management=True, is_primary=True,
            )
            await db.flush()
            assert first.is_primary is False
            assert second.is_primary is True

            with pytest.raises(HTTPException) as invalid_primary:
                await apply_ip_flags(
                    db, device_id=device.id, target=first,
                    is_management=False, is_primary=True,
                )
            assert invalid_primary.value.detail["code"] == "PRIMARY_IP_MUST_BE_MANAGEMENT"

            with pytest.raises(HTTPException) as primary_recycle:
                await ensure_ip_recycle_permitted(db, second)
            assert primary_recycle.value.detail["code"] == "PRIMARY_IP_PROTECTED"

    import asyncio
    asyncio.run(_isolated(scenario))


def test_group_criteria_change_rejects_or_explicitly_reconciles_invalid_memberships():
    async def scenario(factory):
        async with factory() as db:
            device = await _switch(db)
            group = DeviceGroup(
                name=f"Stage F group {uuid4().hex}", code=f"SF-{uuid4().hex[:12]}",
                scope_type="GLOBAL", device_scope="ANY", metadata_={},
            )
            db.add(group)
            await db.flush()
            membership = DeviceGroupMembership(device_id=device.id, group_id=group.id)
            db.add(membership)
            await db.commit()
            group_id = group.id
            membership_id = membership.id

            with pytest.raises(HTTPException) as rejected:
                await update_group(
                    group_id,
                    DeviceGroupUpdate(device_scope=DeviceScope.ROUTER),
                    db,
                )
            assert rejected.value.status_code == 409
            assert rejected.value.detail["code"] == "GROUP_CRITERIA_HAS_INCOMPATIBLE_MEMBERS"
            await db.rollback()

            result = await update_group(
                group_id,
                DeviceGroupUpdate(device_scope=DeviceScope.ROUTER, reconcile_memberships=True),
                db,
            )
            assert result.device_scope == "ROUTER"
            assert await db.scalar(select(DeviceGroupMembership).where(DeviceGroupMembership.id == membership_id)) is None

    import asyncio
    asyncio.run(_isolated(scenario))
