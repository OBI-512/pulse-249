from __future__ import annotations

import asyncio
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.models import DeviceGroup, DeviceGroupNesting, RecycleBinItem
from app.services.recycle_bin import purge_recycle_batch, recycle_entity, restore_recycle_batch
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


def _group(label: str) -> DeviceGroup:
    marker = uuid4().hex[:12]
    return DeviceGroup(
        name=f"{label} {marker}",
        code=f"{label[:3].upper()}-{marker}",
        group_kind="CUSTOM",
        membership_mode="MANUAL",
        scope_type="GLOBAL",
        device_scope="ANY",
        metadata_={},
    )


def test_custom_group_purge_retires_cross_batch_nesting_history_without_blocking_other_restore():
    async def scenario(factory) -> None:
        async with factory() as db:
            parent = _group("Parent")
            child = _group("Child")
            db.add_all([parent, child])
            await db.flush()
            nesting = DeviceGroupNesting(parent_group_id=parent.id, child_group_id=child.id)
            db.add(nesting)
            await db.flush()

            parent_id = parent.id
            child_id = child.id
            nesting_id = nesting.id

            parent_batch = await recycle_entity(
                db,
                entity_type="DEVICE_GROUP",
                entity_id=parent_id,
                actor_user_id=None,
            )
            await db.flush()

            # Parent recycle owns the historical nesting row.  The child is
            # then recycled independently in a second batch.
            child_batch = await recycle_entity(
                db,
                entity_type="DEVICE_GROUP",
                entity_id=child_id,
                actor_user_id=None,
            )
            await db.flush()

            nesting_item = await db.scalar(
                select(RecycleBinItem).where(
                    RecycleBinItem.batch_id == parent_batch.id,
                    RecycleBinItem.entity_type == "DEVICE_GROUP_NESTING",
                    RecycleBinItem.entity_id == nesting_id,
                )
            )
            assert nesting_item is not None

            # Permanent child purge must retire the impossible cross-batch
            # relationship rather than returning a dependency conflict.
            await purge_recycle_batch(
                db,
                batch_id=child_batch.id,
                actor_user_id=None,
                enforce_retention=False,
            )
            await db.flush()

            assert (
                await db.scalar(
                    select(DeviceGroup)
                    .where(DeviceGroup.id == child_id)
                    .execution_options(include_recycled=True)
                )
                is None
            )
            assert (
                await db.scalar(
                    select(DeviceGroupNesting)
                    .where(DeviceGroupNesting.id == nesting_id)
                    .execution_options(include_recycled=True)
                )
                is None
            )
            assert (
                await db.scalar(
                    select(RecycleBinItem).where(
                        RecycleBinItem.batch_id == parent_batch.id,
                        RecycleBinItem.entity_type == "DEVICE_GROUP_NESTING",
                        RecycleBinItem.entity_id == nesting_id,
                    )
                )
                is None
            )

            # The other recycle batch remains valid and restores the parent
            # without attempting to resurrect a link to the purged child.
            await restore_recycle_batch(db, batch_id=parent_batch.id, actor_user_id=None)
            await db.flush()
            restored_parent = await db.scalar(select(DeviceGroup).where(DeviceGroup.id == parent_id))
            assert restored_parent is not None
            assert restored_parent.deleted_at is None

    asyncio.run(_run_isolated(scenario))
