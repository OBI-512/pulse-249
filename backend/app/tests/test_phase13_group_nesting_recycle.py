import asyncio
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.models import DeviceGroup, DeviceGroupNesting, RecycleBinItem
from app.services.recycle_bin import purge_recycle_batch, recycle_entity, restore_recycle_batch
from app.settings import settings


def test_group_recycle_bundles_incoming_and_outgoing_nesting_without_deleting_other_groups():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with factory() as db:
                transaction = await db.begin()
                try:
                    marker = uuid4().hex[:10]
                    grandparent = DeviceGroup(
                        name=f"Phase13 Grandparent {marker}",
                        code=f"P13-GP-{marker}",
                        scope_type="GLOBAL",
                        device_scope="ANY",
                        metadata_={},
                    )
                    target = DeviceGroup(
                        name=f"Phase13 Target {marker}",
                        code=f"P13-T-{marker}",
                        scope_type="GLOBAL",
                        device_scope="ANY",
                        metadata_={},
                    )
                    child = DeviceGroup(
                        name=f"Phase13 Child {marker}",
                        code=f"P13-C-{marker}",
                        scope_type="GLOBAL",
                        device_scope="ANY",
                        metadata_={},
                    )
                    db.add_all([grandparent, target, child])
                    await db.flush()

                    incoming = DeviceGroupNesting(
                        parent_group_id=grandparent.id,
                        child_group_id=target.id,
                    )
                    outgoing = DeviceGroupNesting(
                        parent_group_id=target.id,
                        child_group_id=child.id,
                    )
                    db.add_all([incoming, outgoing])
                    await db.flush()

                    first = await recycle_entity(
                        db,
                        entity_type="DEVICE_GROUP",
                        entity_id=target.id,
                        actor_user_id=None,
                    )

                    item_types = list(
                        await db.scalars(
                            select(RecycleBinItem.entity_type).where(
                                RecycleBinItem.batch_id == first.id
                            )
                        )
                    )
                    assert item_types.count("DEVICE_GROUP_NESTING") == 2
                    assert await db.scalar(
                        select(DeviceGroup).where(DeviceGroup.id == target.id)
                    ) is None
                    assert await db.scalar(
                        select(DeviceGroup).where(DeviceGroup.id == grandparent.id)
                    ) is not None
                    assert await db.scalar(
                        select(DeviceGroup).where(DeviceGroup.id == child.id)
                    ) is not None
                    assert await db.scalar(
                        select(DeviceGroupNesting).where(DeviceGroupNesting.id == incoming.id)
                    ) is None
                    assert await db.scalar(
                        select(DeviceGroupNesting).where(DeviceGroupNesting.id == outgoing.id)
                    ) is None

                    await restore_recycle_batch(
                        db,
                        batch_id=first.id,
                        actor_user_id=None,
                    )
                    assert await db.scalar(
                        select(DeviceGroup).where(DeviceGroup.id == target.id)
                    ) is not None
                    assert await db.scalar(
                        select(DeviceGroupNesting).where(DeviceGroupNesting.id == incoming.id)
                    ) is not None
                    assert await db.scalar(
                        select(DeviceGroupNesting).where(DeviceGroupNesting.id == outgoing.id)
                    ) is not None

                    second = await recycle_entity(
                        db,
                        entity_type="DEVICE_GROUP",
                        entity_id=target.id,
                        actor_user_id=None,
                    )
                    await purge_recycle_batch(
                        db,
                        batch_id=second.id,
                        actor_user_id=None,
                        enforce_retention=False,
                    )

                    target_hidden = await db.scalar(
                        select(DeviceGroup)
                        .where(DeviceGroup.id == target.id)
                        .execution_options(include_recycled=True)
                    )
                    incoming_hidden = await db.scalar(
                        select(DeviceGroupNesting)
                        .where(DeviceGroupNesting.id == incoming.id)
                        .execution_options(include_recycled=True)
                    )
                    outgoing_hidden = await db.scalar(
                        select(DeviceGroupNesting)
                        .where(DeviceGroupNesting.id == outgoing.id)
                        .execution_options(include_recycled=True)
                    )
                    assert target_hidden is None
                    assert incoming_hidden is None
                    assert outgoing_hidden is None
                    assert await db.scalar(
                        select(DeviceGroup).where(DeviceGroup.id == grandparent.id)
                    ) is not None
                    assert await db.scalar(
                        select(DeviceGroup).where(DeviceGroup.id == child.id)
                    ) is not None
                finally:
                    await transaction.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())
