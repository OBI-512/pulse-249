import asyncio
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.db.session import AsyncSessionLocal, engine
from app.models import (
    Device,
    DeviceRelationship,
    DeviceType,
)
from app.services.relationships import (
    RelationshipValidationError,
    create_device_relationship,
)


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()

    try:
        loop.run_until_complete(engine.dispose())

        yield loop

    finally:
        loop.run_until_complete(engine.dispose())
        loop.close()


async def create_test_devices(db):
    device_type = await db.scalar(
        select(DeviceType).where(DeviceType.code == "SWITCH")
    )
    assert device_type is not None

    device_a = Device(
        device_type_id=device_type.id,
        display_name=f"Relationship Device A {uuid4()}",
        hostname=f"relationship-a-{uuid4().hex[:10]}",
        vendor="Integration-Test",
        model="TEST",
    )

    device_b = Device(
        device_type_id=device_type.id,
        display_name=f"Relationship Device B {uuid4()}",
        hostname=f"relationship-b-{uuid4().hex[:10]}",
        vendor="Integration-Test",
        model="TEST",
    )

    device_c = Device(
        device_type_id=device_type.id,
        display_name=f"Relationship Device C {uuid4()}",
        hostname=f"relationship-c-{uuid4().hex[:10]}",
        vendor="Integration-Test",
        model="TEST",
    )

    db.add_all(
        [
            device_a,
            device_b,
            device_c,
        ]
    )

    await db.flush()

    return device_type, device_a, device_b, device_c


def test_directed_relationship_can_be_created(event_loop):
    async def run_test():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()

            try:
                _, device_a, device_b, _ = await create_test_devices(db)

                relationship = await create_device_relationship(
                    db,
                    source_device_id=device_a.id,
                    target_device_id=device_b.id,
                    relationship_type="PHYSICAL_LINK",
                    direction="DIRECTED",
                    metadata={},
                )

                assert relationship.source_device_id == device_a.id
                assert relationship.target_device_id == device_b.id
                assert relationship.relationship_type == "PHYSICAL_LINK"
                assert relationship.direction == "DIRECTED"

            finally:
                await transaction.rollback()

    event_loop.run_until_complete(run_test())


def test_self_relationship_is_rejected(event_loop):
    async def run_test():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()

            try:
                _, device_a, _, _ = await create_test_devices(db)

                with pytest.raises(
                    RelationshipValidationError
                ) as exc_info:
                    await create_device_relationship(
                        db,
                        source_device_id=device_a.id,
                        target_device_id=device_a.id,
                        relationship_type="PHYSICAL_LINK",
                        direction="DIRECTED",
                        metadata={},
                    )

                assert exc_info.value.code == "SELF_RELATIONSHIP"

            finally:
                await transaction.rollback()

    event_loop.run_until_complete(run_test())


def test_exact_duplicate_relationship_is_rejected(event_loop):
    async def run_test():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()

            try:
                _, device_a, device_b, _ = await create_test_devices(db)

                await create_device_relationship(
                    db,
                    source_device_id=device_a.id,
                    target_device_id=device_b.id,
                    relationship_type="PHYSICAL_LINK",
                    direction="DIRECTED",
                    metadata={},
                )

                with pytest.raises(
                    RelationshipValidationError
                ) as exc_info:
                    await create_device_relationship(
                        db,
                        source_device_id=device_a.id,
                        target_device_id=device_b.id,
                        relationship_type="PHYSICAL_LINK",
                        direction="DIRECTED",
                        metadata={},
                    )

                assert exc_info.value.code == "RELATIONSHIP_CONFLICT"

            finally:
                await transaction.rollback()

    event_loop.run_until_complete(run_test())


def test_reverse_relationship_is_rejected(event_loop):
    async def run_test():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()

            try:
                _, device_a, device_b, _ = await create_test_devices(db)

                await create_device_relationship(
                    db,
                    source_device_id=device_a.id,
                    target_device_id=device_b.id,
                    relationship_type="PHYSICAL_LINK",
                    direction="DIRECTED",
                    metadata={},
                )

                with pytest.raises(
                    RelationshipValidationError
                ) as exc_info:
                    await create_device_relationship(
                        db,
                        source_device_id=device_b.id,
                        target_device_id=device_a.id,
                        relationship_type="PHYSICAL_LINK",
                        direction="DIRECTED",
                        metadata={},
                    )

                assert exc_info.value.code == "RELATIONSHIP_CONFLICT"

            finally:
                await transaction.rollback()

    event_loop.run_until_complete(run_test())


def test_reverse_undirected_relationship_is_rejected(event_loop):
    async def run_test():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()

            try:
                _, device_a, device_b, _ = await create_test_devices(db)

                await create_device_relationship(
                    db,
                    source_device_id=device_a.id,
                    target_device_id=device_b.id,
                    relationship_type="PHYSICAL_LINK",
                    direction="UNDIRECTED",
                    metadata={},
                )

                with pytest.raises(
                    RelationshipValidationError
                ) as exc_info:
                    await create_device_relationship(
                        db,
                        source_device_id=device_b.id,
                        target_device_id=device_a.id,
                        relationship_type="PHYSICAL_LINK",
                        direction="UNDIRECTED",
                        metadata={},
                    )

                assert exc_info.value.code == "RELATIONSHIP_CONFLICT"

            finally:
                await transaction.rollback()

    event_loop.run_until_complete(run_test())


def test_invalid_direction_is_rejected(event_loop):
    async def run_test():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()

            try:
                _, device_a, device_b, _ = await create_test_devices(db)

                with pytest.raises(
                    RelationshipValidationError
                ) as exc_info:
                    await create_device_relationship(
                        db,
                        source_device_id=device_a.id,
                        target_device_id=device_b.id,
                        relationship_type="PHYSICAL_LINK",
                        direction="INVALID",
                        metadata={},
                    )

                assert exc_info.value.code == "INVALID_DIRECTION"

            finally:
                await transaction.rollback()

    event_loop.run_until_complete(run_test())


def test_relationship_does_not_create_additional_relationships(
    event_loop,
):
    async def run_test():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()

            try:
                _, device_a, device_b, device_c = await create_test_devices(
                    db
                )

                await create_device_relationship(
                    db,
                    source_device_id=device_a.id,
                    target_device_id=device_b.id,
                    relationship_type="PHYSICAL_LINK",
                    direction="DIRECTED",
                    metadata={},
                )

                await create_device_relationship(
                    db,
                    source_device_id=device_b.id,
                    target_device_id=device_c.id,
                    relationship_type="PHYSICAL_LINK",
                    direction="DIRECTED",
                    metadata={},
                )

                result = await db.execute(
                    select(DeviceRelationship).where(
                        DeviceRelationship.source_device_id == device_a.id
                    )
                )

                relationships = result.scalars().all()

                assert len(relationships) == 1
                assert relationships[0].target_device_id == device_b.id

            finally:
                await transaction.rollback()

    event_loop.run_until_complete(run_test())
