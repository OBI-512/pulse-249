import asyncio
from uuid import uuid4

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

from app.api.deps import get_db
from app.models import Permission, Role, RolePermission, User, UserRole
from app.security.authorization import get_current_user, require_permission


_TEST_EVENT_LOOP = asyncio.new_event_loop()


def run(coro):
    return _TEST_EVENT_LOOP.run_until_complete(coro)


@pytest.fixture(scope="module", autouse=True)
def dispose_loop():
    yield
    _TEST_EVENT_LOOP.close()


async def create_security_context(db):
    user = User(
        external_subject=f"test-subject-{uuid4()}",
        username=f"test-user-{uuid4().hex[:10]}",
        display_name="Authorization Test User",
        is_active=True,
        metadata_={},
    )

    role = Role(
        name=f"Authorization Test Role {uuid4()}",
        code=f"AUTH-TEST-{uuid4().hex[:10]}",
        description="Authorization test role",
    )

    permission = Permission(
        name=f"Authorization Test Permission {uuid4()}",
        code=f"authorization.test.{uuid4().hex[:10]}",
        description="Authorization test permission",
    )

    db.add_all([user, role, permission])
    await db.flush()

    user_role = UserRole(
        user_id=user.id,
        role_id=role.id,
    )

    role_permission = RolePermission(
        role_id=role.id,
        permission_id=permission.id,
    )

    db.add_all([user_role, role_permission])
    await db.flush()

    return user, role, permission


async def cleanup_security_context(db, user_id, role_id, permission_id):
    await db.execute(delete(UserRole).where(UserRole.user_id == user_id))
    await db.execute(delete(RolePermission).where(RolePermission.role_id == role_id))
    await db.execute(delete(User).where(User.id == user_id))
    await db.execute(delete(Role).where(Role.id == role_id))
    await db.execute(delete(Permission).where(Permission.id == permission_id))
    await db.commit()


def test_user_has_assigned_permission():
    async def scenario():
        async for db in _db_session():
            user, role, permission = await create_security_context(db)

            try:
                from app.security.authorization import user_has_permission

                allowed = await user_has_permission(
                    db,
                    user_id=user.id,
                    permission_code=permission.code,
                )

                assert allowed is True

            finally:
                await cleanup_security_context(
                    db,
                    user.id,
                    role.id,
                    permission.id,
                )

    run(scenario())


def test_user_without_permission_is_denied():
    async def scenario():
        async for db in _db_session():
            user = User(
                external_subject=f"test-subject-{uuid4()}",
                username=f"test-user-{uuid4().hex[:10]}",
                display_name="No Permission User",
                is_active=True,
                metadata_={},
            )

            permission = Permission(
                name=f"Unused Permission {uuid4()}",
                code=f"authorization.unassigned.{uuid4().hex[:10]}",
                description="Unassigned permission",
            )

            db.add_all([user, permission])
            await db.flush()

            try:
                from app.security.authorization import user_has_permission

                allowed = await user_has_permission(
                    db,
                    user_id=user.id,
                    permission_code=permission.code,
                )

                assert allowed is False

            finally:
                await db.execute(delete(User).where(User.id == user.id))
                await db.execute(
                    delete(Permission).where(Permission.id == permission.id)
                )
                await db.commit()

    run(scenario())


async def _db_session():
    from app.db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        yield db
