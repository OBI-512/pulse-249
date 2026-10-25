"""Restricted-role and permission-workspace regression contracts."""
from __future__ import annotations

import asyncio
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.models import Role, RolePermission
from app.security.permissions import Permission as P
from app.services.user_security import resolve_permission_assignment, resolve_roles_or_error
from app.settings import settings


def test_restricted_role_exists_and_has_zero_role_permissions():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with factory() as db:
                restricted = await db.scalar(select(Role).where(Role.code == "restricted"))
                assert restricted is not None
                assert restricted.name == "Restricted"
                count = int(await db.scalar(
                    select(func.count(RolePermission.id)).where(RolePermission.role_id == restricted.id)
                ) or 0)
                assert count == 0
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_restricted_role_direct_grant_still_expands_real_prerequisites():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with factory() as db:
                restricted = await resolve_roles_or_error(db, ["restricted"])
                resolved = await resolve_permission_assignment(db, [P.DEVICE_DELETE], restricted)
                assert {permission.code for permission in resolved} == {P.DEVICE_DELETE, P.DEVICE_READ}
        finally:
            await engine.dispose()

    asyncio.run(scenario())

