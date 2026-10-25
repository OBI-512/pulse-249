"""Stage G typed-settings registry and bounded system-information coverage."""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.deps import get_db
from app.main import app
from app.models import SystemSetting
from app.security.authorization import authorize_request, permission_for_request
from app.services.settings_registry import (
    SETTINGS_REGISTRY,
    ensure_typed_defaults,
    get_typed_setting,
    validate_setting_value,
)
from app.settings import settings


async def _isolated(scenario) -> None:
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    async with engine.connect() as connection:
        transaction = await connection.begin()
        factory = async_sessionmaker(bind=connection, class_=AsyncSession, expire_on_commit=False, join_transaction_mode="create_savepoint")
        try:
            await scenario(factory)
        finally:
            await transaction.rollback()
    await engine.dispose()


def test_registry_is_allowlisted_validated_and_fails_safe_for_bad_legacy_values():
    async def scenario(factory):
        async with factory() as db:
            assert (await get_typed_setting(db, "auth.login_rate_limit")) == {"attempts": 5, "window_seconds": 900}
            _, normalized = validate_setting_value("restore_points.schedule_time", {"value": "01:30"})
            assert normalized == {"value": "01:30"}
            with pytest.raises(HTTPException) as unknown:
                validate_setting_value("arbitrary.unsafe", {"value": {"anything": True}})
            assert unknown.value.detail["code"] == "SETTING_KEY_UNSUPPORTED"
            with pytest.raises(HTTPException) as malformed:
                validate_setting_value("auth.login_rate_limit", {"attempts": 0, "window_seconds": 1})
            assert malformed.value.detail["code"] == "SETTING_VALUE_INVALID"

            key = "auth.session_lifetime_minutes"
            prior = await db.scalar(select(SystemSetting).where(SystemSetting.key == key))
            if prior is not None:
                await db.delete(prior)
                await db.flush()
            db.add(SystemSetting(key=key, value={"value": "invalid"}, description="bad legacy data", is_secret=False))
            await db.flush()
            assert (await get_typed_setting(db, key)) == {"value": 480}
            await db.execute(delete(SystemSetting).where(SystemSetting.key == key))
            await ensure_typed_defaults(db)
            await db.flush()
            assert await db.scalar(select(SystemSetting).where(SystemSetting.key == key)) is not None

    asyncio.run(_isolated(scenario))


def test_system_information_is_explicitly_settings_read_protected_and_bounded():
    async def scenario(factory):
        async def override_get_db():
            async with factory() as db:
                yield db

        async def authorized():
            return None

        previous_db = app.dependency_overrides.get(get_db)
        previous_auth = app.dependency_overrides.get(authorize_request)
        app.dependency_overrides[get_db] = override_get_db
        app.dependency_overrides[authorize_request] = authorized
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.get("/api/system-information")
            assert response.status_code == 200, response.text
            body = response.json()
            assert body["database_status"] == "ONLINE"
            assert "managed_data_root" == body["log_storage"]["path_kind"]
        finally:
            if previous_db is None:
                app.dependency_overrides.pop(get_db, None)
            else:
                app.dependency_overrides[get_db] = previous_db
            if previous_auth is None:
                app.dependency_overrides.pop(authorize_request, None)
            else:
                app.dependency_overrides[authorize_request] = previous_auth

    # Permission mapping is the actual server-side security boundary.
    from starlette.requests import Request
    request = Request({"type": "http", "method": "GET", "path": "/api/system-information", "headers": []})
    assert permission_for_request(request) == "settings.read"
    asyncio.run(_isolated(scenario))
