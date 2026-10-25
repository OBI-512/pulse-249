from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.deps import get_db
from app.db.session import engine as app_engine
from app.main import app
from app.models import AuthSession, AuditLog, User
from app.security.passwords import hash_password
from app.services.settings_registry import get_typed_setting
from app.services.audit import enable_audit_maintenance
from app.security.sessions import (
    SESSION_IDLE_TIMEOUT_MINUTES,
    create_session,
    get_session_user,
    session_extension_eligible,
    session_state,
)
from app.settings import settings


async def _scenario(scenario) -> None:
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with factory() as db:
            yield db

    previous = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    try:
        await scenario(factory)
    finally:
        if previous is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous
        # Tests intentionally use separate asyncio.run() loops. Dispose the
        # application engine before each loop closes so pooled asyncpg
        # connections cannot leak into the next test loop.
        await app_engine.dispose()
        await engine.dispose()


async def _create_user_and_session(factory, marker: str):
    async with factory() as db:
        user = User(
            external_subject=f"test:session-hardening:{marker}",
            username=f"session-hardening-{marker}",
            display_name="Session Hardening Test",
            password_hash=hash_password(f"Session-{marker}-Pass1!"),
            is_active=True,
            metadata_={},
        )
        db.add(user)
        await db.flush()
        token, session = await create_session(db, user_id=user.id, source_ip="10.0.0.77")
        await db.commit()
        return user.id, token, session.id


async def _cleanup(factory, user_id):
    async with factory() as db:
        # audit_logs is intentionally append-only. Test cleanup must use the
        # same transaction-local maintenance gate as authorized maintenance.
        await enable_audit_maintenance(db)
        await db.execute(delete(AuditLog).where(AuditLog.actor_user_id == user_id))
        await db.execute(delete(AuthSession).where(AuthSession.user_id == user_id))
        await db.execute(delete(User).where(User.id == user_id))
        await db.commit()


def test_fifteen_minute_idle_timeout_is_server_authoritative():
    async def scenario(factory):
        marker = uuid4().hex[:12]
        user_id, token, session_id = await _create_user_and_session(factory, marker)
        try:
            async with factory() as db:
                session = await db.get(AuthSession, session_id)
                assert session is not None
                now = datetime.now(timezone.utc)
                session.last_user_activity_at = now - timedelta(minutes=SESSION_IDLE_TIMEOUT_MINUTES, seconds=1)
                session.last_seen_at = now
                await db.commit()

            async with factory() as db:
                assert await get_session_user(db, session_token=token) is None

            await asyncio.sleep(0)
            async with factory() as db:
                session = await db.get(AuthSession, session_id)
                assert session is not None
                assert session.revoked_reason == "IDLE_TIMEOUT"
                assert session_state(session, online_window_minutes=5) in {"REVOKED", "EXPIRED"}

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.get("/api/auth/session/status", headers={"Authorization": f"Bearer {token}"})
                assert response.status_code == 401
        finally:
            await _cleanup(factory, user_id)

    asyncio.run(_scenario(scenario))


def test_extension_requires_final_five_minutes_and_recent_activity_then_renews_full_lifetime():
    async def scenario(factory):
        marker = uuid4().hex[:12]
        user_id, token, session_id = await _create_user_and_session(factory, marker)
        try:
            now = datetime.now(timezone.utc)
            async with factory() as db:
                session = await db.get(AuthSession, session_id)
                assert session is not None
                session.expires_at = now + timedelta(minutes=4)
                session.last_user_activity_at = now - timedelta(minutes=1)
                await db.commit()
                assert session_extension_eligible(session, now=now) is True

            headers = {"Authorization": f"Bearer {token}"}
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                status = await client.get("/api/auth/session/status", headers=headers)
                assert status.status_code == 200, status.text
                body = status.json()
                assert body["idle_timeout_seconds"] == 900
                assert body["extension_window_seconds"] == 300
                assert body["extension_eligible"] is True

                async with factory() as db:
                    configured_lifetime = int((await get_typed_setting(db, "auth.session_lifetime_minutes"))["value"])

                assert body["renewal_minutes"] == configured_lifetime

                extended = await client.post("/api/auth/session/extend", headers=headers)
                assert extended.status_code == 200, extended.text
                renewed = extended.json()
                assert renewed["renewal_minutes"] == configured_lifetime
                assert renewed["seconds_remaining"] >= (configured_lifetime - 1) * 60

            async with factory() as db:
                session = await db.get(AuthSession, session_id)
                assert session is not None
                assert session.expires_at >= datetime.now(timezone.utc) + timedelta(minutes=configured_lifetime - 1)
                audit = await db.scalar(
                    select(AuditLog).where(
                        AuditLog.actor_user_id == user_id,
                        AuditLog.action == "SESSION_EXTENDED",
                    ).order_by(AuditLog.occurred_at.desc())
                )
                assert audit is not None
        finally:
            await _cleanup(factory, user_id)

    asyncio.run(_scenario(scenario))


def test_extension_is_denied_outside_window_or_without_recent_activity():
    async def scenario(factory):
        marker = uuid4().hex[:12]
        user_id, token, session_id = await _create_user_and_session(factory, marker)
        try:
            headers = {"Authorization": f"Bearer {token}"}
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                outside = await client.post("/api/auth/session/extend", headers=headers)
                assert outside.status_code == 409, outside.text
                assert outside.json()["detail"]["code"] == "SESSION_EXTENSION_NOT_AVAILABLE"

                async with factory() as db:
                    session = await db.get(AuthSession, session_id)
                    assert session is not None
                    now = datetime.now(timezone.utc)
                    session.expires_at = now + timedelta(minutes=4)
                    session.last_user_activity_at = now - timedelta(minutes=6)
                    await db.commit()

                status = await client.get("/api/auth/session/status", headers=headers)
                assert status.status_code == 200, status.text
                assert status.json()["extension_eligible"] is False
                stale = await client.post("/api/auth/session/extend", headers=headers)
                assert stale.status_code == 409, stale.text
        finally:
            await _cleanup(factory, user_id)

    asyncio.run(_scenario(scenario))
