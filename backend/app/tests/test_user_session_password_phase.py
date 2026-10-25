from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.deps import get_db
from app.main import app
from app.models import AuthSession, PasswordHistory, Permission, User, UserPermission, UserResourceScope
from app.security.client_metadata import parse_client_metadata
from app.security.password_policy import levenshtein_distance
from app.security.passwords import hash_password
from app.security.sessions import create_session, get_session_user, session_state
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
        await engine.dispose()


def test_client_metadata_and_password_distance_are_conservative():
    metadata = parse_client_metadata(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
    )
    assert metadata.browser_name == "Chrome"
    assert metadata.browser_version == "140.0.0.0"
    assert metadata.os_name == "Windows"
    assert metadata.os_version == "10/11"
    assert metadata.device_type == "DESKTOP"
    assert levenshtein_distance("Password1!", "Password2!") == 1
    assert levenshtein_distance("Password1!", "Different2!") >= 3


def test_session_state_uses_recent_activity_not_only_expiration():
    now = datetime.now(timezone.utc)
    session = AuthSession(
        user_id=uuid4(),
        token_hash="a" * 64,
        created_at=now - timedelta(hours=1),
        updated_at=now - timedelta(hours=1),
        last_seen_at=now - timedelta(minutes=2),
        last_user_activity_at=now - timedelta(minutes=2),
        expires_at=now + timedelta(hours=1),
    )
    assert session_state(session, online_window_minutes=5, now=now) == "ACTIVE"
    session.last_seen_at = now - timedelta(minutes=1)  # keep-alive/liveness remains recent
    session.last_user_activity_at = now - timedelta(minutes=6)
    assert session_state(session, online_window_minutes=5, now=now) == "IDLE"
    session.revoked_at = now
    assert session_state(session, online_window_minutes=5, now=now) == "REVOKED"


def test_required_password_change_is_backend_enforced_and_rotates_session():
    async def scenario(factory):
        marker = uuid4().hex[:12]
        username = f"required-change-{marker}"
        temporary = f"Temp-{marker}-Pass1!"
        replacement = f"New-{marker}-Secure2@"
        user_id = None
        old_token = None
        try:
            async with factory() as db:
                user = User(
                    external_subject=f"test:{username}",
                    username=username,
                    display_name="Required Change Test",
                    password_hash=hash_password(temporary),
                    is_active=True,
                    must_change_password=True,
                    password_change_reason="FIRST_LOGIN",
                    password_changed_at=datetime.now(timezone.utc),
                    metadata_={},
                )
                db.add(user)
                await db.flush()
                user_id = user.id
                old_token, _ = await create_session(
                    db,
                    user_id=user.id,
                    source_ip="10.20.30.40",
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0.0.0 Safari/537.36",
                )
                await db.commit()

            old_headers = {"Authorization": f"Bearer {old_token}"}
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                me = await client.get("/api/auth/me", headers=old_headers)
                assert me.status_code == 200, me.text
                assert me.json()["must_change_password"] is True
                assert me.json()["password_change_reason"] == "FIRST_LOGIN"

                blocked = await client.get("/api/auth/sessions", headers=old_headers)
                assert blocked.status_code == 403, blocked.text
                assert blocked.json()["detail"]["code"] == "PASSWORD_CHANGE_REQUIRED"

                changed = await client.post(
                    "/api/auth/password/change-required",
                    headers=old_headers,
                    json={"current_password": temporary, "new_password": replacement},
                )
                assert changed.status_code == 200, changed.text
                new_token = changed.json()["access_token"]
                assert new_token and new_token != old_token

                old_me = await client.get("/api/auth/me", headers=old_headers)
                assert old_me.status_code == 401

                new_me = await client.get(
                    "/api/auth/me",
                    headers={"Authorization": f"Bearer {new_token}"},
                )
                assert new_me.status_code == 200, new_me.text
                assert new_me.json()["must_change_password"] is False

            async with factory() as db:
                assert await get_session_user(db, session_token=old_token) is None
                history_count = len((await db.scalars(select(PasswordHistory).where(PasswordHistory.user_id == user_id))).all())
                assert history_count == 1
        finally:
            if user_id is not None:
                async with factory() as db:
                    await db.execute(delete(PasswordHistory).where(PasswordHistory.user_id == user_id))
                    await db.execute(delete(AuthSession).where(AuthSession.user_id == user_id))
                    await db.execute(delete(UserPermission).where(UserPermission.user_id == user_id))
                    await db.execute(delete(User).where(User.id == user_id))
                    await db.commit()

    asyncio.run(_scenario(scenario))


def test_online_sessions_endpoint_exposes_safe_client_metadata_with_read_permission():
    async def scenario(factory):
        marker = uuid4().hex[:12]
        actor_id = None
        target_id = None
        try:
            async with factory() as db:
                permission = await db.scalar(select(Permission).where(Permission.code == "user.sessions.read"))
                assert permission is not None

                actor = User(
                    external_subject=f"test:session-reader:{marker}",
                    username=f"session-reader-{marker}",
                    display_name="Session Reader",
                    password_hash=hash_password(f"Reader-{marker}-Pass1!"),
                    is_active=True,
                    metadata_={},
                )
                target = User(
                    external_subject=f"test:session-target:{marker}",
                    username=f"session-target-{marker}",
                    display_name="Session Target",
                    password_hash=hash_password(f"Target-{marker}-Pass1!"),
                    is_active=True,
                    metadata_={},
                )
                db.add_all([actor, target])
                await db.flush()
                actor_id, target_id = actor.id, target.id
                db.add(UserResourceScope(user_id=actor.id, scope_type="GLOBAL"))
                db.add(UserPermission(user_id=actor.id, permission_id=permission.id))
                actor_token, _ = await create_session(db, user_id=actor.id, source_ip="10.0.0.10")
                await create_session(
                    db,
                    user_id=target.id,
                    source_ip="10.50.60.70",
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Edg/140.0.0.0 Chrome/140.0.0.0 Safari/537.36"
                    ),
                )
                await db.commit()

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.get(
                    f"/api/admin/sessions/online?search=session-target-{marker}&page=1&page_size=50",
                    headers={"Authorization": f"Bearer {actor_token}"},
                )
                assert response.status_code == 200, response.text
                body = response.json()
                assert body["total"] == 1
                item = body["items"][0]
                assert item["username"] == f"session-target-{marker}"
                assert item["login_ip"] == "10.50.60.70"
                assert item["browser_name"] == "Microsoft Edge"
                assert item["os_name"] == "Windows"
                assert item["device_type"] == "DESKTOP"
                assert item["status"] == "ACTIVE"
                assert "token" not in item
        finally:
            ids = [value for value in (actor_id, target_id) if value is not None]
            if ids:
                async with factory() as db:
                    await db.execute(delete(AuthSession).where(AuthSession.user_id.in_(ids)))
                    await db.execute(delete(UserPermission).where(UserPermission.user_id.in_(ids)))
                    await db.execute(delete(User).where(User.id.in_(ids)))
                    await db.commit()

    asyncio.run(_scenario(scenario))


def test_session_status_keepalive_is_separate_from_human_activity_and_metadata_can_backfill():
    async def scenario(factory):
        marker = uuid4().hex[:12]
        user_id = None
        token = None
        try:
            async with factory() as db:
                user = User(
                    external_subject=f"test:activity:{marker}",
                    username=f"activity-{marker}",
                    display_name="Activity Test",
                    password_hash=hash_password(f"Activity-{marker}-Pass1!"),
                    is_active=True,
                    metadata_={},
                )
                db.add(user)
                await db.flush()
                user_id = user.id
                token, session = await create_session(db, user_id=user.id, source_ip="10.0.0.55")
                session.last_user_activity_at = datetime.now(timezone.utc) - timedelta(minutes=10)
                session.last_seen_at = datetime.now(timezone.utc) - timedelta(minutes=10)
                await db.commit()

            headers = {"Authorization": f"Bearer {token}"}
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                status = await client.get("/api/auth/session/status", headers=headers)
                assert status.status_code == 200, status.text
                assert status.json()["seconds_remaining"] > 0

                async with factory() as db:
                    session = await db.scalar(select(AuthSession).where(AuthSession.user_id == user_id))
                    assert session is not None
                    # The authenticated status request may refresh network liveness,
                    # but it must not refresh explicit human activity.
                    assert session.last_user_activity_at < datetime.now(timezone.utc) - timedelta(minutes=5)
                    assert session_state(session, online_window_minutes=5) == "IDLE"

                metadata = await client.post(
                    "/api/auth/session/client-metadata",
                    headers=headers,
                    json={
                        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0.0.0 Safari/537.36",
                        "browser_name": "Chrome",
                        "browser_version": "140.0.0.0",
                        "os_name": "Windows",
                        "os_version": "10/11",
                        "device_type": "DESKTOP",
                    },
                )
                assert metadata.status_code == 204, metadata.text

                activity = await client.post("/api/auth/session/activity", headers=headers)
                assert activity.status_code == 204, activity.text

                async with factory() as db:
                    session = await db.scalar(select(AuthSession).where(AuthSession.user_id == user_id))
                    assert session is not None
                    assert session.browser_name == "Chrome"
                    assert session.os_name == "Windows"
                    assert session.device_type == "DESKTOP"
                    assert session.last_user_activity_at >= datetime.now(timezone.utc) - timedelta(minutes=1)
                    assert session_state(session, online_window_minutes=5) == "ACTIVE"
        finally:
            if user_id is not None:
                async with factory() as db:
                    await db.execute(delete(AuthSession).where(AuthSession.user_id == user_id))
                    await db.execute(delete(UserPermission).where(UserPermission.user_id == user_id))
                    await db.execute(delete(User).where(User.id == user_id))
                    await db.commit()

    asyncio.run(_scenario(scenario))
