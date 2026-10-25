import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import delete

from app.models import User, AuthSession
from app.security.sessions import (
    DEFAULT_SESSION_LIFETIME_MINUTES,
    create_session,
    get_session_user,
    hash_session_token,
    revoke_session,
)


_TEST_EVENT_LOOP = asyncio.new_event_loop()


def run(coro):
    return _TEST_EVENT_LOOP.run_until_complete(coro)


@pytest.fixture(scope="module", autouse=True)
def dispose_loop():
    yield
    _TEST_EVENT_LOOP.close()


async def _db_session():
    from app.db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        yield db


async def _create_user(db):
    user = User(
        external_subject=f"session-test-{uuid4()}",
        username=f"session-user-{uuid4().hex[:10]}",
        display_name="Session Test User",
        is_active=True,
        metadata_={},
    )

    db.add(user)
    await db.flush()

    return user


async def _cleanup_user(db, user_id):
    await db.execute(
        delete(AuthSession).where(AuthSession.user_id == user_id)
    )
    await db.execute(
        delete(User).where(User.id == user_id)
    )
    await db.commit()


def test_hash_session_token_is_deterministic():
    token = "test-session-token"

    first = hash_session_token(token)
    second = hash_session_token(token)

    assert first == second
    assert len(first) == 64
    assert first != token


def test_create_session_persists_only_token_hash():
    async def scenario():
        async for db in _db_session():
            user = await _create_user(db)

            try:
                token, session = await create_session(
                    db,
                    user_id=user.id,
                )

                assert token
                assert token != session.token_hash
                assert session.token_hash == hash_session_token(token)
                assert session.user_id == user.id
                assert session.revoked_at is None
                assert session.expires_at > datetime.now(timezone.utc)
                assert session.expires_at <= (
                    datetime.now(timezone.utc)
                    + timedelta(
                        minutes=DEFAULT_SESSION_LIFETIME_MINUTES + 1
                    )
                )

                await db.commit()

            finally:
                await _cleanup_user(db, user.id)

    run(scenario())


def test_session_resolves_to_active_user():
    async def scenario():
        async for db in _db_session():
            user = await _create_user(db)

            try:
                token, _ = await create_session(
                    db,
                    user_id=user.id,
                )

                await db.commit()

                resolved = await get_session_user(
                    db,
                    session_token=token,
                )

                assert resolved is not None
                assert resolved.id == user.id

            finally:
                await _cleanup_user(db, user.id)

    run(scenario())


def test_invalid_session_token_is_rejected():
    async def scenario():
        async for db in _db_session():
            user = await _create_user(db)

            try:
                token, _ = await create_session(
                    db,
                    user_id=user.id,
                )

                await db.commit()

                resolved = await get_session_user(
                    db,
                    session_token=token + "-invalid",
                )

                assert resolved is None

            finally:
                await _cleanup_user(db, user.id)

    run(scenario())


def test_revoke_session_invalidates_token():
    async def scenario():
        async for db in _db_session():
            user = await _create_user(db)

            try:
                token, _ = await create_session(
                    db,
                    user_id=user.id,
                )

                await db.commit()

                assert await get_session_user(
                    db,
                    session_token=token,
                ) is not None

                revoked = await revoke_session(
                    db,
                    session_token=token,
                )

                await db.commit()

                assert revoked is True

                resolved = await get_session_user(
                    db,
                    session_token=token,
                )

                assert resolved is None

            finally:
                await _cleanup_user(db, user.id)

    run(scenario())


def test_revoking_unknown_session_returns_false():
    async def scenario():
        async for db in _db_session():
            token = f"unknown-{uuid4()}"

            result = await revoke_session(
                db,
                session_token=token,
            )

            assert result is False

    run(scenario())


def test_expired_session_is_rejected():
    async def scenario():
        async for db in _db_session():
            user = await _create_user(db)

            try:
                token, session = await create_session(
                    db,
                    user_id=user.id,
                )

                session.expires_at = (
                    datetime.now(timezone.utc) - timedelta(seconds=1)
                )

                await db.commit()

                resolved = await get_session_user(
                    db,
                    session_token=token,
                )

                assert resolved is None

            finally:
                await _cleanup_user(db, user.id)

    run(scenario())


def test_inactive_user_session_is_rejected():
    async def scenario():
        async for db in _db_session():
            user = await _create_user(db)

            try:
                token, _ = await create_session(
                    db,
                    user_id=user.id,
                )

                await db.commit()

                user.is_active = False
                await db.commit()

                resolved = await get_session_user(
                    db,
                    session_token=token,
                )

                assert resolved is None

            finally:
                await _cleanup_user(db, user.id)

    run(scenario())


def test_session_creation_rejects_missing_user():
    async def scenario():
        async for db in _db_session():
            with pytest.raises(ValueError, match="USER_NOT_FOUND"):
                await create_session(
                    db,
                    user_id=uuid4(),
                )

    run(scenario())


def test_session_creation_rejects_inactive_user():
    async def scenario():
        async for db in _db_session():
            user = await _create_user(db)

            try:
                user.is_active = False
                await db.commit()

                with pytest.raises(ValueError, match="USER_INACTIVE"):
                    await create_session(
                        db,
                        user_id=user.id,
                    )

            finally:
                await _cleanup_user(db, user.id)

    run(scenario())
