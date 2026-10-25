from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.session import AsyncSessionLocal
from ..models import AuthSession, RemoteAccessSession, User
from ..services.settings_registry import get_typed_setting
from .client_metadata import parse_client_metadata


DEFAULT_SESSION_LIFETIME_MINUTES = 480
SESSION_TOKEN_BYTES = 32
LIVENESS_WRITE_INTERVAL_SECONDS = 60
USER_ACTIVITY_WRITE_INTERVAL_SECONDS = 30
SESSION_IDLE_TIMEOUT_MINUTES = 15
SESSION_EXTENSION_WINDOW_SECONDS = 300
SESSION_EXTENSION_ACTIVITY_WINDOW_SECONDS = 300


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def _revoke_remote_sessions_for_auth_ids(
    db: AsyncSession,
    auth_session_ids,
    *,
    reason: str,
) -> int:
    now = _utcnow()
    result = await db.execute(
        update(RemoteAccessSession)
        .where(
            RemoteAccessSession.auth_session_id.in_(auth_session_ids),
            RemoteAccessSession.status.in_(("ISSUED", "ACTIVE")),
        )
        .values(
            status="REVOKED",
            revoked_at=now,
            ended_at=now,
            revoked_reason=reason[:80],
        )
    )
    return int(result.rowcount or 0)


def hash_session_token(token: str) -> str:
    """Return the SHA-256 digest used for persistent session-token storage."""
    if not isinstance(token, str):
        raise TypeError("Session token must be a string.")
    if not token:
        raise ValueError("Session token must not be empty.")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def session_idle_seconds(session: AuthSession, *, now: datetime | None = None) -> int:
    """Return elapsed seconds since explicit human activity for a session."""
    current = now or _utcnow()
    last_activity = session.last_user_activity_at or session.created_at
    return max(0, int((current - last_activity).total_seconds()))


def session_idle_expired(session: AuthSession, *, now: datetime | None = None) -> bool:
    """Return whether the 15-minute human-idle security boundary was crossed."""
    return session_idle_seconds(session, now=now) >= SESSION_IDLE_TIMEOUT_MINUTES * 60


def session_extension_eligible(session: AuthSession, *, now: datetime | None = None) -> bool:
    """Allow explicit renewal only in the final five minutes after recent activity."""
    current = now or _utcnow()
    if session.revoked_at is not None or session.expires_at <= current or session_idle_expired(session, now=current):
        return False
    remaining = int((session.expires_at - current).total_seconds())
    return (
        0 < remaining <= SESSION_EXTENSION_WINDOW_SECONDS
        and session_idle_seconds(session, now=current) <= SESSION_EXTENSION_ACTIVITY_WINDOW_SECONDS
    )


async def _revoke_idle_session(session_id: UUID) -> None:
    """Persist idle expiry independently so read-only requests cannot revive it."""
    now = _utcnow()
    async with AsyncSessionLocal() as activity_db:
        await activity_db.execute(
            update(AuthSession)
            .where(AuthSession.id == session_id, AuthSession.revoked_at.is_(None))
            .values(revoked_at=now, revoked_reason="IDLE_TIMEOUT")
        )
        await _revoke_remote_sessions_for_auth_ids(
            activity_db,
            [session_id],
            reason="AUTH_SESSION_IDLE_TIMEOUT",
        )
        await activity_db.commit()


async def create_session(
    db: AsyncSession,
    *,
    user_id: UUID,
    lifetime_minutes: int | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, AuthSession]:
    """Create a server-side authentication session with safe client metadata."""
    if lifetime_minutes is None:
        lifetime_minutes = int((await get_typed_setting(db, "auth.session_lifetime_minutes"))["value"])
    if lifetime_minutes <= 0:
        raise ValueError("Session lifetime must be positive.")

    user = await db.get(User, user_id)
    if user is None:
        raise ValueError("USER_NOT_FOUND")
    if not user.is_active:
        raise ValueError("USER_INACTIVE")

    now = _utcnow()
    token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
    metadata = parse_client_metadata(user_agent)
    normalized_ip = (source_ip or "").strip()[:64] or None

    session = AuthSession(
        user_id=user_id,
        token_hash=hash_session_token(token),
        expires_at=now + timedelta(minutes=lifetime_minutes),
        login_ip=normalized_ip,
        last_ip=normalized_ip,
        user_agent=metadata.user_agent,
        browser_name=metadata.browser_name,
        browser_version=metadata.browser_version,
        os_name=metadata.os_name,
        os_version=metadata.os_version,
        device_type=metadata.device_type,
        last_seen_at=now,
        last_user_activity_at=now,
    )
    db.add(session)
    await db.flush()
    await db.refresh(session)
    return token, session


async def _touch_liveness(session_id: UUID, *, source_ip: str | None, last_seen_at: datetime | None) -> None:
    """Persist throttled network/session liveness in an independent transaction.

    This field deliberately means only that the browser/session is still
    communicating with FTTW. It MUST NOT be used to classify human ACTIVE/IDLE
    state because background health/status traffic also reaches authenticated
    endpoints.
    """
    now = _utcnow()
    if last_seen_at is not None and last_seen_at > now - timedelta(seconds=LIVENESS_WRITE_INTERVAL_SECONDS):
        return

    values: dict[str, object] = {"last_seen_at": now}
    normalized_ip = (source_ip or "").strip()[:64]
    if normalized_ip:
        values["last_ip"] = normalized_ip

    async with AsyncSessionLocal() as activity_db:
        await activity_db.execute(
            update(AuthSession)
            .where(
                AuthSession.id == session_id,
                AuthSession.revoked_at.is_(None),
                AuthSession.expires_at > now,
            )
            .values(**values)
        )
        await activity_db.commit()


async def get_session_user(
    db: AsyncSession,
    *,
    session_token: str,
    source_ip: str | None = None,
) -> User | None:
    """Resolve a valid session token to its active user and record activity."""
    token_hash = hash_session_token(session_token)
    session = await db.scalar(select(AuthSession).where(AuthSession.token_hash == token_hash))
    if session is None:
        return None

    now = _utcnow()
    if session.revoked_at is not None or session.expires_at <= now:
        return None
    if session_idle_expired(session, now=now):
        await _revoke_idle_session(session.id)
        return None

    user = await db.get(User, session.user_id)
    if user is None or not user.is_active:
        return None

    await _touch_liveness(session.id, source_ip=source_ip, last_seen_at=session.last_seen_at)
    return user


async def revoke_session(
    db: AsyncSession,
    *,
    session_token: str,
    reason: str | None = None,
) -> bool:
    token_hash = hash_session_token(session_token)
    session = await db.scalar(select(AuthSession).where(AuthSession.token_hash == token_hash))
    if session is None or session.revoked_at is not None:
        return False
    session.revoked_at = _utcnow()
    session.revoked_reason = (reason or "SESSION_REVOKED")[:80]
    await _revoke_remote_sessions_for_auth_ids(
        db,
        [session.id],
        reason="AUTH_SESSION_REVOKED",
    )
    await db.flush()
    return True


async def revoke_user_sessions(
    db: AsyncSession,
    *,
    user_id: UUID,
    except_session_id: UUID | None = None,
    reason: str | None = None,
) -> int:
    conditions = [AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None)]
    if except_session_id is not None:
        conditions.append(AuthSession.id != except_session_id)
    session_ids = list((await db.scalars(select(AuthSession.id).where(*conditions))).all())
    result = await db.execute(
        update(AuthSession)
        .where(*conditions)
        .values(
            revoked_at=_utcnow(),
            revoked_reason=(reason or "SESSION_REVOKED")[:80],
        )
    )
    if session_ids:
        await _revoke_remote_sessions_for_auth_ids(
            db,
            session_ids,
            reason="AUTH_SESSION_REVOKED",
        )
    return int(result.rowcount or 0)


async def list_user_sessions(
    db: AsyncSession,
    *,
    user_id: UUID,
    include_revoked: bool = False,
) -> list[AuthSession]:
    statement = select(AuthSession).where(AuthSession.user_id == user_id)
    if not include_revoked:
        current = _utcnow()
        idle_cutoff = current - timedelta(minutes=SESSION_IDLE_TIMEOUT_MINUTES)
        statement = statement.where(
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > current,
            AuthSession.last_user_activity_at > idle_cutoff,
        )
    statement = statement.order_by(AuthSession.created_at.desc(), AuthSession.id.desc())
    return list((await db.scalars(statement)).all())


async def revoke_session_by_id(
    db: AsyncSession,
    *,
    user_id: UUID,
    session_id: UUID,
    reason: str | None = None,
) -> bool:
    session = await db.scalar(
        select(AuthSession)
        .where(AuthSession.id == session_id, AuthSession.user_id == user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if session is None or session.revoked_at is not None:
        return False
    session.revoked_at = _utcnow()
    session.revoked_reason = (reason or "SESSION_REVOKED")[:80]
    await _revoke_remote_sessions_for_auth_ids(
        db,
        [session.id],
        reason="AUTH_SESSION_REVOKED",
    )
    await db.flush()
    return True


async def current_session(
    db: AsyncSession,
    *,
    session_token: str,
) -> AuthSession | None:
    return await db.scalar(
        select(AuthSession).where(AuthSession.token_hash == hash_session_token(session_token))
    )


async def record_user_activity(
    db: AsyncSession,
    *,
    session_token: str,
    source_ip: str | None = None,
) -> bool:
    """Record explicit human interaction, throttled independently of liveness."""
    session = await current_session(db, session_token=session_token)
    if session is None:
        return False
    now = _utcnow()
    if session.revoked_at is not None or session.expires_at <= now or session_idle_expired(session, now=now):
        return False
    previous = session.last_user_activity_at
    if previous is not None and previous > now - timedelta(seconds=USER_ACTIVITY_WRITE_INTERVAL_SECONDS):
        return True
    session.last_user_activity_at = now
    session.last_seen_at = now
    normalized_ip = (source_ip or "").strip()[:64]
    if normalized_ip:
        session.last_ip = normalized_ip
    await db.flush()
    return True


async def extend_session(
    db: AsyncSession,
    *,
    session_token: str,
    source_ip: str | None = None,
) -> AuthSession:
    """Explicitly renew an eligible session for one configured lifetime."""
    now = _utcnow()
    session = await db.scalar(
        select(AuthSession)
        .where(AuthSession.token_hash == hash_session_token(session_token))
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if session is None or session.revoked_at is not None or session.expires_at <= now:
        raise ValueError("SESSION_INVALID")
    if session_idle_expired(session, now=now):
        raise ValueError("SESSION_IDLE_EXPIRED")
    if not session_extension_eligible(session, now=now):
        raise ValueError("SESSION_EXTENSION_NOT_AVAILABLE")

    lifetime_minutes = int((await get_typed_setting(db, "auth.session_lifetime_minutes"))["value"])
    session.expires_at = now + timedelta(minutes=lifetime_minutes)
    session.last_seen_at = now
    session.last_user_activity_at = now
    normalized_ip = (source_ip or "").strip()[:64]
    if normalized_ip:
        session.last_ip = normalized_ip
    await db.flush()
    return session


async def update_session_client_metadata(
    db: AsyncSession,
    *,
    session_token: str,
    user_agent: str | None = None,
    browser_name: str | None = None,
    browser_version: str | None = None,
    os_name: str | None = None,
    os_version: str | None = None,
    device_type: str | None = None,
) -> bool:
    """Update display-only client telemetry for the current valid session.

    The fields are intentionally not used for authentication/authorization.
    Browser APIs cannot provide a trustworthy machine hostname, so one is not
    collected or inferred here.
    """
    session = await current_session(db, session_token=session_token)
    if session is None:
        return False
    now = _utcnow()
    if session.revoked_at is not None or session.expires_at <= now:
        return False

    parsed = parse_client_metadata(user_agent or session.user_agent)
    clean = lambda value, limit: ((value or "").strip()[:limit] or None)
    session.user_agent = clean(user_agent, 1024) or parsed.user_agent or session.user_agent
    session.browser_name = clean(browser_name, 100) or parsed.browser_name or session.browser_name
    session.browser_version = clean(browser_version, 80) or parsed.browser_version or session.browser_version
    session.os_name = clean(os_name, 100) or parsed.os_name or session.os_name
    session.os_version = clean(os_version, 80) or parsed.os_version or session.os_version
    normalized_device = clean(device_type, 30)
    if normalized_device:
        normalized_device = normalized_device.upper()
    if normalized_device not in {"DESKTOP", "MOBILE", "TABLET", "UNKNOWN", None}:
        normalized_device = "UNKNOWN"
    session.device_type = normalized_device or parsed.device_type or session.device_type
    await db.flush()
    return True


def session_state(
    session: AuthSession,
    *,
    online_window_minutes: int,
    now: datetime | None = None,
) -> str:
    current = now or _utcnow()
    if session.revoked_at is not None:
        return "REVOKED"
    if session.expires_at <= current or session_idle_expired(session, now=current):
        return "EXPIRED"
    last_activity = session.last_user_activity_at or session.created_at
    if last_activity >= current - timedelta(minutes=online_window_minutes):
        return "ACTIVE"
    return "IDLE"
