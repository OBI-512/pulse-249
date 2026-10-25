"""Redis-backed, short-lived login throttling.

The key is a digest of the normalized account name and direct client IP.  No
submitted password or raw identifier is written to Redis.  Redis outages fail
open so the control plane remains available; audit logging still records every
authentication failure.
"""

from __future__ import annotations

import hashlib
import logging
import asyncio

from redis.asyncio import Redis

from ..settings import settings


logger = logging.getLogger(__name__)
_client: Redis | None = None
_client_loop = None


def _throttle_key(username: str, source_ip: str | None) -> str:
    material = f"{username.strip().casefold()}|{source_ip or 'unknown'}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"fttw:auth:login-failures:{digest}"


def _redis() -> Redis:
    global _client, _client_loop
    loop = asyncio.get_running_loop()
    # Pytest, ASGI workers, and Celery can legitimately run on different
    # loops. Reusing a Redis client bound to a closed/foreign loop caused the
    # throttle to fail open, so keep the client explicitly loop-local.
    if _client is None or _client_loop is not loop:
        _client = Redis.from_url(settings.redis_url, decode_responses=True)
        _client_loop = loop
    return _client


async def login_is_rate_limited(
    *, username: str, source_ip: str | None, limit: int | None = None
) -> bool:
    try:
        threshold = max(1, int(limit if limit is not None else settings.login_rate_limit_attempts))
        attempts = await _redis().get(_throttle_key(username, source_ip))
        return attempts is not None and int(attempts) >= threshold
    except Exception:  # pragma: no cover - exercised where Redis is absent operationally
        logger.warning("login throttle unavailable; allowing authentication attempt", exc_info=True)
        return False


async def record_login_failure(
    *, username: str, source_ip: str | None, window_seconds: int | None = None
) -> None:
    try:
        ttl = max(1, int(window_seconds if window_seconds is not None else settings.login_rate_limit_window_seconds))
        key = _throttle_key(username, source_ip)
        pipeline = _redis().pipeline()
        pipeline.incr(key)
        pipeline.expire(key, ttl)
        await pipeline.execute()
    except Exception:  # pragma: no cover - safety fallback
        logger.warning("login throttle write unavailable", exc_info=True)


async def clear_login_failures(*, username: str, source_ip: str | None) -> None:
    try:
        await _redis().delete(_throttle_key(username, source_ip))
    except Exception:  # pragma: no cover - safety fallback
        logger.warning("login throttle cleanup unavailable", exc_info=True)
