from __future__ import annotations

import asyncio
import hashlib
import logging

from redis.asyncio import Redis

from app.settings import settings

logger = logging.getLogger(__name__)
_client: Redis | None = None
_loop = None


def _redis() -> Redis:
    global _client, _loop
    loop = asyncio.get_running_loop()
    if _client is None or _loop is not loop:
        _client = Redis.from_url(settings.redis_url, decode_responses=True)
        _loop = loop
    return _client


def _key(prefix: str, identity: str) -> str:
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return f"fttw:integration:{prefix}:{digest}"


async def check_fixed_window(*, prefix: str, identity: str, limit: int, window_seconds: int) -> bool:
    """Return True when limited. Redis failure fails closed for the optional integration boundary."""
    try:
        key = _key(prefix, identity)
        client = _redis()
        value = await client.incr(key)
        if value == 1:
            await client.expire(key, max(1, window_seconds))
        return int(value) > max(1, limit)
    except Exception:
        logger.exception("integration rate limiter unavailable")
        return True
