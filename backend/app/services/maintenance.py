"""Redis-backed maintenance mode kept outside restorable PostgreSQL data."""

from __future__ import annotations

import json
import asyncio
import logging
from datetime import datetime, timezone

from redis.asyncio import Redis

from ..settings import settings

logger = logging.getLogger(__name__)


class MaintenanceModeActive(RuntimeError):
    pass


_KEY = "fttw:maintenance:state"
_LOCK_KEY = "fttw:maintenance:restore-lock"
_client: Redis | None = None
_client_loop = None


def _redis() -> Redis:
    global _client, _client_loop
    loop = asyncio.get_running_loop()
    # Pytest and Celery legitimately use different event loops. Redis clients
    # are loop-bound, so never reuse a client from a closed/foreign loop.
    if _client is None or _client_loop is not loop:
        _client = Redis.from_url(settings.redis_url, decode_responses=True)
        _client_loop = loop
    return _client


async def get_maintenance_state() -> dict[str, object] | None:
    try:
        raw = await _redis().get(_KEY)
        return json.loads(raw) if raw else None
    except Exception:
        logger.exception("maintenance_state_read_failed", extra={"event": "REDIS_MAINTENANCE_READ_FAILED"})
        # A Redis outage must not manufacture maintenance mode. Restore itself
        # refuses to proceed when it cannot acquire the separate global lock.
        return None


async def maintenance_mode_active() -> bool:
    return bool(await get_maintenance_state())


async def set_maintenance_mode(*, restore_point_id: str, request_id: str | None) -> None:
    payload = {
        "restore_point_id": restore_point_id,
        "request_id": request_id,
        "entered_at": datetime.now(timezone.utc).isoformat(),
    }
    await _redis().set(_KEY, json.dumps(payload, sort_keys=True))


async def clear_maintenance_mode() -> None:
    await _redis().delete(_KEY)


async def acquire_restore_lock(*, token: str, ttl_seconds: int = 3600) -> bool:
    return bool(await _redis().set(_LOCK_KEY, token, nx=True, ex=ttl_seconds))


async def release_restore_lock(*, token: str) -> None:
    # Compare-and-delete avoids releasing a lock acquired by a later restore.
    script = """
    if redis.call('GET', KEYS[1]) == ARGV[1] then
        return redis.call('DEL', KEYS[1])
    end
    return 0
    """
    await _redis().eval(script, 1, _LOCK_KEY, token)


async def assert_mutations_allowed() -> None:
    if await maintenance_mode_active():
        raise MaintenanceModeActive("MAINTENANCE_MODE_ACTIVE")
