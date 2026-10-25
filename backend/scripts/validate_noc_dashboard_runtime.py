#!/usr/bin/env python3
from __future__ import annotations

import asyncio
from uuid import UUID

from sqlalchemy import func, select

from app.celery_app.config import celery_app
import app.tasks.availability  # noqa: F401
from app.db.session import AsyncSessionLocal
from app.models import Device, DeviceAvailability
from app.security.resource_scope import EffectiveResourceScope
from app.services.dashboard import build_operations_dashboard


async def main() -> int:
    required = {
        "fttw.availability.dispatch_due",
        "fttw.availability.poll_batch",
        "fttw.availability.reconcile",
        "fttw.availability.worker_heartbeat",
    }
    missing = sorted(required - set(celery_app.tasks))
    if missing:
        raise RuntimeError(f"Missing C4/C1 availability tasks: {missing}")
    heartbeat = celery_app.conf.beat_schedule.get("availability-worker-heartbeat")
    if not heartbeat or heartbeat.get("task") != "fttw.availability.worker_heartbeat":
        raise RuntimeError("Availability worker heartbeat is not scheduled by Beat.")

    async with AsyncSessionLocal() as db:
        scope = EffectiveResourceScope(
            user_id=UUID(int=0), global_access=True,
            network_ids=frozenset(), city_ids=frozenset(), location_ids=frozenset(),
            sector_ids=frozenset(), group_ids=frozenset(),
        )
        snapshot = await build_operations_dashboard(db, scope=scope, include_alarms=True)
        direct_total = int((await db.scalar(
            select(func.count(Device.id))
            .where(Device.deleted_at.is_(None), Device.lifecycle_state != "DECOMMISSIONED")
        )) or 0)
        if snapshot.availability.total != direct_total:
            raise RuntimeError(
                f"Dashboard availability total mismatch: dashboard={snapshot.availability.total} direct={direct_total}"
            )
        if snapshot.polling.redis_status != "ONLINE":
            raise RuntimeError("Redis is not online for dashboard polling health.")
        if snapshot.polling.monitored_devices and snapshot.polling.worker_heartbeat_at is None:
            raise RuntimeError("Polling worker heartbeat has not been observed yet.")
        print({
            "availability_total": snapshot.availability.total,
            "alarm_total": snapshot.alarms.active_total if snapshot.alarms else None,
            "polling_status": snapshot.polling.status,
            "worker_heartbeat_age_seconds": snapshot.polling.worker_heartbeat_age_seconds,
        })
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
