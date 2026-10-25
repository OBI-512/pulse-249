#!/usr/bin/env python3
"""Non-destructive C1 runtime-state validator for the active database."""

from __future__ import annotations

import asyncio
import json

from sqlalchemy import text

from app.availability.settings import AVAILABILITY_SETTING_KEYS, load_availability_settings
from app.celery_app.config import celery_app
# Standalone validators do not execute the worker bootstrap, so import the
# C1 task module explicitly before inspecting celery_app.tasks. The live worker
# registry is independently verified by the milestone validator.
import app.tasks.availability  # noqa: F401
from app.db.session import AsyncSessionLocal, engine


async def main() -> int:
    try:
        async with AsyncSessionLocal() as db:
            revision = await db.scalar(text("SELECT version_num FROM alembic_version"))

            missing_settings = sorted(set(AVAILABILITY_SETTING_KEYS) - set((await db.scalars(text(
                "SELECT key FROM system_settings WHERE key LIKE 'availability.%'"
            ))).all()))
            if missing_settings:
                raise RuntimeError(f"Missing availability settings: {missing_settings}")

            active_devices = int(await db.scalar(text(
                "SELECT COUNT(*) FROM devices WHERE deleted_at IS NULL"
            )) or 0)
            availability_rows = int(await db.scalar(text(
                "SELECT COUNT(*) FROM device_availability da "
                "JOIN devices d ON d.id = da.device_id WHERE d.deleted_at IS NULL"
            )) or 0)
            if active_devices != availability_rows:
                raise RuntimeError(
                    f"Availability row mismatch: rows={availability_rows}, active_devices={active_devices}"
                )

            invalid_statuses = int(await db.scalar(text(
                "SELECT COUNT(*) FROM device_availability "
                "WHERE status NOT IN ('ONLINE','SUSPECT','OFFLINE','UNKNOWN','MAINTENANCE')"
            )) or 0)
            if invalid_statuses:
                raise RuntimeError(f"Invalid availability statuses: {invalid_statuses}")

            runtime = await load_availability_settings(db)

        required_tasks = {
            "fttw.availability.dispatch_due",
            "fttw.availability.poll_batch",
            "fttw.availability.reconcile",
        }
        missing_tasks = sorted(required_tasks - set(celery_app.tasks))
        if missing_tasks:
            raise RuntimeError(f"Missing Celery availability tasks: {missing_tasks}")
        schedule = celery_app.conf.beat_schedule.get("dispatch-device-availability") or {}
        if schedule.get("schedule") != 1.0:
            raise RuntimeError(f"Unexpected availability dispatcher cadence: {schedule}")

        report = {
            "pass": True,
            "revision": revision,
            "active_devices": active_devices,
            "availability_rows": availability_rows,
            "settings": len(AVAILABILITY_SETTING_KEYS),
            "interval_seconds": runtime.interval_seconds,
            "dispatch_limit_per_tick": runtime.dispatch_limit_per_tick,
            "task_batch_size": runtime.task_batch_size,
            "max_outstanding_devices": runtime.max_outstanding_devices,
            "worker_concurrency": runtime.worker_concurrency,
            "tasks": sorted(required_tasks),
            "dispatcher_schedule_seconds": schedule["schedule"],
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    finally:
        await engine.dispose()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
