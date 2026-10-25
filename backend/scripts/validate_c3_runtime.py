#!/usr/bin/env python3
"""Non-destructive C3 runtime-state validator for maintenance/notifications."""
from __future__ import annotations

import asyncio
import json
import os

from sqlalchemy import text

from app.celery_app.config import celery_app
# Standalone validators do not execute worker bootstrap. Import C3 tasks before
# inspecting celery_app.tasks; live worker registration is checked separately.
import app.tasks.notifications  # noqa: F401
from app.db.session import AsyncSessionLocal, engine
from app.services.notifications import load_notification_settings


REQUIRED_TABLES = {
    "maintenance_windows",
    "notification_policies",
    "notification_policy_steps",
    "notification_deliveries",
}
REQUIRED_SETTINGS = {
    "notifications.enabled",
    "notifications.dispatch_limit_per_tick",
    "notifications.task_batch_size",
    "notifications.max_outstanding",
    "notifications.lease_seconds",
    "notifications.worker_concurrency",
}
REQUIRED_TASKS = {
    "fttw.notifications.dispatch_due",
    "fttw.notifications.deliver_batch",
}


async def main() -> int:
    try:
        async with AsyncSessionLocal() as db:
            revision = await db.scalar(text("SELECT version_num FROM alembic_version"))

            tables = set((await db.scalars(text(
                "SELECT tablename FROM pg_tables WHERE schemaname='public'"
            ))).all())
            missing_tables = sorted(REQUIRED_TABLES - tables)
            if missing_tables:
                raise RuntimeError(f"Missing C3 tables: {missing_tables}")

            setting_keys = set((await db.scalars(text(
                "SELECT key FROM system_settings WHERE key LIKE 'notifications.%'"
            ))).all())
            missing_settings = sorted(REQUIRED_SETTINGS - setting_keys)
            if missing_settings:
                raise RuntimeError(f"Missing notification settings: {missing_settings}")

            invalid_deliveries = int(await db.scalar(text(
                "SELECT COUNT(*) FROM notification_deliveries "
                "WHERE status NOT IN ('PENDING','SUPPRESSED','CLAIMED','SENT','FAILED','CANCELLED')"
            )) or 0)
            if invalid_deliveries:
                raise RuntimeError(f"Invalid notification delivery states: {invalid_deliveries}")

            raw_webhooks = int(await db.scalar(text(
                "SELECT COUNT(*) FROM notification_policy_steps "
                "WHERE channel_type='WEBHOOK' AND destination !~ '^env://[A-Za-z_][A-Za-z0-9_]*$'"
            )) or 0)
            if raw_webhooks:
                raise RuntimeError(f"Raw/non-env webhook destinations stored: {raw_webhooks}")

            orphan_suppression = int(await db.scalar(text(
                "SELECT COUNT(*) FROM notification_deliveries d "
                "WHERE d.status='SUPPRESSED' AND d.maintenance_window_id IS NULL"
            )) or 0)
            if orphan_suppression:
                raise RuntimeError(f"Suppressed deliveries without maintenance provenance: {orphan_suppression}")

            runtime = await load_notification_settings(db)
            if os.getenv("FTTW_C3_REQUIRE_NOTIFICATIONS_DISABLED") == "1" and runtime.enabled:
                raise RuntimeError("notifications.enabled must remain false during C3 qualification startup")

        missing_tasks = sorted(REQUIRED_TASKS - set(celery_app.tasks))
        if missing_tasks:
            raise RuntimeError(f"Missing Celery notification tasks: {missing_tasks}")
        schedule = celery_app.conf.beat_schedule.get("dispatch-alarm-notifications") or {}
        if float(schedule.get("schedule", -1)) != 5.0:
            raise RuntimeError(f"Unexpected notification dispatcher cadence: {schedule}")

        report = {
            "pass": True,
            "revision": revision,
            "tables": sorted(REQUIRED_TABLES),
            "settings": sorted(REQUIRED_SETTINGS),
            "tasks": sorted(REQUIRED_TASKS),
            "dispatcher_schedule_seconds": schedule["schedule"],
            "notifications_enabled": runtime.enabled,
            "dispatch_limit_per_tick": runtime.dispatch_limit_per_tick,
            "task_batch_size": runtime.task_batch_size,
            "max_outstanding": runtime.max_outstanding,
            "lease_seconds": runtime.lease_seconds,
            "worker_concurrency": runtime.worker_concurrency,
            "raw_webhook_destinations": raw_webhooks,
            "orphan_suppressed_deliveries": orphan_suppression,
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    finally:
        await engine.dispose()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
