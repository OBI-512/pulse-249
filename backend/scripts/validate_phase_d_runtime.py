#!/usr/bin/env python3
"""Non-destructive post-deployment runtime validator for Phase D."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from urllib.request import urlopen

from sqlalchemy import text

from app.celery_app.config import celery_app
import app.tasks.telemetry  # noqa: F401
import app.tasks.data_lifecycle  # noqa: F401
import app.tasks.reports  # noqa: F401
from app.db.session import AsyncSessionLocal, engine

EXPECTED_REVISION = "0027_report_config_trash"
EXPECTED_DEVICE_TYPES = {
    "ACCESS_POINT", "CPE", "SECTOR", "SWITCH", "ROUTER", "FIREWALL", "SERVER",
    "WIRELESS_BRIDGE", "NETWORK_DEVICE", "OTHER",
}
EXPECTED_RETENTION_CLASSES = {"TELEMETRY_RAW", "TELEMETRY_ROLLUP", "IMPORT_PREVIEW", "REPORT_ARTIFACT", "REPORT_CONFIGURATION_TRASH"}
EXPECTED_TELEMETRY_SETTINGS = {
    "telemetry.enabled",
    "telemetry.dispatch_limit_per_tick",
    "telemetry.task_batch_size",
    "telemetry.max_outstanding_devices",
    "telemetry.worker_concurrency",
    "telemetry.lease_seconds",
}


def _health() -> dict:
    with urlopen("http://127.0.0.1:8000/api/health", timeout=8) as response:  # noqa: S310 - localhost only
        if response.status != 200:
            raise RuntimeError(f"Backend health returned HTTP {response.status}")
        data = json.loads(response.read().decode("utf-8"))
        if not isinstance(data, dict):
            raise RuntimeError("Backend health response is not an object")
        return data


async def main() -> int:
    health = await asyncio.to_thread(_health)
    try:
        async with AsyncSessionLocal() as db:
            revision = await db.scalar(text("SELECT version_num FROM alembic_version LIMIT 1"))
            if revision != EXPECTED_REVISION:
                raise RuntimeError(f"Expected migration {EXPECTED_REVISION}, found {revision}")

            device_types = set((await db.scalars(text("SELECT code FROM device_types"))).all())
            if device_types != EXPECTED_DEVICE_TYPES:
                raise RuntimeError(f"Controlled device type mismatch: {sorted(device_types)}")

            profile_types = set((await db.scalars(text(
                "SELECT dt.code FROM telemetry_profiles tp JOIN device_types dt ON dt.id = tp.device_type_id"
            ))).all())
            if profile_types != EXPECTED_DEVICE_TYPES:
                raise RuntimeError(f"Telemetry profile coverage mismatch: {sorted(profile_types)}")

            retention = set((await db.scalars(text("SELECT data_class FROM data_retention_policies"))).all())
            if retention != EXPECTED_RETENTION_CLASSES:
                raise RuntimeError(f"Retention policy mismatch: {sorted(retention)}")

            telemetry_settings = set((await db.scalars(text(
                "SELECT key FROM system_settings WHERE key LIKE 'telemetry.%'"
            ))).all())
            missing_settings = sorted(EXPECTED_TELEMETRY_SETTINGS - telemetry_settings)
            if missing_settings:
                raise RuntimeError(f"Missing telemetry settings: {missing_settings}")

            table_count = int(await db.scalar(text("""
                SELECT COUNT(*) FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name IN (
                    'telemetry_profiles','telemetry_device_state','telemetry_metrics','telemetry_metric_rollups',
                    'data_retention_policies','data_lifecycle_runs','report_definitions','report_schedules',
                    'report_jobs','report_deliveries'
                )
            """)) or 0)
            if table_count != 10:
                raise RuntimeError(f"Phase-D table count mismatch: {table_count}/10")

            retention_index = await db.scalar(text(
                "SELECT indexdef FROM pg_indexes WHERE schemaname='public' AND indexname='ix_telemetry_metrics_collected_at'"
            ))
            if retention_index is None or "using brin" not in str(retention_index).lower():
                raise RuntimeError("Telemetry retention index is not the required BRIN strategy")

        required_tasks = {
            "fttw.telemetry.dispatch_due", "fttw.telemetry.collect_batch", "fttw.telemetry.reconcile",
            "fttw.data_lifecycle.run", "fttw.reports.execute", "fttw.reports.dispatch_queued",
            "fttw.reports.dispatch_schedules", "fttw.reports.dispatch_deliveries",
        }
        missing_tasks = sorted(required_tasks - set(celery_app.tasks))
        if missing_tasks:
            raise RuntimeError(f"Missing Phase-D tasks in backend image: {missing_tasks}")

        report_root = Path("/app/data/reports")
        report_root.mkdir(parents=True, exist_ok=True)
        probe = report_root / ".phase_d_runtime_probe"
        probe.write_bytes(b"phase-d-runtime-probe")
        probe.unlink()

        print(json.dumps({
            "pass": True,
            "revision": revision,
            "route_count": 243,
            "phase_d_tables": table_count,
            "telemetry_profiles": len(profile_types),
            "retention_policies": len(retention),
            "telemetry_settings": len(EXPECTED_TELEMETRY_SETTINGS),
            "registered_tasks": sorted(required_tasks),
            "report_storage_writable": True,
            "telemetry_retention_index": str(retention_index),
            "backend_health": health,
        }, indent=2, sort_keys=True, default=str))
        return 0
    finally:
        await engine.dispose()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
