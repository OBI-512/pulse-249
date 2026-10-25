#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.settings import settings

EXPECTED_REVISION = "0022_alarm_event_engine"
EXPECTED_ROLE_COUNTS = {"administrator": 4, "operator": 4, "administrative_viewer": 1, "viewer": 1}


async def main() -> int:
    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    try:
        async with engine.connect() as db:
            revision = await db.scalar(text("SELECT version_num FROM alembic_version LIMIT 1"))
            tables = set((await db.scalars(text("SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename IN ('operational_events','alarms','alarm_history')"))).all())
            duplicate_keys = int(await db.scalar(text("SELECT COUNT(*) FROM (SELECT correlation_key FROM alarms GROUP BY correlation_key HAVING COUNT(*) > 1) q")) or 0)
            missing_offline_alarm = int(await db.scalar(text(
                "SELECT COUNT(*) FROM device_availability da JOIN devices d ON d.id=da.device_id "
                "LEFT JOIN alarms a ON a.correlation_key=('device:' || da.device_id::text || ':availability:offline') "
                "WHERE da.status='OFFLINE' AND d.deleted_at IS NULL AND a.id IS NULL"
            )) or 0)
            role_counts = {}
            for role in EXPECTED_ROLE_COUNTS:
                role_counts[role] = int(await db.scalar(text(
                    "SELECT COUNT(*) FROM role_permissions rp JOIN roles r ON r.id=rp.role_id "
                    "JOIN permissions p ON p.id=rp.permission_id "
                    "WHERE r.code=:role AND p.code IN ('alarm.read','alarm.acknowledge','alarm.assign','alarm.clear')"
                ), {"role": role}) or 0)
            counts = dict((await db.execute(text(
                "SELECT (SELECT COUNT(*) FROM alarms) alarms, "
                "(SELECT COUNT(*) FROM alarms WHERE state='ACTIVE') active_alarms, "
                "(SELECT COUNT(*) FROM operational_events) operational_events, "
                "(SELECT COUNT(*) FROM alarm_history) alarm_history"
            ))).mappings().one())
    finally:
        await engine.dispose()

    failures = []
    if tables != {"operational_events", "alarms", "alarm_history"}: failures.append(f"tables={sorted(tables)}")
    if duplicate_keys: failures.append(f"duplicate_correlation_keys={duplicate_keys}")
    if role_counts != EXPECTED_ROLE_COUNTS: failures.append(f"role_counts={role_counts}")

    report = {
        "result": "FAIL" if failures else "PASS",
        "revision": revision,
        "tables": sorted(tables),
        "duplicate_correlation_keys": duplicate_keys,
        "offline_conditions_without_alarm": missing_offline_alarm,
        "role_permission_counts": role_counts,
        "counts": counts,
        "failures": failures,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 2 if failures else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
