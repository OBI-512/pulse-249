#!/usr/bin/env python3
"""Transactional Phase-D database performance evidence.

All synthetic rows are created inside one transaction and rolled back. This
measures the deployed indexes/retention path without leaving business data.
"""
from __future__ import annotations

import asyncio
import json
import time
from uuid import uuid4

from sqlalchemy import text

from app.db.session import engine

SYNTHETIC_ROWS = 100_000
QUERY_LIMIT_SECONDS = 5.0
RETENTION_LIMIT_SECONDS = 10.0


async def main() -> int:
    device_id = uuid4()
    try:
        async with engine.connect() as conn:
            transaction = await conn.begin()
            try:
                dtype = await conn.scalar(text("SELECT id FROM device_types WHERE code='OTHER' LIMIT 1"))
                if dtype is None:
                    raise RuntimeError("Controlled OTHER device type is missing")
                await conn.execute(text("""
                    INSERT INTO devices (id, device_type_id, display_name, lifecycle_state, operational_state, metadata)
                    VALUES (:device_id, :dtype, 'Phase D transactional DB benchmark', 'ACTIVE', 'UNKNOWN', '{}'::jsonb)
                """), {"device_id": device_id, "dtype": dtype})

                insert_started = time.perf_counter()
                await conn.execute(text("""
                    INSERT INTO telemetry_metrics
                        (id, device_id, metric_key, metric_kind, numeric_value, unit, source, collected_at, metadata)
                    SELECT
                        md5(:seed || ':' || g::text)::uuid,
                        :device_id,
                        'phase_d.benchmark',
                        'GAUGE',
                        (g % 10000)::double precision,
                        'unit',
                        'FIXTURE',
                        now() - ((g % 10080)::text || ' minutes')::interval,
                        '{}'::jsonb
                    FROM generate_series(1, :rows) AS g
                """), {"seed": str(device_id), "device_id": device_id, "rows": SYNTHETIC_ROWS})
                insert_seconds = time.perf_counter() - insert_started

                query_started = time.perf_counter()
                rows = (await conn.execute(text("""
                    SELECT numeric_value, collected_at
                    FROM telemetry_metrics
                    WHERE device_id=:device_id AND metric_key='phase_d.benchmark'
                      AND collected_at >= now() - interval '1 day'
                    ORDER BY collected_at DESC
                    LIMIT 1000
                """), {"device_id": device_id})).all()
                query_seconds = time.perf_counter() - query_started
                if not rows:
                    raise RuntimeError("Indexed telemetry query returned no synthetic rows")
                if query_seconds > QUERY_LIMIT_SECONDS:
                    raise RuntimeError(f"Indexed telemetry query exceeded {QUERY_LIMIT_SECONDS}s: {query_seconds:.3f}s")

                retention_started = time.perf_counter()
                result = await conn.execute(text("""
                    DELETE FROM telemetry_metrics
                    WHERE device_id=:device_id AND collected_at < now() - interval '3 days'
                """), {"device_id": device_id})
                retention_seconds = time.perf_counter() - retention_started
                if retention_seconds > RETENTION_LIMIT_SECONDS:
                    raise RuntimeError(f"Telemetry retention delete exceeded {RETENTION_LIMIT_SECONDS}s: {retention_seconds:.3f}s")

                indexdef = await conn.scalar(text(
                    "SELECT indexdef FROM pg_indexes WHERE schemaname='public' AND indexname='ix_telemetry_metrics_collected_at'"
                ))
                if indexdef is None or "using brin" not in str(indexdef).lower():
                    raise RuntimeError("Telemetry retention BRIN index is missing")

                report = {
                    "status": "PASS",
                    "transactional": True,
                    "rolled_back": True,
                    "synthetic_rows": SYNTHETIC_ROWS,
                    "insert_seconds": round(insert_seconds, 6),
                    "indexed_query_seconds": round(query_seconds, 6),
                    "indexed_query_limit_seconds": QUERY_LIMIT_SECONDS,
                    "indexed_query_rows": len(rows),
                    "retention_delete_seconds": round(retention_seconds, 6),
                    "retention_delete_limit_seconds": RETENTION_LIMIT_SECONDS,
                    "retention_rows_matched": max(0, int(result.rowcount or 0)),
                    "retention_index": str(indexdef),
                }
                print(json.dumps(report, indent=2, sort_keys=True))
            finally:
                await transaction.rollback()
        return 0
    finally:
        await engine.dispose()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
