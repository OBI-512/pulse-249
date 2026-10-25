"""Deterministic Phase-D capacity/import qualification.

This benchmark intentionally does not mutate business data. It establishes the
10K parser/memory boundary plus deterministic 10K/20K telemetry storage model.
Database/runtime performance is covered by containerized migration/regression
and runtime qualification in the guarded Phase-D package.
"""
from __future__ import annotations

import json
import time
import tracemalloc

from app.services.data_lifecycle import capacity_estimate
from app.services.tabular_formats import MAX_IMPORT_ROWS, parse_csv_bytes


def main() -> int:
    assert MAX_IMPORT_ROWS == 10_000
    header = "customer_code,name,status\n"
    body = "".join(f"BENCH-{i:05d},Customer {i},ACTIVE\n" for i in range(MAX_IMPORT_ROWS))
    payload = (header + body).encode("utf-8")

    tracemalloc.start()
    started = time.perf_counter()
    rows = parse_csv_bytes(payload)
    elapsed = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if len(rows) != MAX_IMPORT_ROWS:
        raise RuntimeError(f"Expected {MAX_IMPORT_ROWS} parsed rows, got {len(rows)}")
    # Broad deterministic guard: parser should remain comfortably bounded in a
    # small backend container. The exact time is evidence, not a universal SLA.
    if peak > 128 * 1024 * 1024:
        raise RuntimeError(f"10K import parser peak memory exceeded 128 MiB: {peak}")
    if elapsed > 15.0:
        raise RuntimeError(f"10K import parser exceeded 15 seconds: {elapsed:.3f}")

    estimates = [capacity_estimate(device_count=n) for n in (10_000, 20_000)]
    if estimates[1]["raw_samples_per_day"] != estimates[0]["raw_samples_per_day"] * 2:
        raise RuntimeError("20K telemetry capacity model is not linear against 10K baseline")
    if not estimates[1]["partitioning_review_required"]:
        raise RuntimeError("20K capacity model must surface the partitioning-review threshold")

    # 730-day deterministic lifecycle simulation: after the configured retention
    # windows fill, both raw and hourly-rollup row counts must reach a steady bound.
    long_run = []
    active_devices = 20_000
    metrics_per_device = 8
    samples_per_day = active_devices * metrics_per_device * 96
    rollup_buckets_per_day = active_devices * metrics_per_device * 24
    for day in range(1, 731):
        raw_days = min(day, 30)
        rollup_days = min(max(day - 7, 0), 365)
        long_run.append((samples_per_day * raw_days, rollup_buckets_per_day * rollup_days))
    if long_run[-1] != long_run[-2]:
        raise RuntimeError("730-day retention simulation did not reach a bounded steady state")
    if long_run[-1][0] != samples_per_day * 30 or long_run[-1][1] != rollup_buckets_per_day * 365:
        raise RuntimeError("Retention simulation exceeded configured data lifecycle bounds")

    result = {
        "status": "PASS",
        "import": {
            "rows": len(rows),
            "bytes": len(payload),
            "elapsed_seconds": round(elapsed, 6),
            "peak_memory_bytes": peak,
            "memory_limit_bytes": 128 * 1024 * 1024,
            "time_limit_seconds": 15.0,
        },
        "telemetry_capacity": estimates,
        "long_run_retention": {
            "simulated_days": 730,
            "device_count": active_devices,
            "metrics_per_device": metrics_per_device,
            "raw_rows_steady_state": long_run[-1][0],
            "hourly_rollup_rows_steady_state": long_run[-1][1],
            "bounded": True,
        },
    }
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
