#!/usr/bin/env python3
"""Static/runtime registration contract for the consolidated Phase-D worker surface."""
from __future__ import annotations

import json
from pathlib import Path

from app.celery_app.config import celery_app
import app.tasks.availability  # noqa: F401
import app.tasks.telemetry  # noqa: F401
import app.tasks.data_lifecycle  # noqa: F401
import app.tasks.reports  # noqa: F401


def main() -> int:
    required_tasks = {
        "fttw.availability.dispatch_due",
        "fttw.availability.poll_batch",
        "fttw.availability.reconcile",
        "fttw.telemetry.dispatch_due",
        "fttw.telemetry.collect_batch",
        "fttw.telemetry.reconcile",
        "fttw.data_lifecycle.run",
        "fttw.reports.execute",
        "fttw.reports.dispatch_queued",
        "fttw.reports.dispatch_schedules",
        "fttw.reports.dispatch_deliveries",
    }
    missing = sorted(required_tasks - set(celery_app.tasks))
    if missing:
        raise RuntimeError(f"Missing required Celery tasks: {missing}")

    schedule = celery_app.conf.beat_schedule or {}
    required_schedule = {
        "dispatch-device-availability": ("fttw.availability.dispatch_due", 1.0),
        "dispatch-device-telemetry": ("fttw.telemetry.dispatch_due", 5.0),
        "reconcile-device-telemetry": ("fttw.telemetry.reconcile", 60.0),
        "phase-d-data-lifecycle": ("fttw.data_lifecycle.run", 3600.0),
        "dispatch-scheduled-reports": ("fttw.reports.dispatch_schedules", 60.0),
        "dispatch-queued-reports": ("fttw.reports.dispatch_queued", 10.0),
        "dispatch-report-deliveries": ("fttw.reports.dispatch_deliveries", 30.0),
    }
    bad = {}
    for key, (task, cadence) in required_schedule.items():
        row = schedule.get(key) or {}
        if row.get("task") != task or float(row.get("schedule", -1)) != cadence:
            bad[key] = row
    if bad:
        raise RuntimeError(f"Unexpected Phase-D beat schedule: {bad}")

    contract_path = Path(__file__).with_name("ci_route_permission_contract_baseline.json")
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    if contract.get("route_count") != 243 or len(contract.get("routes", [])) != 243:
        raise RuntimeError("Phase-D route/permission contract must contain exactly 243 operations")

    print(json.dumps({
        "pass": True,
        "route_count": 243,
        "tasks": sorted(required_tasks),
        "beat_schedule": {key: {"task": value[0], "seconds": value[1]} for key, value in required_schedule.items()},
        "availability_dispatch_seconds": required_schedule["dispatch-device-availability"][1],
        "telemetry_dispatch_seconds": required_schedule["dispatch-device-telemetry"][1],
        "telemetry_is_independent": True,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
