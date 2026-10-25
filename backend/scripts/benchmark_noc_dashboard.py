#!/usr/bin/env python3
"""PostgreSQL-backed synthetic C4 aggregation benchmark using SQLAlchemy Core."""
from __future__ import annotations

import argparse
import asyncio
import json
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    func,
    select,
)
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

from app.settings import settings


metadata = MetaData()

bench_devices = Table(
    "c4_bench_devices",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("type_code", String, nullable=False),
    Column("network_id", Integer, nullable=False),
    Column("location_id", Integer, nullable=False),
    prefixes=["TEMPORARY"],
    postgresql_on_commit="DROP",
)

bench_availability = Table(
    "c4_bench_availability",
    metadata,
    Column("device_id", Integer, primary_key=True),
    Column("status", String, nullable=False),
    Column("next_check_at", DateTime(timezone=True), nullable=False),
    Column("lease_expires_at", DateTime(timezone=True)),
    Column("last_check_at", DateTime(timezone=True)),
    prefixes=["TEMPORARY"],
    postgresql_on_commit="DROP",
)

bench_alarms = Table(
    "c4_bench_alarms",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("device_id", Integer, nullable=False),
    Column("state", String, nullable=False),
    Column("severity", String, nullable=False),
    prefixes=["TEMPORARY"],
    postgresql_on_commit="DROP",
)

Index("ix_c4_bench_availability_status", bench_availability.c.status)
Index("ix_c4_bench_availability_next_check", bench_availability.c.next_check_at)
Index("ix_c4_bench_availability_lease", bench_availability.c.lease_expires_at)
Index("ix_c4_bench_alarms_state_severity", bench_alarms.c.state, bench_alarms.c.severity)
Index("ix_c4_bench_devices_network", bench_devices.c.network_id)
Index("ix_c4_bench_devices_location", bench_devices.c.location_id)


async def timed_fetch(conn: AsyncConnection, statement) -> float:
    started = time.perf_counter()
    result = await conn.execute(statement)
    result.all()
    return (time.perf_counter() - started) * 1000.0


def benchmark_queries(now: datetime) -> dict[str, object]:
    availability_counts = (
        select(
            func.count().label("total"),
            func.count().filter(bench_availability.c.status == "ONLINE").label("online"),
            func.count().filter(bench_availability.c.status == "OFFLINE").label("offline"),
            func.count().filter(bench_availability.c.status == "SUSPECT").label("suspect"),
            func.count().filter(bench_availability.c.status == "MAINTENANCE").label("maintenance"),
        )
        .select_from(
            bench_devices.join(
                bench_availability,
                bench_availability.c.device_id == bench_devices.c.id,
            )
        )
    )

    device_type_breakdown = (
        select(
            bench_devices.c.type_code,
            bench_availability.c.status,
            func.count().label("count"),
        )
        .select_from(
            bench_devices.join(
                bench_availability,
                bench_availability.c.device_id == bench_devices.c.id,
            )
        )
        .group_by(bench_devices.c.type_code, bench_availability.c.status)
        .order_by(func.count().desc())
    )

    network_breakdown = (
        select(
            bench_devices.c.network_id,
            bench_availability.c.status,
            func.count().label("count"),
        )
        .select_from(
            bench_devices.join(
                bench_availability,
                bench_availability.c.device_id == bench_devices.c.id,
            )
        )
        .group_by(bench_devices.c.network_id, bench_availability.c.status)
        .order_by(func.count().desc())
    )

    polling_health = select(
        func.count().label("monitored"),
        func.count().filter(bench_availability.c.next_check_at <= now).label("due_now"),
        func.count().filter(bench_availability.c.lease_expires_at > now).label("active_leases"),
        func.count()
        .filter(bench_availability.c.last_check_at >= now - timedelta(seconds=300))
        .label("checked_recently"),
    )

    alarm_severity = (
        select(bench_alarms.c.severity, func.count().label("count"))
        .where(bench_alarms.c.state == "ACTIVE")
        .group_by(bench_alarms.c.severity)
    )

    return {
        "availability_counts": availability_counts,
        "device_type_breakdown": device_type_breakdown,
        "network_breakdown": network_breakdown,
        "polling_health": polling_health,
        "alarm_severity": alarm_severity,
    }


async def run(device_count: int, max_query_ms: float) -> dict:
    engine = create_async_engine(settings.database_url)
    now = datetime.now(timezone.utc)
    device_types = ("ACCESS_POINT", "CPE", "SECTOR", "SWITCH", "ROUTER", "OTHER")
    statuses = ("ONLINE", "ONLINE", "ONLINE", "ONLINE", "OFFLINE", "SUSPECT", "UNKNOWN", "MAINTENANCE")
    severities = ("INFO", "WARNING", "MINOR", "MAJOR", "CRITICAL")

    try:
        async with engine.begin() as conn:
            await conn.run_sync(metadata.create_all)

            devices = [
                {
                    "id": i,
                    "type_code": device_types[i % len(device_types)],
                    "network_id": 1 + (i % 20),
                    "location_id": 1 + (i % 250),
                }
                for i in range(1, device_count + 1)
            ]
            availability = [
                {
                    "device_id": i,
                    "status": statuses[i % len(statuses)],
                    "next_check_at": now + timedelta(seconds=(i % 300) - 150),
                    "lease_expires_at": now + timedelta(seconds=45) if i % 17 == 0 else None,
                    "last_check_at": now - timedelta(seconds=i % 320),
                }
                for i in range(1, device_count + 1)
            ]
            alarm_count = max(1, device_count // 8)
            alarms = [
                {
                    "id": i,
                    "device_id": 1 + (i % device_count),
                    "state": "CLEARED" if i % 5 == 0 else "ACTIVE",
                    "severity": severities[i % len(severities)],
                }
                for i in range(1, alarm_count + 1)
            ]

            await conn.execute(bench_devices.insert(), devices)
            await conn.execute(bench_availability.insert(), availability)
            await conn.execute(bench_alarms.insert(), alarms)

            timings = {
                name: round(await timed_fetch(conn, statement), 3)
                for name, statement in benchmark_queries(now).items()
            }
    finally:
        await engine.dispose()

    peak = max(timings.values())
    return {
        "devices": device_count,
        "queries": timings,
        "peak_query_ms": peak,
        "max_query_ms": max_query_ms,
        "pass": peak <= max_query_ms,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--devices", type=int, default=20_000)
    parser.add_argument("--max-query-ms", type=float, default=250.0)
    args = parser.parse_args()
    report = asyncio.run(run(args.devices, args.max_query_ms))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
