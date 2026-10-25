from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from sqlalchemy import delete, func, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    DataLifecycleRun,
    DataRetentionPolicy,
    ImportJob,
    ReportDefinition,
    ReportJob,
    ReportSchedule,
    TelemetryMetric,
    TelemetryMetricRollup,
)
from app.services.audit import record_audit
from app.settings import settings


DEFAULT_RETENTION_POLICIES = (
    {
        "data_class": "TELEMETRY_RAW",
        "retain_days": 30,
        "rollup_after_days": 7,
        "batch_hours": 24,
        "description": "Raw telemetry is hourly-rollup eligible after 7 days and purged after 30 days.",
    },
    {
        "data_class": "TELEMETRY_ROLLUP",
        "retain_days": 365,
        "rollup_after_days": None,
        "batch_hours": 168,
        "description": "Hourly telemetry rollups are retained for one year.",
    },
    {
        "data_class": "IMPORT_PREVIEW",
        "retain_days": 7,
        "rollup_after_days": None,
        "batch_hours": 24,
        "description": "Uncommitted import previews and row diagnostics expire after seven days.",
    },
    {
        "data_class": "REPORT_ARTIFACT",
        "retain_days": 30,
        "rollup_after_days": None,
        "batch_hours": 24,
        "description": "Generated report artifacts expire after thirty days.",
    },
    {
        "data_class": "REPORT_CONFIGURATION_TRASH",
        "retain_days": 30,
        "rollup_after_days": None,
        "batch_hours": 24,
        "description": "Deleted saved report definitions and schedules remain recoverable before automatic purge.",
    },
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def ensure_default_retention_policies(db: AsyncSession) -> int:
    existing = set((await db.scalars(select(DataRetentionPolicy.data_class))).all())
    created = 0
    for item in DEFAULT_RETENTION_POLICIES:
        if item["data_class"] in existing:
            continue
        db.add(DataRetentionPolicy(enabled=True, **item))
        created += 1
    return created


ensure_default_policies = ensure_default_retention_policies

def capacity_estimate(
    *,
    device_count: int,
    enabled_device_fraction: float = 1.0,
    metrics_per_device: int = 8,
    interval_seconds: int = 900,
    raw_retention_days: int = 30,
    rollup_retention_days: int = 365,
    raw_bytes_per_sample: int = 180,
    rollup_bytes_per_bucket: int = 140,
) -> dict[str, object]:
    active = max(0, int(round(device_count * max(0.0, min(1.0, enabled_device_fraction)))))
    samples_per_metric_day = max(1, int(86400 / max(60, interval_seconds)))
    raw_samples_per_day = active * max(1, metrics_per_device) * samples_per_metric_day
    raw_per_day = raw_samples_per_day * raw_bytes_per_sample
    raw_storage = raw_per_day * raw_retention_days
    retained_raw_rows = raw_samples_per_day * raw_retention_days
    partitioning_review_threshold = 250_000_000
    rollup_per_day = active * max(1, metrics_per_device) * 24 * rollup_bytes_per_bucket
    rollup_storage = rollup_per_day * rollup_retention_days
    return {
        "device_count": device_count,
        "enabled_device_fraction": enabled_device_fraction,
        "metrics_per_device": metrics_per_device,
        "interval_seconds": interval_seconds,
        "raw_samples_per_day": raw_samples_per_day,
        "estimated_raw_bytes_per_day": raw_per_day,
        "estimated_raw_storage_bytes": raw_storage,
        "estimated_raw_rows_retained": retained_raw_rows,
        "partitioning_review_required": retained_raw_rows >= partitioning_review_threshold,
        "storage_strategy": {
            "time_retention_index": "BRIN(telemetry_metrics.collected_at, pages_per_range=128)",
            "device_metric_query_index": "BTREE(device_id, metric_key, collected_at)",
            "metric_time_query_index": "BTREE(metric_key, collected_at)",
            "partitioning_strategy": "Review native PostgreSQL time partitioning before sustained operation above the raw-row review threshold; BRIN is the deployed Phase-D scale guard without changing ORM identity semantics.",
        },
        "estimated_hourly_rollup_bytes_per_day": rollup_per_day,
        "estimated_rollup_storage_bytes": rollup_storage,
        "assumptions": {
            "raw_bytes_per_sample": raw_bytes_per_sample,
            "rollup_bytes_per_bucket": rollup_bytes_per_bucket,
            "raw_retention_days": raw_retention_days,
            "rollup_retention_days": rollup_retention_days,
            "index_overhead_not_included": True,
            "partitioning_review_threshold_raw_rows": partitioning_review_threshold,
        },
    }


def capacity_model() -> dict[str, object]:
    return {
        "generated_at": utcnow(),
        "estimates": [capacity_estimate(device_count=10_000), capacity_estimate(device_count=20_000)],
    }


async def _start_run(db: AsyncSession, data_class: str, *, now: datetime) -> DataLifecycleRun:
    key = f"{data_class.lower()}:{now.strftime('%Y%m%d%H')}"
    existing = await db.scalar(select(DataLifecycleRun).where(DataLifecycleRun.idempotency_key == key))
    if existing is not None:
        return existing
    row = DataLifecycleRun(
        data_class=data_class,
        status="RUNNING",
        idempotency_key=key,
        started_at=now,
        metadata_={},
    )
    db.add(row)
    await db.flush()
    return row


async def _rollup_raw_window(db: AsyncSession, *, start: datetime, end: datetime) -> tuple[int, int]:
    """Upsert hourly numeric aggregates for a bounded raw window.

    PostgreSQL performs the aggregation in-database. The unique rollup bucket
    makes replay idempotent after a worker interruption.
    """
    aggregate = (
        select(
            TelemetryMetric.device_id.label("device_id"),
            TelemetryMetric.metric_key.label("metric_key"),
            func.max(TelemetryMetric.unit).label("unit"),
            func.date_trunc("hour", TelemetryMetric.collected_at).label("bucket_start"),
            func.count(TelemetryMetric.id).label("sample_count"),
            func.min(TelemetryMetric.numeric_value).label("min_value"),
            func.max(TelemetryMetric.numeric_value).label("max_value"),
            func.avg(TelemetryMetric.numeric_value).label("avg_value"),
            func.sum(TelemetryMetric.numeric_value).label("sum_value"),
        )
        .where(
            TelemetryMetric.collected_at >= start,
            TelemetryMetric.collected_at < end,
            TelemetryMetric.numeric_value.is_not(None),
        )
        .group_by(
            TelemetryMetric.device_id,
            TelemetryMetric.metric_key,
            func.date_trunc("hour", TelemetryMetric.collected_at),
        )
    )
    groups = (await db.execute(aggregate)).all()
    for row in groups:
        stmt = insert(TelemetryMetricRollup).values(
            id=uuid4(),
            device_id=row.device_id,
            metric_key=row.metric_key,
            unit=row.unit,
            bucket_start=row.bucket_start,
            bucket_seconds=3600,
            sample_count=int(row.sample_count),
            min_value=row.min_value,
            max_value=row.max_value,
            avg_value=float(row.avg_value) if row.avg_value is not None else None,
            sum_value=row.sum_value,
            first_value=None,
            last_value=None,
            metadata_={"source": "TELEMETRY_RAW_HOURLY"},
        ).on_conflict_do_update(
            constraint="uq_telemetry_rollup_bucket",
            set_={
                "unit": row.unit,
                "sample_count": int(row.sample_count),
                "min_value": row.min_value,
                "max_value": row.max_value,
                "avg_value": float(row.avg_value) if row.avg_value is not None else None,
                "sum_value": row.sum_value,
                "metadata": {"source": "TELEMETRY_RAW_HOURLY"},
            },
        )
        await db.execute(stmt)
    scanned = int((await db.scalar(select(func.count(TelemetryMetric.id)).where(
        TelemetryMetric.collected_at >= start,
        TelemetryMetric.collected_at < end,
    ))) or 0)
    return scanned, len(groups)


async def run_telemetry_raw_lifecycle(db: AsyncSession, policy: DataRetentionPolicy, *, now: datetime | None = None) -> DataLifecycleRun:
    current = now or utcnow()
    lock = bool(await db.scalar(select(func.pg_try_advisory_xact_lock(0x46544432))))
    run = await _start_run(db, "TELEMETRY_RAW", now=current)
    if run.status != "RUNNING":
        return run
    if not lock or not policy.enabled:
        run.status = "SKIPPED"
        run.completed_at = current
        run.metadata_ = {"reason": "LOCKED" if not lock else "DISABLED"}
        return run

    rollup_cutoff = current - timedelta(days=policy.rollup_after_days or policy.retain_days)
    purge_cutoff = current - timedelta(days=policy.retain_days)
    oldest = await db.scalar(select(func.min(TelemetryMetric.collected_at)).where(TelemetryMetric.collected_at < rollup_cutoff))
    if oldest is not None:
        start = max(oldest, run.cursor_at) if run.cursor_at else oldest
        end = min(start + timedelta(hours=policy.batch_hours), rollup_cutoff)
        scanned, rolled = await _rollup_raw_window(db, start=start, end=end)
        run.scanned_rows += scanned
        run.rolled_up_rows += rolled
        run.cursor_at = end

    # Never purge a raw range that the resumable rollup cursor has not passed.
    # This prevents a long backlog from being deleted faster than it can be aggregated.
    purge_boundary = min(purge_cutoff, run.cursor_at) if run.cursor_at is not None else None
    if purge_boundary is not None:
        purge_result = await db.execute(delete(TelemetryMetric).where(TelemetryMetric.collected_at < purge_boundary))
        run.purged_rows += max(0, int(purge_result.rowcount or 0))
    run.status = "COMPLETED"
    run.completed_at = current
    run.metadata_ = {
        "rollup_cutoff": rollup_cutoff.isoformat(),
        "purge_cutoff": purge_cutoff.isoformat(),
        "safe_purge_boundary": purge_boundary.isoformat() if purge_boundary is not None else None,
        "operational_state_protected": True,
    }
    await record_audit(
        db,
        action="DATA_RETENTION_RUN",
        entity_type="DataLifecycleRun",
        entity_id=run.id,
        description="Telemetry retention/rollup lifecycle executed.",
        metadata={
            "data_class": "TELEMETRY_RAW",
            "scanned_rows": run.scanned_rows,
            "rolled_up_rows": run.rolled_up_rows,
            "purged_rows": run.purged_rows,
        },
    )
    return run


async def run_rollup_retention(db: AsyncSession, policy: DataRetentionPolicy, *, now: datetime | None = None) -> DataLifecycleRun:
    current = now or utcnow()
    run = await _start_run(db, "TELEMETRY_ROLLUP", now=current)
    if run.status != "RUNNING":
        return run
    cutoff = current - timedelta(days=policy.retain_days)
    result = await db.execute(delete(TelemetryMetricRollup).where(TelemetryMetricRollup.bucket_start < cutoff))
    run.purged_rows = max(0, int(result.rowcount or 0))
    run.status = "COMPLETED"
    run.completed_at = current
    run.metadata_ = {"purge_cutoff": cutoff.isoformat()}
    return run


def _report_root() -> Path:
    root = Path(settings.data_root).resolve() / "reports"
    root.mkdir(parents=True, exist_ok=True)
    return root


async def run_report_artifact_retention(db: AsyncSession, policy: DataRetentionPolicy, *, now: datetime | None = None) -> DataLifecycleRun:
    current = now or utcnow()
    run = await _start_run(db, "REPORT_ARTIFACT", now=current)
    if run.status != "RUNNING":
        return run
    cutoff = current - timedelta(days=policy.retain_days)
    rows = list((await db.scalars(
        select(ReportJob).where(
            ReportJob.status == "COMPLETED",
            ReportJob.completed_at.is_not(None),
            ReportJob.completed_at < cutoff,
        ).with_for_update(skip_locked=True).limit(500)
    )).all())
    root = _report_root()
    removed = 0
    for row in rows:
        if row.artifact_name:
            candidate = (root / Path(row.artifact_name).name).resolve()
            if candidate.parent == root and candidate.exists():
                try:
                    candidate.unlink()
                except OSError:
                    continue
        row.status = "EXPIRED"
        row.artifact_name = None
        row.artifact_size = None
        row.artifact_sha256 = None
        removed += 1
    run.purged_rows = removed
    run.status = "COMPLETED"
    run.completed_at = current
    run.metadata_ = {"cutoff": cutoff.isoformat()}
    return run




async def run_report_configuration_trash_retention(
    db: AsyncSession, policy: DataRetentionPolicy, *, now: datetime | None = None
) -> DataLifecycleRun:
    current = now or utcnow()
    run = await _start_run(db, "REPORT_CONFIGURATION_TRASH", now=current)
    if run.status != "RUNNING":
        return run
    if not policy.enabled:
        run.status = "SKIPPED"
        run.completed_at = current
        run.metadata_ = {"reason": "DISABLED"}
        return run

    schedules = list((await db.scalars(
        select(ReportSchedule).where(
            ReportSchedule.deleted_at.is_not(None),
            ReportSchedule.purge_after.is_not(None),
            ReportSchedule.purge_after <= current,
        ).order_by(ReportSchedule.purge_after, ReportSchedule.id).with_for_update(skip_locked=True).limit(500)
    )).all())
    for row in schedules:
        await record_audit(
            db, action="REPORT_SCHEDULE_AUTO_PURGED", entity_type="ReportSchedule", entity_id=row.id,
            description="Deleted scheduled report automatically purged after report-trash retention expired.",
            metadata={"deleted_at": row.deleted_at.isoformat() if row.deleted_at else None, "purge_after": row.purge_after.isoformat() if row.purge_after else None},
        )
        await db.delete(row)
    await db.flush()

    definitions = list((await db.scalars(
        select(ReportDefinition).where(
            ReportDefinition.deleted_at.is_not(None),
            ReportDefinition.purge_after.is_not(None),
            ReportDefinition.purge_after <= current,
            ~select(ReportSchedule.id).where(ReportSchedule.definition_id == ReportDefinition.id).exists(),
        ).order_by(ReportDefinition.purge_after, ReportDefinition.id).with_for_update(skip_locked=True).limit(500)
    )).all())
    for row in definitions:
        await record_audit(
            db, action="REPORT_DEFINITION_AUTO_PURGED", entity_type="ReportDefinition", entity_id=row.id,
            description="Deleted saved report definition automatically purged after report-trash retention expired.",
            metadata={"deleted_at": row.deleted_at.isoformat() if row.deleted_at else None, "purge_after": row.purge_after.isoformat() if row.purge_after else None},
        )
        await db.delete(row)

    run.scanned_rows = len(schedules) + len(definitions)
    run.purged_rows = len(schedules) + len(definitions)
    run.status = "COMPLETED"
    run.completed_at = current
    run.metadata_ = {
        "schedule_purged": len(schedules),
        "definition_purged": len(definitions),
        "retention_days": policy.retain_days,
        "dependency_safe": True,
    }
    return run


async def run_import_preview_retention(db: AsyncSession, policy: DataRetentionPolicy, *, now: datetime | None = None) -> DataLifecycleRun:
    current = now or utcnow()
    run = await _start_run(db, "IMPORT_PREVIEW", now=current)
    if run.status != "RUNNING":
        return run
    cutoff = current - timedelta(days=policy.retain_days)
    rows = list((await db.scalars(select(ImportJob).where(
        ImportJob.status.in_(("PENDING", "PREVIEWED", "FAILED", "EXPIRED")),
        ImportJob.created_at < cutoff,
    ).with_for_update(skip_locked=True).limit(500))).all())
    for row in rows:
        await db.delete(row)
    run.purged_rows = len(rows)
    run.status = "COMPLETED"
    run.completed_at = current
    run.metadata_ = {"cutoff": cutoff.isoformat()}
    return run


async def run_all_lifecycle_once(db: AsyncSession, *, now: datetime | None = None) -> list[DataLifecycleRun]:
    current = now or utcnow()
    await ensure_default_retention_policies(db)
    policies = {
        row.data_class: row for row in (await db.scalars(select(DataRetentionPolicy))).all()
    }
    runs: list[DataLifecycleRun] = []
    handlers = {
        "TELEMETRY_RAW": run_telemetry_raw_lifecycle,
        "TELEMETRY_ROLLUP": run_rollup_retention,
        "REPORT_ARTIFACT": run_report_artifact_retention,
        "REPORT_CONFIGURATION_TRASH": run_report_configuration_trash_retention,
        "IMPORT_PREVIEW": run_import_preview_retention,
    }
    for data_class, handler in handlers.items():
        policy = policies.get(data_class)
        if policy is None:
            continue
        try:
            async with db.begin_nested():
                runs.append(await handler(db, policy, now=current))
        except Exception as exc:
            # The savepoint rollback keeps the session usable, preserves other classes,
            # and lets the next idempotent run resume this class safely.
            failed = DataLifecycleRun(
                data_class=data_class,
                status="FAILED",
                idempotency_key=f"{data_class.lower()}:{current.strftime('%Y%m%d%H%M')}:{uuid4()}",
                started_at=current,
                completed_at=utcnow(),
                error_code=f"{type(exc).__name__}"[:120],
                metadata_={"resumable": True},
            )
            db.add(failed)
            runs.append(failed)
    return runs
