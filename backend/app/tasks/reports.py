from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import logging
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.celery_app.config import celery_app
from app.models import ReportDelivery, ReportJob, ReportSchedule, User
from app.notifications import deliver_notification
from app.security.permissions import Permission as P
from app.security.resource_scope import load_effective_resource_scope
from app.services.authorization_snapshot import scope_fingerprint
from app.services.audit import record_audit
from app.services.reports import (
    REPORT_REQUIRED_PERMISSION, create_report_job, effective_permission_codes, execute_report_job,
    media_type_for, report_root, validate_report_request,
)
from app.settings import settings as app_settings

logger = logging.getLogger(__name__)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _session_factory():
    engine = create_async_engine(app_settings.database_url, pool_pre_ping=True)
    return engine, async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def _run_job(job_id: UUID) -> dict[str, object]:
    engine, SessionLocal = _session_factory()
    try:
        try:
            async with SessionLocal() as db:
                job = await execute_report_job(db, job_id)
                await db.commit()
                return {"job_id": str(job.id), "status": job.status, "row_count": job.row_count}
        except Exception as exc:
            logger.exception("report_generation_failed", extra={"event": "REPORT_GENERATION_FAILED", "job_id": str(job_id), "error_type": type(exc).__name__})
            # File creation precedes the database commit. If generation or the
            # commit fails, remove any uncommitted artifact/temp file so the
            # filesystem cannot accumulate report data with no authoritative job.
            root = report_root()
            for suffix in ("csv", "xlsx", "pdf", "json"):
                for candidate in (root / f"report_{job_id}.{suffix}", root / f"report_{job_id}.{suffix}.tmp"):
                    try:
                        if candidate.is_file():
                            candidate.unlink()
                    except OSError:
                        logger.exception("report_orphan_cleanup_failed", extra={"event": "REPORT_ORPHAN_CLEANUP_FAILED", "job_id": str(job_id), "path": candidate.name})
            async with SessionLocal() as db:
                job = await db.scalar(select(ReportJob).where(ReportJob.id == job_id).with_for_update())
                if job and job.status not in {"COMPLETED", "CANCELLED", "EXPIRED"}:
                    job.status = "FAILED"; job.error_code = f"REPORT_{type(exc).__name__.upper()}"[:120]; job.error_message = str(exc)[:1000]; job.completed_at = utcnow()
                    await record_audit(db, action="REPORT_FAILED", entity_type="ReportJob", entity_id=job.id, result="FAILURE", description="Asynchronous report generation failed.", metadata={"error_type": type(exc).__name__})
                    await db.commit()
            return {"job_id": str(job_id), "status": "FAILED", "error_type": type(exc).__name__}
    finally:
        await engine.dispose()


async def _dispatch_queued() -> dict[str, int]:
    engine, SessionLocal = _session_factory()
    try:
        async with SessionLocal() as db:
            # Row-level lock prevents two dispatch ticks from publishing the same batch.
            stale_before = utcnow() - timedelta(minutes=15)
            rows = list((await db.scalars(select(ReportJob).where(
                or_(ReportJob.status == "QUEUED", and_(ReportJob.status == "RUNNING", ReportJob.started_at < stale_before))
            ).order_by(ReportJob.requested_at, ReportJob.id).with_for_update(skip_locked=True).limit(50))).all())
            # Mark as RUNNING before publish. Execute task accepts RUNNING and rechecks authorization.
            for job in rows:
                job.status = "RUNNING"; job.started_at = utcnow()
            await db.commit()
        published = 0
        for job in rows:
            try:
                celery_app.send_task("fttw.reports.execute", args=[str(job.id)], expires=840)
                published += 1
            except Exception:
                logger.exception("report_publish_failed", extra={"event": "REPORT_PUBLISH_FAILED", "job_id": str(job.id)})
                async with SessionLocal() as db:
                    current = await db.scalar(select(ReportJob).where(ReportJob.id == job.id).with_for_update())
                    if current and current.status == "RUNNING":
                        current.status = "QUEUED"; current.started_at = None
                        await db.commit()
        return {"claimed": len(rows), "published": published}
    finally:
        await engine.dispose()


async def _dispatch_schedules() -> dict[str, int]:
    engine, SessionLocal = _session_factory()
    now = utcnow()
    try:
        async with SessionLocal() as db:
            rows = list((await db.scalars(select(ReportSchedule).where(ReportSchedule.enabled.is_(True), ReportSchedule.deleted_at.is_(None), ReportSchedule.next_run_at <= now).order_by(ReportSchedule.next_run_at, ReportSchedule.id).with_for_update(skip_locked=True).limit(50))).all())
            created = 0
            for schedule in rows:
                user = await db.scalar(select(User).where(User.id == schedule.owner_user_id, User.is_active.is_(True)))
                if user is None:
                    schedule.enabled = False
                    continue
                try:
                    await create_report_job(db, owner_user_id=schedule.owner_user_id, report_type=schedule.report_type, format=schedule.format, filters=schedule.filters or {}, include_sensitive=schedule.include_sensitive, definition_id=schedule.definition_id, schedule_id=schedule.id)
                    created += 1
                except (PermissionError, ValueError):
                    # Security/config drift fails closed. Disable the schedule until its owner reviews it.
                    schedule.enabled = False
                    await record_audit(db, action="REPORT_SCHEDULE_DISABLED", entity_type="ReportSchedule", entity_id=schedule.id, result="FAILURE", description="Scheduled report disabled because current authorization or report configuration no longer permits execution.")
                schedule.last_run_at = now
                next_at = schedule.next_run_at
                step = timedelta(minutes=schedule.interval_minutes)
                while next_at <= now:
                    next_at += step
                schedule.next_run_at = next_at
            await db.commit()
        return {"due": len(rows), "created": created}
    finally:
        await engine.dispose()


async def _deliver_one(SessionLocal, delivery_id: UUID) -> str:
    now = utcnow()
    async with SessionLocal() as db:
        row = await db.scalar(select(ReportDelivery).where(ReportDelivery.id == delivery_id).with_for_update().execution_options(populate_existing=True))
        if row is None or row.status not in {"PENDING", "RETRY", "SENDING"}:
            return "STALE"
        job = await db.scalar(select(ReportJob).where(ReportJob.id == row.report_job_id))
        schedule = await db.scalar(select(ReportSchedule).where(ReportSchedule.id == row.schedule_id)) if row.schedule_id else None
        user = await db.scalar(select(User).where(User.id == row.owner_user_id, User.is_active.is_(True)))
        if job is None or job.status != "COMPLETED" or user is None:
            row.status = "CANCELLED"; row.last_error_code = "REPORT_DELIVERY_SOURCE_UNAVAILABLE"; await db.commit(); return "CANCELLED"
        permissions = await effective_permission_codes(db, user.id)
        scope = await load_effective_resource_scope(db, user.id)
        try:
            validate_report_request(report_type=job.report_type, format=job.format, include_sensitive=job.include_sensitive, scope=scope, permissions=permissions)
        except (PermissionError, ValueError):
            row.status = "CANCELLED"; row.last_error_code = "REPORT_DELIVERY_AUTHORIZATION_REVOKED"; await db.commit(); return "CANCELLED"
        if scope_fingerprint(scope) != job.scope_fingerprint or row.scope_fingerprint != job.scope_fingerprint:
            row.status = "CANCELLED"; row.last_error_code = "REPORT_DELIVERY_SCOPE_CHANGED"; await db.commit(); return "CANCELLED"
        root = report_root(); path = (root / (job.artifact_name or "")).resolve()
        if path.parent != root or not path.is_file():
            row.status = "FAILED"; row.last_error_code = "REPORT_ARTIFACT_MISSING"; await db.commit(); return "FAILED"
        content = path.read_bytes()
        if sha256(content).hexdigest() != job.artifact_sha256:
            row.status = "FAILED"; row.last_error_code = "REPORT_ARTIFACT_CHECKSUM_MISMATCH"; await db.commit(); return "FAILED"
        row.status = "SENDING"; row.last_attempt_at = now; row.attempt_count += 1
        await db.commit()
        attachment = (job.artifact_name or f"report.{job.format.lower()}", content, media_type_for(job.format))
        result = await deliver_notification(
            channel_type=row.channel_type, destination=row.destination,
            payload={"kind": "REPORT", "report_type": job.report_type, "report_name": schedule.name if schedule else job.report_type, "format": job.format, "row_count": job.row_count, "generated_at": job.completed_at.isoformat() if job.completed_at else None, "job_id": str(job.id)},
            idempotency_key=row.idempotency_key, attachment=attachment,
        )
    async with SessionLocal() as db:
        row = await db.scalar(select(ReportDelivery).where(ReportDelivery.id == delivery_id).with_for_update())
        if row is None or row.status != "SENDING":
            return "STALE"
        row.response_status = result.response_status
        if result.success:
            row.status = "SENT"; row.delivered_at = utcnow(); row.last_error_code = None
            await record_audit(db, action="REPORT_DELIVERED", entity_type="ReportDelivery", entity_id=row.id, description="Scheduled report delivered through notification foundation.", metadata={"report_job_id": str(row.report_job_id), "channel_type": row.channel_type})
        else:
            max_attempts = schedule.max_attempts if schedule else 3
            base = schedule.retry_base_seconds if schedule else 60
            row.last_error_code = result.error_code
            if row.attempt_count >= max_attempts:
                row.status = "FAILED"
            else:
                row.status = "RETRY"; row.next_attempt_at = utcnow() + timedelta(seconds=min(3600, base * (2 ** max(0, row.attempt_count - 1))))
        await db.commit()
        return row.status


async def _dispatch_deliveries() -> dict[str, int]:
    engine, SessionLocal = _session_factory()
    now = utcnow()
    try:
        async with SessionLocal() as db:
            rows = list((await db.scalars(select(ReportDelivery.id).where(
                or_(
                    and_(ReportDelivery.status.in_(("PENDING", "RETRY")), ReportDelivery.next_attempt_at <= now),
                    and_(ReportDelivery.status == "SENDING", ReportDelivery.last_attempt_at < now - timedelta(minutes=10)),
                )
            ).order_by(ReportDelivery.next_attempt_at, ReportDelivery.id).limit(25))).all())
        results = await asyncio.gather(*(_deliver_one(SessionLocal, row_id) for row_id in rows))
        return {"due": len(rows), "sent": results.count("SENT"), "retry": results.count("RETRY"), "failed": results.count("FAILED"), "cancelled": results.count("CANCELLED")}
    finally:
        await engine.dispose()


@celery_app.task(name="fttw.reports.execute", time_limit=900, soft_time_limit=840)
def execute_report(job_id: str):
    return asyncio.run(_run_job(UUID(job_id)))


@celery_app.task(name="fttw.reports.dispatch_queued", time_limit=30, soft_time_limit=25)
def dispatch_queued_reports():
    return asyncio.run(_dispatch_queued())


@celery_app.task(name="fttw.reports.dispatch_schedules", time_limit=45, soft_time_limit=40)
def dispatch_report_schedules():
    return asyncio.run(_dispatch_schedules())


@celery_app.task(name="fttw.reports.dispatch_deliveries", time_limit=300, soft_time_limit=280)
def dispatch_report_deliveries():
    return asyncio.run(_dispatch_deliveries())
