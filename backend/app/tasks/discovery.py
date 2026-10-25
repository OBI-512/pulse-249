import asyncio
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from celery import Task

from app.celery_app.config import celery_app
from app.settings import settings
from app.discovery.batch_engine import BatchDiscoveryEngine
from app.models import DiscoveryJob, DiscoveryResult, DeviceCandidate
from app.services.audit import record_audit, record_failure_audit
from app.services.discovery_access_templates import (
    require_discovery_snmp_template,
    resolve_discovery_snmp_template,
    snmp_context_kwargs,
)
from app.services.maintenance import MaintenanceModeActive, assert_mutations_allowed


class AsyncTask(Task):
    abstract = True

    def run_async(self, coro):
        return asyncio.run(coro)


async def _execute_discovery_job(
    job_id: UUID,
    targets: list[str],
    methods: list[str],
    timeout_seconds: float,
    concurrency: int,
    request_id: str | None = None,
    actor_user_id: UUID | None = None,
    actor_username_snapshot: str | None = None,
    source_ip: str | None = None,
    task_id: str | None = None,
    access_template_id: UUID | None = None,
):
    await assert_mutations_allowed()
    engine = create_async_engine(
        settings.database_url,
        pool_pre_ping=True,
    )

    SessionLocal = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    audit_kwargs = {
        "actor_user_id": actor_user_id,
        "actor_username_snapshot": actor_username_snapshot,
        "request_id": request_id,
        "source_ip": source_ip,
    }
    try:
        try:
            async with SessionLocal() as db:
                job = await db.get(DiscoveryJob, job_id)

                if job is None:
                    await db.rollback()
                    await record_failure_audit(
                        action="DISCOVERY_FAILED",
                        entity_type="DiscoveryJob",
                        entity_id=job_id,
                        description="Batch discovery job was not found by the worker.",
                        metadata={"phase": "WORKER_LOOKUP", "task_id": task_id},
                        **audit_kwargs,
                    )
                    return {"status": "NOT_FOUND", "job_id": str(job_id)}

                job.status = "RUNNING"
                job.metadata_ = {
                    **(job.metadata_ or {}),
                    "execution": "celery",
                    "celery_task_id": task_id or (job.metadata_ or {}).get("celery_task_id"),
                    "request_id": request_id,
                }
                await record_audit(
                    db,
                    action="DISCOVERY_STARTED",
                    entity_type="DiscoveryJob",
                    entity_id=job.id,
                    entity_display_snapshot={
                        "scope_type": job.scope_type,
                        "scope_value": job.scope_value,
                    },
                    description="Batch discovery worker started.",
                    before_summary={"status": "QUEUED"},
                    after_summary={"status": "RUNNING"},
                    metadata={"phase": "WORKER", "task_id": task_id, "methods": methods},
                    **audit_kwargs,
                )
                await db.commit()

                snmp_context = None
                if "SNMP" in methods:
                    if access_template_id is None:
                        raise RuntimeError("SNMP_BATCH_ACCESS_TEMPLATE_REQUIRED")
                    if actor_user_id is None:
                        raise RuntimeError("SNMP_BATCH_ACTOR_REQUIRED")
                    await require_discovery_snmp_template(
                        db,
                        template_id=access_template_id,
                        actor_user_id=actor_user_id,
                    )
                    runtime = await resolve_discovery_snmp_template(
                        db,
                        template_id=access_template_id,
                    )
                    snmp_context = snmp_context_kwargs(runtime)

                engine_runner = BatchDiscoveryEngine()
                records = await engine_runner.run(
                    job=job,
                    targets=targets,
                    methods=methods,
                    timeout_seconds=timeout_seconds,
                    concurrency=concurrency,
                    db=db,
                    http_port=(job.metadata_ or {}).get("http_port"),
                    https_port=(job.metadata_ or {}).get("https_port"),
                    snmp_context=snmp_context,
                )
                job.metadata_ = {
                    **(job.metadata_ or {}),
                    "result_count": len(records),
                }
                # Results must be visible to the candidate-generation session;
                # the job remains RUNNING until that phase also succeeds.
                await db.commit()

            candidate_count = await _process_results_into_candidates(job_id, SessionLocal)

            async with SessionLocal() as db:
                job = await db.get(DiscoveryJob, job_id)
                if job is None:
                    raise RuntimeError("DISCOVERY_JOB_DISAPPEARED")
                job.status = "COMPLETED"
                job.metadata_ = {
                    **(job.metadata_ or {}),
                    "candidate_count": candidate_count,
                }
                await record_audit(
                    db,
                    action="DISCOVERY_COMPLETED",
                    entity_type="DiscoveryJob",
                    entity_id=job.id,
                    entity_display_snapshot={
                        "scope_type": job.scope_type,
                        "scope_value": job.scope_value,
                    },
                    description="Batch discovery worker completed.",
                    before_summary={"status": "RUNNING"},
                    after_summary={
                        "status": "COMPLETED",
                        "result_count": len(records),
                        "candidate_count": candidate_count,
                    },
                    metadata={"phase": "WORKER", "task_id": task_id, "methods": methods},
                    **audit_kwargs,
                )
                await db.commit()

            return {
                "status": "COMPLETED",
                "job_id": str(job_id),
                "result_count": len(records),
                "candidate_count": candidate_count,
            }
        except Exception as exc:
            # Every business session above either commits or exits through an
            # explicit rollback before durable failure evidence is written.
            await record_failure_audit(
                action="DISCOVERY_FAILED",
                entity_type="DiscoveryJob",
                entity_id=job_id,
                description="Batch discovery worker failed.",
                before_summary={"status": "RUNNING"},
                after_summary={"status": "FAILED"},
                metadata={
                    "phase": "WORKER",
                    "task_id": task_id,
                    "methods": methods,
                    "error_type": type(exc).__name__,
                },
                **audit_kwargs,
            )
            async with SessionLocal() as db:
                job = await db.get(DiscoveryJob, job_id)
                if job is not None:
                    job.status = "FAILED"
                    job.metadata_ = {
                        **(job.metadata_ or {}),
                        "error_type": type(exc).__name__,
                    }
                    await db.commit()
            raise
    finally:
        await engine.dispose()


async def _process_results_into_candidates(
    job_id: UUID,
    SessionLocal,
):
    from app.services.candidates import generate_candidate_from_results

    async with SessionLocal() as db:
        results = (
            await db.execute(
                select(DiscoveryResult)
                .where(
                    DiscoveryResult.discovery_job_id == job_id
                )
                .order_by(DiscoveryResult.created_at)
            )
        ).scalars().all()

        created = 0
        grouped: dict[str, list[DiscoveryResult]] = {}
        for result in results:
            grouped.setdefault(result.ip_address, []).append(result)

        for ip_address, evidence in grouped.items():
            before = await db.scalar(
                select(DeviceCandidate).where(
                    DeviceCandidate.ip_address == ip_address
                )
            )
            candidate = await generate_candidate_from_results(db, evidence)
            if candidate is not None and before is None:
                created += 1

        try:
            await db.commit()
            return created
        except Exception:
            await db.rollback()
            raise


@celery_app.task(
    bind=True,
    base=AsyncTask,
    name="fttw.discovery.batch",
    autoretry_for=(ConnectionError, TimeoutError, MaintenanceModeActive),
    retry_backoff=True,
    retry_backoff_max=60,
    retry_kwargs={"max_retries": 60},
)
def run_batch_discovery(
    self,
    job_id: str,
    targets: list[str],
    methods: list[str],
    timeout_seconds: float,
    concurrency: int,
    request_id: str | None = None,
    actor_user_id: str | None = None,
    actor_username_snapshot: str | None = None,
    source_ip: str | None = None,
    access_template_id: str | None = None,
):
    return self.run_async(
        _execute_discovery_job(
            UUID(job_id),
            targets,
            methods,
            timeout_seconds,
            concurrency,
            request_id,
            UUID(actor_user_id) if actor_user_id else None,
            actor_username_snapshot,
            source_ip,
            getattr(self.request, "id", None),
            UUID(access_template_id) if access_template_id else None,
        )
    )
