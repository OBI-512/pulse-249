from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...security.authorization import authorize_request
from ...security.resource_scope import authorization_scope_metadata, expanded_authorization_scope_keys, scope_for_actor, not_found_scope_error
from ...security.scope_queries import origin_scope_clause
from ...celery_app.config import celery_app
from ...discovery.batch import expand_targets
from ...discovery.registry import registry
from ...models import DiscoveryJob, DiscoveryResult
from ...schemas.batch_discovery import (
    BatchDiscoveryCreateResponse,
    BatchDiscoveryRequest,
)
from ...core.audit_context import get_audit_context
from ...services.audit import record_audit, record_failure_audit
from ...services.discovery_access_templates import require_discovery_snmp_template

router = APIRouter(prefix="/discovery/batch", tags=["Batch Discovery"], dependencies=[Depends(authorize_request)])


@router.post(
    "/jobs",
    response_model=BatchDiscoveryCreateResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_batch_job(
    payload: BatchDiscoveryRequest,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    authorization_keys = await expanded_authorization_scope_keys(db, scope)
    methods = [method.upper() for method in payload.methods]
    unsupported = [method for method in methods if registry.get(method) is None]
    if unsupported:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "UNSUPPORTED_DISCOVERY_METHOD",
                "message": f"Unsupported discovery method(s): {', '.join(unsupported)}",
            },
        )

    if "SNMP" in methods:
        if payload.access_template_id is None:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "SNMP_BATCH_ACCESS_TEMPLATE_REQUIRED",
                    "message": "Select an active SNMP Access Template before starting SNMP batch discovery.",
                },
            )
        await require_discovery_snmp_template(
            db,
            template_id=payload.access_template_id,
            actor_user_id=actor.id,
        )

    if not payload.ip_addresses and not payload.cidrs:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "NO_DISCOVERY_TARGETS",
                "message": "Provide at least one IP address or CIDR.",
            },
        )

    try:
        targets = expand_targets(
            [str(x) for x in payload.ip_addresses],
            payload.cidrs,
            payload.max_targets,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_DISCOVERY_SCOPE", "message": str(exc)},
        )

    job = DiscoveryJob(
        id=uuid4(),
        scope_type="BATCH",
        scope_value=", ".join([*payload.cidrs, *[str(x) for x in payload.ip_addresses]]),
        status="QUEUED",
        metadata_={
            "methods": methods,
            "target_count": len(targets),
            "requested_cidrs": payload.cidrs,
            "requested_ip_addresses": [str(x) for x in payload.ip_addresses],
            "timeout_seconds": payload.timeout_seconds,
            "http_port": payload.http_port,
            "https_port": payload.https_port,
            "concurrency": payload.concurrency,
            "execution": "celery",
            "credential_source": "ACCESS_TEMPLATE" if payload.access_template_id else None,
            "access_template_id": str(payload.access_template_id) if payload.access_template_id else None,
            "_authorization_scope": authorization_scope_metadata(authorization_keys, actor_user_id=scope.user_id),
        },
    )
    db.add(job)
    await db.flush()
    await record_audit(
        db,
        action="DISCOVERY_STARTED",
        entity_type="DiscoveryJob",
        entity_id=job.id,
        entity_display_snapshot={
            "scope_type": job.scope_type,
            "scope_value": job.scope_value,
        },
        description="Batch discovery queued.",
        after_summary={"status": "QUEUED", "target_count": len(targets)},
        metadata={
            "methods": methods,
            "execution": "celery",
            "phase": "QUEUED",
            "credential_source": "ACCESS_TEMPLATE" if payload.access_template_id else None,
        },
    )
    await db.commit()
    await db.refresh(job)
    job_id = job.id
    job_display = {
        "scope_type": job.scope_type,
        "scope_value": job.scope_value,
    }

    audit_context = get_audit_context()
    try:
        task = celery_app.send_task(
            "fttw.discovery.batch",
            args=[
                str(job.id),
                [x.ip_address for x in targets],
                methods,
                payload.timeout_seconds,
                payload.concurrency,
                audit_context.request_id,
                str(audit_context.actor_user_id) if audit_context.actor_user_id else None,
                audit_context.actor_username_snapshot,
                audit_context.source_ip,
                str(payload.access_template_id) if payload.access_template_id else None,
            ],
        )
    except Exception as exc:
        await db.rollback()
        await record_failure_audit(
            action="DISCOVERY_FAILED",
            entity_type="DiscoveryJob",
            entity_id=job_id,
            entity_display_snapshot=job_display,
            description="Batch discovery could not be queued.",
            before_summary={"status": "QUEUED"},
            after_summary={"status": "FAILED"},
            metadata={
                "methods": methods,
                "execution": "celery",
                "phase": "QUEUE",
                "error_type": type(exc).__name__,
            },
        )
        job = await db.get(DiscoveryJob, job_id)
        job.status = "FAILED"
        job.metadata_ = {
            **(job.metadata_ or {}),
            "queue_error_type": type(exc).__name__,
        }
        await db.commit()
        raise HTTPException(
            status_code=503,
            detail={
                "code": "DISCOVERY_QUEUE_UNAVAILABLE",
                "message": "The background discovery queue is unavailable.",
            },
        )

    job.metadata_ = {
        **(job.metadata_ or {}),
        "celery_task_id": task.id,
    }
    await db.commit()

    return BatchDiscoveryCreateResponse(
        job_id=job.id,
        status="QUEUED",
        target_count=len(targets),
        message="Batch discovery job queued in Celery.",
    )


@router.get("/jobs")
async def list_batch_jobs(
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    result = await db.execute(
        select(DiscoveryJob)
        .where(DiscoveryJob.scope_type == "BATCH", await origin_scope_clause(db, scope, DiscoveryJob.metadata_))
        .order_by(DiscoveryJob.created_at.desc())
        .limit(100)
    )
    return result.scalars().all()


@router.get("/jobs/{job_id}")
async def get_batch_job(
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    job = await db.scalar(select(DiscoveryJob).where(DiscoveryJob.id == job_id, DiscoveryJob.scope_type == "BATCH", await origin_scope_clause(db, scope, DiscoveryJob.metadata_)))
    if job is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "BATCH_JOB_NOT_FOUND", "message": "Batch discovery job not found."},
        )

    result = await db.execute(
        select(DiscoveryResult)
        .where(DiscoveryResult.discovery_job_id == job_id)
        .order_by(DiscoveryResult.created_at)
    )
    results = result.scalars().all()

    return {
        "job": job,
        "target_count": job.metadata_.get("target_count", 0),
        "result_count": len(results),
        "celery_task_id": job.metadata_.get("celery_task_id"),
        "results": results,
    }
