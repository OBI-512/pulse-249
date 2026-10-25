from uuid import UUID, uuid4
from ipaddress import ip_address, ip_network

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...security.authorization import authorize_request
from ...security.resource_scope import (authorization_scope_metadata, expanded_authorization_scope_keys, scope_for_actor, not_found_scope_error)
from ...security.scope_queries import origin_scope_clause
from ...discovery.engine import discovery_engine
from ...discovery.aggregation import aggregate_discovery_records
from ...discovery.models import DiscoveryContext
from ...discovery.registry import registry
from ...models import DeviceCandidate, DiscoveryJob, DiscoveryResult
from ...schemas.pagination import PageResult
from ...schemas.discovery import (
    DiscoveryAggregateRead,
    DiscoveryJobRead,
    DiscoveryResultRead,
    DiscoveryRunRequest,
    DiscoveryRunResponse,
)
from ...services.candidates import generate_candidate_from_results
from ...services.audit import record_audit, record_failure_audit
from ...services.discovery_access_templates import (
    require_discovery_snmp_template,
    resolve_discovery_snmp_template,
    snmp_context_kwargs,
)


router = APIRouter(
    prefix="/discovery",
    tags=["Discovery"],
    dependencies=[Depends(authorize_request)],
)


async def _discovery_scope_context(db: AsyncSession, actor):
    scope = await scope_for_actor(db, actor)
    keys = await expanded_authorization_scope_keys(db, scope)
    return scope, keys


async def _scoped_job(db: AsyncSession, actor, job_id: UUID):
    scope = await scope_for_actor(db, actor)
    clause = await origin_scope_clause(db, scope, DiscoveryJob.metadata_)
    job = await db.scalar(select(DiscoveryJob).where(DiscoveryJob.id == job_id, clause))
    if job is None:
        raise not_found_scope_error("Discovery job")
    return job


def _compact_batch_scope(scope_value: str, metadata: dict) -> str:
    requested_cidrs = metadata.get("requested_cidrs") or []
    requested_ips = metadata.get("requested_ip_addresses") or []
    if requested_cidrs or requested_ips:
        return ", ".join([*requested_cidrs, *requested_ips])

    values = [value.strip() for value in scope_value.split(",") if value.strip()]
    if not values or len(values) <= 8:
        return ", ".join(values)

    try:
        addresses = sorted({ip_address(value) for value in values}, key=lambda value: (value.version, int(value)))
    except ValueError:
        return scope_value

    remaining = set(addresses)
    compact: list[str] = []
    while remaining:
        address = min(remaining, key=lambda value: (value.version, int(value)))
        best = None
        for prefix in range(address.max_prefixlen, -1, -1):
            network = ip_network(f"{address}/{prefix}", strict=False)
            if network.num_addresses > len(remaining) + 2:
                continue
            if any(value.version != address.version or value not in network for value in remaining):
                continue
            usable = set(network.hosts()) if network.num_addresses > 2 else set(network)
            if usable == remaining or usable.issubset(remaining):
                if usable == remaining:
                    best = (network, usable)
                    break
                if best is None:
                    best = (network, usable)

        if best is not None:
            network, usable = best
            compact.append(str(network))
            remaining.difference_update(usable)
        else:
            compact.append(str(address))
            remaining.discard(address)

    return ", ".join(compact)


def _validated_snmp_options(payload: DiscoveryRunRequest) -> dict:
    for value in (payload.snmp_community, payload.snmp_v3_auth_password, payload.snmp_v3_priv_password):
        if value is not None and len(value) > 255:
            raise HTTPException(
                status_code=422,
                detail={"code": "SNMP_SECRET_TOO_LONG", "message": "An SNMP credential value exceeds the maximum supported length."},
            )

    version = (payload.snmp_version or "2c").strip().lower()
    if version in {"v1", "1"}:
        version = "1"
    elif version in {"v2c", "2c", "2"}:
        version = "2c"
    elif version in {"v3", "3"}:
        version = "3"
    else:
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_SNMP_VERSION", "message": "SNMP version must be v1, v2c, or v3."},
        )

    if version in {"1", "2c"}:
        community = (payload.snmp_community or "").strip()
        if not community:
            raise HTTPException(
                status_code=422,
                detail={"code": "SNMP_COMMUNITY_REQUIRED", "message": f"SNMP v{version} requires a community string."},
            )
        return {"version": version, "community": community}

    username = (payload.snmp_v3_username or "").strip()
    if not username:
        raise HTTPException(
            status_code=422,
            detail={"code": "SNMP_V3_USERNAME_REQUIRED", "message": "SNMPv3 requires a username."},
        )

    security_level = (payload.snmp_v3_security_level or "noAuthNoPriv").strip()
    if security_level not in {"noAuthNoPriv", "authNoPriv", "authPriv"}:
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_SNMP_V3_SECURITY_LEVEL", "message": "Invalid SNMPv3 security level."},
        )

    auth_protocol = (payload.snmp_v3_auth_protocol or "SHA").upper()
    priv_protocol = (payload.snmp_v3_priv_protocol or "AES").upper()
    auth_password = payload.snmp_v3_auth_password or ""
    priv_password = payload.snmp_v3_priv_password or ""

    if security_level in {"authNoPriv", "authPriv"}:
        if auth_protocol not in {"MD5", "SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"}:
            raise HTTPException(
                status_code=422,
                detail={"code": "INVALID_SNMP_V3_AUTH_PROTOCOL", "message": "Unsupported SNMPv3 authentication protocol."},
            )
        if not auth_password:
            raise HTTPException(
                status_code=422,
                detail={"code": "SNMP_V3_AUTH_PASSWORD_REQUIRED", "message": "SNMPv3 authentication password is required."},
            )

    if security_level == "authPriv":
        if priv_protocol not in {"DES", "AES"}:
            raise HTTPException(
                status_code=422,
                detail={"code": "INVALID_SNMP_V3_PRIV_PROTOCOL", "message": "Unsupported SNMPv3 privacy protocol."},
            )
        if not priv_password:
            raise HTTPException(
                status_code=422,
                detail={"code": "SNMP_V3_PRIV_PASSWORD_REQUIRED", "message": "SNMPv3 privacy password is required."},
            )

    return {
        "version": version,
        "username": username,
        "security_level": security_level,
        "auth_protocol": auth_protocol,
        "auth_password": auth_password,
        "priv_protocol": priv_protocol,
        "priv_password": priv_password,
    }


@router.get("/flush/preview")
async def discovery_flush_preview(db: AsyncSession = Depends(get_db)):
    active = await db.scalar(select(func.count(DiscoveryJob.id)).where(DiscoveryJob.status.in_(("PENDING", "RUNNING"))))
    unregistered_states = ("NEW", "APPROVED", "REJECTED")
    return {
        "active_jobs": int(active or 0),
        "discovery_jobs": int((await db.scalar(select(func.count(DiscoveryJob.id)))) or 0),
        "discovery_results": int((await db.scalar(select(func.count(DiscoveryResult.id)))) or 0),
        "unregistered_candidates": int((await db.scalar(select(func.count(DeviceCandidate.id)).where(DeviceCandidate.state.in_(unregistered_states)))) or 0),
        "registered_candidates": int((await db.scalar(select(func.count(DeviceCandidate.id)).where(DeviceCandidate.state == "REGISTERED"))) or 0),
    }


@router.post("/flush")
async def flush_discovery(actor=Depends(authorize_request), db: AsyncSession = Depends(get_db)):
    # Serialize with job creation/updates inside PostgreSQL. Refuse while work is active.
    await db.execute(text("LOCK TABLE discovery_jobs IN SHARE ROW EXCLUSIVE MODE"))
    active = await db.scalar(select(func.count(DiscoveryJob.id)).where(DiscoveryJob.status.in_(("PENDING", "RUNNING"))))
    if active:
        raise HTTPException(status_code=409, detail={"code":"DISCOVERY_FLUSH_ACTIVE_JOBS","message":"Discovery data cannot be flushed while a discovery job is active."})
    unregistered_states = ("NEW", "APPROVED", "REJECTED")
    counts = {
        "candidates": int((await db.scalar(select(func.count(DeviceCandidate.id)).where(DeviceCandidate.state.in_(unregistered_states)))) or 0),
        "results": int((await db.scalar(select(func.count(DiscoveryResult.id)))) or 0),
        "jobs": int((await db.scalar(select(func.count(DiscoveryJob.id)))) or 0),
    }
    # Registered candidates survive. Their discovery_result FK is SET NULL when results are deleted.
    await db.execute(delete(DeviceCandidate).where(DeviceCandidate.state.in_(unregistered_states)))
    await db.execute(delete(DiscoveryResult))
    await db.execute(delete(DiscoveryJob))
    await record_audit(db, action="DISCOVERY_FLUSHED", entity_type="Discovery", entity_id=None,
        description="Unregistered discovery working data was flushed.", metadata={**counts, "registered_devices_affected": 0})
    await db.commit()
    return {**counts, "registered_devices_affected": 0}

@router.get("/methods")
async def discovery_methods():
    return {
        "methods": registry.methods(),
        "description": {
            "ICMP": "Reachability probe.",
            "HTTP": "HTTP management endpoint reachability and basic metadata.",
            "HTTPS": "HTTPS management endpoint reachability and basic metadata.",
            "SNMP": "SNMP v1/v2c/v3 reachability and sysName discovery.",
            "TCP": "Non-authenticated TCP port reachability probe.",
        },
    }


@router.post(
    "/run",
    response_model=DiscoveryRunResponse,
)
async def run_discovery(
    payload: DiscoveryRunRequest,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope, authorization_keys = await _discovery_scope_context(db, actor)
    methods = [method.upper() for method in payload.methods]

    unsupported = [
        method
        for method in methods
        if registry.get(method) is None
    ]

    if unsupported:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "UNSUPPORTED_DISCOVERY_METHOD",
                "message": (
                    "Unsupported discovery method(s): "
                    + ", ".join(unsupported)
                ),
            },
        )

    snmp: dict[str, object] | None = None
    credential_source = None
    if "SNMP" in methods:
        if payload.access_template_id is not None:
            await require_discovery_snmp_template(
                db,
                template_id=payload.access_template_id,
                actor_user_id=actor.id,
            )
            runtime = await resolve_discovery_snmp_template(
                db,
                template_id=payload.access_template_id,
            )
            snmp = snmp_context_kwargs(runtime)
            credential_source = "ACCESS_TEMPLATE"
        else:
            raw = _validated_snmp_options(payload)
            snmp = {
                "snmp_version": raw.get("version", "2c"),
                "snmp_community": raw.get("community"),
                "snmp_retries": payload.snmp_retries,
                "snmp_v3_username": raw.get("username"),
                "snmp_v3_security_level": raw.get("security_level", "noAuthNoPriv"),
                "snmp_v3_auth_protocol": raw.get("auth_protocol"),
                "snmp_v3_auth_password": raw.get("auth_password"),
                "snmp_v3_priv_protocol": raw.get("priv_protocol"),
                "snmp_v3_priv_password": raw.get("priv_password"),
            }
            credential_source = "ONE_TIME"

    job = DiscoveryJob(
        id=uuid4(),
        scope_type="IP",
        scope_value=str(payload.ip_address),
        status="RUNNING",
        metadata_={
            "methods": methods,
            "timeout_seconds": payload.timeout_seconds,
            "http_port": payload.http_port,
            "https_port": payload.https_port,
            "credential_reference": payload.credential_reference,
            "credential_source": credential_source,
            "access_template_id": str(payload.access_template_id) if payload.access_template_id else None,
            "_authorization_scope": authorization_scope_metadata(authorization_keys, actor_user_id=scope.user_id),
        },
    )

    db.add(job)
    await db.flush()
    job_id = job.id
    job_display = {
        "scope_type": job.scope_type,
        "scope_value": job.scope_value,
    }

    await record_audit(
        db,
        action="DISCOVERY_STARTED",
        entity_type="DiscoveryJob",
        entity_id=job_id,
        entity_display_snapshot=job_display,
        description="Synchronous discovery started.",
        after_summary={"status": "RUNNING"},
        metadata={"methods": methods, "execution": "synchronous", "credential_source": credential_source},
    )
    # Persist the workflow identity and STARTED evidence before probes run.
    await db.commit()

    try:
        results = await discovery_engine.run(
            DiscoveryContext(
                ip_address=str(payload.ip_address),
                timeout_seconds=payload.timeout_seconds,
                http_port=payload.http_port,
                https_port=payload.https_port,
                credential_reference=payload.credential_reference,
                **(snmp or {}),
            ),
            methods,
            db,
            job,
        )

        candidate_before = await db.scalar(
            select(DeviceCandidate).where(
                DeviceCandidate.ip_address == str(payload.ip_address)
            )
        )
        candidate = await generate_candidate_from_results(db, results)
        candidate_count = 1 if candidate is not None and candidate_before is None else 0
        consolidated = aggregate_discovery_records(results)

        job.status = "COMPLETED"
        job.metadata_ = {
            **(job.metadata_ or {}),
            "result_count": len(results),
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
            description="Synchronous discovery completed.",
            before_summary={"status": "RUNNING"},
            after_summary={
                "status": "COMPLETED",
                "result_count": len(results),
                "candidate_count": candidate_count,
            },
            metadata={"methods": methods, "execution": "synchronous"},
        )

        await db.commit()

        for record in results:
            await db.refresh(record)

        return DiscoveryRunResponse(
            job_id=job.id,
            status=job.status,
            results=[
                DiscoveryResultRead.model_validate(record)
                for record in results
            ],
            consolidated=(
                DiscoveryAggregateRead(
                    ip_address=consolidated.ip_address,
                    reachable=consolidated.reachable,
                    hostname=consolidated.hostname,
                    vendor=consolidated.vendor,
                    model=consolidated.model,
                    serial_number=consolidated.serial_number,
                    management_protocol=consolidated.management_protocol,
                    confidence=consolidated.confidence,
                    protocol_status=consolidated.protocol_status,
                    field_sources=consolidated.field_sources,
                )
                if consolidated is not None
                else None
            ),
        )

    except Exception as exc:
        await db.rollback()
        await record_failure_audit(
            action="DISCOVERY_FAILED",
            entity_type="DiscoveryJob",
            entity_id=job_id,
            entity_display_snapshot=job_display,
            description="Synchronous discovery failed.",
            before_summary={"status": "RUNNING"},
            after_summary={"status": "FAILED"},
            metadata={
                "methods": methods,
                "execution": "synchronous",
                "error_type": type(exc).__name__,
            },
        )
        failed_job = await db.get(DiscoveryJob, job_id)
        if failed_job is not None:
            failed_job.status = "FAILED"
            failed_job.metadata_ = {
                **(failed_job.metadata_ or {}),
                "error_type": type(exc).__name__,
            }
            await db.commit()
        raise


@router.get("/jobs/page", response_model=PageResult[DiscoveryJobRead])
async def page_jobs(
    db: AsyncSession = Depends(get_db),
    search: str | None = Query(None, max_length=200),
    status_filter: str | None = Query(None, alias="status", max_length=30),
    scope_type: str | None = Query(None, max_length=30),
    sort_by: str = Query("created_at", max_length=40),
    sort_direction: str = Query("desc", pattern="^(?i:asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    actor=Depends(authorize_request),
):
    sort_map = {
        "status": DiscoveryJob.status, "scope": DiscoveryJob.scope_value,
        "type": DiscoveryJob.scope_type, "created_at": DiscoveryJob.created_at,
    }
    expr = sort_map.get(sort_by)
    if expr is None:
        raise HTTPException(422, detail={"code":"INVALID_DISCOVERY_JOB_SORT","message":"Unsupported discovery-job sort column."})
    scope = await scope_for_actor(db, actor)
    statement = select(DiscoveryJob).where(await origin_scope_clause(db, scope, DiscoveryJob.metadata_))
    if search and search.strip():
        pattern = f"%{search.strip()}%"
        statement = statement.where(or_(DiscoveryJob.scope_value.ilike(pattern), DiscoveryJob.scope_type.ilike(pattern), DiscoveryJob.status.ilike(pattern)))
    if status_filter:
        statement = statement.where(DiscoveryJob.status == status_filter.upper())
    if scope_type:
        statement = statement.where(DiscoveryJob.scope_type == scope_type.upper())
    total = int((await db.scalar(select(func.count()).select_from(statement.order_by(None).subquery()))) or 0)
    order = expr.desc() if sort_direction.lower() == "desc" else expr.asc()
    rows = list((await db.scalars(
        statement.order_by(order, DiscoveryJob.id.asc())
        .offset((page - 1) * page_size).limit(page_size)
    )).all())
    items = [DiscoveryJobRead.model_validate(job).model_copy(update={
        "scope_value": _compact_batch_scope(job.scope_value, job.metadata_ or {}) if job.scope_type == "BATCH" else job.scope_value
    }) for job in rows]
    return PageResult(items=items, total=total, page=page, page_size=page_size)


@router.get(
    "/jobs",
    response_model=list[DiscoveryJobRead],
)
async def list_jobs(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    result = await db.execute(
        select(DiscoveryJob)
        .where(await origin_scope_clause(db, scope, DiscoveryJob.metadata_))
        .order_by(DiscoveryJob.created_at.desc())
        .offset(offset)
        .limit(limit)
    )

    jobs = result.scalars().all()
    return [
        DiscoveryJobRead.model_validate(job).model_copy(
            update={
                "scope_value": _compact_batch_scope(job.scope_value, job.metadata_ or {})
                if job.scope_type == "BATCH" else job.scope_value
            }
        )
        for job in jobs
    ]


@router.get(
    "/jobs/{job_id}",
    response_model=DiscoveryJobRead,
)
async def get_job(
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    job = await _scoped_job(db, actor, job_id)

    return job


@router.get(
    "/jobs/{job_id}/results",
    response_model=list[DiscoveryResultRead],
)
async def get_job_results(
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    job = await _scoped_job(db, actor, job_id)

    result = await db.execute(
        select(DiscoveryResult)
        .where(
            DiscoveryResult.discovery_job_id == job_id
        )
        .order_by(DiscoveryResult.created_at)
    )

    return result.scalars().all()

@router.get(
    "/jobs/{job_id}/aggregate",
    response_model=list[DiscoveryAggregateRead],
)
async def get_job_aggregate(
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    job = await _scoped_job(db, actor, job_id)

    records = (
        await db.execute(
            select(DiscoveryResult)
            .where(DiscoveryResult.discovery_job_id == job_id)
            .order_by(DiscoveryResult.ip_address, DiscoveryResult.created_at)
        )
    ).scalars().all()

    from ...discovery.aggregation import aggregate_by_ip

    return [
        DiscoveryAggregateRead(
            ip_address=item.ip_address,
            reachable=item.reachable,
            hostname=item.hostname,
            vendor=item.vendor,
            model=item.model,
            serial_number=item.serial_number,
            management_protocol=item.management_protocol,
            confidence=item.confidence,
            protocol_status=item.protocol_status,
            field_sources=item.field_sources,
        )
        for item in aggregate_by_ip(records)
    ]