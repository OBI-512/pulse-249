from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import asc, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.models import DataRetentionPolicy, ReportDefinition, ReportDelivery, ReportJob, ReportSchedule
from app.notifications import validate_destination
from app.schemas.pagination import PageResult
from app.schemas.phase_d import (
    ReportCatalogItem, ReportDefinitionCreate, ReportDefinitionRead, ReportDefinitionUpdate,
    ReportDeliveryRead, ReportJobRead, ReportJobsDeleteRequest, ReportJobsDeleteResult, ReportRunRequest,
    ReportScheduleCreate, ReportScheduleRead, ReportScheduleUpdate,
)
from app.security.authorization import authorize_request
from app.security.resource_scope import scope_for_actor
from app.security.scope_queries import require_group
from app.services.authorization_snapshot import scope_fingerprint
from app.services.audit import record_audit
from app.services.reports import (
    REPORT_CATALOG, create_report_job, effective_permission_codes, media_type_for, report_root,
    validate_report_filter_permissions, validate_report_request,
)

router = APIRouter(prefix="/reports", tags=["Reports"], dependencies=[Depends(authorize_request)])
PAGE_SIZES = {50, 100, 200, 300, 400, 500}


def _page_size(value: int) -> int:
    if value not in PAGE_SIZES:
        raise HTTPException(422, detail={"code": "INVALID_PAGE_SIZE", "message": "Page size must be one of 50, 100, 200, 300, 400, 500."})
    return value


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def _report_trash_retention_days(db: AsyncSession) -> int:
    days = await db.scalar(select(DataRetentionPolicy.retain_days).where(
        DataRetentionPolicy.data_class == "REPORT_CONFIGURATION_TRASH",
    ))
    return int(days or 30)


def _trash_state_clause(model, state: str):
    return model.deleted_at.is_not(None) if state == "deleted" else model.deleted_at.is_(None)


async def _validate_actor_report(db: AsyncSession, actor, report_type: str, format: str, include_sensitive: bool, filters: dict | None = None):
    scope = await scope_for_actor(db, actor)
    permissions = await effective_permission_codes(db, actor.id)
    try:
        result = validate_report_request(report_type=report_type, format=format, include_sensitive=include_sensitive, scope=scope, permissions=permissions)
        validate_report_filter_permissions(filters, permissions)
        if filters and filters.get("group_id"):
            try:
                group_id = UUID(str(filters["group_id"]))
            except (TypeError, ValueError) as exc:
                raise ValueError("group_id must be a valid identifier.") from exc
            await require_group(db, scope, group_id)
        return result
    except PermissionError as exc:
        raise HTTPException(403, detail={"code": "REPORT_PERMISSION_DENIED", "message": str(exc)}) from exc
    except ValueError as exc:
        raise HTTPException(422, detail={"code": "REPORT_REQUEST_INVALID", "message": str(exc)}) from exc


@router.get("/catalog", response_model=list[ReportCatalogItem])
async def catalog(actor=Depends(authorize_request)):
    return [ReportCatalogItem(code=code, **item) for code, item in REPORT_CATALOG.items()]


@router.get("/definitions", response_model=PageResult[ReportDefinitionRead])
async def definitions(
    state: str = Query("active", pattern="^(active|deleted)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50),
    search: str | None = Query(default=None, max_length=180),
    report_type: str | None = Query(default=None, max_length=80),
    format: str | None = Query(default=None, max_length=16),
    link_state: str = Query("any", pattern="^(any|linked|unlinked)$"),
    sort_by: str = Query("name"),
    sort_direction: str = Query("asc", pattern="^(asc|desc)$"),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    page_size = _page_size(page_size)
    filters = [ReportDefinition.owner_user_id == actor.id, _trash_state_clause(ReportDefinition, state)]
    needle = (search or "").strip().lower()
    if needle:
        filters.append(or_(func.lower(ReportDefinition.name).contains(needle), func.lower(func.coalesce(ReportDefinition.description, "")).contains(needle)))
    if report_type:
        filters.append(ReportDefinition.report_type == report_type.strip().lower())
    if format:
        filters.append(ReportDefinition.format == format.strip().upper())
    linked = select(ReportSchedule.id).where(ReportSchedule.definition_id == ReportDefinition.id).exists()
    if link_state == "linked":
        filters.append(linked)
    elif link_state == "unlinked":
        filters.append(~linked)
    total = int(await db.scalar(select(func.count()).select_from(ReportDefinition).where(*filters)) or 0)
    sort_columns = {
        "name": ReportDefinition.name, "report_type": ReportDefinition.report_type, "format": ReportDefinition.format,
        "created_at": ReportDefinition.created_at, "updated_at": ReportDefinition.updated_at,
        "deleted_at": ReportDefinition.deleted_at, "purge_after": ReportDefinition.purge_after,
    }
    sort_column = sort_columns.get(sort_by, ReportDefinition.name)
    order = desc(sort_column) if sort_direction == "desc" else asc(sort_column)
    rows = list((await db.scalars(
        select(ReportDefinition).where(*filters).order_by(order, ReportDefinition.id).offset((page - 1) * page_size).limit(page_size)
    )).all())
    links: dict[UUID, list[dict]] = {row.id: [] for row in rows}
    if rows:
        schedule_rows = (await db.execute(
            select(ReportSchedule.definition_id, ReportSchedule.id, ReportSchedule.name, ReportSchedule.deleted_at)
            .where(ReportSchedule.definition_id.in_(list(links)))
            .order_by(ReportSchedule.name, ReportSchedule.id)
        )).all()
        for definition_id, schedule_id, name, deleted_at in schedule_rows:
            if definition_id in links:
                links[definition_id].append({"id": schedule_id, "name": name, "deleted_at": deleted_at})
    items = []
    for row in rows:
        item_data = ReportDefinitionRead.model_validate(row, from_attributes=True).model_dump()
        item_data["linked_schedules"] = links[row.id]
        items.append(ReportDefinitionRead(**item_data))
    return PageResult(items=items, total=total, page=page, page_size=page_size)


@router.post("/definitions", response_model=ReportDefinitionRead)
async def create_definition(payload: ReportDefinitionCreate, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    report_type, fmt = await _validate_actor_report(db, actor, payload.report_type, payload.format, payload.include_sensitive, payload.filters)
    row = ReportDefinition(owner_user_id=actor.id, name=payload.name.strip(), report_type=report_type, format=fmt, filters=payload.filters, include_sensitive=payload.include_sensitive, description=payload.description.strip() if payload.description and payload.description.strip() else None)
    db.add(row); await db.flush()
    await record_audit(db, action="REPORT_DEFINITION_CREATED", entity_type="ReportDefinition", entity_id=row.id, description="Saved report definition created.", metadata={"report_type": report_type, "format": fmt})
    await db.commit(); await db.refresh(row); return row


@router.patch("/definitions/{definition_id}", response_model=ReportDefinitionRead)
async def update_definition(definition_id: UUID, payload: ReportDefinitionUpdate, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    row = await db.scalar(select(ReportDefinition).where(ReportDefinition.id == definition_id, ReportDefinition.owner_user_id == actor.id, ReportDefinition.deleted_at.is_(None)).with_for_update())
    if row is None:
        raise HTTPException(404, detail={"code": "RESOURCE_NOT_FOUND", "message": "Report definition not found."})
    values = payload.model_dump(exclude_unset=True)
    report_type = values.get("report_type", row.report_type); fmt = values.get("format", row.format); sensitive = values.get("include_sensitive", row.include_sensitive)
    report_type, fmt = await _validate_actor_report(db, actor, report_type, fmt, sensitive, values.get("filters", row.filters))
    values.update({"report_type": report_type, "format": fmt})
    for key, value in values.items():
        if key in {"name", "description"} and isinstance(value, str):
            value = value.strip() or None
        setattr(row, key, value)
    await record_audit(db, action="REPORT_DEFINITION_UPDATED", entity_type="ReportDefinition", entity_id=row.id, description="Saved report definition updated.")
    await db.commit(); await db.refresh(row); return row


@router.delete("/definitions/{definition_id}")
async def delete_definition(definition_id: UUID, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    row = await db.scalar(select(ReportDefinition).where(
        ReportDefinition.id == definition_id, ReportDefinition.owner_user_id == actor.id, ReportDefinition.deleted_at.is_(None)
    ).with_for_update())
    if row is None:
        raise HTTPException(404, detail={"code": "RESOURCE_NOT_FOUND", "message": "Report definition not found."})
    schedule = await db.scalar(select(ReportSchedule.id).where(
        ReportSchedule.definition_id == row.id, ReportSchedule.deleted_at.is_(None)
    ).limit(1))
    if schedule is not None:
        raise HTTPException(409, detail={"code": "REPORT_DEFINITION_IN_USE", "message": "Delete or detach active schedules using this definition first."})
    now = _utcnow(); retention_days = await _report_trash_retention_days(db)
    row.deleted_at = now; row.purge_after = now + timedelta(days=retention_days)
    await record_audit(db, action="REPORT_DEFINITION_TRASHED", entity_type="ReportDefinition", entity_id=row.id, description="Saved report definition moved to report configuration trash.", metadata={"purge_after": row.purge_after.isoformat()})
    await db.commit(); await db.refresh(row); return {"deleted": True, "recoverable": True, "purge_after": row.purge_after}


@router.post("/definitions/{definition_id}/restore", response_model=ReportDefinitionRead)
async def restore_definition(definition_id: UUID, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    row = await db.scalar(select(ReportDefinition).where(
        ReportDefinition.id == definition_id, ReportDefinition.owner_user_id == actor.id, ReportDefinition.deleted_at.is_not(None)
    ).with_for_update())
    if row is None:
        raise HTTPException(404, detail={"code": "RESOURCE_NOT_FOUND", "message": "Deleted report definition not found."})
    row.deleted_at = None; row.purge_after = None
    await record_audit(db, action="REPORT_DEFINITION_RESTORED", entity_type="ReportDefinition", entity_id=row.id, description="Saved report definition restored from report configuration trash.")
    await db.commit(); await db.refresh(row); return row


@router.delete("/definitions/{definition_id}/permanent")
async def permanently_delete_definition(definition_id: UUID, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    row = await db.scalar(select(ReportDefinition).where(
        ReportDefinition.id == definition_id, ReportDefinition.owner_user_id == actor.id, ReportDefinition.deleted_at.is_not(None)
    ).with_for_update())
    if row is None:
        raise HTTPException(404, detail={"code": "RESOURCE_NOT_FOUND", "message": "Deleted report definition not found."})
    schedule = await db.scalar(select(ReportSchedule.id).where(ReportSchedule.definition_id == row.id).limit(1))
    if schedule is not None:
        raise HTTPException(409, detail={"code": "REPORT_DEFINITION_IN_USE", "message": "Permanently delete or restore schedules using this definition first."})
    await record_audit(db, action="REPORT_DEFINITION_PURGED", entity_type="ReportDefinition", entity_id=row.id, description="Saved report definition permanently deleted from report configuration trash.")
    await db.delete(row); await db.commit(); return {"deleted": True, "permanent": True}


@router.post("/run", response_model=ReportJobRead)
async def run_report(payload: ReportRunRequest, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    definition = None
    schedule = None
    if payload.schedule_id:
        schedule = await db.scalar(select(ReportSchedule).where(ReportSchedule.id == payload.schedule_id, ReportSchedule.owner_user_id == actor.id, ReportSchedule.deleted_at.is_(None)).with_for_update())
        if schedule is None:
            raise HTTPException(404, detail={"code": "RESOURCE_NOT_FOUND", "message": "Report schedule not found."})
    elif payload.definition_id:
        definition = await db.scalar(select(ReportDefinition).where(ReportDefinition.id == payload.definition_id, ReportDefinition.owner_user_id == actor.id, ReportDefinition.deleted_at.is_(None)))
        if definition is None:
            raise HTTPException(404, detail={"code": "RESOURCE_NOT_FOUND", "message": "Report definition not found."})

    if schedule is not None:
        report_type = schedule.report_type
        fmt = schedule.format
        filters = schedule.filters or {}
        include_sensitive = schedule.include_sensitive
        definition_id = schedule.definition_id
    else:
        report_type = definition.report_type if definition else (payload.report_type or "")
        fmt = (payload.format or (definition.format if definition else "CSV")).upper()
        filters = definition.filters if definition and not payload.filters else payload.filters
        include_sensitive = definition.include_sensitive if definition else payload.include_sensitive
        definition_id = definition.id if definition else None

    await _validate_actor_report(db, actor, report_type, fmt, include_sensitive, filters)
    try:
        job = await create_report_job(
            db, owner_user_id=actor.id, report_type=report_type, format=fmt, filters=filters,
            include_sensitive=include_sensitive, definition_id=definition_id,
            schedule_id=schedule.id if schedule else None,
        )
    except (PermissionError, ValueError) as exc:
        raise HTTPException(403 if isinstance(exc, PermissionError) else 422, detail={"code": "REPORT_REQUEST_DENIED", "message": str(exc)}) from exc
    if schedule is not None:
        schedule.last_run_at = job.requested_at
        await record_audit(
            db, action="REPORT_SCHEDULE_RUN_NOW", entity_type="ReportSchedule", entity_id=schedule.id,
            description="Scheduled report manually queued without changing its next planned run.",
            metadata={"report_job_id": str(job.id), "next_run_at": schedule.next_run_at.isoformat()},
        )
    await db.commit(); await db.refresh(job); return job


@router.get("/jobs", response_model=PageResult[ReportJobRead])
async def jobs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50),
    status: str | None = Query(None, max_length=20),
    sort_by: str = Query("requested_at", max_length=40),
    sort_direction: str = Query("desc", pattern="^(?i:asc|desc)$"),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    page_size = _page_size(page_size)
    stmt = select(ReportJob).where(ReportJob.owner_user_id == actor.id)
    if status:
        stmt = stmt.where(ReportJob.status == status.upper())
    total = int((await db.scalar(select(func.count()).select_from(stmt.subquery()))) or 0)
    sort_map = {
        "requested_at": ReportJob.requested_at,
        "display_name": func.coalesce(ReportJob.metadata_["display_name"].astext, ReportJob.report_type),
        "report_type": ReportJob.report_type,
        "format": ReportJob.format,
        "status": ReportJob.status,
        "row_count": ReportJob.row_count,
        "artifact_name": ReportJob.artifact_name,
        "error_code": ReportJob.error_code,
    }
    sort_expr = sort_map.get(sort_by)
    if sort_expr is None:
        raise HTTPException(422, detail={"code": "INVALID_SORT", "message": "Unsupported report-job sort field."})
    order = sort_expr.desc() if sort_direction.lower() == "desc" else sort_expr.asc()
    items = list((await db.scalars(
        stmt.order_by(order.nullslast(), ReportJob.id.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )).all())
    return PageResult(items=items, total=total, page=page, page_size=page_size)


@router.delete("/jobs", response_model=ReportJobsDeleteResult)
async def delete_jobs(payload: ReportJobsDeleteRequest, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    requested_ids = list(payload.job_ids)
    rows = list((await db.scalars(
        select(ReportJob).where(ReportJob.owner_user_id == actor.id, ReportJob.id.in_(requested_ids)).with_for_update()
    )).all())
    by_id = {row.id: row for row in rows}
    missing = [str(job_id) for job_id in requested_ids if job_id not in by_id]
    if missing:
        raise HTTPException(404, detail={"code": "RESOURCE_NOT_FOUND", "message": "One or more report jobs were not found.", "job_ids": missing})
    active = [str(row.id) for row in rows if row.status in {"QUEUED", "RUNNING"}]
    if active:
        raise HTTPException(409, detail={"code": "REPORT_JOB_ACTIVE", "message": "Queued or running reports cannot be deleted. Wait for them to finish first.", "job_ids": active})

    root = report_root()
    staged: list[tuple[Path, Path]] = []
    try:
        for row in rows:
            if not row.artifact_name:
                continue
            candidate = (root / Path(row.artifact_name).name).resolve()
            if candidate.parent != root:
                raise HTTPException(409, detail={"code": "REPORT_ARTIFACT_INVALID", "message": "A report artifact path is invalid; deletion was cancelled."})
            if candidate.exists():
                staged_path = candidate.with_name(f".{candidate.name}.delete-{uuid4().hex}.tmp")
                try:
                    candidate.replace(staged_path)
                except OSError as exc:
                    raise HTTPException(409, detail={"code": "REPORT_ARTIFACT_DELETE_FAILED", "message": "A report artifact could not be prepared for deletion; no report jobs were removed."}) from exc
                staged.append((candidate, staged_path))

        for row in rows:
            await record_audit(
                db, action="REPORT_JOB_DELETED", entity_type="ReportJob", entity_id=row.id,
                description="Generated report job and retained artifact deleted by its owner.",
                metadata={"display_name": row.display_name, "status": row.status, "artifact_name": row.artifact_name},
            )
            await db.delete(row)
        await db.commit()
    except Exception:
        await db.rollback()
        for original, staged_path in reversed(staged):
            try:
                if staged_path.exists() and not original.exists():
                    staged_path.replace(original)
            except OSError:
                pass
        raise

    for _, staged_path in staged:
        try:
            staged_path.unlink(missing_ok=True)
        except OSError:
            pass
    return ReportJobsDeleteResult(deleted=len(requested_ids), deleted_ids=requested_ids)


@router.get("/jobs/{job_id}", response_model=ReportJobRead)
async def get_job(job_id: UUID, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    row = await db.scalar(select(ReportJob).where(ReportJob.id == job_id, ReportJob.owner_user_id == actor.id))
    if row is None:
        raise HTTPException(404, detail={"code": "RESOURCE_NOT_FOUND", "message": "Report job not found."})
    return row


@router.get("/jobs/{job_id}/download")
async def download_report(job_id: UUID, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    job = await db.scalar(select(ReportJob).where(ReportJob.id == job_id, ReportJob.owner_user_id == actor.id))
    if job is None or job.status != "COMPLETED" or not job.artifact_name:
        raise HTTPException(404, detail={"code": "RESOURCE_NOT_FOUND", "message": "Report artifact not found."})
    scope = await scope_for_actor(db, actor); permissions = await effective_permission_codes(db, actor.id)
    try:
        validate_report_request(report_type=job.report_type, format=job.format, include_sensitive=job.include_sensitive, scope=scope, permissions=permissions)
    except (PermissionError, ValueError) as exc:
        raise HTTPException(403, detail={"code": "REPORT_PERMISSION_DENIED", "message": "Current authorization no longer permits this report."}) from exc
    if scope_fingerprint(scope) != job.scope_fingerprint:
        raise HTTPException(409, detail={"code": "REPORT_SCOPE_CHANGED", "message": "Authorization scope changed after generation; run a new report."})
    root = report_root(); path = (root / Path(job.artifact_name).name).resolve()
    if path.parent != root or not path.is_file():
        raise HTTPException(404, detail={"code": "RESOURCE_NOT_FOUND", "message": "Report artifact not found."})
    data = path.read_bytes()
    from hashlib import sha256
    if sha256(data).hexdigest() != job.artifact_sha256:
        raise HTTPException(409, detail={"code": "REPORT_ARTIFACT_INVALID", "message": "Report artifact checksum validation failed."})
    return Response(data, media_type=media_type_for(job.format), headers={"Content-Disposition": f'attachment; filename="{job.artifact_name}"'})


@router.get("/schedules", response_model=PageResult[ReportScheduleRead])
async def schedules(
    state: str = Query("active", pattern="^(active|deleted)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50),
    search: str | None = Query(default=None, max_length=180),
    report_type: str | None = Query(default=None, max_length=80),
    format: str | None = Query(default=None, max_length=16),
    link_state: str = Query("any", pattern="^(any|linked|standalone)$"),
    enabled: bool | None = Query(default=None),
    sort_by: str = Query("name"),
    sort_direction: str = Query("asc", pattern="^(asc|desc)$"),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    page_size = _page_size(page_size)
    filters = [ReportSchedule.owner_user_id == actor.id, _trash_state_clause(ReportSchedule, state)]
    needle = (search or "").strip().lower()
    if needle:
        filters.append(or_(func.lower(ReportSchedule.name).contains(needle), func.lower(func.coalesce(ReportDefinition.name, "")).contains(needle)))
    if report_type:
        filters.append(ReportSchedule.report_type == report_type.strip().lower())
    if format:
        filters.append(ReportSchedule.format == format.strip().upper())
    if link_state == "linked":
        filters.append(ReportSchedule.definition_id.is_not(None))
    elif link_state == "standalone":
        filters.append(ReportSchedule.definition_id.is_(None))
    if enabled is not None:
        filters.append(ReportSchedule.enabled == enabled)
    base = select(ReportSchedule).outerjoin(ReportDefinition, ReportDefinition.id == ReportSchedule.definition_id).where(*filters)
    total = int(await db.scalar(select(func.count()).select_from(ReportSchedule).outerjoin(ReportDefinition, ReportDefinition.id == ReportSchedule.definition_id).where(*filters)) or 0)
    sort_columns = {
        "name": ReportSchedule.name, "report_type": ReportSchedule.report_type, "format": ReportSchedule.format,
        "interval_minutes": ReportSchedule.interval_minutes, "next_run_at": ReportSchedule.next_run_at, "enabled": ReportSchedule.enabled,
        "deleted_at": ReportSchedule.deleted_at, "purge_after": ReportSchedule.purge_after,
    }
    sort_column = sort_columns.get(sort_by, ReportSchedule.name)
    order = desc(sort_column) if sort_direction == "desc" else asc(sort_column)
    rows = list((await db.scalars(base.order_by(order, ReportSchedule.id).offset((page - 1) * page_size).limit(page_size))).all())
    definitions_by_id: dict[UUID, ReportDefinition] = {}
    definition_ids = {row.definition_id for row in rows if row.definition_id is not None}
    if definition_ids:
        definition_rows = list((await db.scalars(select(ReportDefinition).where(ReportDefinition.id.in_(definition_ids)))).all())
        definitions_by_id = {row.id: row for row in definition_rows}
    items = []
    for row in rows:
        definition = definitions_by_id.get(row.definition_id) if row.definition_id else None
        item_data = ReportScheduleRead.model_validate(row, from_attributes=True).model_dump()
        item_data["definition_name"] = definition.name if definition else None
        item_data["definition_deleted_at"] = definition.deleted_at if definition else None
        items.append(ReportScheduleRead(**item_data))
    return PageResult(items=items, total=total, page=page, page_size=page_size)


@router.post("/schedules", response_model=ReportScheduleRead)
async def create_schedule(payload: ReportScheduleCreate, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    definition = None
    if payload.definition_id:
        definition = await db.scalar(select(ReportDefinition).where(ReportDefinition.id == payload.definition_id, ReportDefinition.owner_user_id == actor.id, ReportDefinition.deleted_at.is_(None)))
        if definition is None:
            raise HTTPException(404, detail={"code": "RESOURCE_NOT_FOUND", "message": "Report definition not found."})
    report_type = definition.report_type if definition else (payload.report_type or "")
    fmt = (payload.format or (definition.format if definition else "CSV")).upper()
    filters = definition.filters if definition and not payload.filters else payload.filters
    sensitive = definition.include_sensitive if definition else payload.include_sensitive
    await _validate_actor_report(db, actor, report_type, fmt, sensitive, filters)
    if payload.channel_type and payload.destination:
        try:
            validate_destination(payload.channel_type, payload.destination)
        except ValueError as exc:
            raise HTTPException(422, detail={"code": str(exc), "message": "Report delivery destination is invalid."}) from exc
    row = ReportSchedule(owner_user_id=actor.id, definition_id=definition.id if definition else None, name=payload.name.strip(), report_type=report_type, format=fmt, filters=filters, include_sensitive=sensitive, interval_minutes=payload.interval_minutes, enabled=payload.enabled, next_run_at=payload.next_run_at, channel_type=payload.channel_type, destination=payload.destination, max_attempts=payload.max_attempts, retry_base_seconds=payload.retry_base_seconds)
    db.add(row); await db.flush()
    await record_audit(db, action="REPORT_SCHEDULE_CREATED", entity_type="ReportSchedule", entity_id=row.id, description="Scheduled report created.", metadata={"report_type": report_type, "interval_minutes": row.interval_minutes, "delivery": bool(row.channel_type)})
    await db.commit(); await db.refresh(row); return row


@router.patch("/schedules/{schedule_id}", response_model=ReportScheduleRead)
async def update_schedule(schedule_id: UUID, payload: ReportScheduleUpdate, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    row = await db.scalar(select(ReportSchedule).where(ReportSchedule.id == schedule_id, ReportSchedule.owner_user_id == actor.id, ReportSchedule.deleted_at.is_(None)).with_for_update())
    if row is None:
        raise HTTPException(404, detail={"code": "RESOURCE_NOT_FOUND", "message": "Report schedule not found."})
    values = payload.model_dump(exclude_unset=True)

    definition = None
    if "definition_id" in values and values["definition_id"] is not None:
        definition = await db.scalar(select(ReportDefinition).where(ReportDefinition.id == values["definition_id"], ReportDefinition.owner_user_id == actor.id, ReportDefinition.deleted_at.is_(None)))
        if definition is None:
            raise HTTPException(404, detail={"code": "RESOURCE_NOT_FOUND", "message": "Report definition not found."})

    if definition is not None:
        report_type = definition.report_type
        fmt = definition.format
        filters = definition.filters or {}
        sensitive = definition.include_sensitive
        values.update({
            "definition_id": definition.id,
            "report_type": report_type,
            "format": fmt,
            "filters": filters,
            "include_sensitive": sensitive,
        })
    else:
        report_type = values.get("report_type", row.report_type)
        fmt = values.get("format", row.format)
        filters = values.get("filters", row.filters)
        sensitive = values.get("include_sensitive", row.include_sensitive)

    report_type, fmt = await _validate_actor_report(db, actor, report_type, fmt, sensitive, filters)
    values.update({"report_type": report_type, "format": fmt})

    channel = values.get("channel_type", row.channel_type); destination = values.get("destination", row.destination)
    if (channel is None) != (destination is None):
        raise HTTPException(422, detail={"code": "REPORT_DELIVERY_INCOMPLETE", "message": "channel_type and destination must be set or cleared together."})
    if channel and destination:
        try: validate_destination(channel, destination)
        except ValueError as exc: raise HTTPException(422, detail={"code": str(exc), "message": "Report delivery destination is invalid."}) from exc
    for key, value in values.items():
        setattr(row, key, value.strip() if key == "name" and isinstance(value, str) else value)
    await record_audit(db, action="REPORT_SCHEDULE_UPDATED", entity_type="ReportSchedule", entity_id=row.id, description="Scheduled report updated.")
    await db.commit(); await db.refresh(row); return row


@router.delete("/schedules/{schedule_id}")
async def delete_schedule(schedule_id: UUID, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    row = await db.scalar(select(ReportSchedule).where(
        ReportSchedule.id == schedule_id, ReportSchedule.owner_user_id == actor.id, ReportSchedule.deleted_at.is_(None)
    ).with_for_update())
    if row is None:
        raise HTTPException(404, detail={"code": "RESOURCE_NOT_FOUND", "message": "Report schedule not found."})
    now = _utcnow(); retention_days = await _report_trash_retention_days(db)
    row.deleted_at = now; row.purge_after = now + timedelta(days=retention_days); row.enabled = False
    await record_audit(db, action="REPORT_SCHEDULE_TRASHED", entity_type="ReportSchedule", entity_id=row.id, description="Scheduled report moved to report configuration trash and disabled.", metadata={"purge_after": row.purge_after.isoformat()})
    await db.commit(); await db.refresh(row); return {"deleted": True, "recoverable": True, "purge_after": row.purge_after}


@router.post("/schedules/{schedule_id}/restore", response_model=ReportScheduleRead)
async def restore_schedule(schedule_id: UUID, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    row = await db.scalar(select(ReportSchedule).where(
        ReportSchedule.id == schedule_id, ReportSchedule.owner_user_id == actor.id, ReportSchedule.deleted_at.is_not(None)
    ).with_for_update())
    if row is None:
        raise HTTPException(404, detail={"code": "RESOURCE_NOT_FOUND", "message": "Deleted report schedule not found."})
    if row.definition_id is not None:
        definition = await db.scalar(select(ReportDefinition).where(
            ReportDefinition.id == row.definition_id, ReportDefinition.owner_user_id == actor.id, ReportDefinition.deleted_at.is_(None)
        ))
        if definition is None:
            raise HTTPException(409, detail={"code": "REPORT_DEFINITION_DELETED", "message": "Restore the linked saved definition before restoring this schedule."})
    row.deleted_at = None; row.purge_after = None; row.enabled = False
    await record_audit(db, action="REPORT_SCHEDULE_RESTORED", entity_type="ReportSchedule", entity_id=row.id, description="Scheduled report restored from report configuration trash in disabled state.")
    await db.commit(); await db.refresh(row); return row


@router.delete("/schedules/{schedule_id}/permanent")
async def permanently_delete_schedule(schedule_id: UUID, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    row = await db.scalar(select(ReportSchedule).where(
        ReportSchedule.id == schedule_id, ReportSchedule.owner_user_id == actor.id, ReportSchedule.deleted_at.is_not(None)
    ).with_for_update())
    if row is None:
        raise HTTPException(404, detail={"code": "RESOURCE_NOT_FOUND", "message": "Deleted report schedule not found."})
    await record_audit(db, action="REPORT_SCHEDULE_PURGED", entity_type="ReportSchedule", entity_id=row.id, description="Scheduled report permanently deleted from report configuration trash.")
    await db.delete(row); await db.commit(); return {"deleted": True, "permanent": True}


@router.get("/deliveries", response_model=PageResult[ReportDeliveryRead])
async def deliveries(
    page: int = Query(1, ge=1),
    page_size: int = Query(50),
    sort_by: str = Query("created_at", max_length=40),
    sort_direction: str = Query("desc", pattern="^(?i:asc|desc)$"),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    page_size = _page_size(page_size)
    stmt = select(ReportDelivery).where(ReportDelivery.owner_user_id == actor.id)
    total = int((await db.scalar(select(func.count()).select_from(stmt.subquery()))) or 0)
    sort_map = {
        "created_at": ReportDelivery.created_at,
        "status": ReportDelivery.status,
        "channel_type": ReportDelivery.channel_type,
        "destination": ReportDelivery.destination,
        "attempt_count": ReportDelivery.attempt_count,
        "next_attempt_at": ReportDelivery.next_attempt_at,
        "last_error_code": ReportDelivery.last_error_code,
    }
    sort_expr = sort_map.get(sort_by)
    if sort_expr is None:
        raise HTTPException(422, detail={"code": "INVALID_SORT", "message": "Unsupported report-delivery sort field."})
    order = sort_expr.desc() if sort_direction.lower() == "desc" else sort_expr.asc()
    items = list((await db.scalars(
        stmt.order_by(order.nullslast(), ReportDelivery.id.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )).all())
    return PageResult(items=items, total=total, page=page, page_size=page_size)
