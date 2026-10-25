from __future__ import annotations

from io import BytesIO
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.models import ImportJob, ImportRecord
from app.schemas.pagination import PageResult
from app.schemas.phase_d import ExportRequest, ImportConfirmRequest, ImportJobRead, ImportPreviewRead, ImportRecordRead
from app.security.authorization import authorize_request, user_has_permission
from app.security.permissions import Permission as P
from app.security.resource_scope import scope_for_actor
from app.security.scope_queries import require_group
from app.services.audit import record_audit
from app.services.data_exchange import ImportPreviewExpired, export_bytes
from app.services.data_exchange_template_mapping import (
    commit_import_with_template_mapping,
    create_import_preview_with_template_mapping,
    template_bytes_with_template_mapping,
)
from app.services.table_exports import export_table_bytes

router = APIRouter(prefix="/data-exchange", tags=["Data Exchange"], dependencies=[Depends(authorize_request)])
PAGE_SIZES = {50, 100, 200, 300, 400, 500}


def _import_permissions(entity_type: str, subtype: str | None) -> tuple[str, ...]:
    entity = entity_type.strip().lower()
    selected = (subtype or "ALL").strip().upper()
    if entity == "geography":
        return (P.NETWORK_CREATE, P.GEO_CREATE) if selected == "ALL" else ((P.NETWORK_CREATE,) if selected == "NETWORK" else (P.GEO_CREATE,))
    return {
        "devices": (P.DEVICE_CREATE,),
        "customers": (P.CUSTOMER_CREATE,),
        "customer_services": (P.CUSTOMER_CREATE,),
        "groups": (P.GROUP_CREATE,),
    }.get(entity, ())


def _export_permissions(entity_type: str, subtype: str | None) -> tuple[str, ...]:
    entity = entity_type.strip().lower()
    selected = (subtype or "ALL").strip().upper()
    if entity == "geography":
        return (P.NETWORK_READ, P.GEO_READ) if selected == "ALL" else ((P.NETWORK_READ,) if selected == "NETWORK" else (P.GEO_READ,))
    return {
        "devices": (P.DEVICE_READ,),
        "customers": (P.CUSTOMER_READ,),
        "customer_services": (P.CUSTOMER_READ,),
        "groups": (P.GROUP_READ,),
    }.get(entity, ())


async def _require_permissions(db: AsyncSession, actor, permissions: tuple[str, ...], *, operation: str) -> None:
    for permission in permissions:
        if not await user_has_permission(db, user_id=actor.id, permission_code=permission):
            raise HTTPException(403, detail={"code": "PERMISSION_DENIED", "message": f"Permission '{permission}' is required for this {operation}."})


def _attachment(data: bytes, filename: str, media_type: str) -> Response:
    safe = filename.replace('"', "")
    return Response(data, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{safe}"'})


@router.get("/templates/{entity_type}")
async def get_template(entity_type: str, format: str = Query("CSV", pattern="^(CSV|XLSX|JSON)$"), subtype: str | None = Query(None, max_length=40), actor=Depends(authorize_request)):
    try:
        data, name, media = template_bytes_with_template_mapping(entity_type, format, subtype)
    except ValueError as exc:
        raise HTTPException(422, detail={"code": "TEMPLATE_REQUEST_INVALID", "message": str(exc)}) from exc
    return _attachment(data, name, media)


@router.post("/imports/{entity_type}/preview", response_model=ImportPreviewRead)
async def preview_import(
    entity_type: str, request: Request, filename: str = Query(..., min_length=1, max_length=255),
    file_format: str | None = Query(None, pattern="^(csv|xlsx|json|CSV|XLSX|JSON)$"),
    idempotency_key: str | None = Query(None, max_length=255),
    subtype: str | None = Query(None, max_length=40),
    db: AsyncSession = Depends(get_db), actor=Depends(authorize_request),
):
    await _require_permissions(db, actor, _import_permissions(entity_type, subtype), operation="import")
    data = await request.body()
    scope = await scope_for_actor(db, actor)
    try:
        job = await create_import_preview_with_template_mapping(db, actor_id=actor.id, scope=scope, entity_type=entity_type, filename=filename, data=data, file_format=file_format, idempotency_key=idempotency_key, expected_subtype=subtype)
        await db.commit(); await db.refresh(job)
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(422, detail={"code": "IMPORT_PREVIEW_INVALID", "message": str(exc)}) from exc
    records = list((await db.scalars(select(ImportRecord).where(ImportRecord.import_job_id == job.id).order_by(ImportRecord.row_number).limit(500))).all())
    return ImportPreviewRead(job=ImportJobRead.model_validate(job), records=[ImportRecordRead.model_validate(record) for record in records])


@router.get("/imports", response_model=PageResult[ImportJobRead])
async def list_imports(
    page: int = Query(1, ge=1),
    page_size: int = Query(50),
    sort_by: str = Query("created_at", max_length=40),
    sort_direction: str = Query("desc", pattern="^(?i:asc|desc)$"),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    if page_size not in PAGE_SIZES:
        raise HTTPException(422, detail={"code": "INVALID_PAGE_SIZE", "message": "Page size must be one of 50, 100, 200, 300, 400, 500."})
    base = select(ImportJob).where(ImportJob.created_by_user_id == actor.id)
    total = int((await db.scalar(select(func.count()).select_from(base.subquery()))) or 0)
    sort_map = {
        "created_at": ImportJob.created_at,
        "entity_type": ImportJob.entity_type,
        "filename": ImportJob.filename,
        "status": ImportJob.status,
        "total_records": ImportJob.total_records,
        "error_records": ImportJob.error_records,
    }
    sort_expr = sort_map.get(sort_by)
    if sort_expr is None:
        raise HTTPException(422, detail={"code": "INVALID_SORT", "message": "Unsupported import-history sort field."})
    order = sort_expr.desc() if sort_direction.lower() == "desc" else sort_expr.asc()
    items = list((await db.scalars(
        base.order_by(order.nullslast(), ImportJob.id.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )).all())
    return PageResult(items=items, total=total, page=page, page_size=page_size)


@router.get("/imports/{job_id}", response_model=ImportPreviewRead)
async def get_import(job_id: UUID, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request), *, record_limit: int = 500):
    job = await db.scalar(select(ImportJob).where(ImportJob.id == job_id, ImportJob.created_by_user_id == actor.id))
    if job is None:
        raise HTTPException(404, detail={"code": "RESOURCE_NOT_FOUND", "message": "Import job not found."})
    records = list((await db.scalars(select(ImportRecord).where(ImportRecord.import_job_id == job.id).order_by(ImportRecord.row_number).limit(max(1, min(int(record_limit), 10_000))))).all())
    return ImportPreviewRead(job=ImportJobRead.model_validate(job), records=[ImportRecordRead.model_validate(record) for record in records])


@router.post("/imports/{job_id}/confirm", response_model=ImportJobRead)
async def confirm_import(job_id: UUID, payload: ImportConfirmRequest, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    job = await db.scalar(select(ImportJob).where(ImportJob.id == job_id, ImportJob.created_by_user_id == actor.id))
    if job is None:
        raise HTTPException(404, detail={"code": "RESOURCE_NOT_FOUND", "message": "Import job not found."})
    await _require_permissions(db, actor, _import_permissions(job.entity_type or "", str((job.metadata_ or {}).get("subtype") or "ALL")), operation="import")
    scope = await scope_for_actor(db, actor)
    try:
        job = await commit_import_with_template_mapping(db, job=job, actor_id=actor.id, scope=scope, expected_file_sha256=payload.expected_file_sha256)
        await db.commit(); await db.refresh(job)
        return job
    except ImportPreviewExpired as exc:
        await db.rollback()
        expired = await db.scalar(select(ImportJob).where(ImportJob.id == job_id, ImportJob.created_by_user_id == actor.id).with_for_update())
        if expired and expired.status != "COMMITTED":
            expired.status = "EXPIRED"
            await record_audit(db, action="IMPORT_PREVIEW_EXPIRED", entity_type="ImportJob", entity_id=expired.id, description="Import preview expired before transactional confirmation.", metadata={})
            await db.commit()
        raise HTTPException(409, detail={"code": "IMPORT_PREVIEW_EXPIRED", "message": str(exc)[:500]}) from exc
    except Exception as exc:
        await db.rollback()
        # Persist failure separately after rollback, preserving the original preview evidence.
        failed = await db.scalar(select(ImportJob).where(ImportJob.id == job_id, ImportJob.created_by_user_id == actor.id).with_for_update())
        if failed and failed.status != "COMMITTED":
            failed.status = "FAILED"
            failed.validation_summary = {**(failed.validation_summary or {}), "commit_error": type(exc).__name__}
            await record_audit(db, action="IMPORT_COMMIT_FAILED", entity_type="ImportJob", entity_id=failed.id, description="Transactional import failed and business-data writes were rolled back.", metadata={"error_type": type(exc).__name__})
            await db.commit()
        raise HTTPException(409, detail={"code": "IMPORT_COMMIT_FAILED", "message": str(exc)[:500]}) from exc


@router.post("/exports")
async def export_data(payload: ExportRequest, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request), *, request: Request = None):
    filters = payload.filters or {}
    if payload.entity_type == "table":
        table_id = str(filters.get("table_id") or "").strip().lower()
        if not table_id:
            raise HTTPException(422, detail={"code": "EXPORT_REQUEST_INVALID", "message": "table_id is required for table export."})
        if request is None:
            raise HTTPException(500, detail={"code": "EXPORT_CONTEXT_UNAVAILABLE", "message": "Table export request context is unavailable."})
        try:
            data, name, media, rows = await export_table_bytes(request, table_id, payload.format, filters)
        except ValueError as exc:
            raise HTTPException(422, detail={"code": "EXPORT_REQUEST_INVALID", "message": str(exc)}) from exc
        await record_audit(db, action="TABLE_EXPORT_CREATED", entity_type="TableExport", description="Complete filtered table export generated.", metadata={"table_id": table_id, "format": payload.format, "row_count": rows})
        await db.commit()
        return _attachment(data, name, media)

    subtype = str(filters.get("subtype") or "ALL")
    await _require_permissions(db, actor, _export_permissions(payload.entity_type, subtype), operation="export")
    if any(filters.get(key) for key in ("network_id", "city_id", "location_id", "sector_id", "service_vlan_id", "customer_vlan_id")):
        await _require_permissions(db, actor, (P.GEO_READ,), operation="geographic filter")
    scope = await scope_for_actor(db, actor)
    if filters.get("group_id"):
        await _require_permissions(db, actor, (P.GROUP_READ,), operation="group filter")
        try:
            group_id = UUID(str(filters["group_id"]))
        except (TypeError, ValueError) as exc:
            raise HTTPException(422, detail={"code":"EXPORT_REQUEST_INVALID","message":"group_id must be a valid identifier."}) from exc
        await require_group(db, scope, group_id)
    try:
        data, name, media, rows = await export_bytes(db, scope, payload.entity_type, payload.format, payload.filters)
    except ValueError as exc:
        raise HTTPException(422, detail={"code": "EXPORT_REQUEST_INVALID", "message": str(exc)}) from exc
    await record_audit(db, action="DATA_EXPORT_CREATED", entity_type="DataExport", description="Scope-filtered data export generated.", metadata={"entity_type": payload.entity_type, "format": payload.format, "row_count": rows})
    await db.commit()
    return _attachment(data, name, media)