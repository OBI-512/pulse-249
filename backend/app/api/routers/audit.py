"""Authorized, bounded read/export API for immutable audit evidence."""

from __future__ import annotations

import csv
from datetime import datetime
from io import StringIO
import json
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import Text, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...core.audit_redaction import redact_audit_value
from ...models import AuditLog
from ...schemas.audit import AuditLogPage, AuditLogRead
from ...schemas.log_filters import LogFilterOption
from ...schemas.pagination import PageResult
from ...security.authorization import authorize_request


router = APIRouter(
    prefix="/audit",
    tags=["Audit"],
    dependencies=[Depends(authorize_request)],
)

_EXPORT_DEFAULT = 1000
_EXPORT_MAX = 5000
_AUDIT_RESULTS = frozenset({"SUCCESS", "FAILURE", "ATTEMPT"})


def _escaped_contains(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return "%" + escaped + "%"


def _filters(
    *,
    occurred_after: datetime | None,
    occurred_before: datetime | None,
    actor_user_id: UUID | None,
    actor: str | None,
    action: str | None,
    entity_type: str | None,
    entity_id: UUID | None,
    entity_key: str | None,
    result: str | None,
    request_id: str | None,
    search: str | None,
) -> list[Any]:
    if occurred_after and occurred_before and occurred_after > occurred_before:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "code": "AUDIT_TIME_RANGE_INVALID",
                "message": "occurred_after must be earlier than or equal to occurred_before.",
            },
        )

    filters: list[Any] = []
    if occurred_after:
        filters.append(AuditLog.occurred_at >= occurred_after)
    if occurred_before:
        filters.append(AuditLog.occurred_at <= occurred_before)
    if actor_user_id:
        filters.append(AuditLog.actor_user_id == actor_user_id)
    if actor:
        normalized_actor = actor.strip()
        if normalized_actor == "SYSTEM":
            filters.append(AuditLog.actor_user_id.is_(None))
        else:
            filters.append(or_(
                AuditLog.actor_display_name_snapshot == normalized_actor,
                AuditLog.actor_username_snapshot == normalized_actor,
            ))
    if action:
        filters.append(AuditLog.action == action.strip().upper())
    if entity_type:
        filters.append(func.lower(AuditLog.entity_type) == entity_type.strip().lower())
    if entity_id:
        filters.append(AuditLog.entity_id == entity_id)
    if entity_key:
        key_type, _, key_id = entity_key.partition("|")
        if key_type:
            filters.append(func.lower(AuditLog.entity_type) == key_type.lower())
        if key_id:
            try:
                filters.append(AuditLog.entity_id == UUID(key_id))
            except ValueError as exc:
                raise HTTPException(422, detail={"code":"AUDIT_ENTITY_FILTER_INVALID","message":"Invalid entity filter."}) from exc
    if result:
        normalized_result = result.strip().upper()
        if normalized_result not in _AUDIT_RESULTS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "code": "AUDIT_RESULT_INVALID",
                    "message": (
                        "result must be one of SUCCESS, FAILURE, or ATTEMPT."
                    ),
                },
            )
        filters.append(AuditLog.result == normalized_result)
    if request_id:
        filters.append(AuditLog.request_id == request_id)
    if search:
        pattern = _escaped_contains(search.strip())
        filters.append(
            or_(
                AuditLog.action.ilike(pattern, escape="\\"),
                AuditLog.actor_username_snapshot.ilike(pattern, escape="\\"),
                AuditLog.actor_display_name_snapshot.ilike(pattern, escape="\\"),
                AuditLog.entity_type.ilike(pattern, escape="\\"),
                AuditLog.result.ilike(pattern, escape="\\"),
                AuditLog.request_id.ilike(pattern, escape="\\"),
                AuditLog.source_ip.ilike(pattern, escape="\\"),
                AuditLog.description.ilike(pattern, escape="\\"),
                cast(AuditLog.entity_display_snapshot, Text).ilike(pattern, escape="\\"),
                cast(AuditLog.before_summary, Text).ilike(pattern, escape="\\"),
                cast(AuditLog.after_summary, Text).ilike(pattern, escape="\\"),
                cast(AuditLog.metadata_, Text).ilike(pattern, escape="\\"),
            )
        )
    return filters


def _read(row: AuditLog) -> AuditLogRead:
    """Redact again on output to protect any pre-Stage-B legacy evidence."""

    return AuditLogRead(
        id=row.id,
        occurred_at=row.occurred_at,
        actor_user_id=row.actor_user_id,
        actor_username_snapshot=redact_audit_value(row.actor_username_snapshot),
        actor_display_name_snapshot=redact_audit_value(row.actor_display_name_snapshot),
        action=row.action,
        entity_type=row.entity_type,
        entity_id=row.entity_id,
        entity_display_snapshot=redact_audit_value(row.entity_display_snapshot),
        result=row.result,
        request_id=row.request_id,
        source_ip=row.source_ip,
        description=redact_audit_value(row.description),
        before_summary=redact_audit_value(row.before_summary),
        after_summary=redact_audit_value(row.after_summary),
        metadata=redact_audit_value(row.metadata_),
    )


@router.get("", response_model=AuditLogPage)
async def list_audit_logs(
    occurred_after: datetime | None = None,
    occurred_before: datetime | None = None,
    actor_user_id: UUID | None = None,
    actor: str | None = Query(None, max_length=200),
    action: str | None = Query(None, min_length=1, max_length=120),
    entity_type: str | None = Query(None, min_length=1, max_length=80),
    entity_id: UUID | None = None,
    entity_key: str | None = Query(None, max_length=200),
    result: str | None = Query(None, min_length=1, max_length=30),
    request_id: str | None = Query(None, min_length=1, max_length=128),
    search: str | None = Query(None, min_length=1, max_length=200),
    sort_by: str = Query("occurred_at", max_length=40),
    sort_direction: str = Query("desc", pattern="^(?i:asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    filters = _filters(
        occurred_after=occurred_after, occurred_before=occurred_before,
        actor_user_id=actor_user_id, actor=actor, action=action, entity_type=entity_type, entity_id=entity_id, entity_key=entity_key,
        result=result, request_id=request_id, search=search,
    )
    total = await db.scalar(select(func.count(AuditLog.id)).where(*filters))
    actor_expr = func.coalesce(AuditLog.actor_display_name_snapshot, AuditLog.actor_username_snapshot, "SYSTEM")
    entity_label_expr = func.coalesce(
        AuditLog.entity_display_snapshot["display_name"].astext,
        AuditLog.entity_display_snapshot["name"].astext,
        AuditLog.entity_display_snapshot["label"].astext,
        AuditLog.entity_display_snapshot["service_code"].astext,
        AuditLog.entity_display_snapshot["customer_code"].astext,
        AuditLog.entity_display_snapshot["ip_address"].astext,
        AuditLog.entity_display_snapshot["code"].astext,
        AuditLog.entity_type,
    )
    sort_map = {
        "occurred_at": AuditLog.occurred_at, "actor": actor_expr, "action": AuditLog.action,
        "entity": entity_label_expr, "result": AuditLog.result, "description": AuditLog.description,
        "request_id": AuditLog.request_id,
    }
    sort_expr = sort_map.get(sort_by)
    if sort_expr is None:
        raise HTTPException(422, detail={"code":"INVALID_AUDIT_SORT","message":"Unsupported audit sort column."})
    order = sort_expr.desc() if sort_direction.lower() == "desc" else sort_expr.asc()
    rows = (
        await db.scalars(
            select(AuditLog).where(*filters).order_by(order.nullslast(), AuditLog.id.desc())
            .offset((page - 1) * page_size).limit(page_size)
        )
    ).all()
    return AuditLogPage(items=[_read(row) for row in rows], total=total or 0, page=page, page_size=page_size)


def _snapshot_label(snapshot: dict[str, Any] | None, entity_type: str | None, entity_id: UUID | None) -> str:
    if isinstance(snapshot, dict):
        for key in ("display_name", "name", "label", "service_code", "customer_code", "ip_address", "code"):
            value = snapshot.get(key)
            if value:
                return str(value)
    if entity_type and entity_id:
        return f"{entity_type} · {str(entity_id)[:8]}…"
    return entity_type or "Unknown entity"


@router.get("/filter-options/{kind}", response_model=PageResult[LogFilterOption])
async def audit_filter_options(
    kind: str, search: str | None = Query(None, max_length=200),
    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    pattern = _escaped_contains(search.strip()) if search and search.strip() else None
    offset = (page - 1) * page_size
    if kind == "actor":
        expr = func.coalesce(AuditLog.actor_display_name_snapshot, AuditLog.actor_username_snapshot, "SYSTEM")
        stmt = select(expr.label("value")).distinct()
        if pattern:
            stmt = stmt.where(expr.ilike(pattern, escape="\\"))
        total = int((await db.scalar(select(func.count()).select_from(stmt.subquery()))) or 0)
        values = (await db.scalars(stmt.order_by(expr).offset(offset).limit(page_size))).all()
        items = [LogFilterOption(id=value, label=value) for value in values if value]
    elif kind == "action":
        stmt = select(AuditLog.action).distinct()
        if pattern:
            stmt = stmt.where(AuditLog.action.ilike(pattern, escape="\\"))
        total = int((await db.scalar(select(func.count()).select_from(stmt.subquery()))) or 0)
        values = (await db.scalars(stmt.order_by(AuditLog.action).offset(offset).limit(page_size))).all()
        items = [LogFilterOption(id=value, label=value) for value in values if value]
    elif kind == "request-id":
        stmt = select(AuditLog.request_id).where(AuditLog.request_id.is_not(None)).distinct()
        if pattern:
            stmt = stmt.where(AuditLog.request_id.ilike(pattern, escape="\\"))
        total = int((await db.scalar(select(func.count()).select_from(stmt.subquery()))) or 0)
        values = (await db.scalars(stmt.order_by(AuditLog.request_id).offset(offset).limit(page_size))).all()
        items = [LogFilterOption(id=value, label=value) for value in values if value]
    elif kind == "entity":
        # One option per audited entity.  Use the newest immutable snapshot for
        # the operator-facing label so repeated audit events for the same
        # entity cannot create duplicate combobox entries.
        ranked = select(
            AuditLog.entity_type.label("entity_type"),
            AuditLog.entity_id.label("entity_id"),
            AuditLog.entity_display_snapshot.label("snapshot"),
            func.row_number().over(
                partition_by=(AuditLog.entity_type, AuditLog.entity_id),
                order_by=(AuditLog.occurred_at.desc(), AuditLog.id.desc()),
            ).label("rank"),
        ).where(AuditLog.entity_type.is_not(None)).subquery()
        latest = select(
            ranked.c.entity_type, ranked.c.entity_id, ranked.c.snapshot
        ).where(ranked.c.rank == 1)
        if pattern:
            latest = latest.where(or_(
                ranked.c.entity_type.ilike(pattern, escape="\\"),
                cast(ranked.c.snapshot, Text).ilike(pattern, escape="\\"),
            ))
        total = int((await db.scalar(
            select(func.count()).select_from(latest.order_by(None).subquery())
        )) or 0)
        rows = (await db.execute(
            latest.order_by(ranked.c.entity_type, ranked.c.entity_id)
            .offset(offset).limit(page_size)
        )).all()
        items = [LogFilterOption(
            id=f"{entity_type_value}|{entity_id_value or ''}",
            label=_snapshot_label(snapshot, entity_type_value, entity_id_value),
            description=entity_type_value,
        ) for entity_type_value, entity_id_value, snapshot in rows]
    else:
        raise HTTPException(422, detail={"code":"AUDIT_FILTER_KIND_INVALID","message":"Unsupported audit filter option."})
    return PageResult(items=items, total=total, page=page, page_size=page_size)


def _csv_safe(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        rendered = json.dumps(value, sort_keys=True, separators=(",", ":"))
    elif isinstance(value, datetime):
        rendered = value.isoformat()
    else:
        rendered = str(value)
    return f"'{rendered}" if rendered.startswith(("=", "+", "-", "@")) else rendered


@router.get("/export")
async def export_audit_logs(
    occurred_after: datetime | None = None,
    occurred_before: datetime | None = None,
    actor_user_id: UUID | None = None,
    actor: str | None = Query(None, max_length=200),
    action: str | None = Query(None, min_length=1, max_length=120),
    entity_type: str | None = Query(None, min_length=1, max_length=80),
    entity_id: UUID | None = None,
    entity_key: str | None = Query(None, max_length=200),
    result: str | None = Query(None, min_length=1, max_length=30),
    request_id: str | None = Query(None, min_length=1, max_length=128),
    search: str | None = Query(None, min_length=1, max_length=200),
    limit: int = Query(_EXPORT_DEFAULT, ge=1, le=_EXPORT_MAX),
    db: AsyncSession = Depends(get_db),
):
    filters = _filters(
        occurred_after=occurred_after,
        occurred_before=occurred_before,
        actor_user_id=actor_user_id,
        actor=actor,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        entity_key=entity_key,
        result=result,
        request_id=request_id,
        search=search,
    )
    rows = list(
        (
            await db.scalars(
                select(AuditLog)
                .where(*filters)
                .order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc())
                .limit(limit + 1)
            )
        ).all()
    )
    truncated = len(rows) > limit
    rows = rows[:limit]

    output = StringIO(newline="")
    writer = csv.writer(output)
    fields = tuple(AuditLogRead.model_fields)
    writer.writerow(fields)
    for row in rows:
        safe = _read(row).model_dump(mode="python")
        writer.writerow([_csv_safe(safe[field]) for field in fields])
    output.seek(0)

    headers = {
        "Content-Disposition": "attachment; filename=fttw-audit-export.csv",
        "X-Audit-Export-Limit": str(limit),
        "X-Audit-Export-Truncated": str(truncated).lower(),
    }
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers=headers,
    )


@router.get("/{audit_id}", response_model=AuditLogRead)
async def retrieve_audit_log(
    audit_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    row = await db.get(AuditLog, audit_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "AUDIT_EVENT_NOT_FOUND",
                "message": "The audit event does not exist.",
            },
        )
    return _read(row)
