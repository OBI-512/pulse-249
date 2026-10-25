from __future__ import annotations

from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.models import DataLifecycleRun, DataRetentionPolicy
from app.schemas.pagination import PageResult
from app.schemas.phase_d import CapacityModelRead, LifecycleRunRead, RetentionPolicyRead, RetentionPolicyUpdate
from app.security.authorization import authorize_request
from app.security.resource_scope import require_global_scope
from app.services.audit import record_audit
from app.services.data_lifecycle import capacity_model, ensure_default_policies

router = APIRouter(prefix="/data-lifecycle", tags=["Data Lifecycle"], dependencies=[Depends(authorize_request)])
PAGE_SIZES = {50, 100, 200, 300, 400, 500}


@router.get("/policies", response_model=list[RetentionPolicyRead])
async def policies(
    search: str | None = Query(None, max_length=120),
    enabled: bool | None = Query(None),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await require_global_scope(db, actor, message="Global resource scope is required to view retention policy.")
    await ensure_default_policies(db)
    await db.commit()
    stmt = select(DataRetentionPolicy)
    if search and search.strip():
        term = f"%{search.strip()}%"
        stmt = stmt.where(or_(DataRetentionPolicy.data_class.ilike(term), DataRetentionPolicy.description.ilike(term)))
    if enabled is not None:
        stmt = stmt.where(DataRetentionPolicy.enabled.is_(enabled))
    return list((await db.scalars(stmt.order_by(DataRetentionPolicy.data_class))).all())


@router.patch("/policies/{policy_id}", response_model=RetentionPolicyRead)
async def update_policy(policy_id: UUID, payload: RetentionPolicyUpdate, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    await require_global_scope(db, actor, message="Global resource scope is required to manage retention policy.")
    policy = await db.scalar(select(DataRetentionPolicy).where(DataRetentionPolicy.id == policy_id).with_for_update().execution_options(populate_existing=True))
    if policy is None:
        raise HTTPException(404, detail={"code": "RESOURCE_NOT_FOUND", "message": "Retention policy not found."})
    for key, value in payload.model_dump().items():
        setattr(policy, key, value)
    await record_audit(db, action="DATA_RETENTION_POLICY_UPDATED", entity_type="DataRetentionPolicy", entity_id=policy.id, description="Phase-D data retention policy updated.", metadata={"data_class": policy.data_class, "retain_days": policy.retain_days})
    await db.commit(); await db.refresh(policy)
    return policy


@router.get("/runs", response_model=PageResult[LifecycleRunRead])
async def runs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50),
    sort_by: str = Query("started_at", max_length=40),
    sort_direction: str = Query("desc", pattern="^(?i:asc|desc)$"),
    search: str | None = Query(None, max_length=120),
    status: str | None = Query(None, pattern="^(RUNNING|COMPLETED|FAILED|SKIPPED)$"),
    data_class: str | None = Query(None, max_length=80),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await require_global_scope(db, actor, message="Global resource scope is required to view lifecycle runs.")
    if page_size not in PAGE_SIZES:
        raise HTTPException(422, detail={"code": "INVALID_PAGE_SIZE", "message": "Page size must be one of 50, 100, 200, 300, 400, 500."})
    conditions = []
    if search and search.strip():
        term = f"%{search.strip()}%"
        conditions.append(or_(
            DataLifecycleRun.data_class.ilike(term),
            DataLifecycleRun.error_code.ilike(term),
            DataLifecycleRun.idempotency_key.ilike(term),
        ))
    if status:
        conditions.append(DataLifecycleRun.status == status)
    if data_class:
        conditions.append(DataLifecycleRun.data_class == data_class)
    base_stmt = select(DataLifecycleRun)
    count_stmt = select(func.count(DataLifecycleRun.id))
    if conditions:
        base_stmt = base_stmt.where(*conditions)
        count_stmt = count_stmt.where(*conditions)
    total = int((await db.scalar(count_stmt)) or 0)
    sort_map = {
        "data_class": DataLifecycleRun.data_class,
        "status": DataLifecycleRun.status,
        "started_at": DataLifecycleRun.started_at,
        "scanned_rows": DataLifecycleRun.scanned_rows,
        "rolled_up_rows": DataLifecycleRun.rolled_up_rows,
        "purged_rows": DataLifecycleRun.purged_rows,
        "error_code": DataLifecycleRun.error_code,
    }
    sort_expr = sort_map.get(sort_by)
    if sort_expr is None:
        raise HTTPException(422, detail={"code": "INVALID_SORT", "message": "Unsupported lifecycle sort field."})
    order = sort_expr.desc() if sort_direction.lower() == "desc" else sort_expr.asc()
    items = list((await db.scalars(
        base_stmt
        .order_by(order.nullslast(), DataLifecycleRun.id.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )).all())
    return PageResult(items=items, total=total, page=page, page_size=page_size)


@router.get("/capacity", response_model=CapacityModelRead)
async def capacity(db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    await require_global_scope(db, actor, message="Global resource scope is required to view capacity estimates.")
    return capacity_model()
