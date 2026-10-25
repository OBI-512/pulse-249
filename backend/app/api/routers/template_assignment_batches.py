from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.schemas.pagination import PageResult
from app.schemas.template_assignment_batches import (
    AccessTemplateAssignmentOption,
    ConfigurationTemplateAssignmentOption,
    TemplateAssignmentBatchApplyRequest,
    TemplateAssignmentBatchDetail,
    TemplateAssignmentBatchPreviewRequest,
    TemplateAssignmentBatchRead,
    TemplateAssignmentBatchTargetRead,
)
from app.security.authorization import authorize_request
from app.services.template_assignment_batches import (
    apply_batch,
    create_preview,
    get_batch_for_actor,
    list_access_assignment_options,
    list_batches_for_actor,
    list_configuration_assignment_options,
)


router = APIRouter(
    tags=["Template Assignment"],
    dependencies=[Depends(authorize_request)],
)


def _detail(batch, targets) -> TemplateAssignmentBatchDetail:
    return TemplateAssignmentBatchDetail(
        batch=TemplateAssignmentBatchRead.model_validate(batch),
        targets=[
            TemplateAssignmentBatchTargetRead.model_validate(target)
            for target in targets
        ],
    )


@router.get(
    "/template-assignment-options/access",
    response_model=PageResult[AccessTemplateAssignmentOption],
)
async def access_template_assignment_options(
    search: str | None = Query(default=None, max_length=200),
    protocol: str | None = Query(default=None, max_length=20),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    return await list_access_assignment_options(
        db,
        actor=actor,
        search=search,
        protocol=protocol,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/template-assignment-options/configuration",
    response_model=PageResult[ConfigurationTemplateAssignmentOption],
)
async def configuration_template_assignment_options(
    search: str | None = Query(default=None, max_length=200),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    return await list_configuration_assignment_options(
        db,
        search=search,
        page=page,
        page_size=page_size,
    )


@router.post(
    "/template-assignment-batches/preview",
    response_model=TemplateAssignmentBatchDetail,
    status_code=201,
)
async def preview_template_assignment_batch(
    payload: TemplateAssignmentBatchPreviewRequest,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    batch, targets, _created = await create_preview(
        db,
        payload=payload,
        actor=actor,
    )
    await db.commit()
    return _detail(batch, targets)


@router.get(
    "/template-assignment-batches",
    response_model=list[TemplateAssignmentBatchRead],
)
async def list_template_assignment_batches(
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    rows = await list_batches_for_actor(db, actor=actor, limit=limit)
    return [TemplateAssignmentBatchRead.model_validate(row) for row in rows]


@router.get(
    "/template-assignment-batches/{batch_id}",
    response_model=TemplateAssignmentBatchDetail,
)
async def get_template_assignment_batch(
    batch_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    batch, targets = await get_batch_for_actor(
        db,
        batch_id=batch_id,
        actor=actor,
    )
    return _detail(batch, targets)


@router.post(
    "/template-assignment-batches/{batch_id}/apply",
    response_model=TemplateAssignmentBatchDetail,
)
async def apply_template_assignment_batch(
    batch_id: UUID,
    payload: TemplateAssignmentBatchApplyRequest,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    batch, targets = await apply_batch(
        db,
        batch_id=batch_id,
        expected_request_fingerprint=payload.expected_request_fingerprint,
        actor=actor,
    )
    await db.commit()
    return _detail(batch, targets)
