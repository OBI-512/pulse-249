from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ..recycle_support import recycle_from_delete_endpoint
from ...security.authorization import authorize_request
from ...security.resource_scope import scope_for_actor
from ...security.scope_queries import relationship_scope_clause, require_device
from ...models import DeviceRelationship
from ...schemas.relationships import DeviceRelationshipCreate, DeviceRelationshipRead
from ...services.relationships import (
    RelationshipValidationError,
    create_device_relationship,
)


router = APIRouter(
    prefix="/device-relationships",
    tags=["Device Relationships"],
    dependencies=[Depends(authorize_request)],
)


@router.get(
    "",
    response_model=list[DeviceRelationshipRead],
)
async def list_relationships(
    source_device_id: UUID | None = None,
    target_device_id: UUID | None = None,
    relationship_type: str | None = None,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    stmt = select(DeviceRelationship).where(await relationship_scope_clause(db, scope))

    if source_device_id:
        stmt = stmt.where(
            DeviceRelationship.source_device_id == source_device_id
        )

    if target_device_id:
        stmt = stmt.where(
            DeviceRelationship.target_device_id == target_device_id
        )

    if relationship_type:
        stmt = stmt.where(
            DeviceRelationship.relationship_type == relationship_type
        )

    result = await db.execute(stmt)

    return result.scalars().all()


@router.post(
    "",
    response_model=DeviceRelationshipRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_relationship(
    payload: DeviceRelationshipCreate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    try:
        await require_device(db, scope, payload.source_device_id)
    except HTTPException as exc:
        if exc.status_code != status.HTTP_404_NOT_FOUND:
            raise
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "SOURCE_DEVICE_NOT_FOUND",
                "message": "The source device does not exist.",
            },
        ) from exc
    try:
        await require_device(db, scope, payload.target_device_id)
    except HTTPException as exc:
        if exc.status_code != status.HTTP_404_NOT_FOUND:
            raise
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "TARGET_DEVICE_NOT_FOUND",
                "message": "The target device does not exist.",
            },
        ) from exc
    try:
        obj = await create_device_relationship(
            db,
            source_device_id=payload.source_device_id,
            target_device_id=payload.target_device_id,
            relationship_type=payload.relationship_type,
            direction=payload.direction,
            metadata=payload.metadata,
        )

    except RelationshipValidationError as exc:
        status_code = (
            404
            if exc.code
            in {
                "SOURCE_DEVICE_NOT_FOUND",
                "TARGET_DEVICE_NOT_FOUND",
            }
            else 409
            if exc.code
            in {
                "SELF_RELATIONSHIP",
                "RELATIONSHIP_CONFLICT",
            }
            else 422
        )

        raise HTTPException(
            status_code=status_code,
            detail={
                "code": exc.code,
                "message": exc.message,
            },
        ) from exc

    await db.commit()
    await db.refresh(obj)

    return obj


@router.delete(
    "/{relationship_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_relationship(
    relationship_id: UUID,
    reason: str | None = None,
    confirmed: bool = False,
    actor=Depends(authorize_request),
    db: AsyncSession = Depends(get_db),
):
    scope = await scope_for_actor(db, actor)
    rel = await db.scalar(select(DeviceRelationship).where(DeviceRelationship.id == relationship_id, await relationship_scope_clause(db, scope)))
    if rel is None:
        from ...security.resource_scope import not_found_scope_error
        raise not_found_scope_error("Device relationship")
    await recycle_from_delete_endpoint(
        db,
        entity_type="DEVICE_RELATIONSHIP",
        entity_id=relationship_id,
        actor=actor,
        reason=reason,
        confirmed=confirmed,
    )
    return None
