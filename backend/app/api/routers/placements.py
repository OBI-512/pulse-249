from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...security.authorization import authorize_request
from ...security.resource_scope import scope_for_actor
from ...security.scope_queries import require_device, require_location, require_sector
from ...models import DevicePlacement
from ...schemas.placement import (
    DevicePlacementRead,
    DevicePlacementUpdate,
)
from ...services.placements import (
    PlacementValidationError,
    update_device_placement,
)


router = APIRouter(
    prefix="/devices",
    tags=["Device Placement"],
    dependencies=[Depends(authorize_request)],
)


@router.get(
    "/{device_id}/placement",
    response_model=DevicePlacementRead,
)
async def get_device_placement(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await require_device(db, await scope_for_actor(db, actor), device_id)
    result = await db.execute(
        select(DevicePlacement).where(
            DevicePlacement.device_id == device_id
        )
    )

    placement = result.scalar_one_or_none()

    if placement is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "PLACEMENT_NOT_FOUND",
                "message": "Device placement not found.",
            },
        )

    return placement


@router.patch(
    "/{device_id}/placement",
    response_model=DevicePlacementRead,
)
async def update_device_placement_endpoint(
    device_id: UUID,
    payload: DevicePlacementUpdate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    data = payload.model_dump(exclude_unset=True)
    scope = await scope_for_actor(db, actor)
    if not scope.global_access:
        await require_device(db, scope, device_id)
        if data.get("sector_id") is not None:
            await require_sector(db, scope, data["sector_id"])
        elif data.get("location_id") is not None:
            await require_location(db, scope, data["location_id"])

    try:
        placement = await update_device_placement(
            db,
            device_id,
            data,
        )
    except PlacementValidationError as exc:
        status_code = (
            404
            if exc.code in {
                "PLACEMENT_NOT_FOUND",
                "DEVICE_NOT_FOUND",
                "NETWORK_NOT_FOUND",
                "CITY_NOT_FOUND",
                "LOCATION_NOT_FOUND",
                "SECTOR_NOT_FOUND",
            }
            else 400
        )

        raise HTTPException(
            status_code=status_code,
            detail={
                "code": exc.code,
                "message": exc.message,
            },
        ) from exc

    await db.commit()
    await db.refresh(placement)

    return placement
