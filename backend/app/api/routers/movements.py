from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...models import Device, Sector
from ...schemas.geo import SectorRead
from ...schemas.device import DeviceRead
from ...schemas.movement import AccessPointReassignment, CpeMove, SectorMove
from ...security.authorization import authorize_request
from ...security.resource_scope import scope_for_actor
from ...security.scope_queries import require_device, require_location, require_sector
from ...services.hierarchy import resolve_effective_hierarchy
from ...services.movement import (
    MovementValidationError,
    move_cpe_to_sector,
    move_sector_to_location,
    reassign_access_point,
)


router = APIRouter(
    prefix="/physical-movements",
    tags=["Physical Movements"],
    dependencies=[Depends(authorize_request)],
)


def _movement_http_error(exc: MovementValidationError) -> HTTPException:
    return HTTPException(
        status_code=exc.status_code,
        detail={"code": exc.code, "message": exc.message},
    )


@router.post("/sectors/{sector_id}", response_model=SectorRead)
async def move_sector(
    sector_id: UUID,
    payload: SectorMove,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    await require_sector(db, scope, sector_id)
    await require_location(db, scope, payload.destination_location_id)
    try:
        sector = await move_sector_to_location(
            db,
            sector_id=sector_id,
            destination_location_id=payload.destination_location_id,
            sequence_number=payload.sequence_number,
        )
        await db.commit()
        await db.refresh(sector)
        return sector
    except MovementValidationError as exc:
        await db.rollback()
        raise _movement_http_error(exc) from exc
    except Exception:
        await db.rollback()
        raise


@router.post("/cpes/{cpe_device_id}", response_model=DeviceRead)
async def move_cpe(
    cpe_device_id: UUID,
    payload: CpeMove,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    await require_device(db, scope, cpe_device_id)
    parent = await require_device(db, scope, payload.destination_sector_device_id)
    hierarchy = await resolve_effective_hierarchy(db, parent)
    if hierarchy.sector_id is not None:
        await require_sector(db, scope, hierarchy.sector_id)
    try:
        cpe = await move_cpe_to_sector(
            db,
            cpe_device_id=cpe_device_id,
            destination_sector_device_id=payload.destination_sector_device_id,
        )
        await db.commit()
        await db.refresh(cpe)
        return cpe
    except MovementValidationError as exc:
        await db.rollback()
        raise _movement_http_error(exc) from exc
    except Exception:
        await db.rollback()
        raise


@router.post("/access-points/{access_point_device_id}", response_model=DeviceRead)
async def move_access_point(
    access_point_device_id: UUID,
    payload: AccessPointReassignment,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    await require_device(db, scope, access_point_device_id)
    parent = await require_device(db, scope, payload.destination_cpe_device_id)
    hierarchy = await resolve_effective_hierarchy(db, parent)
    if hierarchy.sector_id is not None:
        await require_sector(db, scope, hierarchy.sector_id)
    try:
        access_point = await reassign_access_point(
            db,
            access_point_device_id=access_point_device_id,
            destination_cpe_device_id=payload.destination_cpe_device_id,
        )
        await db.commit()
        await db.refresh(access_point)
        return access_point
    except MovementValidationError as exc:
        await db.rollback()
        raise _movement_http_error(exc) from exc
    except Exception:
        await db.rollback()
        raise
