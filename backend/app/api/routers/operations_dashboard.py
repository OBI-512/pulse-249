from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...schemas.dashboard import OperationsDashboardRead
from ...security.authorization import authorize_request, user_has_permission
from ...security.permissions import Permission as PermissionCode
from ...security.resource_scope import scope_for_actor
from ...services.dashboard import build_operations_dashboard


router = APIRouter(
    prefix="/operations-dashboard",
    tags=["Operations Dashboard"],
    dependencies=[Depends(authorize_request)],
)


@router.get("", response_model=OperationsDashboardRead)
async def operations_dashboard(
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    include_alarms = await user_has_permission(
        db,
        user_id=actor.id,
        permission_code=PermissionCode.ALARM_READ,
    )
    return await build_operations_dashboard(
        db,
        scope=scope,
        include_alarms=include_alarms,
    )
