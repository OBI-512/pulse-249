from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...security.authorization import authorize_request
from ...security.resource_scope import scope_for_actor
from ...security.scope_queries import require_device
from ...models import Device, DeviceIP, DeviceInterface, DeviceType
from ...services.crud import get_or_404

router = APIRouter(prefix="/device-summary", tags=["Device Summary"], dependencies=[Depends(authorize_request)])


@router.get("/{device_id}")
async def get_device_summary(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    device = await require_device(db, scope, device_id)

    ip_count = await db.scalar(
        select(func.count(DeviceIP.id)).where(DeviceIP.device_id == device_id)
    )
    interface_count = await db.scalar(
        select(func.count(DeviceInterface.id)).where(
            DeviceInterface.device_id == device_id
        )
    )

    device_type = await get_or_404(db, DeviceType, device.device_type_id)

    return {
        "id": device.id,
        "display_name": device.display_name,
        "device_type": {
            "id": device_type.id,
            "name": device_type.name,
            "code": device_type.code,
        },
        "hostname": device.hostname,
        "vendor": device.vendor,
        "model": device.model,
        "serial_number": device.serial_number,
        "lifecycle_state": device.lifecycle_state,
        "operational_state": device.operational_state,
        "management_protocol": device.management_protocol,
        "ip_count": ip_count or 0,
        "interface_count": interface_count or 0,
    }
