"""Device router aggregator and compatibility import facade.

Route implementation is split by inventory, lifecycle, addressing, and
interface responsibilities while preserving the /devices API contract.
"""
import httpx

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.audit_context import get_audit_context
from ...core.exceptions import APIError
from ...security.authorization import authorize_request, user_has_permission
from . import devices_inventory, devices_availability, devices_lifecycle, devices_addresses, devices_interfaces, devices_remote_access

router = APIRouter()
_route_options = {"prefix": "/devices", "tags": ["Devices"], "dependencies": [Depends(authorize_request)]}
router.include_router(devices_inventory.router, **_route_options)
router.include_router(devices_availability.router, **_route_options)
router.include_router(devices_lifecycle.router, **_route_options)
router.include_router(devices_addresses.router, **_route_options)
router.include_router(devices_interfaces.router, **_route_options)
router.include_router(devices_remote_access.router, **_route_options)


async def _require_actor_permission_for_change(db: AsyncSession, permission_code: str) -> None:
    """Require an additional permission for a request-scoped domain change.

    Route authorization still requires device.update first. This secondary check
    protects physical movement/placement changes submitted through the generic
    device PATCH endpoint. Direct service-level test calls have no bound actor
    and therefore continue to exercise domain behavior without HTTP RBAC state.
    """
    actor_user_id = get_audit_context().actor_user_id
    if actor_user_id is None:
        return
    if not await user_has_permission(db, user_id=actor_user_id, permission_code=permission_code):
        raise APIError(
            403,
            "PERMISSION_DENIED",
            f"Permission '{permission_code}' is required.",
        )


# Compatibility exports retained for tests and internal callers.  ``httpx`` is
# intentionally imported above as the same module object used by lifecycle
# handlers, so historical monkeypatches of ``devices.httpx.AsyncClient`` still
# affect accessibility tests exactly as before the split.
from .devices_inventory import (
    list_device_types, device_operational_summary, list_device_inventory_page,
    list_device_inventory, list_device_management_page, list_device_management, list_devices,
)
from .devices_lifecycle import (
    create_device, test_device_accessibility, get_device, update_device, update_device_status,
    decommission_device, reactivate_device, delete_device,
)
from .devices_addresses import list_device_ips, add_device_ip, update_device_ip, delete_device_ip
from .devices_interfaces import list_device_interfaces, add_device_interface, update_device_interface, delete_device_interface
