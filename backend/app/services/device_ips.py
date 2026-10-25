"""Authoritative DeviceIP invariant checks shared by all mutable IP paths."""

from __future__ import annotations

from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import DeviceIP


def _error(code: str, message: str, status: int = 409) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message})


async def lock_device_ips(db: AsyncSession, device_id: UUID) -> list[DeviceIP]:
    return list((await db.scalars(
        select(DeviceIP).where(DeviceIP.device_id == device_id).order_by(DeviceIP.id)
        .with_for_update().execution_options(populate_existing=True)
    )).all())


async def apply_ip_flags(
    db: AsyncSession, *, device_id: UUID, target: DeviceIP,
    is_management: bool | None = None, is_primary: bool | None = None,
) -> None:
    """Apply flag changes without permitting an invalid final device state."""
    rows = await lock_device_ips(db, device_id)
    if target.id not in {row.id for row in rows}:
        raise _error("IP_NOT_FOUND", "Device IP not found.", 404)
    requested_primary = target.is_primary if is_primary is None else is_primary
    requested_management = target.is_management if is_management is None else is_management
    if requested_primary and not requested_management:
        raise _error("PRIMARY_IP_MUST_BE_MANAGEMENT", "A primary IP must also be a management IP.", 422)
    if target.is_primary and is_management is False:
        raise _error("PRIMARY_IP_MUST_BE_MANAGEMENT", "A primary IP must also be a management IP.", 422)
    if requested_primary:
        # A PostgreSQL partial unique index enforces one active primary.  Make
        # the transition in two flushes so promoting a *new* row can never
        # temporarily violate that index, regardless of UPDATE ordering.
        demoted = False
        for row in rows:
            if row.id != target.id and row.is_primary:
                row.is_primary = False
                demoted = True
        if demoted:
            await db.flush()
        target.is_primary = True
        target.is_management = True
    else:
        target.is_primary = False
        target.is_management = requested_management
    if sum(1 for row in rows if row.is_management) < 1:
        raise _error("LAST_MANAGEMENT_IP_PROTECTED", "A device must retain at least one management IP.")
    if sum(1 for row in rows if row.is_primary) != 1:
        raise _error("PRIMARY_IP_REQUIRED", "A device must retain exactly one primary IP.")


async def ensure_ip_recycle_permitted(db: AsyncSession, ip: DeviceIP) -> None:
    rows = await lock_device_ips(db, ip.device_id)
    if ip.is_management and sum(1 for row in rows if row.is_management) <= 1:
        raise _error("LAST_MANAGEMENT_IP_PROTECTED", "A device must retain at least one management IP.")
    if ip.is_primary:
        raise _error("PRIMARY_IP_PROTECTED", "Promote another management IP before recycling the primary IP.")
