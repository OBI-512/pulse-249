from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import DeviceIP, DeviceRemoteAccessProfile
from .audit import record_audit
from .web_tls_trust import revoke_linked_internal_web_tls_trust


async def current_management_ip_snapshot(db: AsyncSession, device_id: UUID) -> str | None:
    return await db.scalar(
        select(DeviceIP.ip_address)
        .where(
            DeviceIP.device_id == device_id,
            DeviceIP.deleted_at.is_(None),
            DeviceIP.is_management.is_(True),
        )
        .order_by(DeviceIP.is_primary.desc(), DeviceIP.created_at.asc())
        .limit(1)
    )


async def invalidate_web_tls_trust_if_management_endpoint_changed(
    db: AsyncSession,
    *,
    device_id: UUID,
    before_management_ip: str | None,
    actor_user_id: UUID | None,
) -> bool:
    after_management_ip = await current_management_ip_snapshot(db, device_id)
    if before_management_ip == after_management_ip:
        return False

    profile = await db.scalar(
        select(DeviceRemoteAccessProfile)
        .where(DeviceRemoteAccessProfile.device_id == device_id)
        .with_for_update()
    )
    if profile is None or profile.web_tls_trust_id is None:
        return False

    await revoke_linked_internal_web_tls_trust(
        db,
        profile,
        reason="Registered device management IP changed",
        actor_user_id=actor_user_id,
    )
    await record_audit(
        db,
        action="REMOTE_ACCESS_WEB_TLS_TRUST_REVOKED_ENDPOINT_CHANGED",
        entity_type="Device",
        entity_id=device_id,
        actor_user_id=actor_user_id,
        description="Internal HTTPS certificate trust was retired because the registered management endpoint changed.",
        metadata={
            "previous_management_ip": before_management_ip,
            "new_management_ip": after_management_ip,
            "requires_reinspection": True,
            "device_connection": False,
        },
    )
    return True
