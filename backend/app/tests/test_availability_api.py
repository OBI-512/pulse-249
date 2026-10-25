from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.routers.devices_availability import get_device_availability, update_device_availability
from app.availability.service import ensure_device_availability
from app.models import AuditLog, Device, DeviceAvailability, DeviceIP, DeviceType
from app.schemas.availability import DeviceAvailabilityUpdate
from app.services.audit import enable_audit_maintenance
from app.settings import settings as app_settings


def test_availability_api_configuration_reset_synchronizes_operational_state_and_preserves_degraded_override():
    async def scenario():
        # Keep this asyncio.run() database work off the application-global pool;
        # the legacy integration suite deliberately owns a separate event loop.
        engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
        SessionLocal = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        device_id = None
        try:
            async with SessionLocal() as db:
                try:
                    device_type = await db.scalar(select(DeviceType).where(DeviceType.code == "OTHER"))
                    assert device_type is not None
                    device = Device(
                        device_type_id=device_type.id,
                        display_name=f"Availability API {uuid4().hex[:8]}",
                        lifecycle_state="ACTIVE",
                        operational_state="DEGRADED",
                        manual_degraded_override=True,
                        metadata_={},
                    )
                    db.add(device)
                    await db.flush()
                    device_id = device.id
                    db.add(DeviceIP(
                        device_id=device.id,
                        ip_address=f"198.51.100.{(device.id.int % 200) + 1}",
                        address_family=4,
                        is_management=True,
                        is_primary=True,
                        source="TEST",
                    ))
                    availability = await ensure_device_availability(db, device)
                    await db.commit()

                    row = await get_device_availability(device.id, db, None)
                    assert row.status == "UNKNOWN"
                    assert row.profile == "ICMP"

                    # Establish an observed state so a configuration change has
                    # a real availability transition to audit when it resets the
                    # server-authoritative status back to UNKNOWN.
                    availability.status = "ONLINE"
                    availability.status_changed_at = datetime.now(timezone.utc)
                    await db.commit()

                    updated = await update_device_availability(
                        device.id,
                        DeviceAvailabilityUpdate(profile="TCP", enabled=True),
                        db,
                        None,
                    )
                    assert updated.profile == "TCP"
                    assert updated.status == "UNKNOWN"
                    stored_device = await db.get(Device, device.id)
                    assert stored_device.operational_state == "UNKNOWN"
                    assert stored_device.manual_degraded_override is True
                    stored = await db.scalar(select(DeviceAvailability).where(DeviceAvailability.device_id == device.id))
                    assert stored is not None and stored.profile == "TCP"
                    audit_actions = set((await db.scalars(
                        select(AuditLog.action).where(AuditLog.entity_id == device.id)
                    )).all())
                    assert "DEVICE_AVAILABILITY_CONFIGURATION_CHANGED" in audit_actions
                    assert "DEVICE_AVAILABILITY_CHANGED" in audit_actions
                finally:
                    if device_id is not None:
                        await enable_audit_maintenance(db)
                        await db.execute(delete(AuditLog).where(AuditLog.entity_id == device_id))
                        await db.execute(delete(DeviceAvailability).where(DeviceAvailability.device_id == device_id))
                        await db.execute(delete(DeviceIP).where(DeviceIP.device_id == device_id))
                        await db.execute(delete(Device).where(Device.id == device_id))
                        await db.commit()
        finally:
            await engine.dispose()

    asyncio.run(scenario())
