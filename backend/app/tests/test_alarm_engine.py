from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.availability.service import apply_observation, ensure_device_availability
from app.availability.state import ProbeObservation, ProbeOutcome
from app.models import Alarm, AlarmHistory, AuditLog, Device, DeviceAvailability, DeviceIP, DeviceType, OperationalEvent, User
from app.services.alarms import acknowledge_alarm, assign_alarm, clear_alarm
from app.services.audit import enable_audit_maintenance
from app.settings import settings as app_settings


def test_availability_alarm_lifecycle_deduplicates_and_reopens_deterministically():
    async def scenario():
        engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
        SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        device_id = alarm_id = owner_id = None
        try:
            async with SessionLocal() as db:
                device_type = await db.scalar(select(DeviceType).where(DeviceType.code == "OTHER"))
                assert device_type is not None
                owner = User(external_subject=f"alarm-owner-{uuid4()}", username=f"alarm-owner-{uuid4().hex[:10]}", display_name="Alarm Owner", is_active=True, metadata_={})
                device = Device(device_type_id=device_type.id, display_name=f"C2 Alarm {uuid4().hex[:8]}", lifecycle_state="ACTIVE", operational_state="UNKNOWN", metadata_={})
                db.add_all([owner, device]); await db.flush()
                owner_id, device_id = owner.id, device.id
                db.add(DeviceIP(device_id=device.id, ip_address=f"203.0.113.{(device.id.int % 200)+1}", address_family=4, is_management=True, is_primary=True, source="TEST"))
                availability = await ensure_device_availability(db, device)
                base = datetime(2030, 1, 1, tzinfo=timezone.utc)

                changed = await apply_observation(db, availability=availability, device=device, observation=ProbeObservation(ProbeOutcome.FAILURE, "TIMEOUT"), failure_threshold=2, checked_at=base)
                assert changed and availability.status == "SUSPECT"
                assert await db.scalar(select(func.count(Alarm.id)).where(Alarm.device_id == device.id)) == 0

                await apply_observation(db, availability=availability, device=device, observation=ProbeObservation(ProbeOutcome.FAILURE, "TIMEOUT"), failure_threshold=2, checked_at=base+timedelta(seconds=1))
                alarm = await db.scalar(select(Alarm).where(Alarm.device_id == device.id))
                assert alarm is not None and alarm.state == "ACTIVE" and alarm.occurrence_count == 1
                alarm_id = alarm.id
                assert await db.scalar(select(func.count(OperationalEvent.id)).where(OperationalEvent.device_id == device.id)) == 1

                await apply_observation(db, availability=availability, device=device, observation=ProbeObservation(ProbeOutcome.FAILURE, "TIMEOUT"), failure_threshold=2, checked_at=base+timedelta(seconds=2))
                assert await db.scalar(select(func.count(Alarm.id)).where(Alarm.device_id == device.id)) == 1
                assert await db.scalar(select(func.count(OperationalEvent.id)).where(OperationalEvent.device_id == device.id)) == 1

                assert await acknowledge_alarm(db, alarm=alarm, actor_user_id=owner.id, note="Investigating", now=base+timedelta(seconds=3))
                assert await assign_alarm(db, alarm=alarm, owner_user_id=owner.id, actor_user_id=owner.id, note=None, now=base+timedelta(seconds=4))
                assert await clear_alarm(db, alarm=alarm, actor_user_id=owner.id, note="Operator clear", now=base+timedelta(seconds=5))
                assert alarm.state == "CLEARED"

                await apply_observation(db, availability=availability, device=device, observation=ProbeObservation(ProbeOutcome.FAILURE, "TIMEOUT"), failure_threshold=2, checked_at=base+timedelta(seconds=6))
                assert alarm.state == "ACTIVE" and alarm.occurrence_count == 2
                assert alarm.acknowledged_at is None and alarm.owner_user_id == owner.id

                await apply_observation(db, availability=availability, device=device, observation=ProbeObservation(ProbeOutcome.SUCCESS, "SUCCESS", 3.5), failure_threshold=2, checked_at=base+timedelta(seconds=7))
                assert availability.status == "ONLINE" and alarm.state == "CLEARED"
                assert await db.scalar(select(func.count(OperationalEvent.id)).where(OperationalEvent.device_id == device.id)) == 3
                actions = list((await db.scalars(select(AlarmHistory.action).where(AlarmHistory.alarm_id == alarm.id).order_by(AlarmHistory.occurred_at))).all())
                assert actions == ["OPENED", "ACKNOWLEDGED", "ASSIGNED", "MANUALLY_CLEARED", "REOPENED", "AUTO_CLEARED"]
                audit_actions = set((await db.scalars(select(AuditLog.action).where(AuditLog.entity_id == alarm.id))).all())
                assert {"ALARM_OPENED", "ALARM_ACKNOWLEDGED", "ALARM_ASSIGNED", "ALARM_MANUALLY_CLEARED", "ALARM_REOPENED", "ALARM_AUTO_CLEARED"} <= audit_actions
                await db.commit()

                await enable_audit_maintenance(db)
                if alarm_id: await db.execute(delete(AuditLog).where(AuditLog.entity_id == alarm_id))
                if device_id: await db.execute(delete(AuditLog).where(AuditLog.entity_id == device_id))
                if alarm_id: await db.execute(delete(AlarmHistory).where(AlarmHistory.alarm_id == alarm_id))
                if device_id: await db.execute(delete(Alarm).where(Alarm.device_id == device_id)); await db.execute(delete(OperationalEvent).where(OperationalEvent.device_id == device_id)); await db.execute(delete(DeviceAvailability).where(DeviceAvailability.device_id == device_id)); await db.execute(delete(DeviceIP).where(DeviceIP.device_id == device_id)); await db.execute(delete(Device).where(Device.id == device_id))
                if owner_id: await db.execute(delete(User).where(User.id == owner_id))
                await db.commit()
        finally:
            await engine.dispose()
    asyncio.run(scenario())
