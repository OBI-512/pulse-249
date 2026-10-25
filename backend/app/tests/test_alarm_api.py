from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.routers.alarms import (
    acknowledge_alarm_api,
    alarm_summary,
    clear_alarm_api,
    get_alarm,
    get_alarm_events,
    get_alarm_history,
    list_alarms_page,
    update_alarm_owner,
)
from app.core.exceptions import APIError
from app.models import Alarm, AlarmHistory, AuditLog, Device, DeviceAvailability, DeviceType, OperationalEvent, User, UserResourceScope
from app.schemas.alarm import AlarmAcknowledgeRequest, AlarmClearRequest, AlarmOwnerUpdate
from app.services.audit import enable_audit_maintenance
from app.settings import settings as app_settings


def test_alarm_api_obeys_existing_device_resource_scope_and_exposes_events():
    async def scenario():
        engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
        SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        ids = {}
        try:
            async with SessionLocal() as db:
                dtype = await db.scalar(select(DeviceType).where(DeviceType.code == "OTHER")); assert dtype
                user = User(external_subject=f"alarm-scope-{uuid4()}", username=f"alarm-scope-{uuid4().hex[:10]}", display_name="Alarm Scope", is_active=True, metadata_={})
                device = Device(device_type_id=dtype.id, display_name=f"Scoped alarm {uuid4().hex[:8]}", lifecycle_state="ACTIVE", operational_state="UNKNOWN", metadata_={})
                db.add_all([user, device]); await db.flush(); ids={"user":user.id,"device":device.id}
                availability = DeviceAvailability(device_id=device.id, status="OFFLINE", profile="ICMP", enabled=True)
                event = OperationalEvent(device_id=device.id, event_type="DEVICE_AVAILABILITY_OFFLINE", severity="MAJOR", correlation_key=f"device:{device.id}:availability:offline", occurred_at=datetime.now(timezone.utc), summary="offline", metadata_={})
                db.add_all([availability,event]); await db.flush()
                alarm = Alarm(device_id=device.id, alarm_type="DEVICE_AVAILABILITY_OFFLINE", correlation_key=event.correlation_key, severity="MAJOR", state="ACTIVE", summary="offline", first_raised_at=event.occurred_at, last_raised_at=event.occurred_at, occurrence_count=1, last_event_id=event.id)
                db.add(alarm); await db.flush(); ids["alarm"]=alarm.id; ids["event"]=event.id

                page = await list_alarms_page(state="ACTIVE", severity=None, acknowledged=None, owner=None, search=None, page=1, page_size=50, db=db, actor=user)
                assert page.total == 0
                with pytest.raises(APIError) as exc: await get_alarm(alarm.id, db, user)
                assert exc.value.status_code == 404

                db.add(UserResourceScope(user_id=user.id, scope_type="GLOBAL")); await db.flush()
                page = await list_alarms_page(state="ACTIVE", severity=None, acknowledged=None, owner=None, search=device.display_name, page=1, page_size=50, db=db, actor=user)
                assert page.total == 1 and page.items[0].id == alarm.id
                summary = await alarm_summary(db, user); assert summary.active_total >= 1 and summary.major >= 1
                events = await get_alarm_events(alarm.id, 100, db, user); assert len(events) == 1 and events[0].id == event.id

                acknowledged = await acknowledge_alarm_api(
                    alarm.id, AlarmAcknowledgeRequest(note="API acknowledgement"), db, user
                )
                assert acknowledged.acknowledged_by_user_id == user.id
                assigned = await update_alarm_owner(
                    alarm.id, AlarmOwnerUpdate(owner_user_id=user.id, note="Take ownership"), db, user
                )
                assert assigned.owner_user_id == user.id
                history = await get_alarm_history(alarm.id, 100, db, user)
                assert {row.action for row in history} >= {"ACKNOWLEDGED", "ASSIGNED"}
                cleared = await clear_alarm_api(
                    alarm.id, AlarmClearRequest(note="Resolved operationally"), db, user
                )
                assert cleared.state == "CLEARED"
                cleared_page = await list_alarms_page(state="CLEARED", severity=None, acknowledged=None, owner=None, search=device.display_name, page=1, page_size=50, db=db, actor=user)
                assert cleared_page.total == 1 and cleared_page.items[0].id == alarm.id

                await enable_audit_maintenance(db)
                await db.execute(delete(AuditLog).where(AuditLog.entity_id == alarm.id))
                await db.execute(delete(UserResourceScope).where(UserResourceScope.user_id == user.id))
                await db.execute(delete(AlarmHistory).where(AlarmHistory.alarm_id == alarm.id))
                await db.execute(delete(Alarm).where(Alarm.id == alarm.id)); await db.execute(delete(OperationalEvent).where(OperationalEvent.device_id == device.id)); await db.execute(delete(DeviceAvailability).where(DeviceAvailability.device_id == device.id)); await db.execute(delete(Device).where(Device.id == device.id)); await db.execute(delete(User).where(User.id == user.id)); await db.commit()
        finally: await engine.dispose()
    asyncio.run(scenario())
