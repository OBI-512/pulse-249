from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alarm, AlarmHistory, Device, OperationalEvent, User
from app.services.audit import record_audit


AVAILABILITY_ALARM_TYPE = "DEVICE_AVAILABILITY_OFFLINE"
AVAILABILITY_OFFLINE_EVENT = "DEVICE_AVAILABILITY_OFFLINE"
AVAILABILITY_RESTORED_EVENT = "DEVICE_AVAILABILITY_RESTORED"
AVAILABILITY_ALARM_SEVERITY = "MAJOR"


def availability_correlation_key(device_id: UUID) -> str:
    return f"device:{device_id}:availability:offline"


def _alarm_snapshot(alarm: Alarm) -> dict:
    return {
        "state": alarm.state,
        "severity": alarm.severity,
        "acknowledged_at": alarm.acknowledged_at.isoformat() if alarm.acknowledged_at else None,
        "acknowledged_by_user_id": str(alarm.acknowledged_by_user_id) if alarm.acknowledged_by_user_id else None,
        "owner_user_id": str(alarm.owner_user_id) if alarm.owner_user_id else None,
        "occurrence_count": alarm.occurrence_count,
    }


async def _history(
    db: AsyncSession,
    *,
    alarm: Alarm,
    action: str,
    occurred_at: datetime,
    event_id: UUID | None = None,
    actor_user_id: UUID | None = None,
    note: str | None = None,
    before: dict | None = None,
    after: dict | None = None,
    metadata: dict | None = None,
) -> AlarmHistory:
    row = AlarmHistory(
        alarm_id=alarm.id,
        event_id=event_id,
        occurred_at=occurred_at,
        action=action,
        actor_user_id=actor_user_id,
        note=(note.strip() if note and note.strip() else None),
        before_summary=before,
        after_summary=after,
        metadata_=metadata or {},
    )
    db.add(row)
    return row


async def _event(
    db: AsyncSession,
    *,
    device: Device,
    event_type: str,
    severity: str,
    occurred_at: datetime,
    correlation_key: str,
    summary: str,
    metadata: dict | None = None,
) -> OperationalEvent:
    row = OperationalEvent(
        device_id=device.id,
        event_type=event_type,
        severity=severity,
        occurred_at=occurred_at,
        correlation_key=correlation_key,
        summary=summary,
        metadata_=metadata or {},
    )
    db.add(row)
    await db.flush()
    return row


async def _locked_alarm(db: AsyncSession, correlation_key: str) -> Alarm | None:
    return await db.scalar(
        select(Alarm)
        .where(Alarm.correlation_key == correlation_key)
        .with_for_update()
        .execution_options(populate_existing=True)
    )


async def process_availability_observation(
    db: AsyncSession,
    *,
    device: Device,
    previous_status: str,
    current_status: str,
    checked_at: datetime,
    result_code: str | None,
) -> None:
    """Correlate C1 availability observations into C2 events and alarms.

    Repeated OFFLINE polls leave one active alarm untouched. A manually-cleared
    alarm whose underlying condition still exists reopens on the next poll,
    ensuring manual workflow cannot hide a persistent outage.
    """

    correlation_key = availability_correlation_key(device.id)

    if current_status == "OFFLINE":
        alarm = await _locked_alarm(db, correlation_key)
        if alarm is not None and alarm.state == "ACTIVE":
            return

        event = await _event(
            db,
            device=device,
            event_type=AVAILABILITY_OFFLINE_EVENT,
            severity=AVAILABILITY_ALARM_SEVERITY,
            occurred_at=checked_at,
            correlation_key=correlation_key,
            summary=f"{device.display_name} is offline.",
            metadata={
                "previous_status": previous_status,
                "current_status": current_status,
                "result_code": result_code,
                "source": "AVAILABILITY_ENGINE",
            },
        )

        if alarm is None:
            alarm = Alarm(
                device_id=device.id,
                alarm_type=AVAILABILITY_ALARM_TYPE,
                correlation_key=correlation_key,
                severity=AVAILABILITY_ALARM_SEVERITY,
                state="ACTIVE",
                summary=f"{device.display_name} is offline.",
                first_raised_at=checked_at,
                last_raised_at=checked_at,
                occurrence_count=1,
                last_event_id=event.id,
            )
            db.add(alarm)
            await db.flush()
            await _history(
                db,
                alarm=alarm,
                action="OPENED",
                occurred_at=checked_at,
                event_id=event.id,
                after=_alarm_snapshot(alarm),
                metadata={"source": "AVAILABILITY_ENGINE"},
            )
            audit_action = "ALARM_OPENED"
            description = "Availability alarm opened."
        else:
            before = _alarm_snapshot(alarm)
            alarm.state = "ACTIVE"
            alarm.last_raised_at = checked_at
            alarm.last_cleared_at = None
            alarm.acknowledged_at = None
            alarm.acknowledged_by_user_id = None
            alarm.occurrence_count += 1
            alarm.last_event_id = event.id
            alarm.summary = f"{device.display_name} is offline."
            after = _alarm_snapshot(alarm)
            await _history(
                db,
                alarm=alarm,
                action="REOPENED",
                occurred_at=checked_at,
                event_id=event.id,
                before=before,
                after=after,
                metadata={"source": "AVAILABILITY_ENGINE", "condition_still_present": previous_status == "OFFLINE"},
            )
            audit_action = "ALARM_REOPENED"
            description = "Availability alarm reopened because the offline condition is present."

        await record_audit(
            db,
            action=audit_action,
            entity_type="Alarm",
            entity_id=alarm.id,
            entity_display_snapshot={"device": device.display_name, "alarm_type": alarm.alarm_type},
            description=description,
            after_summary=_alarm_snapshot(alarm),
            metadata={"device_id": str(device.id), "correlation_key": correlation_key, "source": "AVAILABILITY_ENGINE"},
        )
        # C3 notification work is created only after the authoritative C2 alarm
        # exists. Scheduled maintenance suppresses delivery, never measurement
        # or alarm/event creation.
        from app.services.notifications import enqueue_alarm_notifications
        await enqueue_alarm_notifications(db, alarm=alarm, event=event, occurred_at=checked_at)
        return

    if previous_status == "OFFLINE" and current_status == "ONLINE":
        event = await _event(
            db,
            device=device,
            event_type=AVAILABILITY_RESTORED_EVENT,
            severity="INFO",
            occurred_at=checked_at,
            correlation_key=correlation_key,
            summary=f"{device.display_name} connectivity was restored.",
            metadata={
                "previous_status": previous_status,
                "current_status": current_status,
                "result_code": result_code,
                "source": "AVAILABILITY_ENGINE",
            },
        )
        alarm = await _locked_alarm(db, correlation_key)
        if alarm is None or alarm.state != "ACTIVE":
            return
        before = _alarm_snapshot(alarm)
        alarm.state = "CLEARED"
        alarm.last_cleared_at = checked_at
        alarm.last_event_id = event.id
        after = _alarm_snapshot(alarm)
        await _history(
            db,
            alarm=alarm,
            action="AUTO_CLEARED",
            occurred_at=checked_at,
            event_id=event.id,
            before=before,
            after=after,
            metadata={"source": "AVAILABILITY_ENGINE", "reason": "CONNECTIVITY_RESTORED"},
        )
        await record_audit(
            db,
            action="ALARM_AUTO_CLEARED",
            entity_type="Alarm",
            entity_id=alarm.id,
            entity_display_snapshot={"device": device.display_name, "alarm_type": alarm.alarm_type},
            description="Availability alarm automatically cleared after connectivity recovery.",
            before_summary=before,
            after_summary=after,
            metadata={"device_id": str(device.id), "correlation_key": correlation_key, "source": "AVAILABILITY_ENGINE"},
        )
        from app.services.notifications import cancel_pending_alarm_deliveries
        await cancel_pending_alarm_deliveries(db, alarm.id)


async def acknowledge_alarm(
    db: AsyncSession,
    *,
    alarm: Alarm,
    actor_user_id: UUID | None,
    note: str | None,
    now: datetime | None = None,
) -> bool:
    if alarm.state != "ACTIVE":
        raise ValueError("CLEARED_ALARM_CANNOT_BE_ACKNOWLEDGED")
    if alarm.acknowledged_at is not None:
        return False
    occurred_at = now or datetime.now(timezone.utc)
    before = _alarm_snapshot(alarm)
    alarm.acknowledged_at = occurred_at
    alarm.acknowledged_by_user_id = actor_user_id
    after = _alarm_snapshot(alarm)
    await _history(
        db,
        alarm=alarm,
        action="ACKNOWLEDGED",
        occurred_at=occurred_at,
        actor_user_id=actor_user_id,
        note=note,
        before=before,
        after=after,
    )
    await record_audit(
        db,
        action="ALARM_ACKNOWLEDGED",
        entity_type="Alarm",
        entity_id=alarm.id,
        description="Alarm acknowledged.",
        before_summary=before,
        after_summary=after,
        metadata={"device_id": str(alarm.device_id)},
    )
    return True


async def assign_alarm(
    db: AsyncSession,
    *,
    alarm: Alarm,
    owner_user_id: UUID | None,
    actor_user_id: UUID | None,
    note: str | None,
    now: datetime | None = None,
) -> bool:
    if alarm.state != "ACTIVE":
        raise ValueError("CLEARED_ALARM_CANNOT_BE_ASSIGNED")
    if owner_user_id is not None:
        owner = await db.get(User, owner_user_id)
        if owner is None or not owner.is_active:
            raise ValueError("ALARM_OWNER_NOT_ACTIVE")
    if alarm.owner_user_id == owner_user_id:
        return False
    occurred_at = now or datetime.now(timezone.utc)
    before = _alarm_snapshot(alarm)
    alarm.owner_user_id = owner_user_id
    after = _alarm_snapshot(alarm)
    action = "ASSIGNED" if owner_user_id is not None else "UNASSIGNED"
    await _history(
        db,
        alarm=alarm,
        action=action,
        occurred_at=occurred_at,
        actor_user_id=actor_user_id,
        note=note,
        before=before,
        after=after,
    )
    await record_audit(
        db,
        action=f"ALARM_{action}",
        entity_type="Alarm",
        entity_id=alarm.id,
        description="Alarm ownership changed.",
        before_summary=before,
        after_summary=after,
        metadata={"device_id": str(alarm.device_id)},
    )
    return True


async def clear_alarm(
    db: AsyncSession,
    *,
    alarm: Alarm,
    actor_user_id: UUID | None,
    note: str | None,
    now: datetime | None = None,
) -> bool:
    if alarm.state == "CLEARED":
        return False
    occurred_at = now or datetime.now(timezone.utc)
    before = _alarm_snapshot(alarm)
    alarm.state = "CLEARED"
    alarm.last_cleared_at = occurred_at
    after = _alarm_snapshot(alarm)
    await _history(
        db,
        alarm=alarm,
        action="MANUALLY_CLEARED",
        occurred_at=occurred_at,
        actor_user_id=actor_user_id,
        note=note,
        before=before,
        after=after,
        metadata={"condition_may_still_be_present": True},
    )
    await record_audit(
        db,
        action="ALARM_MANUALLY_CLEARED",
        entity_type="Alarm",
        entity_id=alarm.id,
        description="Alarm manually cleared. Persistent conditions will reopen on a later observation.",
        before_summary=before,
        after_summary=after,
        metadata={"device_id": str(alarm.device_id)},
    )
    from app.services.notifications import cancel_pending_alarm_deliveries
    await cancel_pending_alarm_deliveries(db, alarm.id)
    return True
