from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Alarm,
    AlarmHistory,
    NotificationDelivery,
    NotificationPolicy,
    NotificationPolicyStep,
    OperationalEvent,
)
from app.services.audit import record_audit
from app.services.maintenance_windows import active_maintenance_for_device
from app.services.settings_registry import get_typed_setting


_SEVERITY_RANK = {"INFO": 0, "WARNING": 1, "MINOR": 2, "MAJOR": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class NotificationRuntimeSettings:
    enabled: bool
    dispatch_limit_per_tick: int
    task_batch_size: int
    max_outstanding: int
    lease_seconds: int
    worker_concurrency: int


@dataclass(frozen=True)
class ClaimedDelivery:
    delivery_id: UUID
    lease_token: UUID


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def load_notification_settings(db: AsyncSession) -> NotificationRuntimeSettings:
    async def val(key: str):
        return (await get_typed_setting(db, key))["value"]

    return NotificationRuntimeSettings(
        enabled=bool(await val("notifications.enabled")),
        dispatch_limit_per_tick=int(await val("notifications.dispatch_limit_per_tick")),
        task_batch_size=int(await val("notifications.task_batch_size")),
        max_outstanding=int(await val("notifications.max_outstanding")),
        lease_seconds=int(await val("notifications.lease_seconds")),
        worker_concurrency=int(await val("notifications.worker_concurrency")),
    )


def _severity_allows(alarm_severity: str, minimum: str) -> bool:
    return _SEVERITY_RANK.get(alarm_severity.upper(), -1) >= _SEVERITY_RANK.get(minimum.upper(), 99)


async def _matching_policy_steps(db: AsyncSession, alarm: Alarm) -> list[tuple[NotificationPolicy, NotificationPolicyStep]]:
    rows = (await db.execute(
        select(NotificationPolicy, NotificationPolicyStep)
        .join(NotificationPolicyStep, NotificationPolicyStep.policy_id == NotificationPolicy.id)
        .where(NotificationPolicy.enabled.is_(True))
        .order_by(NotificationPolicy.name, NotificationPolicyStep.step_order)
    )).all()
    return [
        (policy, step)
        for policy, step in rows
        if (policy.alarm_type is None or policy.alarm_type == alarm.alarm_type)
        and _severity_allows(alarm.severity, policy.minimum_severity)
    ]


async def enqueue_alarm_notifications(
    db: AsyncSession,
    *,
    alarm: Alarm,
    event: OperationalEvent,
    occurred_at: datetime,
) -> int:
    """Create idempotent escalation deliveries for one alarm occurrence.

    Maintenance never prevents the alarm/event itself. It only marks due
    notification work SUPPRESSED until the relevant maintenance windows end.
    """

    if alarm.state != "ACTIVE":
        return 0
    steps = await _matching_policy_steps(db, alarm)
    if not steps:
        return 0

    maintenance = await active_maintenance_for_device(db, alarm.device_id, at=occurred_at)
    created = 0
    suppressed_created = False
    for policy, step in steps:
        key = f"alarm:{alarm.id}:occurrence:{alarm.occurrence_count}:step:{step.id}"
        if await db.scalar(select(NotificationDelivery.id).where(NotificationDelivery.idempotency_key == key)):
            continue
        scheduled_at = occurred_at + timedelta(seconds=step.delay_seconds)
        suppressed = maintenance is not None and scheduled_at < maintenance.suppressed_until
        next_attempt_at = max(scheduled_at, maintenance.suppressed_until) if suppressed and maintenance else scheduled_at
        payload = {
            "alarm_id": str(alarm.id),
            "device_id": str(alarm.device_id),
            "event_id": str(event.id),
            "alarm_type": alarm.alarm_type,
            "severity": alarm.severity,
            "summary": alarm.summary,
            "correlation_key": alarm.correlation_key,
            "occurrence_number": alarm.occurrence_count,
            "raised_at": occurred_at.isoformat(),
            "policy": policy.name,
            "step_order": step.step_order,
        }
        if maintenance:
            payload["maintenance_window_ids"] = [str(row.id) for row in maintenance.windows]
            payload["maintenance_suppressed_until"] = maintenance.suppressed_until.isoformat()
        row = NotificationDelivery(
            alarm_id=alarm.id,
            event_id=event.id,
            policy_id=policy.id,
            policy_step_id=step.id,
            occurrence_number=alarm.occurrence_count,
            channel_type=step.channel_type,
            destination=step.destination,
            status="SUPPRESSED" if suppressed else "PENDING",
            scheduled_at=scheduled_at,
            next_attempt_at=next_attempt_at,
            idempotency_key=key,
            maintenance_window_id=maintenance.primary.id if suppressed and maintenance else None,
            metadata_=payload,
        )
        db.add(row)
        created += 1
        suppressed_created = suppressed_created or suppressed

    if suppressed_created and maintenance:
        db.add(AlarmHistory(
            alarm_id=alarm.id,
            event_id=event.id,
            occurred_at=occurred_at,
            action="NOTIFICATION_SUPPRESSED",
            note="Alarm notifications delayed by scheduled maintenance.",
            after_summary={"notification_suppressed": True, "until": maintenance.suppressed_until.isoformat()},
            metadata_={
                "maintenance_window_ids": [str(row.id) for row in maintenance.windows],
                "source": "MAINTENANCE_WINDOW",
                "occurrence_number": alarm.occurrence_count,
            },
        ))
        await record_audit(
            db,
            action="ALARM_NOTIFICATIONS_SUPPRESSED",
            entity_type="Alarm",
            entity_id=alarm.id,
            description="Alarm notification delivery delayed by scheduled maintenance.",
            metadata={
                "device_id": str(alarm.device_id),
                "maintenance_window_ids": [str(row.id) for row in maintenance.windows],
                "suppressed_until": maintenance.suppressed_until.isoformat(),
                "occurrence_number": alarm.occurrence_count,
            },
        )
    return created


async def cancel_pending_alarm_deliveries(db: AsyncSession, alarm_id: UUID) -> int:
    rows = list((await db.scalars(
        select(NotificationDelivery)
        .where(
            NotificationDelivery.alarm_id == alarm_id,
            NotificationDelivery.status.in_(("PENDING", "SUPPRESSED", "CLAIMED")),
        )
        .with_for_update(skip_locked=True)
    )).all())
    for row in rows:
        row.status = "CANCELLED"
        row.claim_token = None
        row.claim_expires_at = None
    return len(rows)


async def claim_due_deliveries(
    db: AsyncSession,
    settings: NotificationRuntimeSettings,
    *,
    now: datetime | None = None,
) -> tuple[list[ClaimedDelivery], int]:
    current = now or utcnow()
    dispatcher_lock = bool(await db.scalar(select(func.pg_try_advisory_xact_lock(0x46545458))))
    outstanding = int((await db.scalar(select(func.count(NotificationDelivery.id)).where(
        NotificationDelivery.status == "CLAIMED",
        NotificationDelivery.claim_expires_at.is_not(None),
        NotificationDelivery.claim_expires_at > current,
    ))) or 0)
    if not dispatcher_lock or not settings.enabled:
        return [], outstanding
    capacity = max(0, settings.max_outstanding - outstanding)
    limit = min(settings.dispatch_limit_per_tick, capacity)
    if limit <= 0:
        return [], outstanding

    rows = list((await db.scalars(
        select(NotificationDelivery)
        .join(Alarm, Alarm.id == NotificationDelivery.alarm_id)
        .join(NotificationPolicy, NotificationPolicy.id == NotificationDelivery.policy_id)
        .where(
            Alarm.state == "ACTIVE",
            NotificationPolicy.enabled.is_(True),
            NotificationDelivery.next_attempt_at <= current,
            or_(
                NotificationDelivery.status.in_(("PENDING", "SUPPRESSED")),
                (NotificationDelivery.status == "CLAIMED") & (NotificationDelivery.claim_expires_at <= current),
            ),
        )
        .order_by(NotificationDelivery.next_attempt_at, NotificationDelivery.id)
        .with_for_update(skip_locked=True)
        .limit(limit)
    )).all())
    claims: list[ClaimedDelivery] = []
    for row in rows:
        token = uuid4()
        row.status = "CLAIMED"
        row.claim_token = token
        row.claim_expires_at = current + timedelta(seconds=settings.lease_seconds)
        claims.append(ClaimedDelivery(row.id, token))
    return claims, outstanding


async def release_unpublished_deliveries(
    db: AsyncSession,
    claims: list[ClaimedDelivery],
    *,
    now: datetime | None = None,
) -> int:
    if not claims:
        return 0
    current = now or utcnow()
    expected = {item.delivery_id: item.lease_token for item in claims}
    rows = list((await db.scalars(
        select(NotificationDelivery)
        .where(NotificationDelivery.id.in_(list(expected)))
        .with_for_update()
    )).all())
    released = 0
    for row in rows:
        if row.claim_token != expected.get(row.id):
            continue
        row.status = "PENDING"
        row.claim_token = None
        row.claim_expires_at = None
        row.next_attempt_at = current + timedelta(seconds=5 + row.id.int % 11)
        released += 1
    return released


def retry_delay_seconds(step: NotificationPolicyStep, attempt_count: int) -> int:
    exponent = max(0, attempt_count - 1)
    return min(step.retry_max_seconds, step.retry_base_seconds * (2 ** exponent))
