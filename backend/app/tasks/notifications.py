from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.celery_app.config import celery_app
from app.models import Alarm, NotificationDelivery, NotificationPolicy, NotificationPolicyStep
from app.notifications import DeliveryResult, deliver_notification
from app.services.maintenance import maintenance_mode_active
from app.services.maintenance_windows import active_maintenance_for_device
from app.services.notifications import (
    ClaimedDelivery,
    claim_due_deliveries,
    load_notification_settings,
    release_unpublished_deliveries,
    retry_delay_seconds,
)
from app.settings import settings as app_settings


logger = logging.getLogger(__name__)


def _session_factory():
    engine = create_async_engine(app_settings.database_url, pool_pre_ping=True)
    return engine, async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


def _chunks(values: list[ClaimedDelivery], size: int):
    step = max(1, size)
    for index in range(0, len(values), step):
        yield values[index:index + step]


async def _dispatch_due() -> dict[str, int | str]:
    if await maintenance_mode_active():
        return {"claimed": 0, "published": 0, "outstanding": 0, "reason": "SYSTEM_MAINTENANCE_MODE"}
    engine, SessionLocal = _session_factory()
    try:
        async with SessionLocal() as db:
            runtime = await load_notification_settings(db)
            claims, outstanding = await claim_due_deliveries(db, runtime)
            await db.commit()
        if not claims:
            return {"claimed": 0, "published": 0, "outstanding": outstanding, "reason": "DISABLED" if not runtime.enabled else "NO_DUE"}

        published = 0
        for chunk in _chunks(claims, runtime.task_batch_size):
            payload = [{"delivery_id": str(item.delivery_id), "lease_token": str(item.lease_token)} for item in chunk]
            try:
                celery_app.send_task(
                    "fttw.notifications.deliver_batch",
                    args=[payload],
                    expires=max(30, runtime.lease_seconds - 5),
                )
                published += len(chunk)
            except Exception:
                logger.exception("notification_publish_failed", extra={"event": "NOTIFICATION_PUBLISH_FAILED", "delivery_count": len(chunk)})
                async with SessionLocal() as db:
                    released = await release_unpublished_deliveries(db, chunk)
                    await db.commit()
                logger.warning("notification_claims_released", extra={"event": "NOTIFICATION_CLAIMS_RELEASED", "delivery_count": released})
        logger.info("notification_dispatch_completed", extra={"event": "NOTIFICATION_DISPATCH_COMPLETED", "claimed": len(claims), "published": published, "outstanding": outstanding})
        return {"claimed": len(claims), "published": published, "outstanding": outstanding}
    finally:
        await engine.dispose()


@dataclass(frozen=True)
class _PreparedDelivery:
    delivery_id: UUID
    lease_token: UUID
    channel_type: str
    destination: str
    payload: dict
    idempotency_key: str


async def _prepare_delivery(SessionLocal, delivery_id: UUID, lease_token: UUID) -> tuple[str, _PreparedDelivery | None]:
    async with SessionLocal() as db:
        row = (await db.execute(
            select(NotificationDelivery, Alarm, NotificationPolicy)
            .join(Alarm, Alarm.id == NotificationDelivery.alarm_id)
            .join(NotificationPolicy, NotificationPolicy.id == NotificationDelivery.policy_id)
            .where(NotificationDelivery.id == delivery_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )).first()
        if row is None:
            return "STALE", None
        delivery, alarm, policy = row
        if delivery.status != "CLAIMED" or delivery.claim_token != lease_token:
            return "STALE", None
        if alarm.state != "ACTIVE" or not policy.enabled:
            delivery.status = "CANCELLED"
            delivery.claim_token = None
            delivery.claim_expires_at = None
            await db.commit()
            return "CANCELLED", None

        runtime = await load_notification_settings(db)
        if not runtime.enabled:
            delivery.status = "PENDING"
            delivery.claim_token = None
            delivery.claim_expires_at = None
            delivery.next_attempt_at = datetime.now(timezone.utc) + timedelta(seconds=60)
            await db.commit()
            return "DISABLED", None

        now = datetime.now(timezone.utc)
        maintenance = await active_maintenance_for_device(db, alarm.device_id, at=now)
        if maintenance is not None:
            delivery.status = "SUPPRESSED"
            delivery.maintenance_window_id = maintenance.primary.id
            delivery.next_attempt_at = max(now + timedelta(seconds=1), maintenance.suppressed_until)
            delivery.claim_token = None
            delivery.claim_expires_at = None
            metadata = dict(delivery.metadata_ or {})
            metadata["maintenance_window_ids"] = [str(item.id) for item in maintenance.windows]
            metadata["maintenance_suppressed_until"] = maintenance.suppressed_until.isoformat()
            delivery.metadata_ = metadata
            await db.commit()
            return "SUPPRESSED", None

        delivery.maintenance_window_id = None
        prepared = _PreparedDelivery(
            delivery_id=delivery.id,
            lease_token=lease_token,
            channel_type=delivery.channel_type,
            destination=delivery.destination,
            payload=dict(delivery.metadata_ or {}),
            idempotency_key=delivery.idempotency_key,
        )
        await db.commit()
        return "READY", prepared


async def _finish_delivery(SessionLocal, prepared: _PreparedDelivery, result: DeliveryResult) -> str:
    async with SessionLocal() as db:
        row = (await db.execute(
            select(NotificationDelivery, NotificationPolicyStep)
            .join(NotificationPolicyStep, NotificationPolicyStep.id == NotificationDelivery.policy_step_id)
            .where(NotificationDelivery.id == prepared.delivery_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )).first()
        if row is None:
            return "STALE"
        delivery, step = row
        if delivery.status != "CLAIMED" or delivery.claim_token != prepared.lease_token:
            return "STALE"
        now = datetime.now(timezone.utc)
        delivery.attempt_count += 1
        delivery.last_attempt_at = now
        delivery.response_status = result.response_status
        delivery.claim_token = None
        delivery.claim_expires_at = None
        if result.success:
            delivery.status = "SENT"
            delivery.delivered_at = now
            delivery.last_error_code = None
            await db.commit()
            return "SENT"

        delivery.last_error_code = (result.error_code or "DELIVERY_FAILED")[:120]
        if delivery.attempt_count >= step.max_attempts:
            delivery.status = "FAILED"
            await db.commit()
            return "FAILED"
        delivery.status = "PENDING"
        delivery.next_attempt_at = now + timedelta(seconds=retry_delay_seconds(step, delivery.attempt_count))
        await db.commit()
        return "RETRY"


async def _deliver_batch(payload: list[dict]) -> dict[str, int]:
    parsed: list[tuple[UUID, UUID]] = []
    for item in payload[:250]:
        try:
            parsed.append((UUID(str(item["delivery_id"])), UUID(str(item["lease_token"]))))
        except (KeyError, TypeError, ValueError):
            continue
    engine, SessionLocal = _session_factory()
    try:
        async with SessionLocal() as db:
            runtime = await load_notification_settings(db)
        semaphore = asyncio.Semaphore(runtime.worker_concurrency)

        async def process(delivery_id: UUID, lease_token: UUID) -> str:
            async with semaphore:
                status, prepared = await _prepare_delivery(SessionLocal, delivery_id, lease_token)
                if prepared is None:
                    return status
                result = await deliver_notification(
                    channel_type=prepared.channel_type,
                    destination=prepared.destination,
                    payload=prepared.payload,
                    idempotency_key=prepared.idempotency_key,
                )
                return await _finish_delivery(SessionLocal, prepared, result)

        results = await asyncio.gather(*(process(delivery_id, token) for delivery_id, token in parsed))
        counts = {key: results.count(key) for key in {"SENT", "FAILED", "RETRY", "SUPPRESSED", "CANCELLED", "STALE", "DISABLED"}}
        counts["received"] = len(payload)
        counts["parsed"] = len(parsed)
        logger.info("notification_delivery_batch_completed", extra={"event": "NOTIFICATION_DELIVERY_BATCH_COMPLETED", **counts})
        return counts
    finally:
        await engine.dispose()


@celery_app.task(name="fttw.notifications.dispatch_due", time_limit=20, soft_time_limit=15)
def dispatch_due_notifications():
    return asyncio.run(_dispatch_due())


@celery_app.task(name="fttw.notifications.deliver_batch", time_limit=180, soft_time_limit=160)
def deliver_notification_batch(payload: list[dict]):
    return asyncio.run(_deliver_batch(payload))
