from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...core.exceptions import APIError
from ...models import Alarm, Device, NotificationDelivery, NotificationPolicy, NotificationPolicyStep
from ...notifications import validate_destination
from ...schemas.notification import (
    NotificationDeliveryRead,
    NotificationPolicyCreate,
    NotificationPolicyRead,
    NotificationPolicyStepRead,
    NotificationPolicyUpdate,
)
from ...schemas.pagination import PageResult
from ...security.authorization import authorize_request
from ...security.resource_scope import require_global_scope, scope_for_actor
from ...security.scope_queries import device_scope_clause
from ...services.audit import record_audit


router = APIRouter(
    prefix="/notifications",
    tags=["Notifications"],
    dependencies=[Depends(authorize_request)],
)


async def _policy_read(db: AsyncSession, policy: NotificationPolicy) -> NotificationPolicyRead:
    steps = list((await db.scalars(
        select(NotificationPolicyStep)
        .where(NotificationPolicyStep.policy_id == policy.id)
        .order_by(NotificationPolicyStep.step_order, NotificationPolicyStep.id)
    )).all())
    return NotificationPolicyRead(
        id=policy.id,
        name=policy.name,
        description=policy.description,
        enabled=policy.enabled,
        alarm_type=policy.alarm_type,
        minimum_severity=policy.minimum_severity,
        steps=[NotificationPolicyStepRead.model_validate(step) for step in steps],
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


def _validate_steps(steps) -> None:
    previous_delay = -1
    for step in sorted(steps, key=lambda item: item.step_order):
        try:
            validate_destination(step.channel_type, step.destination)
        except ValueError as exc:
            code = str(exc)
            message = "Webhook destinations must be env://VARIABLE references so credentials never enter PostgreSQL." if code == "WEBHOOK_DESTINATION_MUST_BE_ENV_REFERENCE" else "Notification destination is invalid."
            raise APIError(422, code, message) from exc
        if step.delay_seconds < previous_delay:
            raise APIError(422, "INVALID_ESCALATION_ORDER", "Escalation delay_seconds must not decrease as step_order increases.")
        previous_delay = step.delay_seconds


async def _replace_steps(db: AsyncSession, policy: NotificationPolicy, steps) -> None:
    existing_delivery = await db.scalar(select(NotificationDelivery.id).where(NotificationDelivery.policy_id == policy.id).limit(1))
    if existing_delivery is not None:
        raise APIError(409, "NOTIFICATION_POLICY_IN_USE", "Policy escalation steps cannot be replaced after delivery history exists. Disable it and create a new policy instead.")
    rows = list((await db.scalars(select(NotificationPolicyStep).where(NotificationPolicyStep.policy_id == policy.id))).all())
    for row in rows:
        await db.delete(row)
    await db.flush()
    for step in sorted(steps, key=lambda item: item.step_order):
        db.add(NotificationPolicyStep(policy_id=policy.id, **step.model_dump()))


@router.get("/policies", response_model=list[NotificationPolicyRead])
async def list_notification_policies(
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await require_global_scope(db, actor, message="Global resource scope is required to view notification policies.")
    rows = list((await db.scalars(select(NotificationPolicy).order_by(NotificationPolicy.name, NotificationPolicy.id))).all())
    return [await _policy_read(db, row) for row in rows]


@router.post("/policies", response_model=NotificationPolicyRead)
async def create_notification_policy(
    payload: NotificationPolicyCreate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await require_global_scope(db, actor, message="Global resource scope is required to manage notification policies.")
    _validate_steps(payload.steps)
    policy = NotificationPolicy(
        name=payload.name.strip(),
        description=payload.description.strip() if payload.description and payload.description.strip() else None,
        enabled=payload.enabled,
        alarm_type=payload.alarm_type.strip() if payload.alarm_type and payload.alarm_type.strip() else None,
        minimum_severity=payload.minimum_severity,
    )
    db.add(policy)
    try:
        await db.flush()
        for step in sorted(payload.steps, key=lambda item: item.step_order):
            db.add(NotificationPolicyStep(policy_id=policy.id, **step.model_dump()))
        await record_audit(
            db,
            action="NOTIFICATION_POLICY_CREATED",
            entity_type="NotificationPolicy",
            entity_id=policy.id,
            entity_display_snapshot={"name": policy.name},
            description="Notification escalation policy created.",
            after_summary={"enabled": policy.enabled, "minimum_severity": policy.minimum_severity, "steps": len(payload.steps)},
        )
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise APIError(409, "NOTIFICATION_POLICY_EXISTS", "A notification policy with this name already exists.") from exc
    await db.refresh(policy)
    return await _policy_read(db, policy)


@router.patch("/policies/{policy_id}", response_model=NotificationPolicyRead)
async def update_notification_policy(
    policy_id: UUID,
    payload: NotificationPolicyUpdate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    await require_global_scope(db, actor, message="Global resource scope is required to manage notification policies.")
    policy = await db.scalar(select(NotificationPolicy).where(NotificationPolicy.id == policy_id).with_for_update().execution_options(populate_existing=True))
    if policy is None:
        raise APIError(404, "RESOURCE_NOT_FOUND", "Notification policy not found.")
    before = {"name": policy.name, "enabled": policy.enabled, "alarm_type": policy.alarm_type, "minimum_severity": policy.minimum_severity}
    if payload.name is not None:
        policy.name = payload.name.strip()
    if payload.description is not None:
        policy.description = payload.description.strip() or None
    if payload.enabled is not None:
        policy.enabled = payload.enabled
    if "alarm_type" in payload.model_fields_set:
        policy.alarm_type = payload.alarm_type.strip() if payload.alarm_type and payload.alarm_type.strip() else None
    if payload.minimum_severity is not None:
        policy.minimum_severity = payload.minimum_severity
    if payload.steps is not None:
        _validate_steps(payload.steps)
        await _replace_steps(db, policy, payload.steps)
    try:
        await record_audit(
            db,
            action="NOTIFICATION_POLICY_UPDATED",
            entity_type="NotificationPolicy",
            entity_id=policy.id,
            entity_display_snapshot={"name": policy.name},
            description="Notification escalation policy updated.",
            before_summary=before,
            after_summary={"name": policy.name, "enabled": policy.enabled, "alarm_type": policy.alarm_type, "minimum_severity": policy.minimum_severity},
        )
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise APIError(409, "NOTIFICATION_POLICY_EXISTS", "A notification policy with this name already exists.") from exc
    await db.refresh(policy)
    return await _policy_read(db, policy)


@router.get("/deliveries", response_model=PageResult[NotificationDeliveryRead])
async def list_notification_deliveries(
    status: str | None = Query(default=None, max_length=20),
    channel_type: str | None = Query(default=None, max_length=20),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=250),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    scope_clause = await device_scope_clause(db, scope, device_col=Device.id)
    filters = [Device.deleted_at.is_(None), scope_clause]
    if status:
        normalized = status.strip().upper()
        if normalized not in {"PENDING", "SUPPRESSED", "CLAIMED", "SENT", "FAILED", "CANCELLED"}:
            raise APIError(422, "INVALID_NOTIFICATION_STATUS", "Invalid notification delivery status.")
        filters.append(NotificationDelivery.status == normalized)
    if channel_type:
        normalized_channel = channel_type.strip().upper()
        if normalized_channel not in {"EMAIL", "WEBHOOK"}:
            raise APIError(422, "INVALID_NOTIFICATION_CHANNEL", "channel_type must be EMAIL or WEBHOOK.")
        filters.append(NotificationDelivery.channel_type == normalized_channel)

    base = select(NotificationDelivery).join(Alarm, Alarm.id == NotificationDelivery.alarm_id).join(Device, Device.id == Alarm.device_id)
    total = int((await db.scalar(select(func.count(NotificationDelivery.id)).join(Alarm, Alarm.id == NotificationDelivery.alarm_id).join(Device, Device.id == Alarm.device_id).where(*filters))) or 0)
    rows = list((await db.scalars(
        base.where(*filters)
        .order_by(NotificationDelivery.created_at.desc(), NotificationDelivery.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )).all())
    return PageResult(
        items=[NotificationDeliveryRead(
            id=row.id, alarm_id=row.alarm_id, event_id=row.event_id, policy_id=row.policy_id,
            policy_step_id=row.policy_step_id, occurrence_number=row.occurrence_number,
            channel_type=row.channel_type, destination=row.destination, status=row.status,
            scheduled_at=row.scheduled_at, next_attempt_at=row.next_attempt_at,
            attempt_count=row.attempt_count, last_attempt_at=row.last_attempt_at,
            delivered_at=row.delivered_at, last_error_code=row.last_error_code,
            response_status=row.response_status, maintenance_window_id=row.maintenance_window_id,
            metadata=row.metadata_, created_at=row.created_at, updated_at=row.updated_at,
        ) for row in rows],
        total=total, page=page, page_size=page_size,
    )
