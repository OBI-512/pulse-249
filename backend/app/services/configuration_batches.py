from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.celery_app.config import celery_app
from app.configuration.templating import (
    ConfigurationTemplateError,
    function_from_row,
    resolve_parameters,
)
from app.core.exceptions import APIError
from app.models import (
    ConfigurationBatch,
    ConfigurationBatchTarget,
    ConfigurationFunction,
    ConfigurationOperation,
    Device,
    DeviceConfigurationBinding,
    User,
)
from app.schemas.configuration import ConfigurationStepRequest
from app.security.authorization import user_has_permission
from app.security.permissions import Permission as PermissionCode
from app.security.resource_scope import scope_for_actor
from app.security.scope_queries import require_device
from app.services.audit import record_audit
from app.services.authorization_snapshot import scope_fingerprint, scope_snapshot
from app.services.configuration import mark_dispatch_failure, queue_operation
from app.services.maintenance_windows import active_maintenance_for_device
from app.settings import settings


UTC = timezone.utc
ACTIVE_OPERATION_STATUSES = frozenset({"QUEUED", "RUNNING", "ROLLING_BACK"})
TERMINAL_OPERATION_STATUSES = frozenset(
    {"SUCCEEDED", "FAILED", "ROLLED_BACK", "ROLLBACK_FAILED", "CANCELLED"}
)
TERMINAL_TARGET_STATUSES = frozenset({"SUCCEEDED", "FAILED", "SKIPPED", "ABORTED"})
TERMINAL_BATCH_STATUSES = frozenset(
    {"ABORTED", "SUCCEEDED", "PARTIAL", "FAILED", "CANCELLED"}
)


_OPERATION_PERMISSION = {
    "CAPTURE": PermissionCode.DEVICE_CONFIGURATION_CAPTURE,
    "VERIFY": PermissionCode.DEVICE_CONFIGURATION_CAPTURE,
    "APPLY": PermissionCode.DEVICE_CONFIGURATION_APPLY,
    "RESTORE": PermissionCode.DEVICE_CONFIGURATION_RESTORE,
}


def utcnow() -> datetime:
    return datetime.now(UTC)


def required_permission(operation_type: str) -> str:
    try:
        return _OPERATION_PERMISSION[operation_type]
    except KeyError as exc:
        raise APIError(
            422,
            "CONFIGURATION_BATCH_OPERATION_TYPE_INVALID",
            "Unsupported configuration batch operation type.",
        ) from exc


async def _require_operation_permission(
    db: AsyncSession,
    *,
    actor: User,
    operation_type: str,
) -> None:
    code = required_permission(operation_type)
    if not await user_has_permission(db, user_id=actor.id, permission_code=code):
        raise APIError(403, "PERMISSION_DENIED", f"Permission '{code}' is required.")


def _canonical(value):
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise APIError(
                422,
                "CONFIGURATION_BATCH_REQUEST_VALUE_INVALID",
                "Configuration batch values must be finite JSON values.",
            )
        return value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise APIError(
                422,
                "CONFIGURATION_BATCH_NOT_BEFORE_TIMEZONE_REQUIRED",
                "not_before must include a timezone.",
            )
        return value.astimezone(UTC).isoformat()
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _canonical(item) for key, item in value.items()}
    raise APIError(
        422,
        "CONFIGURATION_BATCH_REQUEST_VALUE_INVALID",
        "Configuration batch request contains an unsupported value type.",
    )


def ordered_device_ids(values: list[UUID]) -> list[UUID]:
    return sorted(set(values), key=lambda value: value.bytes)


def wave_numbers(
    *,
    total: int,
    rollout_mode: str,
    canary_percent: int | None = None,
    wave_size: int | None = None,
) -> list[int]:
    if total <= 0:
        return []
    if rollout_mode == "ALL_AT_ONCE":
        return [0] * total
    if rollout_mode == "CANARY_PERCENTAGE":
        if canary_percent is None or not 1 <= canary_percent <= 100:
            raise APIError(
                422,
                "CONFIGURATION_BATCH_CANARY_PERCENT_INVALID",
                "A canary percentage between 1 and 100 is required.",
            )
        canary_count = max(1, math.ceil(total * canary_percent / 100))
        return [0 if ordinal < canary_count else 1 for ordinal in range(total)]
    if rollout_mode == "WAVES":
        if wave_size is None or wave_size < 1:
            raise APIError(
                422,
                "CONFIGURATION_BATCH_WAVE_SIZE_INVALID",
                "A positive wave size is required.",
            )
        return [ordinal // wave_size for ordinal in range(total)]
    raise APIError(
        422,
        "CONFIGURATION_BATCH_ROLLOUT_MODE_INVALID",
        "Unsupported rollout mode.",
    )


def _operation_payload(payload) -> dict:
    return {
        "steps": [
            {
                "function_id": str(item.function_id),
                "parameters": _canonical(dict(item.parameters or {})),
            }
            for item in payload.steps
        ],
        "snapshot_ids": {
            str(device_id): str(snapshot_id)
            for device_id, snapshot_id in sorted(
                payload.snapshot_ids.items(), key=lambda item: item[0].bytes
            )
        },
    }


def _validated_apply_steps(
    function_rows: list[ConfigurationFunction],
    requested_steps: list[ConfigurationStepRequest],
) -> list[dict]:
    by_id = {row.id: row for row in function_rows if row.enabled}
    validated: list[dict] = []
    for requested in requested_steps:
        row = by_id.get(requested.function_id)
        if row is None:
            raise APIError(
                422,
                "CONFIGURATION_BATCH_FUNCTION_UNAVAILABLE",
                "A selected configuration function is unavailable for the common template version.",
            )
        if "APPLY" not in set(row.required_capabilities or []):
            raise APIError(
                422,
                "CONFIGURATION_BATCH_FUNCTION_NOT_APPLICABLE",
                "A selected configuration function is not declared as an APPLY function.",
            )
        try:
            definition = function_from_row(row)
            resolved, _ = resolve_parameters(
                definition.parameters,
                requested.parameters,
            )
        except (ConfigurationTemplateError, ValueError) as exc:
            code = str(exc).strip("'") or "CONFIGURATION_BATCH_PARAMETER_INVALID"
            raise APIError(
                422,
                code,
                f"Parameters for function '{row.code}' are invalid.",
            ) from exc
        validated.append(
            {
                "function_id": str(row.id),
                "parameters": _canonical(resolved),
            }
        )
    return validated


async def _validated_operation_payload(
    db: AsyncSession,
    *,
    payload,
    target_ids: list[UUID],
) -> dict:
    if payload.operation_type != "APPLY":
        return _operation_payload(payload)

    bindings = list(
        (
            await db.scalars(
                select(DeviceConfigurationBinding).where(
                    DeviceConfigurationBinding.device_id.in_(target_ids),
                    DeviceConfigurationBinding.enabled.is_(True),
                )
            )
        ).all()
    )
    binding_by_device = {row.device_id: row for row in bindings}
    if any(device_id not in binding_by_device for device_id in target_ids):
        raise APIError(
            422,
            "CONFIGURATION_BATCH_DEVICE_NOT_BOUND",
            "Every APPLY target must have an enabled configuration template binding.",
        )

    version_ids = {binding_by_device[device_id].template_version_id for device_id in target_ids}
    if len(version_ids) != 1:
        raise APIError(
            422,
            "CONFIGURATION_BATCH_TEMPLATE_VERSION_MISMATCH",
            "All APPLY targets must be bound to the same exact configuration template version.",
        )
    version_id = next(iter(version_ids))
    function_ids = {item.function_id for item in payload.steps}
    function_rows = list(
        (
            await db.scalars(
                select(ConfigurationFunction).where(
                    ConfigurationFunction.template_version_id == version_id,
                    ConfigurationFunction.id.in_(function_ids),
                    ConfigurationFunction.enabled.is_(True),
                )
            )
        ).all()
    )
    return {
        "steps": _validated_apply_steps(function_rows, payload.steps),
        "snapshot_ids": {},
    }


def _batch_request_fingerprint(
    payload,
    target_ids: list[UUID],
    operation_payload: dict,
) -> str:
    request = {
        "operation_type": payload.operation_type,
        "target_device_ids": [str(item) for item in target_ids],
        "operation_payload": operation_payload,
        "rollout_mode": payload.rollout_mode,
        "canary_percent": payload.canary_percent,
        "wave_size": payload.wave_size,
        "not_before": _canonical(payload.not_before),
        "maintenance_policy": payload.maintenance_policy,
    }
    encoded = json.dumps(
        request,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def batch_request_fingerprint(payload, target_ids: list[UUID]) -> str:
    return _batch_request_fingerprint(payload, target_ids, _operation_payload(payload))


def target_idempotency_key(
    *,
    batch_id: UUID,
    device_id: UUID,
    request_fingerprint: str,
) -> str:
    material = f"{batch_id}:{device_id}:{request_fingerprint}".encode("ascii")
    return "f3-" + hashlib.sha256(material).hexdigest()


def _rollout_parameters(payload) -> dict:
    return {
        "canary_percent": payload.canary_percent,
        "wave_size": payload.wave_size,
        "approved_failed_waves": [],
    }


def _failure_code(exc: APIError, fallback: str) -> str:
    detail = exc.detail if isinstance(exc.detail, dict) else {}
    code = detail.get("code") if isinstance(detail, dict) else None
    return str(code or fallback)[:120]


async def create_batch(
    db: AsyncSession,
    *,
    payload,
    actor: User,
) -> tuple[ConfigurationBatch, bool]:
    await _require_operation_permission(
        db, actor=actor, operation_type=payload.operation_type
    )
    scope = await scope_for_actor(db, actor)
    target_ids = ordered_device_ids(payload.device_ids)
    if not target_ids:
        raise APIError(
            422,
            "CONFIGURATION_BATCH_TARGETS_REQUIRED",
            "At least one target device is required.",
        )
    if len(target_ids) > settings.configuration_batch_max_targets:
        raise APIError(
            422,
            "CONFIGURATION_BATCH_TARGET_LIMIT_EXCEEDED",
            f"A configuration batch may contain at most {settings.configuration_batch_max_targets} devices.",
        )

    # Request-time WHERE authorization is fail closed. Persist the exact target
    # population only after every device is proven inside the actor's scope.
    for device_id in target_ids:
        await require_device(db, scope, device_id)

    # APPLY payloads are normalized against one exact common template version
    # before any durable batch row exists. Sensitive parameters therefore can
    # only persist as validated env:// references, never as resolved/raw values.
    operation_payload = await _validated_operation_payload(
        db,
        payload=payload,
        target_ids=target_ids,
    )
    fingerprint = _batch_request_fingerprint(payload, target_ids, operation_payload)
    if payload.idempotency_key:
        existing = await db.scalar(
            select(ConfigurationBatch).where(
                ConfigurationBatch.actor_user_id == actor.id,
                ConfigurationBatch.idempotency_key == payload.idempotency_key,
            )
        )
        if existing is not None:
            if existing.request_fingerprint == fingerprint:
                return existing, False
            raise APIError(
                409,
                "CONFIGURATION_BATCH_IDEMPOTENCY_KEY_REUSED",
                "The batch idempotency key was already used for a different request.",
            )

    now = utcnow()
    not_before = (
        payload.not_before.astimezone(UTC) if payload.not_before is not None else None
    )
    status = "SCHEDULED" if not_before is not None and not_before > now else "QUEUED"
    batch = ConfigurationBatch(
        actor_user_id=actor.id,
        operation_type=payload.operation_type,
        status=status,
        idempotency_key=payload.idempotency_key,
        request_fingerprint=fingerprint,
        authorization_scope=scope_snapshot(scope),
        authorization_scope_fingerprint=scope_fingerprint(scope),
        request_summary={
            "phase": "F3",
            "required_permission": required_permission(payload.operation_type),
            "operation_payload": operation_payload,
        },
        rollout_mode=payload.rollout_mode,
        rollout_parameters=_rollout_parameters(payload),
        not_before=not_before,
        maintenance_policy=payload.maintenance_policy,
        target_count=len(target_ids),
        queued_at=now,
    )
    db.add(batch)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        if payload.idempotency_key:
            existing = await db.scalar(
                select(ConfigurationBatch).where(
                    ConfigurationBatch.actor_user_id == actor.id,
                    ConfigurationBatch.idempotency_key == payload.idempotency_key,
                )
            )
            if existing is not None and existing.request_fingerprint == fingerprint:
                return existing, False
        raise APIError(
            409,
            "CONFIGURATION_BATCH_CONFLICT",
            "A conflicting configuration batch already exists.",
        ) from exc

    waves = wave_numbers(
        total=len(target_ids),
        rollout_mode=payload.rollout_mode,
        canary_percent=payload.canary_percent,
        wave_size=payload.wave_size,
    )
    for ordinal, device_id in enumerate(target_ids):
        db.add(
            ConfigurationBatchTarget(
                batch_id=batch.id,
                device_id=device_id,
                target_ordinal=ordinal,
                wave_number=waves[ordinal],
                status="WAITING",
            )
        )
    await db.flush()
    await record_audit(
        db,
        action="CONFIGURATION_BATCH_CREATED",
        entity_type="ConfigurationBatch",
        entity_id=batch.id,
        actor_user_id=actor.id,
        description="Configuration batch target set materialized.",
        metadata={
            "operation_type": batch.operation_type,
            "target_count": batch.target_count,
            "rollout_mode": batch.rollout_mode,
            "maintenance_policy": batch.maintenance_policy,
            "scheduled": batch.status == "SCHEDULED",
        },
    )
    return batch, True


async def _targets(
    db: AsyncSession,
    batch_id: UUID,
    *,
    for_update: bool = False,
) -> list[ConfigurationBatchTarget]:
    stmt = (
        select(ConfigurationBatchTarget)
        .where(ConfigurationBatchTarget.batch_id == batch_id)
        .order_by(ConfigurationBatchTarget.target_ordinal)
    )
    if for_update:
        stmt = stmt.with_for_update()
    return list((await db.scalars(stmt)).all())


async def get_batch_for_actor(
    db: AsyncSession,
    *,
    batch_id: UUID,
    actor: User,
    for_update: bool = False,
) -> tuple[ConfigurationBatch, list[ConfigurationBatchTarget]]:
    scope = await scope_for_actor(db, actor)
    stmt = select(ConfigurationBatch).where(ConfigurationBatch.id == batch_id)
    if for_update:
        stmt = stmt.with_for_update()
    batch = await db.scalar(stmt)
    if batch is None or (not scope.global_access and batch.actor_user_id != actor.id):
        raise APIError(404, "CONFIGURATION_BATCH_NOT_FOUND", "Configuration batch not found.")
    targets = await _targets(db, batch.id, for_update=for_update)
    for target in targets:
        await require_device(db, scope, target.device_id)
    return batch, targets


async def list_batches_for_actor(
    db: AsyncSession,
    *,
    actor: User,
    limit: int,
) -> list[ConfigurationBatch]:
    scope = await scope_for_actor(db, actor)
    stmt = select(ConfigurationBatch)
    if not scope.global_access:
        stmt = stmt.where(ConfigurationBatch.actor_user_id == actor.id)
    return list(
        (
            await db.scalars(
                stmt.order_by(
                    ConfigurationBatch.created_at.desc(), ConfigurationBatch.id.desc()
                ).limit(limit)
            )
        ).all()
    )


async def pause_batch(
    db: AsyncSession,
    *,
    batch_id: UUID,
    actor: User,
) -> ConfigurationBatch:
    batch, _ = await get_batch_for_actor(
        db, batch_id=batch_id, actor=actor, for_update=True
    )
    await _require_operation_permission(db, actor=actor, operation_type=batch.operation_type)
    if batch.status not in {"QUEUED", "SCHEDULED", "RUNNING"}:
        raise APIError(
            409,
            "CONFIGURATION_BATCH_PAUSE_INVALID_STATE",
            "Only a queued, scheduled, or running batch can be paused.",
        )
    batch.status = "PAUSED"
    batch.paused_at = utcnow()
    await record_audit(
        db,
        action="CONFIGURATION_BATCH_PAUSED",
        entity_type="ConfigurationBatch",
        entity_id=batch.id,
        actor_user_id=actor.id,
        description="Future batch dispatch paused; emitted operations remain authoritative.",
    )
    return batch


def _failed_terminal_waves(targets: list[ConfigurationBatchTarget]) -> set[int]:
    output: set[int] = set()
    waves = sorted({target.wave_number for target in targets})
    for wave in waves:
        members = [target for target in targets if target.wave_number == wave]
        if members and all(target.status in TERMINAL_TARGET_STATUSES for target in members):
            if any(target.status in {"FAILED", "SKIPPED"} for target in members):
                output.add(wave)
    return output


async def resume_batch(
    db: AsyncSession,
    *,
    batch_id: UUID,
    actor: User,
) -> ConfigurationBatch:
    batch, targets = await get_batch_for_actor(
        db, batch_id=batch_id, actor=actor, for_update=True
    )
    await _require_operation_permission(db, actor=actor, operation_type=batch.operation_type)
    if batch.status != "PAUSED":
        raise APIError(
            409,
            "CONFIGURATION_BATCH_RESUME_INVALID_STATE",
            "Only a paused batch can be resumed.",
        )
    parameters = dict(batch.rollout_parameters or {})
    approved = {int(value) for value in parameters.get("approved_failed_waves", [])}
    approved.update(_failed_terminal_waves(targets))
    parameters["approved_failed_waves"] = sorted(approved)
    batch.rollout_parameters = parameters
    now = utcnow()
    if batch.not_before is not None and batch.not_before > now:
        batch.status = "SCHEDULED"
    else:
        batch.status = "RUNNING"
        if batch.started_at is None:
            batch.started_at = now
    batch.paused_at = None
    await record_audit(
        db,
        action="CONFIGURATION_BATCH_RESUMED",
        entity_type="ConfigurationBatch",
        entity_id=batch.id,
        actor_user_id=actor.id,
        description="Batch dispatch resumed only for targets without an emitted operation ID.",
    )
    return batch


async def abort_batch(
    db: AsyncSession,
    *,
    batch_id: UUID,
    actor: User,
) -> ConfigurationBatch:
    batch, targets = await get_batch_for_actor(
        db, batch_id=batch_id, actor=actor, for_update=True
    )
    await _require_operation_permission(db, actor=actor, operation_type=batch.operation_type)
    if batch.status in TERMINAL_BATCH_STATUSES:
        raise APIError(
            409,
            "CONFIGURATION_BATCH_ABORT_INVALID_STATE",
            "The configuration batch is already terminal.",
        )
    now = utcnow()
    emitted = 0
    for target in targets:
        if target.configuration_operation_id is None:
            if target.status not in TERMINAL_TARGET_STATUSES:
                target.status = "ABORTED"
                target.failure_code = "CONFIGURATION_BATCH_ABORTED"
                target.failure_message = "Target was aborted before an operation was emitted."
                target.terminal_at = now
        else:
            emitted += 1
    batch.aborted_at = now
    batch.aborted_count = sum(target.status == "ABORTED" for target in targets)
    if emitted == 0:
        batch.status = "CANCELLED"
        batch.finished_at = now
    else:
        batch.status = "ABORTING"
    await record_audit(
        db,
        action="CONFIGURATION_BATCH_ABORT_REQUESTED",
        entity_type="ConfigurationBatch",
        entity_id=batch.id,
        actor_user_id=actor.id,
        description="Never-emitted targets were aborted; emitted operations were not killed or replaced.",
        metadata={"emitted_operation_count": emitted},
    )
    return batch


def _recompute_counters(
    batch: ConfigurationBatch,
    targets: list[ConfigurationBatchTarget],
) -> None:
    batch.dispatched_count = sum(
        target.configuration_operation_id is not None for target in targets
    )
    batch.succeeded_count = sum(target.status == "SUCCEEDED" for target in targets)
    batch.failed_count = sum(
        target.status in {"FAILED", "SKIPPED"} for target in targets
    )
    batch.aborted_count = sum(target.status == "ABORTED" for target in targets)


def _maybe_pause_failed_wave(
    batch: ConfigurationBatch,
    targets: list[ConfigurationBatchTarget],
) -> bool:
    if batch.rollout_mode == "ALL_AT_ONCE" or batch.status in {"PAUSED", "ABORTING"}:
        return False
    parameters = dict(batch.rollout_parameters or {})
    approved = {int(value) for value in parameters.get("approved_failed_waves", [])}
    waves = sorted({target.wave_number for target in targets})
    for wave in waves:
        members = [target for target in targets if target.wave_number == wave]
        later_pending = any(
            target.wave_number > wave
            and target.status in {"WAITING", "READY", "DISPATCHED"}
            for target in targets
        )
        if (
            later_pending
            and wave not in approved
            and members
            and all(target.status in TERMINAL_TARGET_STATUSES for target in members)
            and any(target.status in {"FAILED", "SKIPPED"} for target in members)
        ):
            batch.status = "PAUSED"
            batch.paused_at = utcnow()
            return True
    return False


def _terminalize_batch(
    batch: ConfigurationBatch,
    targets: list[ConfigurationBatchTarget],
) -> None:
    if not targets or not all(
        target.status in TERMINAL_TARGET_STATUSES for target in targets
    ):
        return
    now = utcnow()
    if batch.status == "ABORTING":
        batch.status = "ABORTED"
    elif batch.status == "CANCELLED":
        pass
    elif batch.succeeded_count == batch.target_count:
        batch.status = "SUCCEEDED"
    elif batch.succeeded_count > 0:
        batch.status = "PARTIAL"
    elif batch.failed_count > 0:
        batch.status = "FAILED"
    else:
        batch.status = "ABORTED"
    batch.finished_at = batch.finished_at or now


async def reconcile_batch(
    db: AsyncSession,
    batch_id: UUID,
) -> ConfigurationBatch | None:
    batch = await db.scalar(
        select(ConfigurationBatch)
        .where(ConfigurationBatch.id == batch_id)
        .with_for_update()
    )
    if batch is None:
        return None
    targets = await _targets(db, batch.id, for_update=True)
    now = utcnow()
    for target in targets:
        if target.configuration_operation_id is None or target.status != "DISPATCHED":
            continue
        operation = await db.get(ConfigurationOperation, target.configuration_operation_id)
        if operation is None:
            target.status = "FAILED"
            target.failure_code = "CONFIGURATION_BATCH_LINKED_OPERATION_MISSING"
            target.failure_message = "The linked configuration operation is unavailable."
            target.terminal_at = now
            continue
        if operation.status not in TERMINAL_OPERATION_STATUSES:
            continue
        target.terminal_at = operation.finished_at or now
        if operation.status == "SUCCEEDED":
            target.status = "SUCCEEDED"
            target.failure_code = None
            target.failure_message = None
        else:
            target.status = "FAILED"
            target.failure_code = (
                operation.failure_code
                or f"CONFIGURATION_OPERATION_{operation.status}"
            )[:120]
            target.failure_message = (
                f"Linked configuration operation ended with status {operation.status}."
            )

    _recompute_counters(batch, targets)
    _maybe_pause_failed_wave(batch, targets)
    _terminalize_batch(batch, targets)
    return batch


def _stored_steps(batch: ConfigurationBatch) -> list[ConfigurationStepRequest]:
    payload = dict((batch.request_summary or {}).get("operation_payload") or {})
    return [ConfigurationStepRequest.model_validate(item) for item in payload.get("steps", [])]


def _stored_snapshot_id(batch: ConfigurationBatch, device_id: UUID) -> UUID | None:
    payload = dict((batch.request_summary or {}).get("operation_payload") or {})
    raw = dict(payload.get("snapshot_ids") or {}).get(str(device_id))
    return UUID(raw) if raw else None


async def _mark_unemitted_skipped(
    db: AsyncSession,
    *,
    batch: ConfigurationBatch,
    code: str,
    message: str,
) -> None:
    targets = await _targets(db, batch.id, for_update=True)
    now = utcnow()
    for target in targets:
        if (
            target.configuration_operation_id is None
            and target.status in {"WAITING", "READY"}
        ):
            target.status = "SKIPPED"
            target.failure_code = code[:120]
            target.failure_message = message
            target.terminal_at = now
    _recompute_counters(batch, targets)
    _terminalize_batch(batch, targets)


async def _active_operation_count(db: AsyncSession, batch_id: UUID) -> int:
    return int(
        await db.scalar(
            select(func.count())
            .select_from(ConfigurationBatchTarget)
            .join(
                ConfigurationOperation,
                ConfigurationOperation.id
                == ConfigurationBatchTarget.configuration_operation_id,
            )
            .where(
                ConfigurationBatchTarget.batch_id == batch_id,
                ConfigurationOperation.status.in_(ACTIVE_OPERATION_STATUSES),
            )
        )
        or 0
    )


async def _current_wave_targets(
    db: AsyncSession,
    batch_id: UUID,
) -> list[ConfigurationBatchTarget]:
    targets = await _targets(db, batch_id, for_update=True)
    pending_waves = [
        target.wave_number
        for target in targets
        if target.status in {"WAITING", "READY", "DISPATCHED"}
    ]
    if not pending_waves:
        return []
    wave = min(pending_waves)
    return [target for target in targets if target.wave_number == wave]


async def dispatch_batch(
    db: AsyncSession,
    batch_id: UUID,
) -> ConfigurationBatch | None:
    # Reconcile first. This is inspection only and never re-emits a linked F1
    # operation. Committing here makes terminal child state durable before any
    # decision about advancing a rollout wave.
    batch = await reconcile_batch(db, batch_id)
    await db.commit()
    if batch is None:
        return None

    while True:
        batch = await db.scalar(
            select(ConfigurationBatch)
            .where(ConfigurationBatch.id == batch_id)
            .with_for_update()
        )
        if batch is None:
            return None
        if batch.status in TERMINAL_BATCH_STATUSES | {"PAUSED", "ABORTING"}:
            await db.commit()
            return batch

        now = utcnow()
        if batch.not_before is not None and batch.not_before > now:
            batch.status = "SCHEDULED"
            await db.commit()
            return batch
        if batch.status in {"QUEUED", "SCHEDULED"}:
            batch.status = "RUNNING"
            batch.started_at = batch.started_at or now

        actor = await db.get(User, batch.actor_user_id) if batch.actor_user_id else None
        if actor is None or not actor.is_active:
            await _mark_unemitted_skipped(
                db,
                batch=batch,
                code="CONFIGURATION_BATCH_ACTOR_UNAVAILABLE",
                message="The batch actor is unavailable; no new operation was emitted.",
            )
            await db.commit()
            return batch
        if not await user_has_permission(
            db,
            user_id=actor.id,
            permission_code=required_permission(batch.operation_type),
        ):
            await _mark_unemitted_skipped(
                db,
                batch=batch,
                code="CONFIGURATION_BATCH_PERMISSION_REVOKED",
                message="Required configuration permission is no longer granted.",
            )
            await db.commit()
            return batch

        active_count = await _active_operation_count(db, batch.id)
        if active_count >= settings.configuration_batch_max_concurrency:
            await db.commit()
            return batch

        wave_targets = await _current_wave_targets(db, batch.id)
        candidate = next(
            (
                target
                for target in wave_targets
                if target.configuration_operation_id is None
                and target.status in {"WAITING", "READY"}
            ),
            None,
        )
        if candidate is None:
            await db.commit()
            return batch

        if batch.maintenance_policy == "REQUIRE_ACTIVE_WINDOW":
            maintenance = await active_maintenance_for_device(db, candidate.device_id)
            if maintenance is None:
                # Try another never-emitted target in the same wave. If every
                # target is outside a window, stop this pass and let Beat retry.
                eligible = None
                for target in wave_targets:
                    if (
                        target.id == candidate.id
                        or target.configuration_operation_id is not None
                        or target.status not in {"WAITING", "READY"}
                    ):
                        continue
                    if await active_maintenance_for_device(db, target.device_id):
                        eligible = target
                        break
                if eligible is None:
                    await db.commit()
                    return batch
                candidate = eligible

        scope = await scope_for_actor(db, actor)
        try:
            device: Device = await require_device(
                db, scope, candidate.device_id, for_update=True
            )
        except APIError:
            candidate.status = "SKIPPED"
            candidate.failure_code = "CONFIGURATION_BATCH_SCOPE_REVOKED"
            candidate.failure_message = (
                "The actor no longer has resource scope for this target."
            )
            candidate.terminal_at = now
            await db.commit()
            continue

        try:
            # F1 validation can flush the operation row before validating APPLY
            # steps. Isolate the complete queue call in a SAVEPOINT so any
            # guarded validation failure cannot leak a partial operation into
            # the outer batch transaction.
            async with db.begin_nested():
                operation, created = await queue_operation(
                    db,
                    device=device,
                    actor=actor,
                    scope=scope,
                    operation_type=batch.operation_type,
                    idempotency_key=target_idempotency_key(
                        batch_id=batch.id,
                        device_id=candidate.device_id,
                        request_fingerprint=batch.request_fingerprint,
                    ),
                    steps=_stored_steps(batch) if batch.operation_type == "APPLY" else None,
                    snapshot_id=(
                        _stored_snapshot_id(batch, candidate.device_id)
                        if batch.operation_type in {"VERIFY", "RESTORE"}
                        else None
                    ),
                )
        except APIError as exc:
            candidate.status = "SKIPPED"
            candidate.failure_code = _failure_code(
                exc, "CONFIGURATION_BATCH_TARGET_VALIDATION_FAILED"
            )
            candidate.failure_message = (
                "The target failed guarded single-device queue validation; no operation was emitted."
            )
            candidate.terminal_at = now
            await db.commit()
            continue

        candidate.configuration_operation_id = operation.id
        candidate.status = "DISPATCHED"
        candidate.dispatched_at = now
        await record_audit(
            db,
            action="CONFIGURATION_BATCH_TARGET_OPERATION_LINKED",
            entity_type="ConfigurationBatchTarget",
            entity_id=candidate.id,
            actor_user_id=actor.id,
            description="Batch target permanently linked to one immutable F1 configuration operation.",
            metadata={
                "batch_id": str(batch.id),
                "device_id": str(candidate.device_id),
                "operation_id": str(operation.id),
                "wave_number": candidate.wave_number,
            },
        )
        # The target -> operation identity is durable before broker submission.
        # A later pass will never call queue_operation for this target again.
        await db.commit()

        if created:
            try:
                celery_app.send_task(
                    "fttw.configuration.execute",
                    args=[str(operation.id)],
                    queue="configuration",
                )
            except Exception:
                await mark_dispatch_failure(db, operation.id)
                linked = await db.scalar(
                    select(ConfigurationBatchTarget)
                    .where(ConfigurationBatchTarget.id == candidate.id)
                    .with_for_update()
                )
                if linked is not None and linked.status == "DISPATCHED":
                    linked.status = "FAILED"
                    linked.failure_code = "CONFIGURATION_TASK_DISPATCH_FAILED"
                    linked.failure_message = (
                        "The linked operation could not be submitted to the isolated configuration worker."
                    )
                    linked.terminal_at = utcnow()
                await db.commit()
                return await reconcile_batch(db, batch.id)
        # created=False means an immutable operation identity already existed.
        # Never auto-submit it because its prior broker state is intentionally
        # treated as unknown rather than risking an operation replay.

        batch = await reconcile_batch(db, batch.id)
        await db.commit()
        if batch is None or batch.status in TERMINAL_BATCH_STATUSES | {"PAUSED", "ABORTING"}:
            return batch


async def due_batch_ids(db: AsyncSession, *, limit: int = 100) -> list[UUID]:
    now = utcnow()
    return list(
        (
            await db.scalars(
                select(ConfigurationBatch.id)
                .where(
                    ConfigurationBatch.status.in_(
                        ("QUEUED", "SCHEDULED", "RUNNING", "ABORTING")
                    ),
                    or_(
                        ConfigurationBatch.not_before.is_(None),
                        ConfigurationBatch.not_before <= now,
                        ConfigurationBatch.status == "ABORTING",
                    ),
                )
                .order_by(
                    ConfigurationBatch.not_before.asc().nullsfirst(),
                    ConfigurationBatch.created_at,
                    ConfigurationBatch.id,
                )
                .limit(limit)
            )
        ).all()
    )
