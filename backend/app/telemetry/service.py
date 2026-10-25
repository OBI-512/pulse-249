from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Device, DeviceType, TelemetryDeviceState, TelemetryProfile
from app.services.settings_registry import get_typed_setting


@dataclass(frozen=True)
class TelemetryRuntimeSettings:
    enabled: bool
    dispatch_limit_per_tick: int
    task_batch_size: int
    max_outstanding_devices: int
    worker_concurrency: int
    lease_seconds: int


@dataclass(frozen=True)
class ClaimedTelemetry:
    device_id: UUID
    lease_token: UUID


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def deterministic_jitter_seconds(device_id: UUID, interval_seconds: int) -> int:
    # Up to 10% cadence jitter (maximum five minutes) spreads 10K/20K fleets.
    window = max(1, min(300, int(interval_seconds * 0.10)))
    return device_id.int % window


async def load_telemetry_runtime_settings(db: AsyncSession) -> TelemetryRuntimeSettings:
    async def val(key: str):
        return (await get_typed_setting(db, key))["value"]

    return TelemetryRuntimeSettings(
        enabled=bool(await val("telemetry.enabled")),
        dispatch_limit_per_tick=int(await val("telemetry.dispatch_limit_per_tick")),
        task_batch_size=int(await val("telemetry.task_batch_size")),
        max_outstanding_devices=int(await val("telemetry.max_outstanding_devices")),
        worker_concurrency=int(await val("telemetry.worker_concurrency")),
        lease_seconds=int(await val("telemetry.lease_seconds")),
    )


async def reconcile_telemetry_states(db: AsyncSession, *, now: datetime | None = None) -> int:
    current = now or utcnow()
    rows = (await db.execute(
        select(Device.id, TelemetryProfile.id, TelemetryProfile.enabled, TelemetryProfile.interval_seconds)
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .outerjoin(TelemetryProfile, TelemetryProfile.device_type_id == DeviceType.id)
        .where(Device.deleted_at.is_(None))
    )).all()
    existing = {
        row.device_id: row
        for row in (await db.scalars(select(TelemetryDeviceState).with_for_update())).all()
    }
    changed = 0
    active_ids: set[UUID] = set()
    for device_id, profile_id, profile_enabled, interval_seconds in rows:
        active_ids.add(device_id)
        state = existing.get(device_id)
        enabled = bool(profile_id and profile_enabled)
        if state is None:
            state = TelemetryDeviceState(
                device_id=device_id,
                profile_id=profile_id,
                enabled=enabled,
                status="PENDING" if enabled else "DISABLED",
                next_collect_at=(current + timedelta(seconds=deterministic_jitter_seconds(device_id, interval_seconds or 900))) if enabled else None,
            )
            db.add(state)
            changed += 1
            continue
        if state.profile_id != profile_id or state.enabled != enabled:
            state.profile_id = profile_id
            state.enabled = enabled
            state.status = "PENDING" if enabled else "DISABLED"
            state.next_collect_at = current if enabled else None
            state.lease_token = None
            state.lease_expires_at = None
            changed += 1
    # Keep historical state rows for recycled devices but disable scheduling.
    for device_id, state in existing.items():
        if device_id not in active_ids and state.enabled:
            state.enabled = False
            state.status = "DISABLED"
            state.next_collect_at = None
            state.lease_token = None
            state.lease_expires_at = None
            changed += 1
    return changed


async def claim_due_telemetry(
    db: AsyncSession,
    runtime: TelemetryRuntimeSettings,
    *,
    now: datetime | None = None,
) -> tuple[list[ClaimedTelemetry], int]:
    current = now or utcnow()
    # Separate advisory key from availability/notifications.
    dispatcher_lock = bool(await db.scalar(select(func.pg_try_advisory_xact_lock(0x46545444))))
    outstanding = int((await db.scalar(select(func.count(TelemetryDeviceState.id)).where(
        TelemetryDeviceState.lease_token.is_not(None),
        TelemetryDeviceState.lease_expires_at.is_not(None),
        TelemetryDeviceState.lease_expires_at > current,
    ))) or 0)
    if not dispatcher_lock or not runtime.enabled:
        return [], outstanding
    capacity = max(0, runtime.max_outstanding_devices - outstanding)
    limit = min(runtime.dispatch_limit_per_tick, capacity)
    if limit <= 0:
        return [], outstanding

    states = list((await db.scalars(
        select(TelemetryDeviceState)
        .join(Device, Device.id == TelemetryDeviceState.device_id)
        .join(TelemetryProfile, TelemetryProfile.id == TelemetryDeviceState.profile_id)
        .where(
            Device.deleted_at.is_(None),
            TelemetryDeviceState.enabled.is_(True),
            TelemetryProfile.enabled.is_(True),
            TelemetryDeviceState.next_collect_at.is_not(None),
            TelemetryDeviceState.next_collect_at <= current,
            or_(
                TelemetryDeviceState.lease_token.is_(None),
                TelemetryDeviceState.lease_expires_at.is_(None),
                TelemetryDeviceState.lease_expires_at <= current,
            ),
        )
        .order_by(TelemetryDeviceState.next_collect_at, TelemetryDeviceState.device_id)
        .with_for_update(skip_locked=True)
        .limit(limit)
    )).all())
    claims: list[ClaimedTelemetry] = []
    for state in states:
        token = uuid4()
        state.lease_token = token
        state.lease_expires_at = current + timedelta(seconds=runtime.lease_seconds)
        state.last_dispatched_at = current
        claims.append(ClaimedTelemetry(state.device_id, token))
    return claims, outstanding


async def release_unpublished_telemetry(
    db: AsyncSession,
    claims: list[ClaimedTelemetry],
    *,
    now: datetime | None = None,
) -> int:
    if not claims:
        return 0
    current = now or utcnow()
    expected = {item.device_id: item.lease_token for item in claims}
    rows = list((await db.scalars(
        select(TelemetryDeviceState)
        .where(TelemetryDeviceState.device_id.in_(list(expected)))
        .with_for_update()
    )).all())
    released = 0
    for row in rows:
        if row.lease_token != expected.get(row.device_id):
            continue
        row.lease_token = None
        row.lease_expires_at = None
        row.next_collect_at = current + timedelta(seconds=5 + row.device_id.int % 11)
        released += 1
    return released

