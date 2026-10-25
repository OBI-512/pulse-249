from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
from uuid import UUID, uuid4

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Device, DeviceAvailability, DeviceIP
from app.services.audit import record_audit

from .settings import AvailabilitySettings
from .state import ProbeObservation, transition_availability


logger = logging.getLogger(__name__)


OPERATIONAL_STATES = {"UP", "DOWN", "DEGRADED", "UNKNOWN"}


def operational_state_from_availability(
    availability_status: str,
    *,
    manual_degraded_override: bool = False,
    current_operational_state: str = "UNKNOWN",
    lifecycle_state: str | None = None,
) -> str:
    """Map server-authoritative availability into the persisted operational state.

    DEGRADED is intentionally not inferred from SUSPECT.  It is a manual
    override that is visible only while the device is confirmed ONLINE.
    Maintenance masks availability, so the last operational state is retained
    until the device leaves maintenance and a fresh observation is made.
    """

    lifecycle = (lifecycle_state or "").upper()
    if lifecycle == "DECOMMISSIONED":
        return "UNKNOWN"

    status = (availability_status or "UNKNOWN").upper()
    if status == "ONLINE":
        return "DEGRADED" if manual_degraded_override else "UP"
    if status == "OFFLINE":
        return "DOWN"
    if status in {"UNKNOWN", "SUSPECT"}:
        return "UNKNOWN"
    if status == "MAINTENANCE":
        current = (current_operational_state or "UNKNOWN").upper()
        return current if current in OPERATIONAL_STATES else "UNKNOWN"
    return "UNKNOWN"


async def synchronize_operational_state(
    db: AsyncSession,
    *,
    device: Device,
    availability: DeviceAvailability,
    source: str,
) -> bool:
    previous = (device.operational_state or "UNKNOWN").upper()
    target = operational_state_from_availability(
        availability.status,
        manual_degraded_override=bool(device.manual_degraded_override),
        current_operational_state=previous,
        lifecycle_state=device.lifecycle_state,
    )
    if target == previous:
        return False

    device.operational_state = target
    await record_audit(
        db,
        action="DEVICE_OPERATIONAL_STATE_CHANGED",
        entity_type="Device",
        entity_id=device.id,
        entity_display_snapshot={"display_name": device.display_name},
        description="Device operational state synchronized from authoritative availability.",
        before_summary={"operational_state": previous},
        after_summary={"operational_state": target},
        metadata={
            "source": source[:40],
            "availability_status": availability.status,
            "manual_degraded_override": bool(device.manual_degraded_override),
        },
    )
    return True


async def set_manual_degraded_override(
    db: AsyncSession,
    *,
    device: Device,
    enabled: bool,
    source: str = "MANUAL",
) -> bool:
    previous_override = bool(device.manual_degraded_override)
    device.manual_degraded_override = bool(enabled)
    availability = await ensure_device_availability(db, device, for_update=True)
    state_changed = await synchronize_operational_state(
        db, device=device, availability=availability, source=source
    )
    if previous_override != bool(enabled):
        await record_audit(
            db,
            action="DEVICE_OPERATIONAL_DEGRADED_OVERRIDE_CHANGED",
            entity_type="Device",
            entity_id=device.id,
            entity_display_snapshot={"display_name": device.display_name},
            description="Manual degraded operational override changed.",
            before_summary={"manual_degraded_override": previous_override},
            after_summary={"manual_degraded_override": bool(enabled)},
            metadata={
                "source": source[:40],
                "availability_status": availability.status,
                "effective_operational_state": device.operational_state,
            },
        )
    return previous_override != bool(enabled) or state_changed


def default_profile(management_protocol: str | None) -> str:
    protocol = (management_protocol or "").strip().upper()
    return protocol if protocol in {"ICMP", "TCP", "SNMP"} else "ICMP"


def initial_next_check_at(device_id: UUID, *, interval_seconds: int = 300, now: datetime | None = None) -> datetime:
    base = now or datetime.now(timezone.utc)
    interval = max(1, int(interval_seconds))
    return base + timedelta(seconds=device_id.int % interval)


def advance_scheduled_time(scheduled_at: datetime, now: datetime, interval_seconds: int) -> datetime:
    interval = max(1, int(interval_seconds))
    if scheduled_at > now:
        return scheduled_at
    overdue = max(0.0, (now - scheduled_at).total_seconds())
    periods = int(overdue // interval) + 1
    return scheduled_at + timedelta(seconds=periods * interval)


def unpublished_retry_at(device_id: UUID, now: datetime) -> datetime:
    # Deterministic 5-15 second retry spread prevents a transient broker
    # publication failure from turning the one-second dispatcher into a hot
    # retry loop while still recovering far sooner than the normal interval.
    return now + timedelta(seconds=5 + (device_id.int % 11))


async def ensure_device_availability(
    db: AsyncSession,
    device: Device,
    *,
    interval_seconds: int = 300,
    for_update: bool = False,
) -> DeviceAvailability:
    stmt = select(DeviceAvailability).where(DeviceAvailability.device_id == device.id)
    if for_update:
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    existing = await db.scalar(stmt)
    if existing is not None:
        return existing
    row = DeviceAvailability(
        device_id=device.id,
        status="MAINTENANCE" if device.lifecycle_state == "MAINTENANCE" else "UNKNOWN",
        profile=default_profile(device.management_protocol),
        enabled=True,
        next_check_at=initial_next_check_at(device.id, interval_seconds=interval_seconds),
    )
    db.add(row)
    await db.flush()
    return row


async def reconcile_missing_availability_rows(db: AsyncSession, *, interval_seconds: int) -> int:
    missing = list((await db.scalars(
        select(Device).where(
            Device.deleted_at.is_(None),
            ~select(DeviceAvailability.id).where(DeviceAvailability.device_id == Device.id).exists(),
        ).order_by(Device.id).with_for_update(skip_locked=True).limit(5000)
    )).all())
    if not missing:
        return 0
    now = datetime.now(timezone.utc)
    for device in missing:
        db.add(DeviceAvailability(
            device_id=device.id,
            status="MAINTENANCE" if device.lifecycle_state == "MAINTENANCE" else "UNKNOWN",
            profile=default_profile(device.management_protocol),
            enabled=True,
            next_check_at=initial_next_check_at(device.id, interval_seconds=interval_seconds, now=now),
        ))
    await db.flush()
    return len(missing)


async def synchronize_lifecycle_state(db: AsyncSession, device: Device) -> None:
    row = await ensure_device_availability(db, device, for_update=True)
    now = datetime.now(timezone.utc)
    previous = row.status
    if device.lifecycle_state == "MAINTENANCE":
        row.status = "MAINTENANCE"
        row.next_check_at = min(row.next_check_at, now)
    elif device.lifecycle_state == "DECOMMISSIONED":
        row.status = "UNKNOWN"
        row.consecutive_failures = 0
        row.lease_token = None
        row.lease_expires_at = None
    elif previous == "MAINTENANCE":
        # Lifecycle recovery must be proven by a new network check rather than
        # reviving a stale pre-maintenance state.
        row.status = "UNKNOWN"
        row.consecutive_failures = 0
        row.next_check_at = now
        row.lease_token = None
        row.lease_expires_at = None
    if row.status != previous:
        row.status_changed_at = now
        await record_audit(
            db,
            action="DEVICE_AVAILABILITY_CHANGED",
            entity_type="Device",
            entity_id=device.id,
            description="Device availability state changed because of lifecycle state.",
            before_summary={"availability_status": previous},
            after_summary={"availability_status": row.status},
            metadata={"source": "LIFECYCLE", "lifecycle_state": device.lifecycle_state},
        )
    await synchronize_operational_state(
        db, device=device, availability=row, source="LIFECYCLE"
    )


@dataclass(frozen=True)
class ClaimedAvailability:
    availability_id: UUID
    device_id: UUID
    lease_token: UUID


async def claim_due_availability(
    db: AsyncSession,
    settings: AvailabilitySettings,
    *,
    now: datetime | None = None,
) -> tuple[list[ClaimedAvailability], int]:
    current = now or datetime.now(timezone.utc)
    # Beat can enqueue a new dispatcher before an earlier dispatcher task has
    # finished. Serialize claims at the database transaction boundary so two
    # dispatchers cannot both calculate capacity and oversubscribe backpressure.
    dispatcher_lock = bool(await db.scalar(select(func.pg_try_advisory_xact_lock(0x46545457))))
    active_leases = int((await db.scalar(select(func.count(DeviceAvailability.id)).where(
        DeviceAvailability.lease_expires_at.is_not(None),
        DeviceAvailability.lease_expires_at > current,
    ))) or 0)
    if not dispatcher_lock:
        return [], active_leases
    capacity = max(0, settings.max_outstanding_devices - active_leases)
    claim_limit = min(settings.dispatch_limit_per_tick, capacity)
    if claim_limit <= 0:
        return [], active_leases

    rows = list((await db.scalars(
        select(DeviceAvailability)
        .join(Device, Device.id == DeviceAvailability.device_id)
        .where(
            DeviceAvailability.enabled.is_(True),
            DeviceAvailability.next_check_at <= current,
            or_(
                DeviceAvailability.lease_expires_at.is_(None),
                DeviceAvailability.lease_expires_at <= current,
            ),
            Device.deleted_at.is_(None),
            Device.lifecycle_state != "DECOMMISSIONED",
        )
        .order_by(DeviceAvailability.next_check_at, DeviceAvailability.device_id)
        .with_for_update(skip_locked=True)
        .limit(claim_limit)
    )).all())

    claimed: list[ClaimedAvailability] = []
    for row in rows:
        token = uuid4()
        row.lease_token = token
        row.lease_expires_at = current + timedelta(seconds=settings.lease_seconds)
        row.last_dispatched_at = current
        row.next_check_at = advance_scheduled_time(row.next_check_at, current, settings.interval_seconds)
        claimed.append(ClaimedAvailability(row.id, row.device_id, token))
    return claimed, active_leases


async def release_unpublished_claims(db: AsyncSession, claims: list[ClaimedAvailability]) -> int:
    if not claims:
        return 0
    current = datetime.now(timezone.utc)
    rows = list((await db.scalars(
        select(DeviceAvailability)
        .where(DeviceAvailability.id.in_([claim.availability_id for claim in claims]))
        .with_for_update()
    )).all())
    expected = {claim.availability_id: claim.lease_token for claim in claims}
    released = 0
    for row in rows:
        if row.lease_token != expected.get(row.id):
            continue
        row.lease_token = None
        row.lease_expires_at = None
        row.next_check_at = min(row.next_check_at, unpublished_retry_at(row.device_id, current))
        released += 1
    return released


async def apply_observation(
    db: AsyncSession,
    *,
    availability: DeviceAvailability,
    device: Device,
    observation: ProbeObservation,
    failure_threshold: int,
    checked_at: datetime | None = None,
) -> bool:
    previous = availability.status
    transition = transition_availability(
        current_status=availability.status,
        current_failures=availability.consecutive_failures,
        last_success_at=availability.last_success_at,
        last_failure_at=availability.last_failure_at,
        lifecycle_state=device.lifecycle_state,
        observation=observation,
        failure_threshold=failure_threshold,
        checked_at=checked_at,
    )
    availability.status = transition.status
    availability.consecutive_failures = transition.consecutive_failures
    availability.last_check_at = transition.last_check_at
    availability.last_success_at = transition.last_success_at
    availability.last_failure_at = transition.last_failure_at
    availability.latency_ms = transition.latency_ms
    availability.last_result_code = transition.result_code
    availability.lease_token = None
    availability.lease_expires_at = None

    changed = previous != transition.status
    if changed:
        availability.status_changed_at = transition.last_check_at
        await record_audit(
            db,
            action="DEVICE_AVAILABILITY_CHANGED",
            entity_type="Device",
            entity_id=device.id,
            entity_display_snapshot={"display_name": device.display_name},
            description="Server-authoritative device availability state changed.",
            before_summary={"availability_status": previous},
            after_summary={"availability_status": transition.status},
            metadata={
                "source": "AVAILABILITY_ENGINE",
                "profile": availability.profile,
                "result_code": transition.result_code,
                "consecutive_failures": transition.consecutive_failures,
            },
        )

    await synchronize_operational_state(
        db, device=device, availability=availability, source="AVAILABILITY_ENGINE"
    )

    # C2 correlates the authoritative observation into an operational alarm.
    # This runs on every completed probe so a manually-cleared alarm reopens
    # if the underlying OFFLINE condition is still present on the next poll.
    from app.services.alarms import process_availability_observation

    await process_availability_observation(
        db,
        device=device,
        previous_status=previous,
        current_status=transition.status,
        checked_at=transition.last_check_at,
        result_code=transition.result_code,
    )
    return changed
