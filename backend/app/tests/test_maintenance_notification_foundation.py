from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.availability.service import apply_observation, ensure_device_availability
from app.availability.state import ProbeObservation, ProbeOutcome
from app.models import (
    Alarm,
    AlarmHistory,
    City,
    Device,
    DeviceAvailability,
    DeviceGroup,
    DeviceGroupMembership,
    DevicePlacement,
    DeviceType,
    Location,
    MaintenanceWindow,
    Network,
    NotificationDelivery,
    NotificationPolicy,
    NotificationPolicyStep,
    OperationalEvent,
)
from app.notifications import deliver_notification, validate_destination
from app.services.maintenance_windows import cancel_maintenance_window
from app.services.notifications import NotificationRuntimeSettings, claim_due_deliveries, retry_delay_seconds
from app.settings import settings as app_settings


def _factory():
    engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
    return engine, async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


def test_maintenance_suppresses_notification_delivery_without_stopping_availability_or_alarms():
    async def scenario():
        engine, SessionLocal = _factory()
        try:
            async with SessionLocal() as db:
                tx = await db.begin()
                try:
                    marker = uuid4().hex[:10]
                    device_type = await db.scalar(select(DeviceType).where(DeviceType.code == "OTHER"))
                    assert device_type is not None
                    network = Network(name=f"C3 Network {marker}", code=f"C3N-{marker}")
                    db.add(network); await db.flush()
                    city = City(network_id=network.id, name=f"C3 City {marker}", code=f"C3C-{marker}")
                    db.add(city); await db.flush()
                    location = Location(city_id=city.id, name=f"C3 Location {marker}", code=f"C3L-{marker}", metadata_={})
                    db.add(location); await db.flush()
                    device = Device(
                        device_type_id=device_type.id,
                        display_name=f"C3 Device {marker}",
                        lifecycle_state="ACTIVE",
                        operational_state="UNKNOWN",
                        metadata_={},
                    )
                    db.add(device); await db.flush()
                    db.add(DevicePlacement(
                        device_id=device.id,
                        network_id=network.id,
                        city_id=city.id,
                        location_id=location.id,
                        metadata_={},
                    ))
                    availability = await ensure_device_availability(db, device)

                    base = datetime(2035, 1, 1, 12, 0, tzinfo=timezone.utc)
                    window = MaintenanceWindow(
                        name="Location maintenance",
                        target_type="LOCATION",
                        target_id=location.id,
                        starts_at=base - timedelta(minutes=5),
                        ends_at=base + timedelta(hours=1),
                        enabled=True,
                    )
                    policy = NotificationPolicy(
                        name=f"C3 Policy {marker}", enabled=True,
                        alarm_type="DEVICE_AVAILABILITY_OFFLINE", minimum_severity="MAJOR",
                    )
                    db.add_all([window, policy]); await db.flush()
                    step = NotificationPolicyStep(
                        policy_id=policy.id, step_order=1, delay_seconds=0,
                        channel_type="WEBHOOK", destination="env://FTTW_TEST_WEBHOOK",
                        max_attempts=3, retry_base_seconds=10, retry_max_seconds=60,
                    )
                    db.add(step); await db.flush()

                    await apply_observation(
                        db, availability=availability, device=device,
                        observation=ProbeObservation(ProbeOutcome.FAILURE, "TIMEOUT"),
                        failure_threshold=2, checked_at=base,
                    )
                    assert availability.status == "SUSPECT"
                    await apply_observation(
                        db, availability=availability, device=device,
                        observation=ProbeObservation(ProbeOutcome.FAILURE, "TIMEOUT"),
                        failure_threshold=2, checked_at=base + timedelta(seconds=1),
                    )
                    assert availability.status == "OFFLINE"
                    assert availability.last_failure_at == base + timedelta(seconds=1)

                    alarm = await db.scalar(select(Alarm).where(Alarm.device_id == device.id))
                    assert alarm is not None and alarm.state == "ACTIVE" and alarm.occurrence_count == 1
                    delivery = await db.scalar(select(NotificationDelivery).where(NotificationDelivery.alarm_id == alarm.id))
                    assert delivery is not None
                    assert delivery.status == "SUPPRESSED"
                    assert delivery.maintenance_window_id == window.id
                    assert delivery.next_attempt_at == window.ends_at
                    assert await db.scalar(select(func.count(OperationalEvent.id)).where(OperationalEvent.device_id == device.id)) == 1
                    assert await db.scalar(select(func.count(AlarmHistory.id)).where(
                        AlarmHistory.alarm_id == alarm.id,
                        AlarmHistory.action == "NOTIFICATION_SUPPRESSED",
                    )) == 1

                    # Repeated OFFLINE observations must not create an alarm or
                    # notification storm for the same correlated occurrence.
                    await apply_observation(
                        db, availability=availability, device=device,
                        observation=ProbeObservation(ProbeOutcome.FAILURE, "TIMEOUT"),
                        failure_threshold=2, checked_at=base + timedelta(seconds=2),
                    )
                    assert await db.scalar(select(func.count(Alarm.id)).where(Alarm.device_id == device.id)) == 1
                    assert await db.scalar(select(func.count(NotificationDelivery.id)).where(NotificationDelivery.alarm_id == alarm.id)) == 1

                    cancelled_at = base + timedelta(seconds=2, milliseconds=500)
                    assert await cancel_maintenance_window(
                        db, window=window, actor_user_id=None, reason="Work completed early", now=cancelled_at
                    )
                    assert delivery.status == "PENDING"
                    assert delivery.next_attempt_at == cancelled_at
                    assert delivery.maintenance_window_id is None

                    # Recovery remains authoritative and clears the alarm while
                    # the alarm while cancelling unsent notification work.
                    await apply_observation(
                        db, availability=availability, device=device,
                        observation=ProbeObservation(ProbeOutcome.SUCCESS, "SUCCESS", 2.25),
                        failure_threshold=2, checked_at=base + timedelta(seconds=3),
                    )
                    assert availability.status == "ONLINE"
                    assert availability.last_success_at == base + timedelta(seconds=3)
                    assert alarm.state == "CLEARED"
                    assert delivery.status == "CANCELLED"
                    assert await db.scalar(select(func.count(OperationalEvent.id)).where(OperationalEvent.device_id == device.id)) == 2
                finally:
                    await tx.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_notification_claiming_is_bounded_and_retry_backoff_is_capped():
    async def scenario():
        engine, SessionLocal = _factory()
        try:
            async with SessionLocal() as db:
                tx = await db.begin()
                try:
                    marker = uuid4().hex[:10]
                    device_type = await db.scalar(select(DeviceType).where(DeviceType.code == "OTHER"))
                    assert device_type is not None
                    device = Device(
                        device_type_id=device_type.id, display_name=f"C3 Claim {marker}",
                        lifecycle_state="ACTIVE", operational_state="UNKNOWN", metadata_={},
                    )
                    db.add(device); await db.flush()
                    now = datetime(2035, 2, 1, tzinfo=timezone.utc)
                    alarm = Alarm(
                        device_id=device.id, alarm_type="DEVICE_AVAILABILITY_OFFLINE",
                        correlation_key=f"c3:{marker}", severity="MAJOR", state="ACTIVE",
                        summary="offline", first_raised_at=now, last_raised_at=now,
                        occurrence_count=1,
                    )
                    policy = NotificationPolicy(name=f"C3 Claim Policy {marker}", enabled=True, minimum_severity="MAJOR")
                    db.add_all([alarm, policy]); await db.flush()
                    step = NotificationPolicyStep(
                        policy_id=policy.id, step_order=1, delay_seconds=0,
                        channel_type="EMAIL", destination="noc@example.test",
                        max_attempts=4, retry_base_seconds=10, retry_max_seconds=25,
                    )
                    db.add(step); await db.flush()
                    for index in range(3):
                        db.add(NotificationDelivery(
                            alarm_id=alarm.id, policy_id=policy.id, policy_step_id=step.id,
                            occurrence_number=1, channel_type="EMAIL", destination="noc@example.test",
                            status="PENDING", scheduled_at=now, next_attempt_at=now,
                            idempotency_key=f"c3-claim-{marker}-{index}", metadata_={},
                        ))
                    await db.flush()
                    runtime = NotificationRuntimeSettings(
                        enabled=True, dispatch_limit_per_tick=100, task_batch_size=25,
                        max_outstanding=1, lease_seconds=120, worker_concurrency=8,
                    )
                    first, outstanding = await claim_due_deliveries(db, runtime, now=now)
                    assert outstanding == 0 and len(first) == 1
                    second, outstanding = await claim_due_deliveries(db, runtime, now=now)
                    assert outstanding == 1 and second == []
                    assert retry_delay_seconds(step, 1) == 10
                    assert retry_delay_seconds(step, 2) == 20
                    assert retry_delay_seconds(step, 3) == 25
                    assert retry_delay_seconds(step, 10) == 25
                finally:
                    await tx.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_notification_destinations_keep_webhook_secrets_out_of_database(monkeypatch):
    validate_destination("EMAIL", "noc@example.test")
    validate_destination("WEBHOOK", "env://FTTW_TEST_WEBHOOK")
    try:
        validate_destination("WEBHOOK", "https://secret.example/hook/token")
    except ValueError as exc:
        assert str(exc) == "WEBHOOK_DESTINATION_MUST_BE_ENV_REFERENCE"
    else:
        raise AssertionError("raw webhook URLs must be rejected")

    monkeypatch.delenv("FTTW_TEST_WEBHOOK", raising=False)
    result = asyncio.run(deliver_notification(
        channel_type="WEBHOOK", destination="env://FTTW_TEST_WEBHOOK",
        payload={}, idempotency_key="test-key",
    ))
    assert result.success is False and result.error_code == "WEBHOOK_ENV_REFERENCE_UNRESOLVED"


def test_notification_environment_references_are_optional_and_resolve_at_runtime(monkeypatch):
    from app.notifications import resolve_env_reference

    reference = "env://FTTW_TEST_WEBHOOK"
    monkeypatch.delenv("FTTW_TEST_WEBHOOK", raising=False)
    assert resolve_env_reference(reference) is None

    monkeypatch.setenv("FTTW_TEST_WEBHOOK", "https://hooks.example.test/fttw")
    assert resolve_env_reference(reference) == "https://hooks.example.test/fttw"
    assert resolve_env_reference("https://hooks.example.test/raw-secret") is None


def test_maintenance_targets_follow_existing_resource_scope_and_fail_closed_outside_scope():
    from app.core.exceptions import APIError
    from app.models import User, UserResourceScope
    from app.security.resource_scope import load_effective_resource_scope
    from app.services.maintenance_windows import create_maintenance_window

    async def scenario():
        engine, SessionLocal = _factory()
        try:
            async with SessionLocal() as db:
                tx = await db.begin()
                try:
                    marker = uuid4().hex[:8]
                    user = User(
                        external_subject=f"c3-scope-{marker}", username=f"c3-scope-{marker}",
                        display_name="C3 Scope", is_active=True, metadata_={},
                    )
                    net_a = Network(name=f"C3 A {marker}", code=f"C3A-{marker}")
                    net_b = Network(name=f"C3 B {marker}", code=f"C3B-{marker}")
                    db.add_all([user, net_a, net_b]); await db.flush()
                    city_a = City(network_id=net_a.id, name=f"C3 CA {marker}", code=f"C3CA-{marker}")
                    city_b = City(network_id=net_b.id, name=f"C3 CB {marker}", code=f"C3CB-{marker}")
                    db.add_all([city_a, city_b]); await db.flush()
                    loc_a = Location(city_id=city_a.id, name=f"C3 LA {marker}", code=f"C3LA-{marker}", metadata_={})
                    loc_b = Location(city_id=city_b.id, name=f"C3 LB {marker}", code=f"C3LB-{marker}", metadata_={})
                    db.add_all([loc_a, loc_b]); await db.flush()
                    db.add(UserResourceScope(user_id=user.id, scope_type="NETWORK", network_id=net_a.id)); await db.flush()
                    scope = await load_effective_resource_scope(db, user.id)
                    starts = datetime.now(timezone.utc) + timedelta(minutes=1)
                    ends = starts + timedelta(hours=1)

                    row = await create_maintenance_window(
                        db, scope=scope, target_type="LOCATION", target_id=loc_a.id,
                        name="Allowed", reason=None, starts_at=starts, ends_at=ends,
                        actor_user_id=user.id,
                    )
                    assert row.target_id == loc_a.id

                    try:
                        await create_maintenance_window(
                            db, scope=scope, target_type="LOCATION", target_id=loc_b.id,
                            name="Denied", reason=None, starts_at=starts, ends_at=ends,
                            actor_user_id=user.id,
                        )
                    except APIError as exc:
                        assert exc.status_code == 404 and exc.detail["code"] == "RESOURCE_NOT_FOUND"
                    else:
                        raise AssertionError("out-of-scope maintenance target must be hidden")
                finally:
                    await tx.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_city_and_group_maintenance_resolve_against_current_device_scope():
    from app.services.maintenance_windows import active_maintenance_for_device

    async def scenario():
        engine, SessionLocal = _factory()
        try:
            async with SessionLocal() as db:
                tx = await db.begin()
                try:
                    marker = uuid4().hex[:8]
                    device_type = await db.scalar(select(DeviceType).where(DeviceType.code == "OTHER"))
                    assert device_type is not None
                    network = Network(name=f"C4 Network {marker}", code=f"C4N-{marker}")
                    db.add(network); await db.flush()
                    city = City(network_id=network.id, name=f"C4 City {marker}", code=f"C4C-{marker}")
                    db.add(city); await db.flush()
                    location = Location(city_id=city.id, name=f"C4 Location {marker}", code=f"C4L-{marker}", metadata_={})
                    db.add(location); await db.flush()
                    device = Device(
                        device_type_id=device_type.id, display_name=f"C4 Device {marker}",
                        lifecycle_state="ACTIVE", operational_state="UNKNOWN", metadata_={},
                    )
                    db.add(device); await db.flush()
                    db.add(DevicePlacement(
                        device_id=device.id, network_id=network.id, city_id=city.id,
                        location_id=location.id, metadata_={},
                    ))
                    group = DeviceGroup(
                        name=f"C4 Group {marker}", code=f"C4G-{marker}",
                        group_kind="CUSTOM", membership_mode="MANUAL", scope_type="GLOBAL",
                        device_scope="ANY", metadata_={},
                    )
                    db.add(group); await db.flush()
                    db.add(DeviceGroupMembership(device_id=device.id, group_id=group.id)); await db.flush()

                    moment = datetime(2036, 1, 1, 12, 0, tzinfo=timezone.utc)
                    city_window = MaintenanceWindow(
                        name="City maintenance", target_type="CITY", target_id=city.id,
                        starts_at=moment - timedelta(minutes=5), ends_at=moment + timedelta(hours=1), enabled=True,
                    )
                    group_window = MaintenanceWindow(
                        name="Group maintenance", target_type="GROUP", target_id=group.id,
                        starts_at=moment - timedelta(minutes=5), ends_at=moment + timedelta(hours=2), enabled=True,
                    )
                    db.add_all([city_window, group_window]); await db.flush()

                    active = await active_maintenance_for_device(db, device.id, at=moment)
                    assert active is not None
                    assert {row.target_type for row in active.windows} == {"CITY", "GROUP"}
                    assert active.primary.id == group_window.id
                    assert active.suppressed_until == group_window.ends_at
                finally:
                    await tx.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())
