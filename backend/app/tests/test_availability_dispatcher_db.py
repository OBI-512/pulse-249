from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.availability.service import claim_due_availability
from app.availability.settings import AvailabilitySettings
from app.models import Device, DeviceAvailability, DeviceType
from app.services.audit import enable_audit_maintenance
from app.settings import settings as app_settings


def _runtime(*, outstanding: int = 3, dispatch_limit: int = 10) -> AvailabilitySettings:
    return AvailabilitySettings(
        enabled=True,
        interval_seconds=300,
        failure_threshold=2,
        probe_timeout_seconds=2,
        probe_retries=1,
        dispatch_limit_per_tick=dispatch_limit,
        task_batch_size=2,
        max_outstanding_devices=outstanding,
        worker_concurrency=4,
        lease_seconds=180,
        tcp_ports=(22, 80, 443),
    )


def test_dispatcher_advisory_lock_and_backpressure_are_database_authoritative():
    async def scenario():
        # This test uses asyncio.run(). Keep its asyncpg connections isolated
        # from the application's process-global engine/pool so later tests that
        # intentionally use a different event loop cannot inherit connections
        # bound to this loop.
        engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
        SessionLocal = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        device_ids = []
        now = datetime.now(timezone.utc)
        test_due_at = datetime(2000, 1, 1, tzinfo=timezone.utc)
        try:
            async with SessionLocal() as db:
                device_type = await db.scalar(select(DeviceType).where(DeviceType.code == "OTHER"))
                assert device_type is not None
                for index in range(5):
                    device = Device(
                        device_type_id=device_type.id,
                        display_name=f"Availability Dispatcher {uuid4().hex[:8]}-{index}",
                        lifecycle_state="ACTIVE",
                        operational_state="UNKNOWN",
                        management_protocol="ICMP",
                        metadata_={},
                    )
                    db.add(device)
                    await db.flush()
                    device_ids.append(device.id)
                    db.add(DeviceAvailability(
                        device_id=device.id,
                        status="UNKNOWN",
                        profile="ICMP",
                        enabled=True,
                        # Sort before every real/backfilled row in this 2026 baseline
                        # so the dispatcher claims only these test devices.
                        next_check_at=test_due_at + timedelta(microseconds=index),
                    ))
                await db.commit()

            # An overlapping dispatcher transaction must fail the advisory lock
            # immediately rather than independently calculating queue capacity.
            async with SessionLocal() as first, SessionLocal() as second:
                claims, _ = await claim_due_availability(first, _runtime(outstanding=10, dispatch_limit=2), now=now)
                assert len(claims) == 2
                overlapping, _ = await claim_due_availability(second, _runtime(outstanding=10, dispatch_limit=2), now=now)
                assert overlapping == []
                await first.rollback()
                await second.rollback()

            # Use a cap relative to any unrelated valid leases already present
            # in the active database. Backpressure is global by design, so the
            # test must not assume the database contains zero operational work.
            async with SessionLocal() as db:
                baseline_active = int((await db.scalar(
                    select(func.count(DeviceAvailability.id)).where(
                        DeviceAvailability.lease_expires_at.is_not(None),
                        DeviceAvailability.lease_expires_at > now,
                    )
                )) or 0)

            runtime = _runtime(outstanding=baseline_active + 3)
            async with SessionLocal() as db:
                claims, active_before = await claim_due_availability(db, runtime, now=now)
                assert active_before == baseline_active
                assert len(claims) == 3
                assert all(claim.lease_token for claim in claims)
                await db.commit()

            async with SessionLocal() as db:
                blocked, active = await claim_due_availability(db, runtime, now=now)
                assert blocked == []
                assert active == baseline_active + 3
                leased = list((await db.scalars(
                    select(DeviceAvailability).where(DeviceAvailability.device_id.in_(device_ids))
                )).all())
                assert sum(row.lease_token is not None for row in leased) == 3
                assert all(row.next_check_at > now for row in leased if row.lease_token is not None)
        finally:
            if device_ids:
                async with SessionLocal() as db:
                    await enable_audit_maintenance(db)
                    await db.execute(delete(DeviceAvailability).where(DeviceAvailability.device_id.in_(device_ids)))
                    await db.execute(delete(Device).where(Device.id.in_(device_ids)))
                    await db.commit()
            await engine.dispose()

    asyncio.run(scenario())
