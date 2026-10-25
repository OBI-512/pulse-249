from pathlib import Path
from datetime import datetime, timedelta, timezone
from uuid import UUID

from app.availability.service import advance_scheduled_time, initial_next_check_at, unpublished_retry_at


def test_initial_stagger_is_deterministic_and_inside_interval():
    device_id = UUID("d2e3a41d-68d1-4d2d-8705-7a8bbb8f0f93")
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    first = initial_next_check_at(device_id, interval_seconds=300, now=now)
    second = initial_next_check_at(device_id, interval_seconds=300, now=now)
    assert first == second
    assert now <= first < now + timedelta(seconds=300)


def test_advance_scheduled_time_skips_missed_periods_without_catchup_storm():
    scheduled = datetime(2030, 1, 1, tzinfo=timezone.utc)
    now = scheduled + timedelta(seconds=905)
    next_check = advance_scheduled_time(scheduled, now, 300)
    assert next_check == scheduled + timedelta(seconds=1200)
    assert next_check > now


def test_dispatcher_uses_transaction_advisory_lock_for_capacity_serialization():
    source = (Path(__file__).resolve().parents[1] / "availability" / "service.py").read_text(encoding="utf-8")
    assert "pg_try_advisory_xact_lock" in source
    assert "if not dispatcher_lock:" in source


def test_unpublished_claim_retry_is_delayed_and_deterministically_spread():
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    ids = [UUID(int=value) for value in range(1, 40)]
    retries = [unpublished_retry_at(device_id, now) for device_id in ids]
    delays = {(value - now).total_seconds() for value in retries}
    assert min(delays) >= 5
    assert max(delays) <= 15
    assert len(delays) > 1
