from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import SystemSetting
from app.services.settings_registry import SETTINGS_REGISTRY


AVAILABILITY_SETTING_KEYS = (
    "availability.enabled",
    "availability.interval_seconds",
    "availability.failure_threshold",
    "availability.probe_timeout_seconds",
    "availability.probe_retries",
    "availability.dispatch_limit_per_tick",
    "availability.task_batch_size",
    "availability.max_outstanding_devices",
    "availability.worker_concurrency",
    "availability.lease_seconds",
    "availability.tcp_ports",
)


@dataclass(frozen=True)
class AvailabilitySettings:
    enabled: bool
    interval_seconds: int
    failure_threshold: int
    probe_timeout_seconds: int
    probe_retries: int
    dispatch_limit_per_tick: int
    task_batch_size: int
    max_outstanding_devices: int
    worker_concurrency: int
    lease_seconds: int
    tcp_ports: tuple[int, ...]


async def load_availability_settings(db: AsyncSession) -> AvailabilitySettings:
    rows = {
        row.key: row.value
        for row in (await db.scalars(
            select(SystemSetting).where(SystemSetting.key.in_(AVAILABILITY_SETTING_KEYS))
        )).all()
    }

    effective: dict[str, dict] = {}
    for key in AVAILABILITY_SETTING_KEYS:
        definition = SETTINGS_REGISTRY[key]
        raw = rows.get(key, definition.default)
        try:
            effective[key] = definition.validator(raw)
        except ValueError:
            effective[key] = definition.validator(definition.default)

    return AvailabilitySettings(
        enabled=effective["availability.enabled"]["value"],
        interval_seconds=effective["availability.interval_seconds"]["value"],
        failure_threshold=effective["availability.failure_threshold"]["value"],
        probe_timeout_seconds=effective["availability.probe_timeout_seconds"]["value"],
        probe_retries=effective["availability.probe_retries"]["value"],
        dispatch_limit_per_tick=effective["availability.dispatch_limit_per_tick"]["value"],
        task_batch_size=effective["availability.task_batch_size"]["value"],
        max_outstanding_devices=effective["availability.max_outstanding_devices"]["value"],
        worker_concurrency=effective["availability.worker_concurrency"]["value"],
        lease_seconds=effective["availability.lease_seconds"]["value"],
        tcp_ports=tuple(effective["availability.tcp_ports"]["value"]),
    )
