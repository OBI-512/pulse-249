"""Typed, allow-listed operational configuration stored in ``SystemSetting``.

The database remains extensible, but HTTP callers cannot create arbitrary JSON
settings.  Internal marker keys (for example the deterministic demo-seed
marker) remain private implementation data and are intentionally not part of
this registry.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import re
from typing import Callable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import APIError
from ..models import SystemSetting


ValueValidator = Callable[[dict], dict]


@dataclass(frozen=True)
class SettingDefinition:
    key: str
    default: dict
    description: str
    category: str
    validator: ValueValidator
    is_secret: bool = False
    mutable: bool = True


def _single_int(name: str, *, minimum: int, maximum: int) -> ValueValidator:
    def validate(value: dict) -> dict:
        candidate = value.get("value") if isinstance(value, dict) else None
        if isinstance(candidate, bool) or not isinstance(candidate, int) or not minimum <= candidate <= maximum:
            raise ValueError(f"{name} must be an integer between {minimum} and {maximum}.")
        return {"value": candidate}
    return validate


def _single_bool(name: str) -> ValueValidator:
    def validate(value: dict) -> dict:
        candidate = value.get("value") if isinstance(value, dict) else None
        if not isinstance(candidate, bool):
            raise ValueError(f"{name} must be a boolean.")
        return {"value": candidate}
    return validate


def _int_list(name: str, *, minimum: int, maximum: int, max_items: int = 32) -> ValueValidator:
    def validate(value: dict) -> dict:
        candidate = value.get("value") if isinstance(value, dict) else None
        if not isinstance(candidate, list) or not candidate or len(candidate) > max_items:
            raise ValueError(f"{name} must be a non-empty list with at most {max_items} entries.")
        normalized: list[int] = []
        for item in candidate:
            if isinstance(item, bool) or not isinstance(item, int) or not minimum <= item <= maximum:
                raise ValueError(f"{name} entries must be integers between {minimum} and {maximum}.")
            if item not in normalized:
                normalized.append(item)
        return {"value": normalized}
    return validate


def _time(value: dict) -> dict:
    candidate = value.get("value") if isinstance(value, dict) else None
    if not isinstance(candidate, str) or not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", candidate):
        raise ValueError("schedule_time must use HH:MM in 24-hour time.")
    return {"value": candidate}


def _timezone(value: dict) -> dict:
    candidate = value.get("value") if isinstance(value, dict) else None
    if not isinstance(candidate, str) or not candidate.strip():
        raise ValueError("timezone must be a non-empty IANA timezone name.")
    try:
        ZoneInfo(candidate)
    except ZoneInfoNotFoundError as exc:
        raise ValueError("timezone must be a valid IANA timezone name.") from exc
    return {"value": candidate}


def _rate_limit(value: dict) -> dict:
    if not isinstance(value, dict) or set(value) != {"attempts", "window_seconds"}:
        raise ValueError("login rate limit must contain attempts and window_seconds only.")
    attempts = value["attempts"]
    window = value["window_seconds"]
    if isinstance(attempts, bool) or not isinstance(attempts, int) or not 1 <= attempts <= 100:
        raise ValueError("login rate-limit attempts must be between 1 and 100.")
    if isinstance(window, bool) or not isinstance(window, int) or not 10 <= window <= 86_400:
        raise ValueError("login rate-limit window_seconds must be between 10 and 86400.")
    return {"attempts": attempts, "window_seconds": window}


_DEFINITIONS = (
    SettingDefinition("system.timezone", {"value": "UTC"}, "Default operational timezone.", "system", _timezone),
    SettingDefinition("auth.session_lifetime_minutes", {"value": 480}, "Session lifetime in minutes.", "auth", _single_int("session lifetime", minimum=5, maximum=10_080)),
    SettingDefinition("auth.login_rate_limit", {"attempts": 5, "window_seconds": 900}, "Failed-login threshold and rolling window.", "auth", _rate_limit),
    SettingDefinition("auth.password.min_length", {"value": 8}, "Minimum password length.", "auth", _single_int("password minimum length", minimum=8, maximum=200)),
    SettingDefinition("auth.password.require_complexity", {"value": True}, "Require uppercase, lowercase, number, and symbol characters.", "auth", _single_bool("password complexity")),
    SettingDefinition("auth.password.history_count", {"value": 5}, "Number of previous password hashes blocked from reuse.", "auth", _single_int("password history count", minimum=0, maximum=20)),
    SettingDefinition("auth.password.min_edit_distance", {"value": 3}, "Minimum edit distance from the current password when the current secret is available.", "auth", _single_int("password minimum edit distance", minimum=0, maximum=20)),
    SettingDefinition("auth.password.max_age_days", {"value": 0}, "Maximum password age in days; 0 disables periodic expiration.", "auth", _single_int("password maximum age", minimum=0, maximum=3650)),
    SettingDefinition("auth.password.expiry_warning_days", {"value": 14}, "Warning window before password expiration.", "auth", _single_int("password expiry warning", minimum=0, maximum=365)),
    SettingDefinition("auth.session_online_window_minutes", {"value": 5}, "Recent-activity window used to classify active sessions as online.", "auth", _single_int("session online window", minimum=1, maximum=1440)),
    SettingDefinition("discovery.default_timeout_seconds", {"value": 10}, "Default discovery timeout in seconds.", "discovery", _single_int("discovery timeout", minimum=1, maximum=300)),
    SettingDefinition("discovery.default_retries", {"value": 1}, "Default discovery retry count.", "discovery", _single_int("discovery retries", minimum=0, maximum=10)),
    SettingDefinition("availability.enabled", {"value": True}, "Enable server-authoritative availability polling.", "availability", _single_bool("availability enabled")),
    SettingDefinition("availability.interval_seconds", {"value": 300}, "Target interval between device availability checks.", "availability", _single_int("availability interval", minimum=30, maximum=3600)),
    SettingDefinition("availability.failure_threshold", {"value": 2}, "Consecutive failed checks required before OFFLINE.", "availability", _single_int("availability failure threshold", minimum=2, maximum=10)),
    SettingDefinition("availability.probe_timeout_seconds", {"value": 2}, "Per-attempt availability probe timeout.", "availability", _single_int("availability probe timeout", minimum=1, maximum=30)),
    SettingDefinition("availability.probe_retries", {"value": 1}, "Retry attempts inside one scheduled availability check.", "availability", _single_int("availability probe retries", minimum=0, maximum=3)),
    SettingDefinition("availability.dispatch_limit_per_tick", {"value": 100}, "Maximum devices claimed by each one-second dispatcher tick.", "availability", _single_int("availability dispatch limit", minimum=1, maximum=1000)),
    SettingDefinition("availability.task_batch_size", {"value": 50}, "Maximum devices carried by one availability worker task.", "availability", _single_int("availability task batch size", minimum=1, maximum=250)),
    SettingDefinition("availability.max_outstanding_devices", {"value": 2000}, "Backpressure cap for leased/published availability checks.", "availability", _single_int("availability outstanding cap", minimum=100, maximum=20000)),
    SettingDefinition("availability.worker_concurrency", {"value": 32}, "Async probe concurrency inside one Celery batch task.", "availability", _single_int("availability worker concurrency", minimum=1, maximum=128)),
    SettingDefinition("availability.lease_seconds", {"value": 180}, "Idempotency lease duration for a claimed availability check.", "availability", _single_int("availability lease", minimum=30, maximum=900)),
    SettingDefinition("availability.tcp_ports", {"value": [22, 80, 443]}, "TCP availability profile ports.", "availability", _int_list("availability TCP ports", minimum=1, maximum=65535, max_items=32)),
    SettingDefinition("telemetry.enabled", {"value": True}, "Enable the independent telemetry collector engine.", "telemetry", _single_bool("telemetry enabled")),
    SettingDefinition("telemetry.dispatch_limit_per_tick", {"value": 250}, "Maximum telemetry devices claimed per dispatcher tick.", "telemetry", _single_int("telemetry dispatch limit", minimum=1, maximum=2000)),
    SettingDefinition("telemetry.task_batch_size", {"value": 50}, "Maximum telemetry devices carried by one worker task.", "telemetry", _single_int("telemetry task batch size", minimum=1, maximum=250)),
    SettingDefinition("telemetry.max_outstanding_devices", {"value": 2000}, "Backpressure cap for telemetry leases.", "telemetry", _single_int("telemetry outstanding cap", minimum=100, maximum=20000)),
    SettingDefinition("telemetry.worker_concurrency", {"value": 16}, "Concurrent telemetry collections inside one Celery batch.", "telemetry", _single_int("telemetry worker concurrency", minimum=1, maximum=128)),
    SettingDefinition("telemetry.lease_seconds", {"value": 180}, "Idempotency lease for claimed telemetry work.", "telemetry", _single_int("telemetry lease", minimum=30, maximum=900)),
    SettingDefinition("notifications.enabled", {"value": False}, "Enable outbound alarm notification delivery.", "notifications", _single_bool("notifications enabled")),
    SettingDefinition("notifications.dispatch_limit_per_tick", {"value": 100}, "Maximum notification deliveries claimed per dispatcher tick.", "notifications", _single_int("notification dispatch limit", minimum=1, maximum=1000)),
    SettingDefinition("notifications.task_batch_size", {"value": 25}, "Maximum notification deliveries carried by one worker task.", "notifications", _single_int("notification task batch size", minimum=1, maximum=100)),
    SettingDefinition("notifications.max_outstanding", {"value": 500}, "Backpressure cap for claimed notification deliveries.", "notifications", _single_int("notification outstanding cap", minimum=10, maximum=10000)),
    SettingDefinition("notifications.lease_seconds", {"value": 120}, "Idempotency lease duration for claimed notification deliveries.", "notifications", _single_int("notification lease", minimum=30, maximum=900)),
    SettingDefinition("notifications.worker_concurrency", {"value": 8}, "Concurrent external notification sends inside one worker batch.", "notifications", _single_int("notification worker concurrency", minimum=1, maximum=64)),
    SettingDefinition("restore_points.enabled", {"value": True}, "Enable scheduled restore-point creation.", "restore_points", _single_bool("restore points enabled")),
    SettingDefinition("restore_points.schedule_time", {"value": "00:00"}, "Daily restore-point schedule in the configured timezone.", "restore_points", _time),
    SettingDefinition("restore_points.timezone", {"value": "UTC"}, "IANA timezone for scheduled restore points.", "restore_points", _timezone),
    SettingDefinition("restore_points.retention_days", {"value": 30}, "Restore-point artifact retention in days.", "restore_points", _single_int("restore-point retention", minimum=1, maximum=3650)),
    SettingDefinition("recycle_bin.retention_days", {"value": 30}, "Recycle-bin retention in days.", "recycle_bin", _single_int("recycle retention", minimum=1, maximum=3650)),
    SettingDefinition("logs.retention_days", {"value": 30}, "Retention period for rotated operational logs.", "logs", _single_int("log retention", minimum=1, maximum=3650)),
)

SETTINGS_REGISTRY = {definition.key: definition for definition in _DEFINITIONS}


def definition_for(key: str) -> SettingDefinition:
    definition = SETTINGS_REGISTRY.get(key)
    if definition is None:
        raise APIError(422, "SETTING_KEY_UNSUPPORTED", "This setting key is not part of the typed settings registry.")
    return definition


def validate_setting_value(key: str, value: dict, *, supplied_secret: bool | None = None) -> tuple[SettingDefinition, dict]:
    definition = definition_for(key)
    if supplied_secret is not None and supplied_secret != definition.is_secret:
        raise APIError(422, "SETTING_SECRET_CLASSIFICATION_FIXED", "The secret classification is defined by the settings registry.")
    if not definition.mutable:
        raise APIError(409, "SETTING_READ_ONLY", "This setting is read-only.")
    try:
        return definition, definition.validator(value)
    except ValueError as exc:
        raise APIError(422, "SETTING_VALUE_INVALID", str(exc)) from exc


async def get_typed_setting(db: AsyncSession, key: str) -> dict:
    """Return a validated effective value, falling back safely on corrupt legacy data."""

    definition = definition_for(key)
    row = await db.scalar(select(SystemSetting).where(SystemSetting.key == key))
    if row is None:
        return deepcopy(definition.default)
    try:
        return definition.validator(row.value)
    except ValueError:
        # Existing hand-written legacy data must never turn a security control
        # off.  The controlled default stays effective until an administrator
        # replaces the invalid stored value through the typed API.
        return deepcopy(definition.default)


async def list_typed_settings(db: AsyncSession) -> list[tuple[SettingDefinition, dict, bool]]:
    rows = {
        row.key: row
        for row in (await db.scalars(select(SystemSetting).where(SystemSetting.key.in_(SETTINGS_REGISTRY)))).all()
    }
    result: list[tuple[SettingDefinition, dict, bool]] = []
    for key in sorted(SETTINGS_REGISTRY):
        definition = SETTINGS_REGISTRY[key]
        row = rows.get(key)
        try:
            value = definition.validator(row.value) if row is not None else deepcopy(definition.default)
        except ValueError:
            value = deepcopy(definition.default)
        result.append((definition, value, row is not None))
    return result


async def ensure_typed_defaults(db: AsyncSession) -> None:
    """Stage missing registry rows; callers decide the transaction boundary."""

    existing = set((await db.scalars(select(SystemSetting.key).where(SystemSetting.key.in_(SETTINGS_REGISTRY)))).all())
    for definition in _DEFINITIONS:
        if definition.key not in existing:
            db.add(SystemSetting(
                key=definition.key,
                value=deepcopy(definition.default),
                description=definition.description,
                is_secret=definition.is_secret,
            ))
