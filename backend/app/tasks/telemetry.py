from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import logging
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.celery_app.config import celery_app
from app.models import Device, DeviceIP, TelemetryDeviceState, TelemetryMetric, TelemetryProfile
from app.services.access_templates import AccessTemplateSecretError, resolve_snmp_runtime_access
from app.services.maintenance import maintenance_mode_active
from app.settings import settings as app_settings
from app.telemetry.collectors import TelemetryCollectionError, collect_snmp_metrics
from app.telemetry.service import (
    ClaimedTelemetry,
    claim_due_telemetry,
    deterministic_jitter_seconds,
    load_telemetry_runtime_settings,
    reconcile_telemetry_states,
    release_unpublished_telemetry,
)


logger = logging.getLogger(__name__)


def _session_factory():
    engine = create_async_engine(app_settings.database_url, pool_pre_ping=True)
    return engine, async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


def _chunks(values: list[ClaimedTelemetry], size: int):
    step = max(1, size)
    for index in range(0, len(values), step):
        yield values[index:index + step]


async def _reconcile() -> dict[str, int | str]:
    if await maintenance_mode_active():
        return {"changed": 0, "reason": "SYSTEM_MAINTENANCE_MODE"}
    engine, SessionLocal = _session_factory()
    try:
        async with SessionLocal() as db:
            changed = await reconcile_telemetry_states(db)
            await db.commit()
        return {"changed": changed}
    finally:
        await engine.dispose()


async def _dispatch_due() -> dict[str, int | str]:
    if await maintenance_mode_active():
        return {"claimed": 0, "published": 0, "outstanding": 0, "reason": "SYSTEM_MAINTENANCE_MODE"}
    engine, SessionLocal = _session_factory()
    try:
        async with SessionLocal() as db:
            runtime = await load_telemetry_runtime_settings(db)
            claims, outstanding = await claim_due_telemetry(db, runtime)
            await db.commit()
        if not claims:
            return {"claimed": 0, "published": 0, "outstanding": outstanding, "reason": "DISABLED" if not runtime.enabled else "NO_DUE"}
        published = 0
        for chunk in _chunks(claims, runtime.task_batch_size):
            # Only opaque device/lease identifiers cross the Celery broker.
            # Access Template secrets are resolved later inside the worker.
            payload = [{"device_id": str(item.device_id), "lease_token": str(item.lease_token)} for item in chunk]
            try:
                celery_app.send_task(
                    "fttw.telemetry.collect_batch",
                    args=[payload],
                    expires=max(30, runtime.lease_seconds - 5),
                )
                published += len(chunk)
            except Exception:
                logger.exception("telemetry_publish_failed", extra={"event": "TELEMETRY_PUBLISH_FAILED", "device_count": len(chunk)})
                async with SessionLocal() as db:
                    await release_unpublished_telemetry(db, chunk)
                    await db.commit()
        return {"claimed": len(claims), "published": published, "outstanding": outstanding}
    finally:
        await engine.dispose()


async def _prepare_device(SessionLocal, device_id: UUID, lease_token: UUID):
    async with SessionLocal() as db:
        row = (await db.execute(
            select(Device, TelemetryDeviceState, TelemetryProfile)
            .join(TelemetryDeviceState, TelemetryDeviceState.device_id == Device.id)
            .join(TelemetryProfile, TelemetryProfile.id == TelemetryDeviceState.profile_id)
            .where(Device.id == device_id, Device.deleted_at.is_(None))
            .with_for_update()
            .execution_options(populate_existing=True)
        )).first()
        if row is None:
            return "STALE", None
        device, state, profile = row
        if not state.enabled or not profile.enabled or state.lease_token != lease_token:
            return "STALE", None
        ip = await db.scalar(
            select(DeviceIP.ip_address)
            .where(DeviceIP.device_id == device.id, DeviceIP.deleted_at.is_(None), DeviceIP.is_management.is_(True))
            .order_by(DeviceIP.is_primary.desc(), DeviceIP.id)
            .limit(1)
        )
        failure_base = {
            "device_id": device.id,
            "lease_token": lease_token,
            "profile_id": profile.id,
            "interval_seconds": profile.interval_seconds,
        }
        if not ip:
            return "NO_MANAGEMENT_IP", failure_base

        try:
            template_access = await resolve_snmp_runtime_access(db, device_id=device.id)
        except AccessTemplateSecretError as exc:
            # Only a controlled error code leaves the secret-resolution boundary.
            return "CREDENTIAL_ERROR", {**failure_base, "failure_code": str(exc)[:120]}

        prepared = {
            **failure_base,
            "ip_address": ip,
            "credential_reference": device.credential_reference if template_access is None else None,
            "credential": None if template_access is None else template_access.credential,
            "snmp_port": 161 if template_access is None else template_access.port,
            "timeout_seconds": profile.timeout_seconds if template_access is None else template_access.timeout_seconds,
            "retries": profile.retries if template_access is None else template_access.retries,
            "metric_definitions": list(profile.metric_definitions or []),
            "max_metrics": profile.max_metrics,
        }
        return "READY", prepared


async def _finish_failure(SessionLocal, prepared: dict, code: str, *, duration_ms: float | None = None) -> str:
    async with SessionLocal() as db:
        state = await db.scalar(
            select(TelemetryDeviceState)
            .where(TelemetryDeviceState.device_id == prepared["device_id"])
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if state is None or state.lease_token != prepared["lease_token"]:
            return "STALE"
        now = datetime.now(timezone.utc)
        state.status = "ERROR"
        state.last_collect_at = now
        state.last_failure_at = now
        state.consecutive_failures += 1
        state.last_error_code = code[:120]
        state.last_duration_ms = duration_ms
        state.lease_token = None
        state.lease_expires_at = None
        state.next_collect_at = now + timedelta(
            seconds=prepared["interval_seconds"] + deterministic_jitter_seconds(prepared["device_id"], prepared["interval_seconds"])
        )
        await db.commit()
        return "ERROR"


async def _finish_success(SessionLocal, prepared: dict, metrics, duration_ms: float) -> str:
    async with SessionLocal() as db:
        state = await db.scalar(
            select(TelemetryDeviceState)
            .where(TelemetryDeviceState.device_id == prepared["device_id"])
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if state is None or state.lease_token != prepared["lease_token"]:
            return "STALE"
        now = datetime.now(timezone.utc)
        for item in metrics:
            db.add(TelemetryMetric(
                device_id=prepared["device_id"],
                profile_id=prepared["profile_id"],
                metric_key=item.key,
                metric_kind=item.kind,
                numeric_value=item.numeric_value,
                text_value=item.text_value,
                unit=item.unit,
                source="SNMP",
                vendor_key=item.vendor_key,
                collected_at=now,
                metadata_={"oid": item.oid},
            ))
        state.status = "OK"
        state.last_collect_at = now
        state.last_success_at = now
        state.consecutive_failures = 0
        state.last_error_code = None
        state.last_duration_ms = duration_ms
        state.lease_token = None
        state.lease_expires_at = None
        state.next_collect_at = now + timedelta(
            seconds=prepared["interval_seconds"] + deterministic_jitter_seconds(prepared["device_id"], prepared["interval_seconds"])
        )
        await db.commit()
        return "OK"


async def _collect_batch(payload: list[dict]) -> dict[str, int]:
    parsed: list[tuple[UUID, UUID]] = []
    for item in payload[:500]:
        try:
            parsed.append((UUID(str(item["device_id"])), UUID(str(item["lease_token"]))))
        except (KeyError, TypeError, ValueError):
            continue
    engine, SessionLocal = _session_factory()
    try:
        async with SessionLocal() as db:
            runtime = await load_telemetry_runtime_settings(db)
        semaphore = asyncio.Semaphore(runtime.worker_concurrency)

        async def process(device_id: UUID, lease_token: UUID) -> str:
            async with semaphore:
                status, prepared = await _prepare_device(SessionLocal, device_id, lease_token)
                if prepared is None:
                    return status
                if status == "NO_MANAGEMENT_IP":
                    return await _finish_failure(SessionLocal, prepared, "TELEMETRY_MANAGEMENT_IP_MISSING")
                if status == "CREDENTIAL_ERROR":
                    return await _finish_failure(SessionLocal, prepared, prepared["failure_code"])
                started = asyncio.get_running_loop().time()
                try:
                    metrics, duration_ms = await collect_snmp_metrics(
                        ip_address=prepared["ip_address"],
                        credential_reference=prepared["credential_reference"],
                        credential=prepared["credential"],
                        port=prepared["snmp_port"],
                        timeout_seconds=prepared["timeout_seconds"],
                        retries=prepared["retries"],
                        metric_definitions=prepared["metric_definitions"],
                        max_metrics=prepared["max_metrics"],
                    )
                except TelemetryCollectionError as exc:
                    duration_ms = (asyncio.get_running_loop().time() - started) * 1000.0
                    return await _finish_failure(SessionLocal, prepared, exc.code, duration_ms=duration_ms)
                except Exception as exc:
                    # Telemetry failures are contained here and never call or
                    # mutate the authoritative availability subsystem.
                    logger.exception("telemetry_collection_unexpected", extra={"event": "TELEMETRY_COLLECTION_UNEXPECTED", "device_id": str(device_id), "error_type": type(exc).__name__})
                    duration_ms = (asyncio.get_running_loop().time() - started) * 1000.0
                    return await _finish_failure(SessionLocal, prepared, "TELEMETRY_UNEXPECTED_FAILURE", duration_ms=duration_ms)
                return await _finish_success(SessionLocal, prepared, metrics, duration_ms)

        results = await asyncio.gather(*(process(device_id, token) for device_id, token in parsed))
        return {key.lower(): results.count(key) for key in {"OK", "ERROR", "STALE", "NO_MANAGEMENT_IP"}} | {"received": len(payload), "parsed": len(parsed)}
    finally:
        await engine.dispose()


@celery_app.task(name="fttw.telemetry.reconcile", time_limit=45, soft_time_limit=40)
def reconcile_telemetry():
    return asyncio.run(_reconcile())


@celery_app.task(name="fttw.telemetry.dispatch_due", time_limit=20, soft_time_limit=15)
def dispatch_due_telemetry():
    return asyncio.run(_dispatch_due())


@celery_app.task(name="fttw.telemetry.collect_batch", time_limit=300, soft_time_limit=280)
def collect_telemetry_batch(payload: list[dict]):
    return asyncio.run(_collect_batch(payload))
