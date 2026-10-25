from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
from uuid import UUID

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.availability.probes import probe_availability
from app.availability.service import (
    ClaimedAvailability,
    apply_observation,
    claim_due_availability,
    reconcile_missing_availability_rows,
    release_unpublished_claims,
)
from app.availability.settings import load_availability_settings
from app.availability.state import ProbeObservation, ProbeOutcome
from app.celery_app.config import celery_app
from app.models import Device, DeviceAvailability, DeviceIP
from app.services.access_templates import AccessTemplateSecretError, resolve_snmp_runtime_access
from app.services.maintenance import maintenance_mode_active
from app.settings import settings as app_settings


logger = logging.getLogger(__name__)


def _session_factory():
    engine = create_async_engine(app_settings.database_url, pool_pre_ping=True)
    return engine, async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


def _chunks(values: list[ClaimedAvailability], size: int):
    step = max(1, size)
    for index in range(0, len(values), step):
        yield values[index:index + step]


async def _dispatch_due() -> dict[str, int | str]:
    if await maintenance_mode_active():
        return {"claimed": 0, "published": 0, "active_leases": 0, "reason": "MAINTENANCE_MODE"}
    engine, SessionLocal = _session_factory()
    try:
        async with SessionLocal() as db:
            runtime = await load_availability_settings(db)
            if not runtime.enabled:
                return {"claimed": 0, "published": 0, "active_leases": 0, "reason": "DISABLED"}
            claims, active_leases = await claim_due_availability(db, runtime)
            await db.commit()
        if not claims:
            return {"claimed": 0, "published": 0, "active_leases": active_leases}

        published = 0
        for chunk in _chunks(claims, runtime.task_batch_size):
            payload = [
                {"availability_id": str(item.availability_id), "device_id": str(item.device_id), "lease_token": str(item.lease_token)}
                for item in chunk
            ]
            try:
                celery_app.send_task(
                    "fttw.availability.poll_batch",
                    args=[payload],
                    expires=max(30, runtime.lease_seconds - 5),
                )
                published += len(chunk)
            except Exception:
                logger.exception(
                    "availability_publish_failed",
                    extra={"event": "AVAILABILITY_PUBLISH_FAILED", "device_count": len(chunk)},
                )
                async with SessionLocal() as db:
                    released = await release_unpublished_claims(db, chunk)
                    await db.commit()
                logger.warning(
                    "availability_claims_released",
                    extra={"event": "AVAILABILITY_CLAIMS_RELEASED", "device_count": released},
                )
        logger.info(
            "availability_dispatch_completed",
            extra={
                "event": "AVAILABILITY_DISPATCH_COMPLETED",
                "claimed": len(claims),
                "published": published,
                "active_leases": active_leases,
            },
        )
        return {"claimed": len(claims), "published": published, "active_leases": active_leases}
    finally:
        await engine.dispose()


@dataclass(frozen=True)
class _ProbeTarget:
    availability_id: UUID
    device_id: UUID
    lease_token: UUID
    profile: str
    ip_address: str | None
    credential_reference: str | None


@dataclass(frozen=True)
class _ProbeAccess:
    credential_reference: str | None
    credential: dict[str, str] | None = field(default=None, repr=False)
    snmp_port: int = 161
    timeout_seconds: float = 2.0
    retries: int = 0
    error_code: str | None = None


async def _resolve_probe_access(SessionLocal, target: _ProbeTarget, runtime) -> _ProbeAccess:
    timeout_seconds = float(runtime.probe_timeout_seconds)
    retries = int(runtime.probe_retries)

    if (target.profile or "").upper() != "SNMP":
        return _ProbeAccess(
            credential_reference=target.credential_reference,
            timeout_seconds=timeout_seconds,
            retries=retries,
        )

    async with SessionLocal() as db:
        try:
            template_access = await resolve_snmp_runtime_access(db, device_id=target.device_id)
        except AccessTemplateSecretError as exc:
            # Preserve fail-closed behavior. Configuration conflicts and secret
            # resolution failures are indeterminate, not evidence of downtime.
            return _ProbeAccess(
                credential_reference=None,
                timeout_seconds=timeout_seconds,
                retries=retries,
                error_code=str(exc)[:80],
            )

    if template_access is None:
        # Backward compatibility for pre-0038 deployments.
        return _ProbeAccess(
            credential_reference=target.credential_reference,
            timeout_seconds=timeout_seconds,
            retries=retries,
        )

    return _ProbeAccess(
        credential_reference=None,
        credential=template_access.credential,
        snmp_port=template_access.port,
        timeout_seconds=float(template_access.timeout_seconds),
        retries=int(template_access.retries),
    )


async def _load_targets(SessionLocal, payload: list[dict]) -> tuple[list[_ProbeTarget], object]:
    parsed: dict[UUID, tuple[UUID, UUID]] = {}
    for item in payload[:500]:
        try:
            availability_id = UUID(str(item["availability_id"]))
            device_id = UUID(str(item["device_id"]))
            token = UUID(str(item["lease_token"]))
        except (KeyError, TypeError, ValueError):
            continue
        parsed[availability_id] = (device_id, token)
    if not parsed:
        return [], None

    async with SessionLocal() as db:
        runtime = await load_availability_settings(db)
        management_ip = (
            select(DeviceIP.ip_address)
            .where(DeviceIP.device_id == Device.id)
            .order_by(DeviceIP.is_management.desc(), DeviceIP.is_primary.desc(), DeviceIP.id)
            .limit(1)
            .scalar_subquery()
        )
        rows = (await db.execute(
            select(DeviceAvailability, Device, management_ip.label("management_ip"))
            .join(Device, Device.id == DeviceAvailability.device_id)
            .where(DeviceAvailability.id.in_(list(parsed)))
        )).all()
        targets: list[_ProbeTarget] = []
        for availability, device, ip_address in rows:
            expected_device_id, expected_token = parsed[availability.id]
            if device.id != expected_device_id or availability.lease_token != expected_token:
                continue
            if not availability.enabled or device.lifecycle_state == "DECOMMISSIONED":
                continue
            targets.append(_ProbeTarget(
                availability_id=availability.id,
                device_id=device.id,
                lease_token=expected_token,
                profile=availability.profile,
                ip_address=ip_address,
                credential_reference=device.credential_reference,
            ))
        return targets, runtime


async def _poll_batch(payload: list[dict]) -> dict[str, int]:
    engine, SessionLocal = _session_factory()
    try:
        targets, runtime = await _load_targets(SessionLocal, payload)
        if runtime is None or not targets:
            return {"received": len(payload), "processed": 0, "stale": len(payload), "changed": 0}

        semaphore = asyncio.Semaphore(runtime.worker_concurrency)

        async def run_probe(target: _ProbeTarget):
            async with semaphore:
                access = await _resolve_probe_access(SessionLocal, target, runtime)
                if access.error_code:
                    return target, ProbeObservation(
                        ProbeOutcome.INDETERMINATE,
                        access.error_code,
                    )
                observation = await probe_availability(
                    profile=target.profile,
                    ip_address=target.ip_address,
                    timeout_seconds=access.timeout_seconds,
                    retries=access.retries,
                    tcp_ports=runtime.tcp_ports,
                    credential_reference=access.credential_reference,
                    credential=access.credential,
                    snmp_port=access.snmp_port,
                )
                return target, observation

        logger.info(
            "availability_poll_batch_started",
            extra={"event": "AVAILABILITY_POLL_BATCH_STARTED", "device_count": len(targets)},
        )
        results = await asyncio.gather(*(run_probe(target) for target in targets))
        target_tokens = {target.availability_id: target.lease_token for target in targets}
        observations = {target.availability_id: (target, observation) for target, observation in results}

        processed = changed = 0
        async with SessionLocal() as db:
            rows = (await db.execute(
                select(DeviceAvailability, Device)
                .join(Device, Device.id == DeviceAvailability.device_id)
                .where(DeviceAvailability.id.in_(list(observations)))
                .with_for_update()
            )).all()
            checked_at = datetime.now(timezone.utc)
            for availability, device in rows:
                if availability.lease_token != target_tokens.get(availability.id):
                    continue
                _, observation = observations[availability.id]
                if await apply_observation(
                    db,
                    availability=availability,
                    device=device,
                    observation=observation,
                    failure_threshold=runtime.failure_threshold,
                    checked_at=checked_at,
                ):
                    changed += 1
                processed += 1
            await db.commit()
        stale = max(0, len(payload) - processed)
        logger.info(
            "availability_poll_batch_completed",
            extra={
                "event": "AVAILABILITY_POLL_BATCH_COMPLETED",
                "received": len(payload),
                "processed": processed,
                "stale": stale,
                "changed": changed,
            },
        )
        return {"received": len(payload), "processed": processed, "stale": stale, "changed": changed}
    finally:
        await engine.dispose()


async def _reconcile() -> dict[str, int | str]:
    if await maintenance_mode_active():
        return {"created": 0, "reason": "MAINTENANCE_MODE"}
    engine, SessionLocal = _session_factory()
    try:
        async with SessionLocal() as db:
            runtime = await load_availability_settings(db)
            created = await reconcile_missing_availability_rows(db, interval_seconds=runtime.interval_seconds)
            await db.commit()
        if created:
            logger.info(
                "availability_reconcile_created",
                extra={"event": "AVAILABILITY_RECONCILE_CREATED", "device_count": created},
            )
        return {"created": created}
    finally:
        await engine.dispose()


async def _worker_heartbeat() -> dict[str, str]:
    now = datetime.now(timezone.utc)
    client = Redis.from_url(app_settings.redis_url, decode_responses=True)
    try:
        await client.set(
            "fttw:availability:worker_heartbeat",
            now.isoformat(),
            ex=120,
        )
    finally:
        await client.aclose()
    return {"heartbeat_at": now.isoformat()}


@celery_app.task(name="fttw.availability.dispatch_due", time_limit=20, soft_time_limit=15)
def dispatch_due_availability():
    return asyncio.run(_dispatch_due())


@celery_app.task(name="fttw.availability.poll_batch", time_limit=240, soft_time_limit=220)
def poll_availability_batch(payload: list[dict]):
    return asyncio.run(_poll_batch(payload))


@celery_app.task(name="fttw.availability.reconcile", time_limit=60, soft_time_limit=50)
def reconcile_device_availability():
    return asyncio.run(_reconcile())


@celery_app.task(name="fttw.availability.worker_heartbeat", time_limit=10, soft_time_limit=8)
def availability_worker_heartbeat():
    return asyncio.run(_worker_heartbeat())
