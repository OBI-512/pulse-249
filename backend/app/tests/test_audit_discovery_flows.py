from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.deps import get_db
from app.discovery.models import DiscoveryResult as AdapterResult
from app.main import app
from app.models import (
    AuditLog,
    AuthSession,
    DeviceCandidate,
    DiscoveryJob,
    DiscoveryResult,
    Permission,
    User,
    UserPermission,
)
from app.security.authorization import authorize_request
from app.security.passwords import hash_password
from app.services.audit import enable_audit_maintenance
from app.settings import settings
from app.tasks.discovery import _execute_discovery_job


class SuccessfulAdapter:
    async def discover(self, context):
        return AdapterResult(
            success=True,
            method="ICMP",
            ip_address=context.ip_address,
            vendor=None,
            model=None,
            hostname=None,
            serial_number=None,
            management_protocol="ICMP",
            response_time_ms=1.0,
            message="Reachable.",
            raw_data={},
        )


async def _run_api_scenario(scenario):
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with factory() as db:
            yield db

    previous_db = app.dependency_overrides.get(get_db)
    previous_auth = app.dependency_overrides.pop(authorize_request, None)
    app.dependency_overrides[get_db] = override_get_db
    try:
        await scenario(factory)
    finally:
        if previous_db is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous_db
        if previous_auth is not None:
            app.dependency_overrides[authorize_request] = previous_auth
        await engine.dispose()


async def _actor(db, marker):
    user = User(
        external_subject=f"audit-discovery:{marker}",
        username=f"audit-discovery-{marker}",
        display_name="Discovery Auditor",
        password_hash=hash_password(f"Discovery-{marker}-Password"),
        is_active=True,
        metadata_={},
    )
    permission = await db.scalar(select(Permission).where(Permission.code == "discovery.run"))
    assert permission is not None
    db.add(user)
    await db.flush()
    db.add(UserPermission(user_id=user.id, permission_id=permission.id))
    await db.commit()
    return user, f"Discovery-{marker}-Password"


async def _cleanup(factory, *, actor_id, request_prefix, job_ids=(), candidate_ips=()):
    async with factory() as db:
        await enable_audit_maintenance(db)
        await db.execute(delete(AuditLog).where(AuditLog.request_id.like(f"{request_prefix}%")))
        if candidate_ips:
            await db.execute(
                delete(DeviceCandidate).where(DeviceCandidate.ip_address.in_(candidate_ips))
            )
        if job_ids:
            normalized_job_ids = [UUID(str(job_id)) for job_id in job_ids]
            await db.execute(
                delete(DiscoveryResult).where(
                    DiscoveryResult.discovery_job_id.in_(normalized_job_ids)
                )
            )
            await db.execute(delete(DiscoveryJob).where(DiscoveryJob.id.in_(normalized_job_ids)))
        await db.execute(delete(AuthSession).where(AuthSession.user_id == actor_id))
        await db.execute(delete(User).where(User.id == actor_id))
        await db.commit()


async def _login(client, user, password, request_id):
    response = await client.post(
        "/api/auth/login",
        headers={"X-Request-ID": request_id},
        json={"username": user.username, "password": password},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def test_synchronous_discovery_success_and_failure_are_correlated_and_redacted():
    async def scenario(factory):
        marker = uuid4().hex[:12]
        prefix = f"audit-sync-{marker}"
        success_ip = f"198.17.{uuid4().int % 250 + 1}.{uuid4().int % 250 + 1}"
        failure_ip = f"198.16.{uuid4().int % 250 + 1}.{uuid4().int % 250 + 1}"
        job_ids = []
        async with factory() as db:
            actor, password = await _actor(db, marker)
            actor_id = actor.id
        failure_secret = f"DISCOVERY-{marker}-CREDENTIAL-SECRET"
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test"
            ) as client:
                token = await _login(client, actor, password, f"{prefix}-login")
                headers = {"Authorization": f"Bearer {token}"}
                with patch(
                    "app.api.routers.discovery.registry.get",
                    return_value=SuccessfulAdapter(),
                ):
                    success = await client.post(
                        "/api/discovery/run",
                        headers={**headers, "X-Request-ID": f"{prefix}-success"},
                        json={
                            "ip_address": success_ip,
                            "methods": ["ICMP"],
                            "timeout_seconds": 1,
                        },
                    )
                assert success.status_code == 200, success.text
                job_ids.append(success.json()["job_id"])

                with patch(
                    "app.api.routers.discovery.discovery_engine.run",
                    AsyncMock(side_effect=RuntimeError(failure_secret)),
                ):
                    failed = await client.post(
                        "/api/discovery/run",
                        headers={**headers, "X-Request-ID": f"{prefix}-failed"},
                        json={
                            "ip_address": failure_ip,
                            "methods": ["ICMP"],
                            "timeout_seconds": 1,
                        },
                    )
                assert failed.status_code == 500

            async with factory() as db:
                jobs = list(
                    (
                        await db.scalars(
                            select(DiscoveryJob).where(
                                DiscoveryJob.scope_value.in_([success_ip, failure_ip])
                            )
                        )
                    ).all()
                )
                job_ids[:] = [str(job.id) for job in jobs]
                assert {job.status for job in jobs} == {"COMPLETED", "FAILED"}
                audits = list(
                    (
                        await db.scalars(
                            select(AuditLog).where(AuditLog.request_id.like(f"{prefix}%"))
                        )
                    ).all()
                )
                success_actions = {
                    row.action
                    for row in audits
                    if row.request_id == f"{prefix}-success"
                }
                assert {"DISCOVERY_STARTED", "DISCOVERY_COMPLETED"} <= success_actions
                failure_audit = next(
                    row
                    for row in audits
                    if row.action == "DISCOVERY_FAILED"
                    and row.request_id == f"{prefix}-failed"
                )
                assert failure_audit.result == "FAILURE"
                assert failure_audit.actor_user_id == actor_id
                assert failure_audit.actor_username_snapshot == actor.username
                assert failure_audit.source_ip is not None
                serialized = json.dumps(
                    [
                        {
                            "description": row.description,
                            "metadata": row.metadata_,
                            "before": row.before_summary,
                            "after": row.after_summary,
                        }
                        for row in audits
                    ],
                    default=str,
                )
                assert failure_secret not in serialized
        finally:
            await _cleanup(
                factory,
                actor_id=actor_id,
                request_prefix=prefix,
                job_ids=job_ids,
                candidate_ips=[success_ip, failure_ip],
            )

    asyncio.run(_run_api_scenario(scenario))


def test_batch_queue_and_worker_propagate_request_actor_and_task_correlation():
    async def scenario(factory):
        marker = uuid4().hex[:12]
        prefix = f"audit-batch-{marker}"
        target_ip = f"198.15.{uuid4().int % 250 + 1}.{uuid4().int % 250 + 1}"
        job_ids = []
        async with factory() as db:
            actor, password = await _actor(db, marker)
            actor_id = actor.id
        captured_args = None
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test"
            ) as client:
                token = await _login(client, actor, password, f"{prefix}-login")
                with patch(
                    "app.api.routers.batch_discovery.celery_app.send_task",
                    return_value=SimpleNamespace(id=f"task-{marker}"),
                ) as send_task:
                    queued = await client.post(
                        "/api/discovery/batch/jobs",
                        headers={
                            "Authorization": f"Bearer {token}",
                            "X-Request-ID": f"{prefix}-request",
                        },
                        json={
                            "ip_addresses": [target_ip],
                            "cidrs": [],
                            "methods": ["ICMP"],
                            "timeout_seconds": 1,
                            "concurrency": 1,
                            "max_targets": 10,
                        },
                    )
                assert queued.status_code == 202, queued.text
                job_id = queued.json()["job_id"]
                job_ids.append(job_id)
                captured_args = send_task.call_args.kwargs["args"]
                assert captured_args[5] == f"{prefix}-request"
                assert captured_args[6] == str(actor_id)
                assert captured_args[7] == actor.username
                assert captured_args[8] is not None

            with patch(
                "app.tasks.discovery.BatchDiscoveryEngine.run",
                AsyncMock(return_value=[]),
            ), patch(
                "app.tasks.discovery._process_results_into_candidates",
                AsyncMock(return_value=0),
            ):
                result = await _execute_discovery_job(
                    job_id=UUID(job_id),
                    targets=[target_ip],
                    methods=["ICMP"],
                    timeout_seconds=1,
                    concurrency=1,
                    request_id=captured_args[5],
                    actor_user_id=actor_id,
                    actor_username_snapshot=actor.username,
                    source_ip=captured_args[8],
                    task_id=f"task-{marker}",
                )
            assert result["status"] == "COMPLETED"

            async with factory() as db:
                job = await db.get(DiscoveryJob, UUID(job_id))
                assert job is not None
                assert job.status == "COMPLETED"
                rows = list(
                    (
                        await db.scalars(
                            select(AuditLog).where(
                                AuditLog.request_id == f"{prefix}-request",
                                AuditLog.entity_id == job.id,
                            )
                        )
                    ).all()
                )
                started_phases = {
                    row.metadata_.get("phase")
                    for row in rows
                    if row.action == "DISCOVERY_STARTED"
                }
                assert {"QUEUED", "WORKER"} <= started_phases
                completed = next(row for row in rows if row.action == "DISCOVERY_COMPLETED")
                assert completed.actor_user_id == actor_id
                assert completed.metadata_["task_id"] == f"task-{marker}"
                assert completed.result == "SUCCESS"
        finally:
            await _cleanup(
                factory,
                actor_id=actor_id,
                request_prefix=prefix,
                job_ids=job_ids,
                candidate_ips=[target_ip],
            )

    asyncio.run(_run_api_scenario(scenario))


def test_batch_queue_and_worker_failures_are_durable_without_raw_errors():
    async def scenario(factory):
        marker = uuid4().hex[:12]
        prefix = f"audit-batch-fail-{marker}"
        queue_ip = f"198.14.{uuid4().int % 250 + 1}.{uuid4().int % 250 + 1}"
        worker_ip = f"198.13.{uuid4().int % 250 + 1}.{uuid4().int % 250 + 1}"
        queue_secret = f"QUEUE-{marker}-SECRET"
        worker_secret = f"WORKER-{marker}-SECRET"
        job_ids = []
        async with factory() as db:
            actor, password = await _actor(db, marker)
            actor_id = actor.id
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test"
            ) as client:
                token = await _login(client, actor, password, f"{prefix}-login")
                with patch(
                    "app.api.routers.batch_discovery.celery_app.send_task",
                    side_effect=RuntimeError(queue_secret),
                ):
                    failed = await client.post(
                        "/api/discovery/batch/jobs",
                        headers={
                            "Authorization": f"Bearer {token}",
                            "X-Request-ID": f"{prefix}-queue",
                        },
                        json={
                            "ip_addresses": [queue_ip],
                            "cidrs": [],
                            "methods": ["ICMP"],
                            "timeout_seconds": 1,
                            "concurrency": 1,
                            "max_targets": 10,
                        },
                    )
                assert failed.status_code == 503

            async with factory() as db:
                queue_job = await db.scalar(
                    select(DiscoveryJob).where(DiscoveryJob.scope_value == queue_ip)
                )
                assert queue_job is not None and queue_job.status == "FAILED"
                job_ids.append(str(queue_job.id))
                worker_job = DiscoveryJob(
                    scope_type="BATCH",
                    scope_value=worker_ip,
                    status="QUEUED",
                    metadata_={"methods": ["ICMP"]},
                )
                db.add(worker_job)
                await db.commit()
                job_ids.append(str(worker_job.id))

            with patch(
                "app.tasks.discovery.BatchDiscoveryEngine.run",
                AsyncMock(side_effect=RuntimeError(worker_secret)),
            ):
                with pytest.raises(RuntimeError):
                    await _execute_discovery_job(
                        job_id=worker_job.id,
                        targets=[worker_ip],
                        methods=["ICMP"],
                        timeout_seconds=1,
                        concurrency=1,
                        request_id=f"{prefix}-worker",
                        actor_user_id=actor_id,
                        actor_username_snapshot=actor.username,
                        source_ip="127.0.0.1",
                        task_id=f"task-fail-{marker}",
                    )

            async with factory() as db:
                refreshed_worker = await db.get(DiscoveryJob, worker_job.id)
                assert refreshed_worker is not None and refreshed_worker.status == "FAILED"
                failures = list(
                    (
                        await db.scalars(
                            select(AuditLog).where(
                                AuditLog.action == "DISCOVERY_FAILED",
                                AuditLog.request_id.in_(
                                    [f"{prefix}-queue", f"{prefix}-worker"]
                                ),
                            )
                        )
                    ).all()
                )
                assert len(failures) == 2
                assert all(row.result == "FAILURE" for row in failures)
                assert all(row.actor_user_id == actor_id for row in failures)
                serialized = json.dumps([row.metadata_ for row in failures])
                assert queue_secret not in serialized
                assert worker_secret not in serialized
        finally:
            await _cleanup(
                factory,
                actor_id=actor_id,
                request_prefix=prefix,
                job_ids=job_ids,
                candidate_ips=[queue_ip, worker_ip],
            )

    asyncio.run(_run_api_scenario(scenario))
