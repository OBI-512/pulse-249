from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.routers import reports as reports_router
from app.models import AuditLog, DataLifecycleRun, ReportDefinition, ReportJob, ReportSchedule, User
from app.schemas.phase_d import (
    ReportDefinitionRead, ReportJobsDeleteRequest, ReportRunRequest, ReportScheduleRead,
    ReportScheduleUpdate, TelemetryProfileRead,
)
from app.services.data_lifecycle import run_report_configuration_trash_retention
from app.services.reports import report_artifact_filename, report_root
from app.settings import settings as app_settings


def _job(owner_id, *, status="COMPLETED", artifact_name=None) -> ReportJob:
    now = datetime.now(timezone.utc)
    return ReportJob(
        owner_user_id=owner_id,
        definition_id=None,
        schedule_id=None,
        report_type="inventory",
        format="CSV",
        status=status,
        filters={},
        include_sensitive=False,
        scope_snapshot={"global_access": True},
        scope_fingerprint="f" * 64,
        permission_snapshot=["report.read", "report.export", "device.read"],
        requested_at=now,
        completed_at=now if status == "COMPLETED" else None,
        row_count=1,
        artifact_name=artifact_name,
        artifact_size=3 if artifact_name else None,
        artifact_sha256="a" * 64 if artifact_name else None,
        metadata_={"display_name": "North Inventory — 2030-01-01 00:00 UTC"},
    )


def test_report_job_display_name_and_artifact_filename_are_meaningful():
    job = _job(uuid4())
    job.id = uuid4()
    job.requested_at = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert job.display_name == "North Inventory — 2030-01-01 00:00 UTC"
    filename = report_artifact_filename(job)
    assert filename.startswith("north-inventory-2030-01-01-00-00-utc_20300102_030405Z_")
    assert filename.endswith(".csv")
    assert str(job.id)[:8] in filename


def test_generated_report_delete_is_owner_scoped_terminal_only_and_removes_artifacts_in_bulk():
    async def scenario():
        engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
        SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        user_id = None
        completed_ids: list = []
        active_id = None
        artifact_paths: list[Path] = []
        try:
            async with SessionLocal() as db:
                user = User(external_subject=f"enh-b-{uuid4()}", username=f"enh-b-{uuid4().hex[:12]}", display_name="ENH-B report lifecycle", is_active=True, metadata_={})
                db.add(user); await db.flush(); user_id = user.id
                completed_a = _job(user.id, artifact_name=f"enh_b_{uuid4().hex}.csv")
                completed_b = _job(user.id, artifact_name=f"enh_b_{uuid4().hex}.csv")
                active = _job(user.id, status="QUEUED")
                db.add_all([completed_a, completed_b, active]); await db.flush()
                completed_ids=[completed_a.id, completed_b.id]; active_id=active.id
                for row in (completed_a, completed_b):
                    artifact_path = report_root() / row.artifact_name
                    artifact_path.write_bytes(b"abc")
                    artifact_paths.append(artifact_path)
                await db.commit()

            actor = SimpleNamespace(id=user_id)
            async with SessionLocal() as db:
                result = await reports_router.delete_jobs(ReportJobsDeleteRequest(job_ids=completed_ids), db=db, actor=actor)
                assert result.deleted == 2
                assert result.deleted_ids == completed_ids
                assert not list((await db.scalars(select(ReportJob).where(ReportJob.id.in_(completed_ids)))).all())
                assert all(not path.exists() for path in artifact_paths)

            async with SessionLocal() as db:
                with pytest.raises(HTTPException) as exc:
                    await reports_router.delete_jobs(ReportJobsDeleteRequest(job_ids=[active_id]), db=db, actor=actor)
                assert exc.value.status_code == 409
                assert exc.value.detail["code"] == "REPORT_JOB_ACTIVE"
                assert await db.scalar(select(ReportJob).where(ReportJob.id == active_id)) is not None
        finally:
            for artifact_path in artifact_paths:
                artifact_path.unlink(missing_ok=True)
            if user_id is not None:
                async with SessionLocal() as db:
                    await db.execute(delete(ReportJob).where(ReportJob.owner_user_id == user_id))
                    await db.execute(delete(ReportSchedule).where(ReportSchedule.owner_user_id == user_id))
                    await db.execute(delete(ReportDefinition).where(ReportDefinition.owner_user_id == user_id))
                    await db.execute(delete(User).where(User.id == user_id))
                    await db.commit()
            await engine.dispose()
    asyncio.run(scenario())


def test_report_configuration_trash_fields_are_scoped_to_report_configuration_schemas():
    assert {"deleted_at", "purge_after"} <= set(ReportDefinitionRead.model_fields)
    assert {"deleted_at", "purge_after"} <= set(ReportScheduleRead.model_fields)
    assert "deleted_at" not in TelemetryProfileRead.model_fields
    assert "purge_after" not in TelemetryProfileRead.model_fields


def test_definition_and_schedule_trash_lifecycle_is_dependency_safe_and_preserves_history():
    async def scenario():
        engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
        SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        user_id = definition_id = schedule_id = job_id = None
        try:
            async with SessionLocal() as db:
                user = User(external_subject=f"enh-b-{uuid4()}", username=f"enh-b-{uuid4().hex[:12]}", display_name="ENH-B dependency safety", is_active=True, metadata_={})
                db.add(user); await db.flush(); user_id = user.id
                definition = ReportDefinition(owner_user_id=user.id, name="Dependency Definition", report_type="inventory", format="CSV", filters={}, include_sensitive=False, description=None)
                db.add(definition); await db.flush(); definition_id = definition.id
                schedule = ReportSchedule(owner_user_id=user.id, definition_id=definition.id, name="Dependency Schedule", report_type="inventory", format="CSV", filters={}, include_sensitive=False, interval_minutes=1440, enabled=True, next_run_at=datetime.now(timezone.utc)+timedelta(days=1), channel_type=None, destination=None, max_attempts=3, retry_base_seconds=60)
                db.add(schedule); await db.flush(); schedule_id = schedule.id
                historical = _job(user.id)
                historical.definition_id = definition.id
                historical.schedule_id = schedule.id
                db.add(historical); await db.flush(); job_id = historical.id
                await db.commit()

            actor = SimpleNamespace(id=user_id)
            async with SessionLocal() as db:
                with pytest.raises(HTTPException) as exc:
                    await reports_router.delete_definition(definition_id, db=db, actor=actor)
                assert exc.value.status_code == 409
                assert exc.value.detail["code"] == "REPORT_DEFINITION_IN_USE"
                await db.rollback()

            async with SessionLocal() as db:
                result = await reports_router.delete_schedule(schedule_id, db=db, actor=actor)
                assert result["deleted"] is True
                assert result["recoverable"] is True
                schedule = await db.scalar(select(ReportSchedule).where(ReportSchedule.id == schedule_id).execution_options(populate_existing=True))
                history = await db.scalar(select(ReportJob).where(ReportJob.id == job_id).execution_options(populate_existing=True))
                assert schedule is not None and schedule.deleted_at is not None and schedule.purge_after is not None
                assert schedule.enabled is False
                assert history is not None
                assert history.schedule_id == schedule_id
                assert history.definition_id == definition_id

            async with SessionLocal() as db:
                result = await reports_router.delete_definition(definition_id, db=db, actor=actor)
                assert result["deleted"] is True
                assert result["recoverable"] is True
                definition = await db.scalar(select(ReportDefinition).where(ReportDefinition.id == definition_id).execution_options(populate_existing=True))
                history = await db.scalar(select(ReportJob).where(ReportJob.id == job_id).execution_options(populate_existing=True))
                assert definition is not None and definition.deleted_at is not None and definition.purge_after is not None
                assert history is not None
                assert history.schedule_id == schedule_id
                assert history.definition_id == definition_id

            async with SessionLocal() as db:
                with pytest.raises(HTTPException) as exc:
                    await reports_router.restore_schedule(schedule_id, db=db, actor=actor)
                assert exc.value.status_code == 409
                assert exc.value.detail["code"] == "REPORT_DEFINITION_DELETED"
                await db.rollback()

            async with SessionLocal() as db:
                restored_definition = await reports_router.restore_definition(definition_id, db=db, actor=actor)
                assert restored_definition.deleted_at is None
                assert restored_definition.purge_after is None

            async with SessionLocal() as db:
                restored_schedule = await reports_router.restore_schedule(schedule_id, db=db, actor=actor)
                assert restored_schedule.deleted_at is None
                assert restored_schedule.purge_after is None
                assert restored_schedule.enabled is False

            async with SessionLocal() as db:
                await reports_router.delete_schedule(schedule_id, db=db, actor=actor)
            async with SessionLocal() as db:
                result = await reports_router.permanently_delete_schedule(schedule_id, db=db, actor=actor)
                assert result == {"deleted": True, "permanent": True}
                history = await db.scalar(select(ReportJob).where(ReportJob.id == job_id).execution_options(populate_existing=True))
                assert history is not None
                assert history.schedule_id is None
                assert history.definition_id == definition_id

            async with SessionLocal() as db:
                await reports_router.delete_definition(definition_id, db=db, actor=actor)
            async with SessionLocal() as db:
                result = await reports_router.permanently_delete_definition(definition_id, db=db, actor=actor)
                assert result == {"deleted": True, "permanent": True}
                history = await db.scalar(select(ReportJob).where(ReportJob.id == job_id).execution_options(populate_existing=True))
                assert history is not None
                assert history.schedule_id is None
                assert history.definition_id is None
        finally:
            if user_id is not None:
                async with SessionLocal() as db:
                    if job_id is not None:
                        await db.execute(delete(ReportJob).where(ReportJob.id == job_id))
                    if schedule_id is not None:
                        await db.execute(delete(ReportSchedule).where(ReportSchedule.id == schedule_id))
                    if definition_id is not None:
                        await db.execute(delete(ReportDefinition).where(ReportDefinition.id == definition_id))
                    await db.execute(delete(User).where(User.id == user_id))
                    await db.commit()
            await engine.dispose()
    asyncio.run(scenario())


def test_report_configuration_trash_auto_purge_is_dependency_safe_and_preserves_history():
    async def scenario():
        engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
        SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        user_id = definition_id = schedule_id = job_id = lifecycle_run_id = None
        current = datetime(2040, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        try:
            async with SessionLocal() as db:
                user = User(external_subject=f"enh-b-{uuid4()}", username=f"enh-b-{uuid4().hex[:12]}", display_name="ENH-B trash retention", is_active=True, metadata_={})
                db.add(user); await db.flush(); user_id = user.id
                definition = ReportDefinition(owner_user_id=user.id, name="Expired Definition", report_type="inventory", format="CSV", filters={}, include_sensitive=False, description=None, deleted_at=current-timedelta(days=31), purge_after=current-timedelta(minutes=1))
                db.add(definition); await db.flush(); definition_id = definition.id
                schedule = ReportSchedule(owner_user_id=user.id, definition_id=definition.id, name="Expired Schedule", report_type="inventory", format="CSV", filters={}, include_sensitive=False, interval_minutes=1440, enabled=False, next_run_at=current+timedelta(days=1), channel_type=None, destination=None, max_attempts=3, retry_base_seconds=60, deleted_at=current-timedelta(days=31), purge_after=current-timedelta(minutes=1))
                db.add(schedule); await db.flush(); schedule_id = schedule.id
                historical = _job(user.id); historical.definition_id=definition.id; historical.schedule_id=schedule.id
                db.add(historical); await db.flush(); job_id=historical.id
                await db.commit()

            async with SessionLocal() as db:
                run = await run_report_configuration_trash_retention(db, SimpleNamespace(enabled=True, retain_days=30), now=current)
                lifecycle_run_id = run.id
                await db.commit()
                history = await db.scalar(select(ReportJob).where(ReportJob.id == job_id).execution_options(populate_existing=True))
                assert run.status == "COMPLETED"
                assert run.scanned_rows == 2
                assert run.purged_rows == 2
                assert await db.scalar(select(ReportSchedule).where(ReportSchedule.id == schedule_id)) is None
                assert await db.scalar(select(ReportDefinition).where(ReportDefinition.id == definition_id)) is None
                assert history is not None
                assert history.schedule_id is None
                assert history.definition_id is None
        finally:
            if user_id is not None:
                async with SessionLocal() as db:
                    if job_id is not None:
                        await db.execute(delete(ReportJob).where(ReportJob.id == job_id))
                    if schedule_id is not None:
                        await db.execute(delete(ReportSchedule).where(ReportSchedule.id == schedule_id))
                    if definition_id is not None:
                        await db.execute(delete(ReportDefinition).where(ReportDefinition.id == definition_id))
                    if lifecycle_run_id is not None:
                        await db.execute(delete(DataLifecycleRun).where(DataLifecycleRun.id == lifecycle_run_id))
                    await db.execute(delete(User).where(User.id == user_id))
                    await db.commit()
            await engine.dispose()
    asyncio.run(scenario())

def test_schedule_edit_can_relink_definition_and_run_now_preserves_next_run(monkeypatch):
    async def allow_report(_db, _actor, report_type, format, _include_sensitive, _filters=None):
        return report_type.strip().lower(), format.strip().upper()

    async def fake_create_report_job(db, *, owner_user_id, report_type, format, filters, include_sensitive, definition_id=None, schedule_id=None):
        now = datetime.now(timezone.utc)
        row = ReportJob(
            owner_user_id=owner_user_id,
            definition_id=definition_id,
            schedule_id=schedule_id,
            report_type=report_type,
            format=format,
            status="QUEUED",
            filters=filters,
            include_sensitive=include_sensitive,
            scope_snapshot={"global_access": True},
            scope_fingerprint="f" * 64,
            permission_snapshot=["report.read", "report.export", "device.read"],
            requested_at=now,
            row_count=0,
            metadata_={"display_name": "Manual scheduled run"},
        )
        db.add(row); await db.flush(); return row

    monkeypatch.setattr(reports_router, "_validate_actor_report", allow_report)
    monkeypatch.setattr(reports_router, "create_report_job", fake_create_report_job)

    async def scenario():
        engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
        SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        user_id = definition_id = schedule_id = created_job_id = None
        try:
            async with SessionLocal() as db:
                user = User(external_subject=f"enh-b-{uuid4()}", username=f"enh-b-{uuid4().hex[:12]}", display_name="ENH-B schedule lifecycle", is_active=True, metadata_={})
                db.add(user); await db.flush(); user_id=user.id
                definition = ReportDefinition(owner_user_id=user.id, name="Definition B", report_type="customer_service", format="XLSX", filters={"status":"ACTIVE"}, include_sensitive=False, description="Linked definition")
                db.add(definition); await db.flush(); definition_id=definition.id
                next_run = datetime.now(timezone.utc) + timedelta(days=2)
                schedule = ReportSchedule(owner_user_id=user.id, definition_id=None, name="Schedule B", report_type="inventory", format="CSV", filters={}, include_sensitive=False, interval_minutes=1440, enabled=True, next_run_at=next_run, channel_type=None, destination=None, max_attempts=3, retry_base_seconds=60)
                db.add(schedule); await db.flush(); schedule_id=schedule.id
                await db.commit()

            actor=SimpleNamespace(id=user_id)
            async with SessionLocal() as db:
                updated = await reports_router.update_schedule(schedule_id, ReportScheduleUpdate(definition_id=definition_id, name="Schedule B Updated"), db=db, actor=actor)
                assert updated.definition_id == definition_id
                assert updated.report_type == "customer_service"
                assert updated.format == "XLSX"
                assert updated.filters == {"status":"ACTIVE"}

            async with SessionLocal() as db:
                before = await db.scalar(select(ReportSchedule).where(ReportSchedule.id == schedule_id))
                assert before is not None
                planned = before.next_run_at
                result = await reports_router.run_report(ReportRunRequest(schedule_id=schedule_id), db=db, actor=actor)
                created_job_id=result.id
                refreshed = await db.scalar(select(ReportSchedule).where(ReportSchedule.id == schedule_id).execution_options(populate_existing=True))
                assert refreshed is not None
                assert refreshed.next_run_at == planned
                assert refreshed.last_run_at is not None
                assert result.schedule_id == schedule_id
                assert result.definition_id == definition_id
                assert result.report_type == "customer_service"
        finally:
            if user_id is not None:
                async with SessionLocal() as db:
                    if created_job_id is not None:
                        await db.execute(delete(ReportJob).where(ReportJob.id == created_job_id))
                    if schedule_id is not None:
                        await db.execute(delete(ReportSchedule).where(ReportSchedule.id == schedule_id))
                    if definition_id is not None:
                        await db.execute(delete(ReportDefinition).where(ReportDefinition.id == definition_id))
                    await db.execute(delete(User).where(User.id == user_id))
                    await db.commit()
            await engine.dispose()
    asyncio.run(scenario())


def test_report_configuration_lists_are_server_paginated_filterable_and_relationship_aware():
    async def scenario():
        engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
        SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        user_id = definition_id = schedule_id = None
        try:
            async with SessionLocal() as db:
                user = User(external_subject=f"enh-b-list-{uuid4()}", username=f"enh-b-list-{uuid4().hex[:12]}", display_name="ENH-B list scaling", is_active=True, metadata_={})
                db.add(user); await db.flush(); user_id = user.id
                definition = ReportDefinition(owner_user_id=user.id, name="North Inventory", report_type="inventory", format="CSV", filters={}, include_sensitive=False, description="North")
                db.add(definition); await db.flush(); definition_id = definition.id
                schedule = ReportSchedule(owner_user_id=user.id, definition_id=definition.id, name="Daily North", report_type="inventory", format="CSV", filters={}, include_sensitive=False, interval_minutes=1440, enabled=True, next_run_at=datetime.now(timezone.utc)+timedelta(days=1), channel_type=None, destination=None, max_attempts=3, retry_base_seconds=60)
                db.add(schedule); await db.flush(); schedule_id = schedule.id
                await db.commit()

            actor = SimpleNamespace(id=user_id)
            async with SessionLocal() as db:
                definitions_page = await reports_router.definitions(
                    state="active", page=1, page_size=50, search="North", report_type="inventory", format="CSV",
                    link_state="linked", sort_by="name", sort_direction="asc", db=db, actor=actor,
                )
                assert definitions_page.total == 1
                assert definitions_page.page_size == 50
                assert definitions_page.items[0].name == "North Inventory"
                assert len(definitions_page.items[0].linked_schedules) == 1
                assert definitions_page.items[0].linked_schedules[0].name == "Daily North"

            async with SessionLocal() as db:
                schedules_page = await reports_router.schedules(
                    state="active", page=1, page_size=50, search="North", report_type="inventory", format="CSV",
                    link_state="linked", enabled=True, sort_by="name", sort_direction="asc", db=db, actor=actor,
                )
                assert schedules_page.total == 1
                assert schedules_page.items[0].name == "Daily North"
                assert schedules_page.items[0].definition_name == "North Inventory"
                assert schedules_page.items[0].definition_deleted_at is None
        finally:
            if user_id is not None:
                async with SessionLocal() as db:
                    if schedule_id is not None:
                        await db.execute(delete(ReportSchedule).where(ReportSchedule.id == schedule_id))
                    if definition_id is not None:
                        await db.execute(delete(ReportDefinition).where(ReportDefinition.id == definition_id))
                    await db.execute(delete(User).where(User.id == user_id))
                    await db.commit()
            await engine.dispose()
    asyncio.run(scenario())
