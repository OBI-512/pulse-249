from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.deps import get_db
from app.main import app
from app.models import AuditLog, Permission, RestorePoint, User, UserPermission, UserResourceScope
from app.security.sessions import create_session
from app.services.audit import enable_audit_maintenance
from app.services.maintenance import clear_maintenance_mode, set_maintenance_mode
from app.services.restore_points import (
    _artifact_path,
    _manifest_path,
    automatic_restore_point_due,
    create_restore_point,
    delete_restore_point,
    delete_restore_point_artifacts,
    request_database_restore,
    verify_restore_point,
)
from app.security.passwords import hash_password
from app.security.authorization import authorize_request
from app.settings import settings


async def _run_api_scenario(scenario) -> None:
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with factory() as db:
            yield db

    old = app.dependency_overrides.get(get_db)
    old_auth = app.dependency_overrides.pop(authorize_request, None)
    app.dependency_overrides[get_db] = override_get_db
    try:
        await scenario(factory)
    finally:
        if old is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = old
        if old_auth is not None:
            app.dependency_overrides[authorize_request] = old_auth
        await clear_maintenance_mode()
        await engine.dispose()


async def _user(db: AsyncSession, marker: str, *, permissions: tuple[str, ...]) -> tuple[User, dict[str, str]]:
    user = User(
        external_subject=f"restore-test:{marker}", username=f"restore-test-{marker}",
        display_name="Restore Test", password_hash=hash_password(f"Restore-{marker}-Password!"),
        is_active=True, metadata_={},
    )
    db.add(user)
    await db.flush()
    db.add(UserResourceScope(user_id=user.id, scope_type="GLOBAL"))
    for code in permissions:
        permission = await db.scalar(select(Permission).where(Permission.code == code))
        assert permission is not None
        db.add(UserPermission(user_id=user.id, permission_id=permission.id))
    token, _ = await create_session(db, user_id=user.id)
    await db.commit()
    return user, {"Authorization": f"Bearer {token}"}


async def _cleanup(factory, user_ids, point_ids) -> None:
    async with factory() as db:
        for point_id in point_ids:
            point = await db.get(RestorePoint, point_id)
            if point and point.artifact_name:
                _artifact_path(point.artifact_name).unlink(missing_ok=True)
                _manifest_path(point.artifact_name).unlink(missing_ok=True)
        await enable_audit_maintenance(db)
        await db.execute(delete(AuditLog).where(AuditLog.entity_id.in_(point_ids + user_ids)))
        await db.execute(delete(RestorePoint).where(RestorePoint.id.in_(point_ids)))
        await db.execute(delete(User).where(User.id.in_(user_ids)))
        await db.commit()


def test_manual_restore_point_is_persistent_checksum_verified_and_deletable():
    async def scenario(factory):
        point_ids = []
        try:
            async with factory() as db:
                point = await create_restore_point(
                    db, source="MANUAL", created_by_user_id=None, description="test restore point"
                )
                await db.commit()
                point_ids.append(point.id)
                assert point.status == "READY"
                assert point.artifact_name is not None
                assert _artifact_path(point.artifact_name).exists()
                assert _manifest_path(point.artifact_name).exists()
                verified = await verify_restore_point(db, restore_point_id=point.id)
                assert verified.id == point.id
                point_count = len((await db.scalars(select(RestorePoint))).all())
                previous_restore_setting = settings.enable_database_restore
                settings.enable_database_restore = False
                try:
                    with pytest.raises(Exception) as disabled:
                        await request_database_restore(
                            db, restore_point_id=point.id, confirmation=str(point.id), actor_user_id=uuid4()
                        )
                    assert disabled.value.detail["code"] == "RESTORE_OPERATION_DISABLED"
                finally:
                    settings.enable_database_restore = previous_restore_setting
                assert len((await db.scalars(select(RestorePoint))).all()) == point_count
                deleted_point = await delete_restore_point(db, restore_point_id=point.id)
                artifact_name = deleted_point.artifact_name
                await db.commit()
                assert delete_restore_point_artifacts(artifact_name)
                assert not _artifact_path(artifact_name).exists()
        finally:
            await _cleanup(factory, [], point_ids)

    asyncio.run(_run_api_scenario(scenario))


def test_restore_point_permissions_maintenance_gate_and_automatic_schedule_check():
    async def scenario(factory):
        marker = uuid4().hex[:12]
        user_ids = []
        try:
            async with factory() as db:
                reader, reader_headers = await _user(db, f"reader-{marker}", permissions=("restore_points.read",))
                creator, creator_headers = await _user(db, f"creator-{marker}", permissions=("restore_points.create", "restore_points.read"))
                user_ids.extend([reader.id, creator.id])
                assert not await automatic_restore_point_due(
                    db, now=datetime(2030, 1, 1, 12, 34, tzinfo=timezone.utc)
                )
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                denied = await client.post("/api/restore-points", headers=reader_headers, json={"description": "denied"})
                assert denied.status_code == 403
                listing = await client.get("/api/restore-points", headers=reader_headers)
                assert listing.status_code == 200
                await set_maintenance_mode(restore_point_id=str(uuid4()), request_id="restore-test")
                blocked_headers = {**creator_headers, "Origin": "http://localhost:3000"}
                blocked = await client.post(
                    "/api/networks",
                    headers=blocked_headers,
                    json={"name": "blocked", "code": f"BLOCK-{marker}"},
                )
                assert blocked.status_code == 503
                assert blocked.json()["detail"]["code"] == "MAINTENANCE_MODE_ACTIVE"
                assert blocked.headers["access-control-allow-origin"] == "http://localhost:3000"
        finally:
            await _cleanup(factory, user_ids, [])

    asyncio.run(_run_api_scenario(scenario))
