from __future__ import annotations

import asyncio
import json
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.deps import get_db
from app.main import app
from app.models import AuditLog, AuthSession, Permission, Role, SystemSetting, User, UserPermission, UserResourceScope, UserRole
from app.security.login_throttle import clear_login_failures
from app.security.passwords import hash_password
from app.security.sessions import create_session, get_session_user
from app.services.audit import enable_audit_maintenance
from app.services.user_security import enforce_user_safety
import app.services.user_security as user_security
from app.settings import settings


ALL_USER_MUTATION_PERMISSIONS = (
    "user.create",
    "user.update",
    "user.deactivate",
    "user.password.reset",
    "user.roles.manage",
    "user.permissions.manage",
)


async def _run_api_scenario(scenario) -> None:
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with factory() as db:
            yield db

    previous = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    try:
        await scenario(factory)
    finally:
        if previous is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous
        await engine.dispose()


async def _create_user(
    db: AsyncSession,
    *,
    marker: str,
    label: str,
    permissions: tuple[str, ...] = (),
    roles: tuple[str, ...] = (),
    password: str | None = None,
) -> tuple[User, str]:
    password = password or f"StageC-{label}-{marker}-Password!"
    user = User(
        external_subject=f"stage-c:{label}:{marker}",
        username=f"stage-c-{label}-{marker}",
        display_name=f"Stage C {label}",
        password_hash=hash_password(password),
        is_active=True,
        metadata_={},
    )
    db.add(user)
    await db.flush()
    db.add(UserResourceScope(user_id=user.id, scope_type="GLOBAL"))
    for code in permissions:
        permission = await db.scalar(select(Permission).where(Permission.code == code))
        assert permission is not None, code
        db.add(UserPermission(user_id=user.id, permission_id=permission.id))
    for code in roles:
        role = await db.scalar(select(Role).where(Role.code == code))
        assert role is not None, code
        db.add(UserRole(user_id=user.id, role_id=role.id))
    await db.commit()
    return user, password


async def _headers_for(db: AsyncSession, user: User) -> dict[str, str]:
    token, _ = await create_session(db, user_id=user.id)
    await db.commit()
    return {"Authorization": f"Bearer {token}"}


async def _cleanup(factory, user_ids: list[UUID], setting_keys: list[str] = []) -> None:
    async with factory() as db:
        await enable_audit_maintenance(db)
        await db.execute(delete(AuditLog).where(AuditLog.entity_id.in_(user_ids)))
        if setting_keys:
            await db.execute(delete(SystemSetting).where(SystemSetting.key.in_(setting_keys)))
        await db.execute(delete(AuthSession).where(AuthSession.user_id.in_(user_ids)))
        await db.execute(delete(User).where(User.id.in_(user_ids)))
        await db.commit()


def test_explicit_user_permissions_unknown_assignments_and_self_deactivation_are_enforced():
    async def scenario(factory):
        marker = uuid4().hex[:12]
        ids: list[UUID] = []
        try:
            async with factory() as db:
                actor, _ = await _create_user(
                    db, marker=marker, label="actor", permissions=ALL_USER_MUTATION_PERMISSIONS
                )
                limited, _ = await _create_user(
                    db, marker=marker, label="limited", permissions=("user.create",)
                )
                ids.extend([actor.id, limited.id])
                actor_headers = await _headers_for(db, actor)
                limited_headers = await _headers_for(db, limited)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                created = await client.post(
                    "/api/admin/users", headers=actor_headers,
                    json={"username": f"stage-c-target-{marker}", "password": f"Target-{marker}-Password!"},
                )
                assert created.status_code == 201, created.text
                target_id = UUID(created.json()["id"])
                ids.append(target_id)

                denied_update = await client.patch(
                    f"/api/admin/users/{target_id}", headers=limited_headers,
                    json={"display_name": "No authority"},
                )
                assert denied_update.status_code == 403

                unknown_role = await client.patch(
                    f"/api/admin/users/{target_id}", headers=actor_headers,
                    json={"role_codes": ["does-not-exist"]},
                )
                assert unknown_role.status_code == 422
                assert unknown_role.json()["detail"]["code"] == "UNKNOWN_ROLE_CODE"

                unknown_permission = await client.patch(
                    f"/api/admin/users/{target_id}", headers=actor_headers,
                    json={"permission_codes": ["does-not-exist"]},
                )
                assert unknown_permission.status_code == 422
                assert unknown_permission.json()["detail"]["code"] == "UNKNOWN_PERMISSION_CODE"

                self_disable = await client.patch(
                    f"/api/admin/users/{actor.id}", headers=actor_headers,
                    json={"is_active": False},
                )
                assert self_disable.status_code == 409
                assert self_disable.json()["detail"]["code"] == "SELF_DEACTIVATION_PROHIBITED"
        finally:
            await _cleanup(factory, ids)

    asyncio.run(_run_api_scenario(scenario))


def test_last_administrator_protection_uses_locked_authoritative_role_rows():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        async with engine.connect() as connection:
            outer = await connection.begin()
            factory = async_sessionmaker(
                bind=connection, class_=AsyncSession, expire_on_commit=False,
                join_transaction_mode="create_savepoint",
            )
            try:
                async with factory() as db:
                    administrator = await db.scalar(select(Role).where(Role.code == "administrator"))
                    assert administrator is not None
                    # This transaction-local setup hides all seeded admin
                    # memberships and leaves one locked synthetic admin; the
                    # outer rollback guarantees no shared environment changes.
                    await db.execute(delete(UserRole).where(UserRole.role_id == administrator.id))
                    sole, _ = await _create_user(db, marker=uuid4().hex[:12], label="sole")
                    db.add(UserRole(user_id=sole.id, role_id=administrator.id))
                    await db.flush()
                    with pytest.raises(Exception) as exc_info:
                        await enforce_user_safety(
                            db, actor_user_id=uuid4(), target=sole,
                            proposed_active=False, proposed_role_codes=["administrator"],
                        )
                    assert exc_info.value.detail["code"] == "LAST_ADMINISTRATOR_PROTECTED"
            finally:
                await outer.rollback()
        await engine.dispose()

    asyncio.run(scenario())


def test_concurrent_last_administrator_deactivations_serialize_safely(monkeypatch):
    """Two real sessions cannot both remove the final administrator role holder."""

    marker = uuid4().hex[:12]
    role_code = f"stage-c-admin-{marker}"
    original = user_security.ADMINISTRATOR_ROLE_CODE
    monkeypatch.setattr(user_security, "ADMINISTRATOR_ROLE_CODE", role_code)

    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        user_ids: list[UUID] = []
        role_id = None
        try:
            async with factory() as db:
                role = Role(name=f"Stage C admin {marker}", code=role_code)
                db.add(role)
                await db.flush()
                role_id = role.id
                for label in ("first", "second"):
                    user, _ = await _create_user(db, marker=marker, label=label)
                    user_ids.append(user.id)
                    db.add(UserRole(user_id=user.id, role_id=role.id))
                await db.commit()

            async def deactivate(user_id: UUID) -> str:
                async with factory() as db:
                    try:
                        target = await user_security.get_user_for_update(db, user_id)
                        await user_security.enforce_user_safety(
                            db, actor_user_id=uuid4(), target=target,
                            proposed_active=False, proposed_role_codes=[role_code],
                        )
                        target.is_active = False
                        await db.commit()
                        return "DEACTIVATED"
                    except Exception as exc:
                        await db.rollback()
                        return exc.detail["code"] if hasattr(exc, "detail") else type(exc).__name__

            outcomes = await asyncio.gather(*(deactivate(user_id) for user_id in user_ids))
            assert sorted(outcomes) == ["DEACTIVATED", "LAST_ADMINISTRATOR_PROTECTED"]
            async with factory() as db:
                active = await db.scalar(
                    select(func.count()).select_from(User).join(UserRole, UserRole.user_id == User.id).where(
                        UserRole.role_id == role_id, User.is_active.is_(True)
                    )
                )
                assert active == 1
        finally:
            async with factory() as db:
                await db.execute(delete(User).where(User.id.in_(user_ids)))
                if role_id is not None:
                    await db.execute(delete(Role).where(Role.id == role_id))
                await db.commit()
            await engine.dispose()

    try:
        asyncio.run(scenario())
    finally:
        monkeypatch.setattr(user_security, "ADMINISTRATOR_ROLE_CODE", original)


def test_password_change_reset_and_security_relevant_user_changes_revoke_sessions_and_redact_audit():
    async def scenario(factory):
        marker = uuid4().hex[:12]
        ids: list[UUID] = []
        secret = f"StageC-Secret-{marker}-Password!"
        try:
            async with factory() as db:
                actor, _ = await _create_user(db, marker=marker, label="admin", permissions=ALL_USER_MUTATION_PERMISSIONS)
                subject, subject_password = await _create_user(db, marker=marker, label="subject", password=secret)
                ids.extend([actor.id, subject.id])
                actor_headers = await _headers_for(db, actor)
                subject_headers = await _headers_for(db, subject)
                token, session = await create_session(db, user_id=subject.id)
                await db.commit()
                session_id = session.id

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                wrong = await client.post(
                    "/api/auth/password/change", headers=subject_headers,
                    json={"current_password": "wrong-password", "new_password": f"Changed-{marker}-Password!"},
                )
                assert wrong.status_code == 422
                changed = await client.post(
                    "/api/auth/password/change", headers=subject_headers,
                    json={"current_password": subject_password, "new_password": f"Changed-{marker}-Password!"},
                )
                assert changed.status_code == 204, changed.text

            async with factory() as db:
                assert await get_session_user(db, session_token=token) is None
                reset_token, _ = await create_session(db, user_id=subject.id)
                await db.commit()

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                reset = await client.post(
                    f"/api/admin/users/{subject.id}/password-reset", headers=actor_headers,
                    json={"new_password": f"Reset-{marker}-Password!"},
                )
                assert reset.status_code == 204, reset.text
            async with factory() as db:
                assert await get_session_user(db, session_token=reset_token) is None
                rows = list((await db.scalars(select(AuditLog).where(AuditLog.entity_id == subject.id))).all())
                audit_blob = json.dumps([
                    {"metadata": row.metadata_, "description": row.description, "before": row.before_summary, "after": row.after_summary}
                    for row in rows
                ], default=str)
                assert secret not in audit_blob
                assert subject_password not in audit_blob
                assert {"PASSWORD_CHANGED", "PASSWORD_RESET", "SESSION_REVOKED"} <= {row.action for row in rows}
        finally:
            await _cleanup(factory, ids)

    asyncio.run(_run_api_scenario(scenario))


def test_role_permission_and_deactivation_changes_revoke_sessions_and_secret_setting_is_masked():
    async def scenario(factory):
        marker = uuid4().hex[:12]
        ids: list[UUID] = []
        setting_key = f"stage-c.secret.{marker}"
        try:
            async with factory() as db:
                actor, _ = await _create_user(
                    db, marker=marker, label="manager", permissions=ALL_USER_MUTATION_PERMISSIONS + ("settings.read", "settings.manage")
                )
                reader, _ = await _create_user(db, marker=marker, label="reader", permissions=("settings.read",))
                subject, _ = await _create_user(db, marker=marker, label="subject")
                ids.extend([actor.id, reader.id, subject.id])
                actor_headers = await _headers_for(db, actor)
                reader_headers = await _headers_for(db, reader)
                db.add(SystemSetting(key=setting_key, value={"password": "must-not-leak"}, description="secret", is_secret=True))
                await db.commit()
                role_token, _ = await create_session(db, user_id=subject.id)
                await db.commit()

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                role_change = await client.patch(f"/api/admin/users/{subject.id}", headers=actor_headers, json={"role_codes": ["operator"]})
                assert role_change.status_code == 200, role_change.text
                hidden = await client.get("/api/admin/settings", headers=reader_headers)
                assert hidden.status_code == 200
                setting = next(item for item in hidden.json() if item["key"] == setting_key)
                assert setting["value"] == {"value": "[REDACTED]"}
            async with factory() as db:
                assert await get_session_user(db, session_token=role_token) is None
                permission_token, _ = await create_session(db, user_id=subject.id)
                await db.commit()
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                permission_change = await client.patch(f"/api/admin/users/{subject.id}", headers=actor_headers, json={"permission_codes": ["device.read"]})
                assert permission_change.status_code == 200, permission_change.text
            async with factory() as db:
                assert await get_session_user(db, session_token=permission_token) is None
                deactivate_token, _ = await create_session(db, user_id=subject.id)
                await db.commit()
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                deactivated = await client.delete(f"/api/admin/users/{subject.id}", headers=actor_headers)
                assert deactivated.status_code == 204, deactivated.text
            async with factory() as db:
                assert await get_session_user(db, session_token=deactivate_token) is None
        finally:
            await _cleanup(factory, ids, [setting_key])

    asyncio.run(_run_api_scenario(scenario))


def test_redis_login_throttle_records_failures_and_resets_after_success():
    async def scenario(factory):
        marker = uuid4().hex[:12]
        user_id = None
        username = f"stage-c-throttle-{marker}"
        source_ip = "127.0.0.1"
        try:
            async with factory() as db:
                user, password = await _create_user(db, marker=marker, label="throttle")
                user_id = user.id
                username = user.username
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                for _ in range(settings.login_rate_limit_attempts):
                    failed = await client.post("/api/auth/login", json={"username": username, "password": "not-the-password"})
                    assert failed.status_code == 401
                limited = await client.post("/api/auth/login", json={"username": username, "password": password})
                assert limited.status_code == 429
                assert limited.json()["detail"]["code"] == "LOGIN_RATE_LIMITED"
                await clear_login_failures(username=username, source_ip=source_ip)
                success = await client.post("/api/auth/login", json={"username": username, "password": password})
                assert success.status_code == 200, success.text
        finally:
            await clear_login_failures(username=username, source_ip=source_ip)
            if user_id is not None:
                await _cleanup(factory, [user_id])

    asyncio.run(_run_api_scenario(scenario))
