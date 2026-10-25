from __future__ import annotations

import asyncio
import json
from uuid import uuid4

from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.deps import get_db
from app.main import app
from app.models import (
    AuditLog,
    AuthSession,
    Permission,
    Role,
    SystemSetting,
    User,
    UserPermission,
    UserResourceScope,
    UserRole,
)
from app.security.authorization import authorize_request
from app.security.passwords import hash_password
from app.services.audit import enable_audit_maintenance
from app.settings import settings


async def _run_api_scenario(scenario) -> None:
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


async def _actor(
    db: AsyncSession,
    *,
    marker: str,
    permission_codes: tuple[str, ...] = (),
) -> tuple[User, str]:
    password = f"Audit-Actor-{marker}-Password"
    user = User(
        external_subject=f"audit:{marker}",
        username=f"audit-{marker}",
        display_name="Audit Actor",
        password_hash=hash_password(password),
        is_active=True,
        metadata_={},
    )
    db.add(user)
    await db.flush()
    db.add(UserResourceScope(user_id=user.id, scope_type="GLOBAL"))
    for code in permission_codes:
        permission = await db.scalar(select(Permission).where(Permission.code == code))
        assert permission is not None
        db.add(UserPermission(user_id=user.id, permission_id=permission.id))
    await db.commit()
    return user, password


async def _cleanup(factory, *, user_ids, request_prefix: str, setting_key: str | None = None):
    async with factory() as db:
        await enable_audit_maintenance(db)
        await db.execute(
            delete(AuditLog).where(AuditLog.request_id.like(f"{request_prefix}%"))
        )
        if setting_key is not None:
            await db.execute(delete(SystemSetting).where(SystemSetting.key == setting_key))
        await db.execute(delete(AuthSession).where(AuthSession.user_id.in_(user_ids)))
        await db.execute(delete(User).where(User.id.in_(user_ids)))
        await db.commit()


def _audit_blob(row: AuditLog) -> str:
    return json.dumps(
        {
            "actor": row.actor_username_snapshot,
            "display": row.entity_display_snapshot,
            "description": row.description,
            "before": row.before_summary,
            "after": row.after_summary,
            "metadata": row.metadata_,
        },
        sort_keys=True,
        default=str,
    )


def test_login_failure_success_logout_are_correlated_durable_and_redacted():
    async def scenario(factory):
        marker = uuid4().hex[:12]
        request_prefix = f"audit-auth-{marker}"
        async with factory() as db:
            actor, password = await _actor(db, marker=marker)
            actor_id = actor.id
            password_hash = actor.password_hash

        failed_secret = f"FAILED-{marker}-PASSWORD-SECRET"
        token = None
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                failed = await client.post(
                    "/api/auth/login",
                    headers={"X-Request-ID": f"{request_prefix}-failed"},
                    json={"username": actor.username, "password": failed_secret},
                )
                assert failed.status_code == 401
                assert failed.headers["X-Request-ID"] == f"{request_prefix}-failed"

                logged_in = await client.post(
                    "/api/auth/login",
                    headers={"X-Request-ID": f"{request_prefix}-success"},
                    json={"username": actor.username, "password": password},
                )
                assert logged_in.status_code == 200
                assert logged_in.headers["X-Request-ID"] == f"{request_prefix}-success"
                token = logged_in.json()["access_token"]

                logged_out = await client.post(
                    "/api/auth/logout",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "X-Request-ID": f"{request_prefix}-logout",
                    },
                )
                assert logged_out.status_code == 200

            async with factory() as db:
                rows = list(
                    (
                        await db.scalars(
                            select(AuditLog)
                            .where(AuditLog.request_id.like(f"{request_prefix}%"))
                            .order_by(AuditLog.occurred_at, AuditLog.id)
                        )
                    ).all()
                )
                by_action = {row.action: row for row in rows}
                assert {"LOGIN_FAILED", "LOGIN_SUCCESS", "SESSION_REVOKED", "LOGOUT"} <= set(
                    by_action
                )
                failed_audit = by_action["LOGIN_FAILED"]
                assert failed_audit.result == "FAILURE"
                assert failed_audit.entity_id == actor_id
                assert failed_audit.actor_user_id is None
                assert failed_audit.actor_username_snapshot == actor.username
                assert failed_audit.source_ip is not None

                success_audit = by_action["LOGIN_SUCCESS"]
                assert success_audit.result == "SUCCESS"
                assert success_audit.actor_user_id == actor_id
                assert success_audit.actor_username_snapshot == actor.username
                assert success_audit.request_id == f"{request_prefix}-success"

                logout_audit = by_action["LOGOUT"]
                assert logout_audit.actor_user_id == actor_id
                assert logout_audit.request_id == f"{request_prefix}-logout"
                combined = " ".join(_audit_blob(row) for row in rows)
                assert failed_secret not in combined
                assert password not in combined
                assert password_hash not in combined
                assert token not in combined
        finally:
            await _cleanup(factory, user_ids=[actor_id], request_prefix=request_prefix)

    asyncio.run(_run_api_scenario(scenario))


def test_admin_user_and_setting_changes_capture_actor_diffs_and_mask_secret_downgrade():
    async def scenario(factory):
        marker = uuid4().hex[:12]
        request_prefix = f"audit-admin-{marker}"
        setting_key = f"audit.secret.{marker}"
        target_id = None
        async with factory() as db:
            actor, password = await _actor(
                db,
                marker=marker,
                permission_codes=(
                    "user.create",
                    "user.update",
                    "user.deactivate",
                    "user.roles.manage",
                    "user.permissions.manage",
                    "settings.manage",
                ),
            )
            actor_id = actor.id
            operator = await db.scalar(select(Role).where(Role.code == "operator"))
            assert operator is not None
            # Legacy rows predate the typed Stage G registry.  They remain
            # writable only for controlled migration/cleanup, which preserves
            # the Stage B secret-downgrade audit guarantee without allowing
            # arbitrary new settings to be created through the API.
            db.add(SystemSetting(
                key=setting_key,
                value={"credential": "initial-secret"},
                description="Legacy audit secret setting",
                is_secret=True,
            ))
            await db.commit()

        target_password = f"TARGET-{marker}-PASSWORD-SECRET"
        secret_value = f"SETTING-{marker}-FIRST-SECRET"
        downgraded_value = f"SETTING-{marker}-DOWNGRADED-SECRET"
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                login = await client.post(
                    "/api/auth/login",
                    headers={"X-Request-ID": f"{request_prefix}-login"},
                    json={"username": actor.username, "password": password},
                )
                assert login.status_code == 200
                headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

                created = await client.post(
                    "/api/admin/users",
                    headers={**headers, "X-Request-ID": f"{request_prefix}-create"},
                    json={
                        "username": f"target-{marker}",
                        "display_name": "Audit Target",
                        "password": target_password,
                        "role_codes": [],
                        "permission_codes": [],
                    },
                )
                assert created.status_code == 201, created.text
                target_id = created.json()["id"]

                changed = await client.patch(
                    f"/api/admin/users/{target_id}",
                    headers={**headers, "X-Request-ID": f"{request_prefix}-change"},
                    json={
                        "display_name": "Changed Target",
                        "is_active": False,
                        "role_codes": ["operator"],
                        "permission_codes": ["device.read"],
                    },
                )
                assert changed.status_code == 200, changed.text

                reactivated = await client.patch(
                    f"/api/admin/users/{target_id}",
                    headers={**headers, "X-Request-ID": f"{request_prefix}-reactivate"},
                    json={"is_active": True},
                )
                assert reactivated.status_code == 200

                first_setting = await client.put(
                    f"/api/admin/settings/{setting_key}",
                    headers={**headers, "X-Request-ID": f"{request_prefix}-setting-secret"},
                    json={
                        "value": {"credential": secret_value},
                        "description": "Audit secret setting",
                        "is_secret": True,
                    },
                )
                assert first_setting.status_code == 200

                downgraded = await client.put(
                    f"/api/admin/settings/{setting_key}",
                    headers={**headers, "X-Request-ID": f"{request_prefix}-setting-downgrade"},
                    json={
                        "value": {"value": downgraded_value},
                        "description": "Audit downgraded setting",
                        "is_secret": False,
                    },
                )
                assert downgraded.status_code == 200

                deactivated = await client.delete(
                    f"/api/admin/users/{target_id}",
                    headers={**headers, "X-Request-ID": f"{request_prefix}-delete"},
                )
                assert deactivated.status_code == 204

            async with factory() as db:
                rows = list(
                    (
                        await db.scalars(
                            select(AuditLog).where(AuditLog.request_id.like(f"{request_prefix}%"))
                        )
                    ).all()
                )
                actions = {row.action for row in rows}
                assert {
                    "USER_CREATED",
                    "USER_UPDATED",
                    "USER_DEACTIVATED",
                    "USER_REACTIVATED",
                    "USER_ROLE_CHANGED",
                    "USER_PERMISSION_CHANGED",
                    "SETTING_CHANGED",
                } <= actions
                mutation_rows = [row for row in rows if row.action != "LOGIN_SUCCESS"]
                assert all(row.actor_user_id == actor_id for row in mutation_rows)
                assert all(row.actor_username_snapshot == actor.username for row in mutation_rows)
                assert all(row.result == "SUCCESS" for row in mutation_rows)
                assert all(row.source_ip is not None for row in mutation_rows)

                role_audit = next(row for row in rows if row.action == "USER_ROLE_CHANGED")
                assert role_audit.before_summary["roles"] == []
                assert role_audit.after_summary["roles"] == ["operator"]
                permission_audit = next(
                    row for row in rows if row.action == "USER_PERMISSION_CHANGED"
                )
                assert permission_audit.after_summary["direct_permissions"] == ["device.read"]

                combined = " ".join(_audit_blob(row) for row in rows)
                assert target_password not in combined
                assert secret_value not in combined
                assert downgraded_value not in combined
        finally:
            user_ids = [actor_id]
            if target_id is not None:
                user_ids.append(target_id)
            await _cleanup(
                factory,
                user_ids=user_ids,
                request_prefix=request_prefix,
                setting_key=setting_key,
            )

    asyncio.run(_run_api_scenario(scenario))
