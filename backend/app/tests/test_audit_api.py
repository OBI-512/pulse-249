from __future__ import annotations

import asyncio
import csv
from datetime import datetime, timedelta, timezone
from io import StringIO
from types import SimpleNamespace
from uuid import uuid4

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from starlette.requests import Request

from app.api.deps import get_db
from app.main import app
from app.models import (
    AuditLog,
    Permission,
    Role,
    RolePermission,
    User,
    UserPermission,
    UserResourceScope,
    UserRole,
)
from app.security.authorization import authorize_request, permission_for_request
from app.security.permissions import Permission as PermissionCode
from app.security.sessions import create_session
from app.services.audit import record_audit
from app.settings import settings


AUDIT_PERMISSIONS = {PermissionCode.AUDIT_READ, PermissionCode.AUDIT_EXPORT}


def _request(path: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "raw_path": path.encode(),
            "root_path": "",
            "scheme": "http",
            "query_string": b"",
            "headers": [],
            "client": ("test", 1),
            "server": ("test", 80),
            "route": SimpleNamespace(path=path),
        }
    )


def test_audit_routes_have_explicit_permissions():
    assert permission_for_request(_request("/api/audit")) == PermissionCode.AUDIT_READ
    assert permission_for_request(_request("/api/audit/{audit_id}")) == PermissionCode.AUDIT_READ
    assert permission_for_request(_request("/api/audit/export")) == PermissionCode.AUDIT_EXPORT


async def _auth_user(
    db: AsyncSession,
    permissions: dict[str, Permission],
    *,
    direct: set[str] | None = None,
    role_permissions: set[str] | None = None,
    default_role: str | None = None,
) -> tuple[User, str]:
    suffix = uuid4().hex[:10]
    user = User(
        external_subject=f"audit-api-{suffix}",
        username=f"audit-api-{suffix}",
        display_name="Audit API Test User",
        is_active=True,
        metadata_={},
    )
    db.add(user)
    await db.flush()
    db.add(UserResourceScope(user_id=user.id, scope_type="GLOBAL"))
    if default_role:
        role = await db.scalar(select(Role).where(Role.code == default_role))
        assert role is not None
        db.add(UserRole(user_id=user.id, role_id=role.id))
    elif role_permissions is not None:
        role = Role(
            name=f"Audit API Role {suffix}",
            code=f"AUDIT-API-{suffix}",
            description="Audit API test role",
        )
        db.add(role)
        await db.flush()
        db.add(UserRole(user_id=user.id, role_id=role.id))
        for code in role_permissions:
            db.add(RolePermission(role_id=role.id, permission_id=permissions[code].id))
    for code in direct or set():
        db.add(UserPermission(user_id=user.id, permission_id=permissions[code].id))
    token, _ = await create_session(db, user_id=user.id)
    await db.commit()
    return user, token


async def _scenario():
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    async with engine.connect() as connection:
        transaction = await connection.begin()
        factory = async_sessionmaker(
            bind=connection,
            class_=AsyncSession,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        )

        async def override_get_db():
            async with factory() as db:
                yield db

        previous_db = app.dependency_overrides.get(get_db)
        # conftest bypasses authorize_request for domain tests. This security
        # test deliberately restores the real dependency boundary.
        previous_auth = app.dependency_overrides.pop(authorize_request, None)
        app.dependency_overrides[get_db] = override_get_db
        try:
            async with factory() as db:
                permissions = {
                    permission.code: permission
                    for permission in (
                        await db.scalars(
                            select(Permission).where(
                                Permission.code.in_(AUDIT_PERMISSIONS)
                            )
                        )
                    ).all()
                }
                assert set(permissions) == AUDIT_PERMISSIONS
                no_grant_user, no_grant_token = await _auth_user(db, permissions)
                _, direct_read_token = await _auth_user(
                    db,
                    permissions,
                    direct={PermissionCode.AUDIT_READ},
                )
                _, direct_export_token = await _auth_user(
                    db,
                    permissions,
                    direct={PermissionCode.AUDIT_EXPORT},
                )
                role_user, role_token = await _auth_user(
                    db,
                    permissions,
                    role_permissions=AUDIT_PERMISSIONS,
                )
                _, viewer_token = await _auth_user(
                    db,
                    permissions,
                    default_role="viewer",
                )

                common_entity = uuid4()
                rows = []
                base_time = datetime.now(timezone.utc)
                for index in range(3):
                    row = await record_audit(
                        db,
                        action="AUDIT_API_TEST",
                        entity_type="AuditFixture",
                        entity_id=common_entity,
                        actor_user_id=role_user.id,
                        actor_username_snapshot=("=FORMULA" if index == 0 else role_user.username),
                        entity_display_snapshot={"name": f"Audit fixture {index}"},
                        result="SUCCESS" if index < 2 else "ATTEMPT",
                        request_id=f"audit-api-request-{index}",
                        source_ip="198.51.100.10",
                        before_summary={"sequence": index},
                        after_summary={"sequence": index + 1},
                        metadata={"marker": "bounded-export"},
                    )
                    row.occurred_at = base_time - timedelta(seconds=index)
                    rows.append(row)

                # Simulate pre-foundation evidence to prove the API/export
                # redacts again even when a legacy row contains a secret.
                legacy = AuditLog(
                    actor_username_snapshot="legacy-user",
                    action="AUDIT_API_LEGACY",
                    entity_type="AuditFixture",
                    entity_id=uuid4(),
                    result="FAILURE",
                    request_id="audit-api-legacy",
                    metadata_={"password": "legacy-password-secret"},
                )
                db.add(legacy)
                await db.commit()
                for row in rows:
                    await db.refresh(row)
                await db.refresh(legacy)

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                response = await client.get("/api/audit")
                assert response.status_code == 401
                assert response.json()["detail"]["code"] == "AUTHENTICATION_REQUIRED"

                response = await client.get(
                    "/api/audit",
                    headers={"Authorization": f"Bearer {no_grant_token}"},
                )
                assert response.status_code == 403
                assert response.json()["detail"]["code"] == "PERMISSION_DENIED"

                response = await client.get(
                    "/api/audit",
                    headers={"Authorization": f"Bearer {viewer_token}"},
                )
                assert response.status_code == 403

                read_headers = {"Authorization": f"Bearer {direct_read_token}"}
                response = await client.get(
                    "/api/audit",
                    headers=read_headers,
                    params={
                        "action": "audit_api_test",
                        "actor_user_id": str(role_user.id),
                        "entity_type": "auditfixture",
                        "entity_id": str(common_entity),
                        "result": "success",
                        "search": "Audit fixture",
                        "page_size": 1,
                    },
                )
                assert response.status_code == 200, response.text
                assert response.json()["total"] == 2
                assert len(response.json()["items"]) == 1

                response = await client.get(
                    "/api/audit",
                    headers=read_headers,
                    params={"request_id": "audit-api-request-2"},
                )
                assert response.status_code == 200
                assert response.json()["total"] == 1
                assert response.json()["items"][0]["result"] == "ATTEMPT"

                response = await client.get(
                    f"/api/audit/{legacy.id}",
                    headers=read_headers,
                )
                assert response.status_code == 200
                assert response.json()["metadata"]["password"] == "[REDACTED]"
                assert "legacy-password-secret" not in response.text

                response = await client.get(
                    "/api/audit",
                    headers=read_headers,
                    params={"result": "not-a-result"},
                )
                assert response.status_code == 422
                assert response.json()["detail"]["code"] == "AUDIT_RESULT_INVALID"

                response = await client.get(
                    "/api/audit/export",
                    headers=read_headers,
                )
                assert response.status_code == 403

                export_only_headers = {
                    "Authorization": f"Bearer {direct_export_token}"
                }
                response = await client.get(
                    "/api/audit",
                    headers=export_only_headers,
                )
                assert response.status_code == 403
                response = await client.get(
                    "/api/audit/export",
                    headers=export_only_headers,
                    params={"action": "AUDIT_API_TEST", "limit": 2},
                )
                assert response.status_code == 200, response.text

                role_headers = {"Authorization": f"Bearer {role_token}"}
                response = await client.get(
                    "/api/audit/export",
                    headers=role_headers,
                    params={"action": "AUDIT_API_TEST", "limit": 2},
                )
                assert response.status_code == 200, response.text
                assert response.headers["x-audit-export-limit"] == "2"
                assert response.headers["x-audit-export-truncated"] == "true"
                exported = list(csv.DictReader(StringIO(response.text)))
                assert len(exported) == 2
                assert any(item["actor_username_snapshot"] == "'=FORMULA" for item in exported)

                # Both permissions through a role allow list and detail.
                response = await client.get("/api/audit", headers=role_headers)
                assert response.status_code == 200
                response = await client.get(
                    f"/api/audit/{rows[0].id}",
                    headers=role_headers,
                )
                assert response.status_code == 200

                assert no_grant_user.id != role_user.id
        finally:
            if previous_db is None:
                app.dependency_overrides.pop(get_db, None)
            else:
                app.dependency_overrides[get_db] = previous_db
            if previous_auth is not None:
                app.dependency_overrides[authorize_request] = previous_auth
            await transaction.rollback()
    await engine.dispose()


def test_audit_api_authorization_filters_redaction_and_bounded_export():
    asyncio.run(_scenario())
