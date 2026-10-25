"""HTTP and RBAC coverage for the Stage A recycle-bin surface."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from starlette.requests import Request

from app.api.deps import get_db
from app.api.routers import recycle_bin as recycle_router
from app.main import app
from app.models import (
    City,
    Device,
    DeviceGroup,
    DeviceIP,
    DevicePlacement,
    DeviceType,
    Location,
    Network,
    Permission,
    Role,
    RolePermission,
    Sector,
    SystemSetting,
    User,
    UserPermission,
    UserResourceScope,
    UserRole,
)
from app.security.authorization import authorize_request, permission_for_request
from app.security.permissions import Permission as PermissionCode
from app.security.sessions import create_session
from app.services.recycle_bin import RecycleBinError, recycle_entity
from app.settings import settings


RECYCLE_PERMISSIONS = {
    PermissionCode.RECYCLE_BIN_READ,
    PermissionCode.RECYCLE_BIN_RESTORE,
    PermissionCode.RECYCLE_BIN_PURGE,
}


def _request(method: str, path: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": method,
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


@pytest.mark.parametrize(
    ("method", "path", "expected"),
    (
        ("GET", "/api/recycle-bin", PermissionCode.RECYCLE_BIN_READ),
        ("GET", "/api/recycle-bin/items", PermissionCode.RECYCLE_BIN_READ),
        ("GET", "/api/recycle-bin/preview", PermissionCode.RECYCLE_BIN_READ),
        ("GET", "/api/recycle-bin/{batch_id}", PermissionCode.RECYCLE_BIN_READ),
        (
            "POST",
            "/api/recycle-bin/{batch_id}/restore",
            PermissionCode.RECYCLE_BIN_RESTORE,
        ),
        ("DELETE", "/api/recycle-bin/{batch_id}", PermissionCode.RECYCLE_BIN_PURGE),
    ),
)
def test_recycle_routes_have_explicit_permissions(method, path, expected):
    assert permission_for_request(_request(method, path)) == expected


@pytest.mark.parametrize(
    ("path", "expected"),
    (
        ("/api/networks/{network_id}", PermissionCode.NETWORK_DELETE),
        ("/api/cities/{city_id}", PermissionCode.GEO_DELETE),
        ("/api/locations/{location_id}", PermissionCode.GEO_DELETE),
        ("/api/sectors/{sector_id}", PermissionCode.GEO_DELETE),
        ("/api/customers/{customer_id}", PermissionCode.CUSTOMER_DELETE),
        ("/api/customers/services/{service_id}", PermissionCode.CUSTOMER_DELETE),
        ("/api/devices/{device_id}", PermissionCode.DEVICE_DELETE),
        ("/api/devices/{device_id}/ips/{ip_id}", PermissionCode.DEVICE_DELETE),
        (
            "/api/devices/{device_id}/interfaces/{interface_id}",
            PermissionCode.DEVICE_DELETE,
        ),
        ("/api/device-groups/{group_id}", PermissionCode.GROUP_DELETE),
        (
            "/api/device-relationships/{relationship_id}",
            PermissionCode.RELATIONSHIP_DELETE,
        ),
    ),
)
def test_recoverable_delete_routes_are_fail_closed_and_explicit(path, expected):
    assert permission_for_request(_request("DELETE", path)) == expected


async def _auth_user(
    db: AsyncSession,
    permissions: dict[str, Permission],
    *,
    grant_kind: str,
    role_code: str | None = None,
) -> tuple[User, str]:
    suffix = uuid4().hex[:10]
    user = User(
        external_subject=f"recycle-api-{suffix}",
        username=f"recycle-api-{suffix}",
        display_name="Recycle API Test User",
        is_active=True,
        metadata_={},
    )
    db.add(user)
    await db.flush()
    # These authorization-matrix users test recycle WHAT permissions. Give
    # them GLOBAL WHERE access; scoped recycle boundaries are tested separately.
    db.add(UserResourceScope(user_id=user.id, scope_type="GLOBAL"))
    await db.flush()

    if role_code:
        role = await db.scalar(select(Role).where(Role.code == role_code))
        assert role is not None
        db.add(UserRole(user_id=user.id, role_id=role.id))
    elif grant_kind == "role":
        role = Role(
            name=f"Recycle API Role {suffix}",
            code=f"RECYCLE-API-{suffix}",
            description="Recycle API authorization test role",
        )
        db.add(role)
        await db.flush()
        db.add(UserRole(user_id=user.id, role_id=role.id))
        for permission in permissions.values():
            db.add(RolePermission(role_id=role.id, permission_id=permission.id))
    elif grant_kind == "direct":
        for permission in permissions.values():
            db.add(UserPermission(user_id=user.id, permission_id=permission.id))

    token, _ = await create_session(db, user_id=user.id)
    await db.commit()
    return user, token


async def _recycled_network(db: AsyncSession, actor_id):
    suffix = uuid4().hex[:10]
    network = Network(
        name=f"Recycle API Network {suffix}",
        code=f"RCY-API-{suffix}",
        status="ACTIVE",
    )
    db.add(network)
    await db.flush()
    batch = await recycle_entity(
        db,
        entity_type="NETWORK",
        entity_id=network.id,
        actor_user_id=actor_id,
        reason="Recycle API authorization integration test",
    )
    await db.commit()
    return batch


async def _isolated_recycle_authorization_scenario():
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
        previous_auth = app.dependency_overrides.pop(authorize_request, None)
        app.dependency_overrides[get_db] = override_get_db
        try:
            async with factory() as db:
                permissions = {
                    permission.code: permission
                    for permission in (
                        await db.scalars(
                            select(Permission).where(
                                Permission.code.in_(RECYCLE_PERMISSIONS)
                            )
                        )
                    ).all()
                }
                assert set(permissions) == RECYCLE_PERMISSIONS

                no_grant_user, no_grant_token = await _auth_user(
                    db, permissions, grant_kind="none"
                )
                role_user, role_token = await _auth_user(
                    db, permissions, grant_kind="role"
                )
                direct_user, direct_token = await _auth_user(
                    db, permissions, grant_kind="direct"
                )
                _, viewer_token = await _auth_user(
                    db, permissions, grant_kind="none", role_code="viewer"
                )
                _, read_only_token = await _auth_user(
                    db,
                    permissions,
                    grant_kind="none",
                    role_code="administrative_viewer",
                )

                role_restore = await _recycled_network(db, role_user.id)
                role_purge = await _recycled_network(db, role_user.id)
                direct_restore = await _recycled_network(db, direct_user.id)
                direct_purge = await _recycled_network(db, direct_user.id)

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                # Authentication and authorization fail before domain work.
                response = await client.get("/api/recycle-bin")
                assert response.status_code == 401
                assert response.json()["detail"]["code"] == "AUTHENTICATION_REQUIRED"

                response = await client.get(
                    "/api/recycle-bin",
                    headers={"Authorization": f"Bearer {no_grant_token}"},
                )
                assert response.status_code == 403
                assert response.json()["detail"]["code"] == "PERMISSION_DENIED"

                for token in (viewer_token, read_only_token):
                    response = await client.get(
                        "/api/recycle-bin",
                        headers={"Authorization": f"Bearer {token}"},
                    )
                    assert response.status_code == 403

                role_headers = {"Authorization": f"Bearer {role_token}"}
                response = await client.get("/api/recycle-bin", headers=role_headers)
                assert response.status_code == 200, response.text
                response = await client.post(
                    f"/api/recycle-bin/{role_restore.id}/restore",
                    headers=role_headers,
                )
                assert response.status_code == 200, response.text
                assert response.json()["status"] == "RESTORED"
                response = await client.get(
                    "/api/recycle-bin/items",
                    headers=role_headers,
                    params={"batch_id": str(role_restore.id)},
                )
                assert response.status_code == 200
                assert response.json()["total"] == 0
                response = await client.get(
                    "/api/recycle-bin/items",
                    headers=role_headers,
                    params={
                        "batch_id": str(role_restore.id),
                        "batch_status": "history",
                    },
                )
                assert response.status_code == 200
                assert response.json()["total"] == 1
                response = await client.delete(
                    f"/api/recycle-bin/{role_purge.id}",
                    headers=role_headers,
                )
                assert response.status_code == 409, response.text
                assert (
                    response.json()["detail"]["code"]
                    == "RECYCLE_RETENTION_NOT_EXPIRED"
                )
                response = await client.delete(
                    f"/api/recycle-bin/{role_purge.id}",
                    headers=role_headers,
                    params={"force": "true", "confirmation": str(uuid4())},
                )
                assert response.status_code == 422, response.text
                assert (
                    response.json()["detail"]["code"]
                    == "RECYCLE_PURGE_CONFIRMATION_INVALID"
                )
                response = await client.delete(
                    f"/api/recycle-bin/{role_purge.id}",
                    headers=role_headers,
                    params={"force": "true", "confirmation": str(role_purge.id)},
                )
                assert response.status_code == 204, response.text

                direct_headers = {"Authorization": f"Bearer {direct_token}"}
                response = await client.get("/api/recycle-bin", headers=direct_headers)
                assert response.status_code == 200, response.text
                response = await client.post(
                    f"/api/recycle-bin/{direct_restore.id}/restore",
                    headers=direct_headers,
                )
                assert response.status_code == 200, response.text
                response = await client.delete(
                    f"/api/recycle-bin/{direct_purge.id}",
                    headers=direct_headers,
                    params={
                        "force": "true",
                        "confirmation": str(direct_purge.id),
                    },
                )
                assert response.status_code == 204, response.text

                response = await client.get("/api/auth/me", headers=direct_headers)
                assert response.status_code == 200
                assert RECYCLE_PERMISSIONS <= set(response.json()["permissions"])

                # Keep variables used and prove the no-grant account was distinct.
                assert no_grant_user.id not in {role_user.id, direct_user.id}
        finally:
            if previous_db is None:
                app.dependency_overrides.pop(get_db, None)
            else:
                app.dependency_overrides[get_db] = previous_db
            if previous_auth is not None:
                app.dependency_overrides[authorize_request] = previous_auth
            await transaction.rollback()
    await engine.dispose()


def test_recycle_authorization_matrix_and_direct_permission_union():
    asyncio.run(_isolated_recycle_authorization_scenario())


def test_default_roles_grant_recycle_permissions_only_to_administrator():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with factory() as db:
                rows = await db.execute(
                    select(Role.code, Permission.code)
                    .join(RolePermission, RolePermission.role_id == Role.id)
                    .join(Permission, Permission.id == RolePermission.permission_id)
                    .where(
                        Role.code.in_(
                            {
                                "administrator",
                                "operator",
                                "administrative_viewer",
                                "viewer",
                            }
                        ),
                        Permission.code.in_(RECYCLE_PERMISSIONS),
                    )
                )
                grants: dict[str, set[str]] = {}
                for role_code, permission_code in rows:
                    grants.setdefault(role_code, set()).add(permission_code)

                assert grants.get("administrator") == RECYCLE_PERMISSIONS
                assert grants.get("operator", set()) == set()
                assert grants.get("administrative_viewer", set()) == set()
                assert grants.get("viewer", set()) == set()
        finally:
            await engine.dispose()

    asyncio.run(scenario())


async def _run_isolated_domain_scenario(scenario):
    """Share one rollback-only PostgreSQL transaction with API dependencies."""

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
        app.dependency_overrides[get_db] = override_get_db
        try:
            await scenario(factory)
        finally:
            if previous_db is None:
                app.dependency_overrides.pop(get_db, None)
            else:
                app.dependency_overrides[get_db] = previous_db
            await transaction.rollback()
    await engine.dispose()


def test_recycle_list_items_detail_filters_pagination_preview_and_not_found():
    async def scenario(factory):
        marker = uuid4().hex[:12]
        batches = []
        async with factory() as db:
            for index in range(3):
                network = Network(
                    name=f"Recycle list {marker} {index}",
                    code=f"RCL-{marker}-{index}",
                    status="ACTIVE",
                )
                db.add(network)
                await db.flush()
                batches.append(
                    await recycle_entity(
                        db,
                        entity_type="NETWORK",
                        entity_id=network.id,
                        actor_user_id=None,
                        reason=f"pagination-{marker}",
                    )
                )

            blocked_network = Network(
                name=f"Recycle preview {marker}",
                code=f"RCL-PREVIEW-{marker}",
                status="ACTIVE",
            )
            db.add(blocked_network)
            await db.flush()
            child = City(
                network_id=blocked_network.id,
                name=f"Preview child {marker}",
                code=f"RCL-CITY-{marker}",
                status="ACTIVE",
            )
            db.add(child)
            await db.commit()

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            first = await client.get(
                "/api/recycle-bin",
                params={
                    "status": "recycled",
                    "entity_type": "network",
                    "search": marker,
                    "page": 1,
                    "page_size": 2,
                },
            )
            assert first.status_code == 200, first.text
            assert first.json()["total"] == 3
            assert len(first.json()["items"]) == 2
            assert first.json()["page"] == 1
            assert all(
                item["root_entity_type"] == "NETWORK"
                for item in first.json()["items"]
            )

            second = await client.get(
                "/api/recycle-bin",
                params={
                    "entity_type": "NETWORK",
                    "search": marker,
                    "page": 2,
                    "page_size": 2,
                },
            )
            assert second.status_code == 200, second.text
            assert second.json()["total"] == 3
            assert len(second.json()["items"]) == 1

            sorted_by_name = await client.get(
                "/api/recycle-bin",
                params={
                    "entity_type": "NETWORK",
                    "search": marker,
                    "page": 1,
                    "page_size": 3,
                    "sort_by": "display",
                    "sort_direction": "asc",
                },
            )
            assert sorted_by_name.status_code == 200, sorted_by_name.text
            names = [
                item["root_display_snapshot"]["label"]
                for item in sorted_by_name.json()["items"]
            ]
            assert names == sorted(names)

            invalid_sort = await client.get(
                "/api/recycle-bin", params={"sort_by": "unsupported"}
            )
            assert invalid_sort.status_code == 422
            assert invalid_sort.json()["detail"]["code"] == "INVALID_RECYCLE_SORT"

            detail = await client.get(f"/api/recycle-bin/{batches[0].id}")
            assert detail.status_code == 200, detail.text
            assert detail.json()["item_count"] == 1
            assert detail.json()["items"][0]["entity_type"] == "NETWORK"

            items = await client.get(
                "/api/recycle-bin/items",
                params={"batch_id": str(batches[0].id), "entity_type": "NETWORK"},
            )
            assert items.status_code == 200, items.text
            assert items.json()["total"] == 1
            assert items.json()["items"][0]["batch_id"] == str(batches[0].id)

            preview = await client.get(
                "/api/recycle-bin/preview",
                params={
                    "entity_type": "network",
                    "entity_id": str(blocked_network.id),
                },
            )
            assert preview.status_code == 200, preview.text
            assert preview.json()["root"]["entity_type"] == "NETWORK"
            assert preview.json()["root"]["entity_id"] == str(blocked_network.id)
            assert preview.json()["blockers"]

            missing = await client.get(f"/api/recycle-bin/{uuid4()}")
            assert missing.status_code == 404
            assert missing.json()["detail"] == {
                "code": "RECYCLE_BATCH_NOT_FOUND",
                "message": "Recycle-bin batch not found.",
            }

            invalid_status = await client.get(
                "/api/recycle-bin", params={"status": "unknown"}
            )
            assert invalid_status.status_code == 422
            assert invalid_status.json()["detail"]["code"] == "INVALID_RECYCLE_STATUS"

            invalid_type = await client.get(
                "/api/recycle-bin/preview",
                params={"entity_type": "AUDIT_LOG", "entity_id": str(uuid4())},
            )
            assert invalid_type.status_code == 422
            assert (
                invalid_type.json()["detail"]["code"]
                == "UNSUPPORTED_RECYCLE_ENTITY_TYPE"
            )

    asyncio.run(_run_isolated_domain_scenario(scenario))


def test_restore_conflict_uses_stable_409_envelope_and_rolls_back(monkeypatch):
    rollback_observed = False
    batch_id = uuid4()

    async def conflict(*args, **kwargs):
        raise RecycleBinError(
            "RECYCLE_RESTORE_CONFLICT",
            "The recycle batch cannot be restored without violating domain rules.",
            conflicts=[
                {
                    "code": "UNIQUE_IDENTITY_IN_USE",
                    "entity_type": "NETWORK",
                    "field": "code",
                }
            ],
        )

    monkeypatch.setattr(recycle_router, "restore_recycle_batch", conflict)

    async def fake_get_batch(*args, **kwargs):
        return (
            SimpleNamespace(
                id=batch_id,
                root_entity_type="NETWORK",
                root_entity_id=uuid4(),
                root_display_snapshot={"name": "Conflict network"},
            ),
            [],
        )

    monkeypatch.setattr(recycle_router, "get_recycle_batch", fake_get_batch)

    async def scenario(factory):
        nonlocal rollback_observed

        class TrackingSession:
            def add(self, value):
                return None

            async def commit(self):
                return None

            async def rollback(self):
                nonlocal rollback_observed
                rollback_observed = True

        async def override_tracking_db():
            yield TrackingSession()

        previous = app.dependency_overrides.get(get_db)
        app.dependency_overrides[get_db] = override_tracking_db
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                response = await client.post(f"/api/recycle-bin/{batch_id}/restore")
            assert response.status_code == 409
            assert response.json()["detail"] == {
                "code": "RECYCLE_RESTORE_CONFLICT",
                "message": (
                    "The recycle batch cannot be restored without violating "
                    "domain rules."
                ),
                "conflicts": [
                    {
                        "code": "UNIQUE_IDENTITY_IN_USE",
                        "entity_type": "NETWORK",
                        "field": "code",
                    }
                ],
            }
        finally:
            if previous is None:
                app.dependency_overrides.pop(get_db, None)
            else:
                app.dependency_overrides[get_db] = previous

    asyncio.run(_run_isolated_domain_scenario(scenario))
    assert rollback_observed is True


def test_network_delete_is_recoverable_and_visible_in_recycle_api():
    async def scenario(factory):
        marker = uuid4().hex[:12]
        async with factory() as db:
            network = Network(
                name=f"HTTP recycle network {marker}",
                code=f"HTTP-RCL-{marker}",
                status="ACTIVE",
            )
            db.add(network)
            await db.commit()
            network_id = network.id

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            deleted = await client.delete(
                f"/api/networks/{network_id}",
                params={"reason": f"http-delete-{marker}"},
            )
            assert deleted.status_code == 204, deleted.text

            active_lookup = await client.get(f"/api/networks/{network_id}")
            assert active_lookup.status_code == 404

            recycled = await client.get(
                "/api/recycle-bin",
                params={"search": marker, "entity_type": "NETWORK"},
            )
            assert recycled.status_code == 200, recycled.text
            assert recycled.json()["total"] == 1
            batch = recycled.json()["items"][0]
            assert batch["root_entity_id"] == str(network_id)
            assert batch["deletion_reason"] == f"http-delete-{marker}"
            assert batch["item_count"] == 1

    asyncio.run(_run_isolated_domain_scenario(scenario))


def test_recycled_geography_parent_cannot_list_or_create_active_children():
    async def scenario(factory):
        marker = uuid4().hex[:10]
        async with factory() as db:
            recycled_network = Network(
                name=f"Recycled parent network {marker}",
                code=f"RPN-{marker}",
                status="ACTIVE",
            )
            active_network = Network(
                name=f"Active parent network {marker}",
                code=f"APN-{marker}",
                status="ACTIVE",
            )
            db.add_all([recycled_network, active_network])
            await db.flush()

            recycled_city = City(
                network_id=active_network.id,
                name=f"Recycled parent city {marker}",
                code=f"RPC-{marker}",
                status="ACTIVE",
            )
            active_city = City(
                network_id=active_network.id,
                name=f"Active parent city {marker}",
                code=f"APC-{marker}",
                status="ACTIVE",
            )
            db.add_all([recycled_city, active_city])
            await db.flush()

            recycled_location = Location(
                city_id=active_city.id,
                name=f"Recycled parent location {marker}",
                code=f"RPL-{marker}",
                status="ACTIVE",
                metadata_={},
            )
            db.add(recycled_location)
            await db.flush()

            await recycle_entity(
                db,
                entity_type="NETWORK",
                entity_id=recycled_network.id,
                actor_user_id=None,
            )
            await recycle_entity(
                db,
                entity_type="CITY",
                entity_id=recycled_city.id,
                actor_user_id=None,
            )
            await recycle_entity(
                db,
                entity_type="LOCATION",
                entity_id=recycled_location.id,
                actor_user_id=None,
            )
            await db.commit()

        cases = (
            (
                f"/api/networks/{recycled_network.id}/cities",
                {"name": "Forbidden City", "code": f"NO-C-{marker}", "service_vlan_id": 4094},
            ),
            (
                f"/api/cities/{recycled_city.id}/locations",
                {"name": "Forbidden Location", "code": f"NO-L-{marker}"},
            ),
            (
                f"/api/locations/{recycled_location.id}/sectors",
                {"name": "Forbidden Sector", "code": f"NO-S-{marker}"},
            ),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            for path, payload in cases:
                listed = await client.get(path)
                assert listed.status_code == 404, listed.text
                assert listed.json()["detail"]["code"] == "RESOURCE_NOT_FOUND"

                created = await client.post(path, json=payload)
                assert created.status_code == 404, created.text
                assert created.json()["detail"]["code"] == "RESOURCE_NOT_FOUND"

        async with factory() as db:
            assert await db.scalar(
                select(City.id).where(City.code == f"NO-C-{marker}")
            ) is None
            assert await db.scalar(
                select(Location.id).where(Location.code == f"NO-L-{marker}")
            ) is None
            assert await db.scalar(
                select(Sector.id).where(Sector.code == f"NO-S-{marker}")
            ) is None

    asyncio.run(_run_isolated_domain_scenario(scenario))


def test_demo_seed_restart_marker_does_not_resurrect_recycled_identity(monkeypatch):
    from scripts import seed_demo_data

    async def scenario(factory):
        monkeypatch.setattr(seed_demo_data, "AsyncSessionLocal", factory)

        async with factory() as db:
            marker = await db.scalar(
                select(SystemSetting).where(
                    SystemSetting.key == seed_demo_data.DEMO_SEED_MARKER_KEY
                )
            )
            if marker is None:
                marker = SystemSetting(
                    key=seed_demo_data.DEMO_SEED_MARKER_KEY,
                    value={"version": seed_demo_data.DEMO_SEED_VERSION},
                    description="Test one-time seed marker.",
                    is_secret=False,
                )
                db.add(marker)

            # Use a current demo-seeded CUSTOM group identity.  ALL-AP is a
            # historical pre-0015 demo identity; on clean/current databases its
            # former display name is reserved by the immutable dynamic system
            # group SYS-ALL-ACCESS-POINTS.  Using BACKHAUL keeps this restart
            # marker regression deterministic on both upgraded and fresh DBs.
            group = await db.scalar(
                select(DeviceGroup).where(DeviceGroup.code == "BACKHAUL")
            )
            if group is None:
                group = DeviceGroup(
                    id=seed_demo_data.did("group:BACKHAUL"),
                    name="Backhaul Sectors",
                    code="BACKHAUL",
                    scope_type="GLOBAL",
                    device_scope="SECTOR",
                    sector_role="BACKHAUL",
                    metadata_={"seed": "baseline"},
                )
                db.add(group)
                await db.flush()
            group_id = group.id
            batch = await recycle_entity(
                db,
                entity_type="DEVICE_GROUP",
                entity_id=group_id,
                actor_user_id=None,
                confirmed=True,
            )
            batch_id = batch.id
            await db.commit()

        # This models backend restart with SEED_DEMO_DATA=true. The marker must
        # stop deterministic `ensure` calls before they can see tombstones as
        # absent and recreate the same product identity.
        await seed_demo_data.seed()

        async with factory() as db:
            assert await db.scalar(
                select(DeviceGroup).where(DeviceGroup.id == group_id)
            ) is None
            recycled_group = await db.scalar(
                select(DeviceGroup)
                .where(DeviceGroup.id == group_id)
                .execution_options(include_recycled=True)
            )
            assert recycled_group is not None
            assert recycled_group.deleted_at is not None
            assert recycled_group.deletion_batch_id == batch_id

    asyncio.run(_run_isolated_domain_scenario(scenario))


def test_recycled_device_and_group_are_rejected_as_mutation_parents():
    async def scenario(factory):
        marker = uuid4().hex[:10]
        async with factory() as db:
            network = Network(name=f"Parent Network {marker}", code=f"PN-{marker}")
            db.add(network)
            await db.flush()
            city = City(network_id=network.id, name=f"Parent City {marker}", code=f"PC-{marker}")
            db.add(city)
            await db.flush()
            location = Location(
                city_id=city.id,
                name=f"Parent Location {marker}",
                code=f"PL-{marker}",
                metadata_={},
            )
            db.add(location)
            switch_type = await db.scalar(
                select(DeviceType).where(DeviceType.code == "SWITCH")
            )
            assert switch_type is not None
            recycled_device = Device(
                device_type_id=switch_type.id,
                display_name=f"Recycled parent switch {marker}",
                lifecycle_state="DECOMMISSIONED",
                operational_state="UNKNOWN",
                metadata_={},
            )
            active_device = Device(
                device_type_id=switch_type.id,
                display_name=f"Active parent switch {marker}",
                lifecycle_state="REGISTERED",
                operational_state="UNKNOWN",
                metadata_={},
            )
            db.add_all([recycled_device, active_device])
            await db.flush()
            db.add_all(
                [
                    DeviceIP(
                        device_id=recycled_device.id,
                        ip_address=f"fd00::{marker[:4]}:{marker[4:8]}",
                        address_family=6,
                        is_management=True,
                        is_primary=True,
                        source="TEST",
                    ),
                    DevicePlacement(
                        device_id=recycled_device.id,
                        network_id=network.id,
                        city_id=city.id,
                        location_id=location.id,
                        metadata_={"placement_mode": "INDEPENDENT"},
                    ),
                    DevicePlacement(
                        device_id=active_device.id,
                        network_id=network.id,
                        city_id=city.id,
                        location_id=location.id,
                        metadata_={"placement_mode": "INDEPENDENT"},
                    ),
                ]
            )
            active_group = DeviceGroup(
                name=f"Active parent group {marker}",
                code=f"APG-{marker}",
                scope_type="GLOBAL",
                device_scope="ANY",
                metadata_={},
            )
            recycled_group = DeviceGroup(
                name=f"Recycled parent group {marker}",
                code=f"RPG-{marker}",
                scope_type="GLOBAL",
                device_scope="ANY",
                metadata_={},
            )
            db.add_all([active_group, recycled_group])
            await db.flush()
            await recycle_entity(
                db,
                entity_type="DEVICE_GROUP",
                entity_id=recycled_group.id,
                actor_user_id=None,
            )
            await recycle_entity(
                db,
                entity_type="DEVICE",
                entity_id=recycled_device.id,
                actor_user_id=None,
            )
            await db.commit()

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            ip = await client.post(
                f"/api/devices/{recycled_device.id}/ips",
                json={"ip_address": f"fd00::{marker[:4]}:{marker[4:8]}:2"},
            )
            assert ip.status_code == 404, ip.text
            assert ip.json()["detail"]["code"] == "RESOURCE_NOT_FOUND"

            interface = await client.post(
                f"/api/devices/{recycled_device.id}/interfaces",
                json={"interface_name": "eth-test"},
            )
            assert interface.status_code == 404, interface.text
            assert interface.json()["detail"]["code"] == "RESOURCE_NOT_FOUND"

            placement = await client.patch(
                f"/api/devices/{recycled_device.id}/placement",
                json={"metadata": {"attempt": "forbidden"}},
            )
            assert placement.status_code == 404, placement.text
            assert placement.json()["detail"]["code"] == "DEVICE_NOT_FOUND"

            relationship = await client.post(
                "/api/device-relationships",
                json={
                    "source_device_id": str(recycled_device.id),
                    "target_device_id": str(active_device.id),
                    "relationship_type": "UPLINK",
                    "direction": "DIRECTED",
                },
            )
            assert relationship.status_code == 404, relationship.text
            assert relationship.json()["detail"]["code"] == "SOURCE_DEVICE_NOT_FOUND"

            membership = await client.post(
                f"/api/device-groups/{active_group.id}/devices/{recycled_device.id}"
            )
            assert membership.status_code == 404, membership.text
            assert membership.json()["detail"]["code"] == "DEVICE_NOT_FOUND"

            recycled_group_membership = await client.post(
                f"/api/device-groups/{recycled_group.id}/devices/{active_device.id}"
            )
            assert recycled_group_membership.status_code == 404, recycled_group_membership.text
            assert recycled_group_membership.json()["detail"]["code"] == "GROUP_NOT_FOUND"

    asyncio.run(_run_isolated_domain_scenario(scenario))
