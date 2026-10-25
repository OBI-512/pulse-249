"""RBAC regression coverage for physical movement API mutations."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from starlette.requests import Request

from app.api.deps import get_db
from app.api.routers import movements as movement_router
from app.core.exceptions import APIError
from app.main import app
from app.models import (
    City,
    Device,
    DeviceType,
    Location,
    Network,
    Permission,
    Role,
    RolePermission,
    Sector,
    User,
    UserPermission,
    UserResourceScope,
    UserRole,
)
from app.security.authorization import authorize_request, permission_for_request
from app.security.permissions import Permission as PermissionCode
from app.security.sessions import create_session
from app.settings import settings


MOVEMENT_PERMISSIONS = {
    PermissionCode.PHYSICAL_MOVEMENT_SECTOR,
    PermissionCode.PHYSICAL_MOVEMENT_CPE,
    PermissionCode.PHYSICAL_MOVEMENT_ACCESS_POINT,
}


def _run(coroutine):
    asyncio.run(coroutine)


async def _run_api_scenario(test_coroutine):
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async def override_get_db():
        async with session_factory() as db:
            yield db

    previous_db_override = app.dependency_overrides.get(get_db)
    previous_authorization_override = app.dependency_overrides.pop(
        authorize_request,
        None,
    )
    app.dependency_overrides[get_db] = override_get_db
    try:
        await test_coroutine(session_factory)
    finally:
        if previous_db_override is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous_db_override
        if previous_authorization_override is not None:
            app.dependency_overrides[
                authorize_request
            ] = previous_authorization_override
        await engine.dispose()


async def _create_targets(db):
    suffix = uuid4().hex[:10]
    network = Network(name=f"RBAC Network {suffix}", code=f"RBAC-NET-{suffix}")
    db.add(network)
    await db.flush()
    city = City(
        network_id=network.id,
        name=f"RBAC City {suffix}",
        code=f"RBAC-CITY-{suffix}",
    )
    db.add(city)
    await db.flush()
    location = Location(
        city_id=city.id,
        name=f"RBAC Location {suffix}",
        code=f"RBAC-LOC-{suffix}",
        metadata_={},
    )
    db.add(location)
    await db.flush()
    sector = Sector(
        location_id=location.id,
        name=f"RBAC Sector {suffix}",
        code=f"RBAC-SEC-{suffix}",
        role="CUSTOMER_ACCESS",
        metadata_={},
    )
    db.add(sector)

    cpe_type = await db.scalar(select(DeviceType).where(DeviceType.code == "CPE"))
    ap_type = await db.scalar(
        select(DeviceType).where(DeviceType.code == "ACCESS_POINT")
    )
    assert cpe_type is not None
    assert ap_type is not None

    cpe = Device(
        device_type_id=cpe_type.id,
        display_name=f"RBAC CPE {suffix}",
        lifecycle_state="ACTIVE",
        operational_state="UP",
        metadata_={},
    )
    access_point = Device(
        device_type_id=ap_type.id,
        display_name=f"RBAC AP {suffix}",
        lifecycle_state="ACTIVE",
        operational_state="UP",
        metadata_={},
    )
    db.add_all([cpe, access_point])
    await db.commit()

    return {
        "network": network,
        "city": city,
        "location": location,
        "sector": sector,
        "cpe": cpe,
        "access_point": access_point,
    }


def _movement_requests(targets):
    return (
        (
            PermissionCode.PHYSICAL_MOVEMENT_SECTOR,
            f"/api/physical-movements/sectors/{targets['sector'].id}",
            {"destination_location_id": str(targets["location"].id)},
            str(targets["sector"].id),
        ),
        (
            PermissionCode.PHYSICAL_MOVEMENT_CPE,
            f"/api/physical-movements/cpes/{targets['cpe'].id}",
            {"destination_sector_device_id": str(targets["cpe"].id)},
            str(targets["cpe"].id),
        ),
        (
            PermissionCode.PHYSICAL_MOVEMENT_ACCESS_POINT,
            f"/api/physical-movements/access-points/{targets['access_point'].id}",
            {"destination_cpe_device_id": str(targets["cpe"].id)},
            str(targets["access_point"].id),
        ),
    )


async def _install_success_stubs(monkeypatch):
    async def fake_resolve_effective_hierarchy(db, device):
        # These tests isolate RBAC WHAT semantics. Destination hierarchy
        # validity is covered by the movement/hierarchy domain suites.
        return SimpleNamespace(sector_id=None)

    async def fake_move_sector(
        db,
        *,
        sector_id,
        destination_location_id,
        sequence_number=None,
    ):
        return await db.get(Sector, sector_id)

    async def fake_move_cpe(
        db,
        *,
        cpe_device_id,
        destination_sector_device_id,
    ):
        return await db.get(Device, cpe_device_id)

    async def fake_move_access_point(
        db,
        *,
        access_point_device_id,
        destination_cpe_device_id,
    ):
        return await db.get(Device, access_point_device_id)

    monkeypatch.setattr(
        movement_router,
        "resolve_effective_hierarchy",
        fake_resolve_effective_hierarchy,
    )
    monkeypatch.setattr(movement_router, "move_sector_to_location", fake_move_sector)
    monkeypatch.setattr(movement_router, "move_cpe_to_sector", fake_move_cpe)
    monkeypatch.setattr(movement_router, "reassign_access_point", fake_move_access_point)


async def _create_auth_context(
    db,
    *,
    role_code: str | None = None,
    role_permissions: set[str] | None = None,
    direct_permissions: set[str] | None = None,
):
    suffix = uuid4().hex[:10]
    user = User(
        external_subject=f"movement-rbac-{suffix}",
        username=f"movement-rbac-{suffix}",
        display_name="Movement RBAC Test User",
        is_active=True,
        metadata_={},
    )
    db.add(user)
    await db.flush()
    # These legacy RBAC tests isolate WHAT. Give their synthetic actor GLOBAL
    # WHERE access so movement assertions remain about permission semantics.
    db.add(UserResourceScope(user_id=user.id, scope_type="GLOBAL"))
    await db.flush()

    role = None
    if role_code is not None:
        role = await db.scalar(select(Role).where(Role.code == role_code))
        assert role is not None
    elif role_permissions is not None:
        role = Role(
            name=f"Movement RBAC Role {suffix}",
            code=f"MOVEMENT-RBAC-{suffix}",
            description="Movement RBAC integration role",
        )
        db.add(role)
        await db.flush()

    if role is not None:
        db.add(UserRole(user_id=user.id, role_id=role.id))

    permissions = {
        permission.code: permission
        for permission in (
            await db.scalars(
                select(Permission).where(Permission.code.in_(MOVEMENT_PERMISSIONS))
            )
        ).all()
    }
    assert set(permissions) == MOVEMENT_PERMISSIONS

    for code in role_permissions or set():
        db.add(RolePermission(role_id=role.id, permission_id=permissions[code].id))
    for code in direct_permissions or set():
        db.add(UserPermission(user_id=user.id, permission_id=permissions[code].id))

    token, _ = await create_session(db, user_id=user.id)
    await db.commit()
    return {"token": token, "user_id": user.id, "role": role}


async def _cleanup(db, targets, auth_contexts):
    for context in auth_contexts:
        await db.execute(delete(User).where(User.id == context["user_id"]))
        role = context.get("role")
        if role is not None and role.code.startswith("MOVEMENT-RBAC-"):
            await db.execute(delete(Role).where(Role.id == role.id))

    await db.execute(
        delete(Device).where(
            Device.id.in_([targets["cpe"].id, targets["access_point"].id])
        )
    )
    await db.execute(delete(Sector).where(Sector.id == targets["sector"].id))
    await db.execute(delete(Location).where(Location.id == targets["location"].id))
    await db.execute(delete(City).where(City.id == targets["city"].id))
    await db.execute(delete(Network).where(Network.id == targets["network"].id))
    await db.commit()


def test_each_movement_requires_authentication(monkeypatch):
    async def scenario(session_factory):
        await _install_success_stubs(monkeypatch)
        async with session_factory() as db:
            targets = await _create_targets(db)
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                for _, path, payload, _ in _movement_requests(targets):
                    response = await client.post(path, json=payload)
                    assert response.status_code == 401
                    assert response.json()["detail"]["code"] == "AUTHENTICATION_REQUIRED"
        finally:
            async with session_factory() as db:
                await _cleanup(db, targets, [])

    _run(_run_api_scenario(scenario))


def test_each_movement_denies_authenticated_user_without_permission(monkeypatch):
    async def scenario(session_factory):
        await _install_success_stubs(monkeypatch)
        async with session_factory() as db:
            targets = await _create_targets(db)
            auth = await _create_auth_context(db, role_permissions=set())
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                for code, path, payload, _ in _movement_requests(targets):
                    response = await client.post(
                        path,
                        json=payload,
                        headers={"Authorization": f"Bearer {auth['token']}"},
                    )
                    assert response.status_code == 403
                    assert response.json()["detail"] == {
                        "code": "PERMISSION_DENIED",
                        "message": f"Permission '{code}' is required.",
                    }
        finally:
            async with session_factory() as db:
                await _cleanup(db, targets, [auth])

    _run(_run_api_scenario(scenario))


def test_each_movement_succeeds_with_role_granted_permission(monkeypatch):
    async def scenario(session_factory):
        await _install_success_stubs(monkeypatch)
        async with session_factory() as db:
            targets = await _create_targets(db)
            auth = await _create_auth_context(
                db,
                role_permissions=MOVEMENT_PERMISSIONS,
            )
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                for _, path, payload, expected_id in _movement_requests(targets):
                    response = await client.post(
                        path,
                        json=payload,
                        headers={"Authorization": f"Bearer {auth['token']}"},
                    )
                    assert response.status_code == 200, response.text
                    assert response.json()["id"] == expected_id
        finally:
            async with session_factory() as db:
                await _cleanup(db, targets, [auth])

    _run(_run_api_scenario(scenario))


def test_each_movement_succeeds_with_direct_permission_and_auth_me_exposes_union(
    monkeypatch,
):
    async def scenario(session_factory):
        await _install_success_stubs(monkeypatch)
        async with session_factory() as db:
            targets = await _create_targets(db)
            auth = await _create_auth_context(
                db,
                role_permissions=set(),
                direct_permissions=MOVEMENT_PERMISSIONS,
            )
        try:
            headers = {"Authorization": f"Bearer {auth['token']}"}
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                for _, path, payload, expected_id in _movement_requests(targets):
                    response = await client.post(path, json=payload, headers=headers)
                    assert response.status_code == 200, response.text
                    assert response.json()["id"] == expected_id

                response = await client.get("/api/auth/me", headers=headers)
                assert response.status_code == 200
                assert MOVEMENT_PERMISSIONS <= set(response.json()["permissions"])
                assert auth["role"].code in response.json()["roles"]
        finally:
            async with session_factory() as db:
                await _cleanup(db, targets, [auth])

    _run(_run_api_scenario(scenario))


def test_default_roles_grant_movements_only_to_administrator(monkeypatch):
    async def scenario(session_factory):
        await _install_success_stubs(monkeypatch)
        async with session_factory() as db:
            targets = await _create_targets(db)
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
                    Permission.code.in_(MOVEMENT_PERMISSIONS),
                )
            )
            grants = {}
            for role_code, permission_code in rows:
                grants.setdefault(role_code, set()).add(permission_code)

            assert grants.get("administrator") == MOVEMENT_PERMISSIONS
            assert grants.get("operator", set()) == set()
            assert grants.get("viewer", set()) == set()
            assert grants.get("administrative_viewer", set()) == set()

            viewer = await _create_auth_context(db, role_code="viewer")
            read_only = await _create_auth_context(
                db, role_code="administrative_viewer"
            )

        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                for auth in (viewer, read_only):
                    headers = {"Authorization": f"Bearer {auth['token']}"}
                    for _, path, payload, _ in _movement_requests(targets):
                        response = await client.post(path, json=payload, headers=headers)
                        assert response.status_code == 403
        finally:
            async with session_factory() as db:
                await _cleanup(db, targets, [viewer, read_only])

    _run(_run_api_scenario(scenario))


@pytest.mark.parametrize(
    ("path", "expected"),
    (
        (
            "/api/physical-movements/sectors/{sector_id}",
            PermissionCode.PHYSICAL_MOVEMENT_SECTOR,
        ),
        (
            "/api/physical-movements/cpes/{cpe_device_id}",
            PermissionCode.PHYSICAL_MOVEMENT_CPE,
        ),
        (
            "/api/physical-movements/access-points/{access_point_device_id}",
            PermissionCode.PHYSICAL_MOVEMENT_ACCESS_POINT,
        ),
    ),
)
def test_movement_routes_have_explicit_authorization_mapping(path, expected):
    request = Request(
        {
            "type": "http",
            "method": "POST",
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
    assert permission_for_request(request) == expected


def test_unmapped_protected_mutation_fails_closed():
    path = "/api/future-protected-resource/{resource_id}"
    request = Request(
        {
            "type": "http",
            "method": "POST",
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

    async def scenario():
        with pytest.raises(APIError) as error:
            await authorize_request(request, user=object(), db=None)
        assert error.value.status_code == 403
        assert error.value.detail["code"] == "PERMISSION_DENIED"

    _run(scenario())
