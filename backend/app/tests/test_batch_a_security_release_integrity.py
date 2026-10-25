"""Batch A security and release-integrity regression coverage."""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.routing import APIRoute
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from starlette.requests import Request

from app.core.exceptions import APIError
from app.db.session import AsyncSessionLocal
from app.main import app
from app.settings import settings
from app.security import authorization as authorization_module
from app.security.authorization import authorize_request, permission_for_request
from app.security.permission_dependencies import (
    dependency_catalog_errors,
    expand_permission_codes,
    prerequisites_for,
)
from app.security.permissions import Permission as P
from app.security.runtime_safety import ensure_demo_seed_allowed, ensure_runtime_safety
from app.services.user_security import resolve_permission_assignment, resolve_roles_or_error
from migrations.canonical.schema_contract import CANONICAL_REVISION, COLUMNS, INDEXES, TABLES


def _request(method: str, path: str, query: str = "") -> Request:
    return Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "raw_path": path.encode(),
            "root_path": "",
            "scheme": "http",
            "query_string": query.encode(),
            "headers": [],
            "client": ("test", 1),
            "server": ("test", 80),
            "route": SimpleNamespace(path=path),
        }
    )


def _dependency_calls(dependant) -> set[object]:
    calls: set[object] = set()
    for child in dependant.dependencies:
        if child.call is not None:
            calls.add(child.call)
        calls.update(_dependency_calls(child))
    return calls


def test_permission_dependency_catalog_is_valid_and_transitive():
    assert dependency_catalog_errors() == []
    assert expand_permission_codes([P.DEVICE_DELETE]) == [P.DEVICE_DELETE, P.DEVICE_READ]
    assert expand_permission_codes([P.USER_SESSIONS_MANAGE]) == [
        P.USER_READ,
        P.USER_SESSIONS_MANAGE,
        P.USER_SESSIONS_READ,
    ]
    # Role-derived prerequisites satisfy the dependency without redundant direct grants.
    assert expand_permission_codes([P.DEVICE_DELETE], satisfied_codes=[P.DEVICE_READ]) == [P.DEVICE_DELETE]
    assert prerequisites_for(P.RECYCLE_BIN_PURGE) == (P.RECYCLE_BIN_READ,)



def test_permission_assignment_automatically_adds_missing_prerequisites():
    async def scenario():
        # Use an isolated, non-pooled engine for this asyncio.run() test.
        # This prevents asyncpg connections created by earlier tests from
        # being reused across different event loops during the full suite.
        engine = create_async_engine(
            settings.database_url,
            poolclass=NullPool,
        )
        session_factory = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        try:
            async with session_factory() as db:
                without_role = await resolve_permission_assignment(
                    db,
                    [P.DEVICE_DELETE],
                    [],
                )
                assert {permission.code for permission in without_role} == {
                    P.DEVICE_DELETE,
                    P.DEVICE_READ,
                }

                viewer = await resolve_roles_or_error(db, ["viewer"])
                with_role = await resolve_permission_assignment(
                    db,
                    [P.DEVICE_DELETE],
                    viewer,
                )

                # viewer already supplies device.read, so the prerequisite
                # is not redundantly persisted as a direct user grant.
                assert {permission.code for permission in with_role} == {
                    P.DEVICE_DELETE
                }
        finally:
            await engine.dispose()

    asyncio.run(scenario())

def test_candidate_collection_requires_candidate_read():
    assert permission_for_request(_request("GET", "/api/device-candidates")) == P.CANDIDATE_READ
    assert permission_for_request(_request("GET", "/api/device-candidates/{candidate_id}")) == P.CANDIDATE_READ


def test_availability_routes_reuse_device_permissions():
    assert permission_for_request(_request("GET", "/api/devices/availability/summary")) == P.DEVICE_READ
    assert permission_for_request(_request("GET", "/api/devices/availability/page")) == P.DEVICE_READ
    assert permission_for_request(_request("GET", "/api/devices/{device_id}/availability")) == P.DEVICE_READ
    assert permission_for_request(_request("PATCH", "/api/devices/{device_id}/availability")) == P.DEVICE_UPDATE


@pytest.mark.parametrize(
    ("entity_type", "expected"),
    (
        ("NETWORK", P.NETWORK_DELETE),
        ("CITY", P.GEO_DELETE),
        ("LOCATION", P.GEO_DELETE),
        ("SECTOR", P.GEO_DELETE),
        ("DEVICE", P.DEVICE_DELETE),
        ("CUSTOMER", P.CUSTOMER_DELETE),
        ("CUSTOMER_SERVICE", P.CUSTOMER_DELETE),
        ("DEVICE_GROUP", P.GROUP_DELETE),
        ("DEVICE_RELATIONSHIP", P.RELATIONSHIP_DELETE),
        ("DEVICE_IP", P.DEVICE_DELETE),
        ("DEVICE_INTERFACE", P.DEVICE_DELETE),
    ),
)
def test_recycle_preview_uses_entity_delete_authority(entity_type: str, expected: str):
    request = _request("GET", "/api/recycle-bin/preview", f"entity_type={entity_type}&entity_id=00000000-0000-0000-0000-000000000001")
    assert permission_for_request(request) == expected


def test_delete_preview_authorizes_with_entity_delete_not_recycle_read(monkeypatch):
    seen: list[str] = []

    async def has_permission(db, *, user_id, permission_code):
        seen.append(permission_code)
        return permission_code == P.DEVICE_DELETE

    monkeypatch.setattr(authorization_module, "user_has_permission", has_permission)
    request = _request(
        "GET",
        "/api/recycle-bin/preview",
        "entity_type=DEVICE&entity_id=00000000-0000-0000-0000-000000000001",
    )

    async def scenario():
        user = SimpleNamespace(id="test-user")
        assert await authorize_request(request, user=user, db=object()) is user

    asyncio.run(scenario())
    assert seen == [P.DEVICE_DELETE]


def test_unmapped_protected_get_fails_closed():
    request = _request("GET", "/api/future-protected-resource")

    async def scenario():
        with pytest.raises(APIError) as error:
            await authorize_request(request, user=object(), db=None)
        assert error.value.status_code == 403
        assert error.value.detail["code"] == "PERMISSION_DENIED"

    asyncio.run(scenario())


def test_every_authorize_request_route_has_an_explicit_permission_mapping():
    unmapped: list[str] = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if authorize_request not in _dependency_calls(route.dependant):
            continue
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            request = Request(
                {
                    "type": "http",
                    "method": method,
                    "path": route.path,
                    "raw_path": route.path.encode(),
                    "root_path": "",
                    "scheme": "http",
                    "query_string": b"",
                    "headers": [],
                    "client": ("test", 1),
                    "server": ("test", 80),
                    "route": route,
                }
            )
            if permission_for_request(request) is None:
                unmapped.append(f"{method} {route.path}")
    assert unmapped == []


def test_production_demo_seed_is_fail_closed():
    with pytest.raises(RuntimeError):
        ensure_runtime_safety(environment="production", seed_demo_data="true")
    ensure_runtime_safety(environment="production", seed_demo_data="false")
    ensure_runtime_safety(environment="development", seed_demo_data="true")
    with pytest.raises(RuntimeError):
        ensure_demo_seed_allowed(environment="production")
    ensure_demo_seed_allowed(environment="development")
    ensure_demo_seed_allowed(environment="validation")


def test_canonical_contract_tracks_current_security_schema():
    assert CANONICAL_REVISION == "0027_report_config_trash"
    assert "password_history" in TABLES
    assert "device_availability" in TABLES
    assert "alarms" in TABLES
    assert "operational_events" in TABLES
    assert "ix_auth_sessions_active_lookup" in INDEXES
    assert "ix_auth_sessions_last_seen" in INDEXES
    assert "ix_auth_sessions_user_activity" in INDEXES
    assert "ix_password_history_user_created" in INDEXES
    assert "last_user_activity_at" in COLUMNS["auth_sessions"]
    assert "must_change_password" in COLUMNS["users"]
    assert "service_vlan_id" in COLUMNS["cities"]
    assert {"customer_vlan_start", "customer_vlan_end"} <= COLUMNS["sectors"]
    assert "customer_vlan_id" in COLUMNS["customer_services"]


def test_fresh_seed_catalog_contains_incremental_permissions():
    seed_text = (Path(__file__).resolve().parents[2] / "scripts" / "seed_demo_data.py").read_text()
    assert '("discovery.flush","Discovery Flush")' in seed_text
    assert '("user.sessions.read","User Sessions Read")' in seed_text
    assert '("alarm.read","Alarm Read")' in seed_text
    assert '("restricted", "Restricted", "Minimal role with no operational permissions; add only the required direct permissions.")' in seed_text
    assert '"restricted": set(),' in seed_text
    # Viewer is intentionally explicit: never derive all *.read permissions,
    # which would leak administrative/security reads such as settings.secret.read.
    assert 'if (x[0].endswith(".read")' not in seed_text

