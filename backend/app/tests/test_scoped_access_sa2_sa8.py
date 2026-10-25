import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.exceptions import APIError
from app.models import City, Device, DeviceCandidate, DeviceType, Location, Network, Sector, User, UserResourceScope
from app.security.resource_scope import (
    expanded_authorization_scope_keys,
    load_effective_resource_scope,
    preserve_authorization_metadata,
    scope_for_actor,
)
from app.settings import settings
from app.security.scope_queries import (
    candidate_scope_clause,
    city_scope_clause,
    location_scope_clause,
    network_scope_clause,
    require_city,
    sector_scope_clause,
)


def test_direct_router_compatibility_scope_is_global_but_real_actor_is_not_bypassed():
    async def scenario():
        compatibility = await scope_for_actor(object(), None)
        assert compatibility.global_access is True
        unresolved_dep = await scope_for_actor(object(), Depends(lambda: None))
        assert unresolved_dep.global_access is True

    asyncio.run(scenario())


def test_reserved_candidate_authorization_metadata_cannot_be_overwritten():
    existing = {"_authorization_scope": {"version": 1, "keys": {"NETWORK:a": True}}, "old": 1}
    replacement = {"_authorization_scope": {"version": 999, "keys": {"GLOBAL": True}}, "user": "value"}
    result = preserve_authorization_metadata(existing, replacement)
    assert result["_authorization_scope"] == existing["_authorization_scope"]
    assert result["user"] == "value"
    assert "old" not in result


def test_geographic_union_downward_inheritance_and_no_upward_leakage():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with factory() as db:
                tx = await db.begin()
                try:
                    suffix = uuid4().hex[:10]
                    user = User(
                        external_subject=f"scope-sa2-{suffix}", username=f"scope-sa2-{suffix}",
                        display_name="SA2 Scope Test", is_active=True, metadata_={},
                    )
                    net_a = Network(name=f"SA2 Net A {suffix}", code=f"S2NA-{suffix}")
                    net_b = Network(name=f"SA2 Net B {suffix}", code=f"S2NB-{suffix}")
                    db.add_all([user, net_a, net_b]); await db.flush()
                    city_a = City(network_id=net_a.id, name=f"SA2 City A {suffix}", code=f"S2CA-{suffix}")
                    city_b = City(network_id=net_b.id, name=f"SA2 City B {suffix}", code=f"S2CB-{suffix}")
                    db.add_all([city_a, city_b]); await db.flush()
                    loc_a = Location(city_id=city_a.id, name=f"SA2 Loc A {suffix}", code=f"S2LA-{suffix}", metadata_={})
                    loc_b = Location(city_id=city_b.id, name=f"SA2 Loc B {suffix}", code=f"S2LB-{suffix}", metadata_={})
                    db.add_all([loc_a, loc_b]); await db.flush()
                    sec_a = Sector(location_id=loc_a.id, name=f"SA2 Sec A {suffix}", code=f"S2SA-{suffix}", metadata_={})
                    sec_b = Sector(location_id=loc_b.id, name=f"SA2 Sec B {suffix}", code=f"S2SB-{suffix}", metadata_={})
                    db.add_all([sec_a, sec_b]); await db.flush()
                    db.add_all([
                        UserResourceScope(user_id=user.id, scope_type="NETWORK", network_id=net_a.id),
                        UserResourceScope(user_id=user.id, scope_type="CITY", city_id=city_b.id),
                    ])
                    await db.flush()

                    scope = await load_effective_resource_scope(db, user.id)
                    assert scope.global_access is False
                    keys = await expanded_authorization_scope_keys(db, scope)
                    assert f"NETWORK:{net_a.id}" in keys
                    assert f"CITY:{city_a.id}" in keys
                    assert f"LOCATION:{loc_a.id}" in keys
                    assert f"SECTOR:{sec_a.id}" in keys
                    assert f"CITY:{city_b.id}" in keys
                    assert f"LOCATION:{loc_b.id}" in keys
                    assert f"SECTOR:{sec_b.id}" in keys
                    assert f"NETWORK:{net_b.id}" not in keys

                    networks = set((await db.scalars(select(Network.id).where(network_scope_clause(scope)))).all())
                    cities = set((await db.scalars(select(City.id).where(city_scope_clause(scope)))).all())
                    locations = set((await db.scalars(select(Location.id).where(location_scope_clause(scope)))).all())
                    sectors = set((await db.scalars(select(Sector.id).where(sector_scope_clause(scope)))).all())
                    assert net_a.id in networks and net_b.id not in networks
                    assert {city_a.id, city_b.id} <= cities
                    assert {loc_a.id, loc_b.id} <= locations
                    assert {sec_a.id, sec_b.id} <= sectors

                    with pytest.raises(APIError) as exc:
                        await require_city(db, scope, uuid4())
                    assert exc.value.status_code == 404
                finally:
                    await tx.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())

def test_candidate_explicit_geography_supersedes_origin_provenance():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with factory() as db:
                tx = await db.begin()
                try:
                    suffix = uuid4().hex[:10]
                    user = User(
                        external_subject=f"cand-scope-{suffix}", username=f"cand-scope-{suffix}",
                        display_name="Candidate Scope Test", is_active=True, metadata_={},
                    )
                    net_a = Network(name=f"Cand Net A {suffix}", code=f"CNA-{suffix}")
                    net_b = Network(name=f"Cand Net B {suffix}", code=f"CNB-{suffix}")
                    db.add_all([user, net_a, net_b]); await db.flush()
                    db.add(UserResourceScope(user_id=user.id, scope_type="NETWORK", network_id=net_a.id)); await db.flush()
                    scope = await load_effective_resource_scope(db, user.id)
                    origin = {"_authorization_scope": {"version": 1, "keys": {f"NETWORK:{net_a.id}": True}}}
                    unanchored = DeviceCandidate(ip_address=f"198.51.100.{int(suffix[:2],16)%200+1}", metadata_=origin)
                    moved = DeviceCandidate(ip_address=f"203.0.113.{int(suffix[2:4],16)%200+1}", network_id=net_b.id, metadata_=origin)
                    db.add_all([unanchored, moved]); await db.flush()
                    clause = await candidate_scope_clause(db, scope)
                    visible = set((await db.scalars(select(DeviceCandidate.id).where(clause))).all())
                    assert unanchored.id in visible
                    assert moved.id not in visible
                finally:
                    await tx.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())

def test_http_route_contract_preserves_pre_scope_operations_and_adds_scope_admin_endpoints():
    import json
    from pathlib import Path
    from fastapi.routing import APIRoute
    from app.main import app

    baseline = json.loads((Path(__file__).parents[2] / "scripts" / "refactor_route_contract_baseline.json").read_text())
    current = {
        (route.path, tuple(sorted(route.methods or set())))
        for route in app.routes if isinstance(route, APIRoute)
    }
    missing = []
    for item in baseline:
        key = (item["path"], tuple(sorted(item["methods"])))
        if key not in current:
            missing.append(key)
    assert missing == []
    for key in (
        ("/api/admin/resource-scope-options", ("GET",)),
        ("/api/admin/users/{user_id}/resource-scopes", ("GET",)),
        ("/api/admin/users/{user_id}/resource-scopes", ("PUT",)),
        ("/api/topology/scope-options", ("GET",)),
    ):
        assert key in current


def test_new_scope_actor_parameter_is_appended_after_legacy_callable_signature():
    """Protect direct router calls used by the established domain-test suite."""
    import ast
    import json
    from pathlib import Path

    root = Path(__file__).parents[2]
    baseline = json.loads((root / "scripts" / "refactor_route_contract_baseline.json").read_text())
    # Duplicate endpoint function names exist across router facades, so compare
    # only baseline entries whose function name is unique in the contract.
    counts = {}
    for item in baseline:
        counts[item["name"]] = counts.get(item["name"], 0) + 1
    expected = {item["name"]: [p["name"] for p in item["signature"]] for item in baseline if counts[item["name"]] == 1}
    for path in (root / "app" / "api" / "routers").glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name not in expected:
                continue
            current = [arg.arg for arg in node.args.args]
            old = expected[node.name]
            if "actor" not in old and "actor" in current:
                assert current[:len(old)] == old, f"{path.name}:{node.name} changed legacy positional parameters"
                assert current[len(old):] == ["actor"], f"{path.name}:{node.name} must append actor at the end"


def test_topology_scope_options_include_read_only_ancestor_context_without_upward_authorization():
    from app.api.routers.topology import get_topology_scope_options

    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with factory() as db:
                tx = await db.begin()
                try:
                    suffix = uuid4().hex[:10]
                    user = User(
                        external_subject=f"topo-context-{suffix}", username=f"topo-context-{suffix}",
                        display_name="Topology context test", is_active=True, metadata_={},
                    )
                    network = Network(name=f"Topology Network {suffix}", code=f"TN-{suffix}")
                    db.add_all([user, network]); await db.flush()
                    city = City(network_id=network.id, name=f"Topology City {suffix}", code=f"TC-{suffix}")
                    db.add(city); await db.flush()
                    location = Location(city_id=city.id, name=f"Topology Location {suffix}", code=f"TL-{suffix}", metadata_={})
                    db.add(location); await db.flush()
                    sector = Sector(location_id=location.id, name=f"Topology Sector {suffix}", code=f"TS-{suffix}", metadata_={})
                    db.add(sector); await db.flush()
                    db.add(UserResourceScope(user_id=user.id, scope_type="SECTOR", sector_id=sector.id)); await db.flush()

                    payload = await get_topology_scope_options(db=db, actor=user)
                    assert payload["source_networks"] == []
                    assert [item.id for item in payload["networks"]] == [network.id]
                    assert [item.id for item in payload["cities"]] == [city.id]
                    assert [item.id for item in payload["locations"]] == [location.id]
                    assert [item.id for item in payload["sectors"]] == [sector.id]

                    scope = await load_effective_resource_scope(db, user.id)
                    visible_networks = set((await db.scalars(select(Network.id).where(network_scope_clause(scope)))).all())
                    assert network.id not in visible_networks, "ancestor context must not become upward authorization"
                finally:
                    await tx.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_hierarchy_network_source_accepts_read_only_ancestor_but_returns_only_scoped_path():
    from app.api.routers.topology import _topology_network_query_access
    from app.services.topology_lazy import TopologyQuery, hierarchy_children

    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with factory() as db:
                tx = await db.begin()
                try:
                    suffix = uuid4().hex[:10]
                    user = User(
                        external_subject=f"topo-tree-context-{suffix}", username=f"topo-tree-context-{suffix}",
                        display_name="Topology tree context test", is_active=True, metadata_={},
                    )
                    network = Network(name=f"Tree Network {suffix}", code=f"TRN-{suffix}")
                    db.add_all([user, network]); await db.flush()
                    city = City(network_id=network.id, name=f"Tree City {suffix}", code=f"TRC-{suffix}")
                    db.add(city); await db.flush()
                    location = Location(city_id=city.id, name=f"Tree Location {suffix}", code=f"TRL-{suffix}", metadata_={})
                    db.add(location); await db.flush()
                    allowed = Sector(location_id=location.id, name=f"Allowed Sector {suffix}", code=f"TRA-{suffix}", metadata_={})
                    sibling = Sector(location_id=location.id, name=f"Sibling Sector {suffix}", code=f"TRS-{suffix}", metadata_={})
                    db.add_all([allowed, sibling]); await db.flush()
                    db.add(UserResourceScope(user_id=user.id, scope_type="SECTOR", sector_id=allowed.id)); await db.flush()

                    scope = await load_effective_resource_scope(db, user.id)
                    envelope = await _topology_network_query_access(db, scope, network.id)
                    assert envelope["resource_scope_restricted"] is True
                    assert network.id in envelope["path_network_ids"]
                    query = TopologyQuery(source_type="network", source_id=network.id, **envelope)

                    root = await hierarchy_children(db, query, node_kind="root", node_id=None)
                    assert [row.id for row in root] == [city.id]
                    locations = await hierarchy_children(db, query, node_kind="city", node_id=city.id)
                    assert [row.id for row in locations] == [location.id]
                    sectors = await hierarchy_children(db, query, node_kind="location", node_id=location.id)
                    sector_ids = [row.id for row in sectors if row.kind == "sector"]
                    assert sector_ids == [allowed.id]
                    assert sibling.id not in sector_ids
                    assert network.id not in set((await db.scalars(select(Network.id).where(network_scope_clause(scope)))).all())
                finally:
                    await tx.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_operational_summary_exposes_device_type_health_breakdowns():
    from app.api.routers.devices_inventory import device_operational_summary

    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with factory() as db:
                tx = await db.begin()
                try:
                    types = {
                        row.code: row
                        for row in (await db.scalars(
                            select(DeviceType).where(DeviceType.code.in_(("CPE", "ACCESS_POINT", "SECTOR")))
                        )).all()
                    }
                    assert set(types) == {"CPE", "ACCESS_POINT", "SECTOR"}
                    before = await device_operational_summary(db=db, actor=None)

                    suffix = uuid4().hex[:10]
                    db.add_all([
                        Device(device_type_id=types["CPE"].id, display_name=f"Health CPE {suffix}", lifecycle_state="REGISTERED", operational_state="UP", metadata_={}),
                        Device(device_type_id=types["ACCESS_POINT"].id, display_name=f"Health AP {suffix}", lifecycle_state="REGISTERED", operational_state="DOWN", metadata_={}),
                        Device(device_type_id=types["SECTOR"].id, display_name=f"Health Sector {suffix}", lifecycle_state="REGISTERED", operational_state="DEGRADED", metadata_={}),
                    ])
                    await db.flush()
                    after = await device_operational_summary(db=db, actor=None)

                    assert after["total"] == before["total"] + 3
                    assert after["by_type"]["CPE"]["total"] == before["by_type"].get("CPE", {"total": 0})["total"] + 1
                    assert after["by_type"]["CPE"]["states"]["UP"] == before["by_type"].get("CPE", {"states": {"UP": 0}})["states"]["UP"] + 1
                    assert after["by_type"]["ACCESS_POINT"]["states"]["DOWN"] == before["by_type"].get("ACCESS_POINT", {"states": {"DOWN": 0}})["states"]["DOWN"] + 1
                    assert after["by_type"]["SECTOR"]["states"]["DEGRADED"] == before["by_type"].get("SECTOR", {"states": {"DEGRADED": 0}})["states"]["DEGRADED"] + 1
                finally:
                    await tx.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())
