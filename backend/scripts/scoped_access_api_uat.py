"""Post-deploy scoped-access API acceptance gate.

Creates uniquely-prefixed synthetic fixtures directly in the validation database,
then exercises the live HTTP API using real /api/auth/login bearer tokens. No
password or token is printed. Only fixtures created by this run are cleaned up.
"""
from __future__ import annotations

import asyncio
import json
import secrets
from dataclasses import dataclass
from uuid import UUID, uuid4

import httpx
from sqlalchemy import delete, select

from app.db.session import AsyncSessionLocal
from app.models import City, Location, Network, Role, Sector, User, UserResourceScope, UserRole
from app.security.passwords import hash_password

BASE_URL = "http://127.0.0.1:8000"


@dataclass
class Check:
    name: str
    passed: bool
    detail: str


async def _login(client: httpx.AsyncClient, username: str, password: str) -> str:
    response = await client.post("/api/auth/login", json={"username": username, "password": password})
    if response.status_code != 200:
        raise RuntimeError(f"login failed for synthetic user: HTTP {response.status_code}")
    token = response.json().get("access_token")
    if not token:
        raise RuntimeError("login response did not contain access_token")
    return token


async def main() -> int:
    suffix = uuid4().hex[:10]
    prefix = f"SA-SCOPE-UAT-{suffix}"
    password = f"Sa!{secrets.token_urlsafe(18)}9Z"
    created_user_ids: list[UUID] = []
    created_network_ids: list[UUID] = []
    checks: list[Check] = []

    async with AsyncSessionLocal() as db:
        admin_role = await db.scalar(select(Role).where(Role.code == "administrator"))
        if admin_role is None:
            raise RuntimeError("administrator role is not configured")

        net_a = Network(name=f"{prefix} Network A", code=f"SUA-{suffix}")
        net_b = Network(name=f"{prefix} Network B", code=f"SUB-{suffix}")
        db.add_all([net_a, net_b]); await db.flush()
        city_a = City(network_id=net_a.id, name=f"{prefix} City A", code=f"SCA-{suffix}")
        city_b = City(network_id=net_b.id, name=f"{prefix} City B", code=f"SCB-{suffix}")
        db.add_all([city_a, city_b]); await db.flush()
        loc_a = Location(city_id=city_a.id, name=f"{prefix} Location A", code=f"SLA-{suffix}", metadata_={})
        loc_b = Location(city_id=city_b.id, name=f"{prefix} Location B", code=f"SLB-{suffix}", metadata_={})
        db.add_all([loc_a, loc_b]); await db.flush()
        sec_a = Sector(location_id=loc_a.id, name=f"{prefix} Sector A", code=f"SSA-{suffix}", metadata_={})
        sec_b = Sector(location_id=loc_b.id, name=f"{prefix} Sector B", code=f"SSB-{suffix}", metadata_={})
        db.add_all([sec_a, sec_b]); await db.flush()

        scoped = User(external_subject=f"{prefix}-scoped", username=f"sa-scoped-{suffix}", display_name="Scoped UAT", password_hash=hash_password(password), is_active=True, must_change_password=False, metadata_={})
        empty = User(external_subject=f"{prefix}-empty", username=f"sa-empty-{suffix}", display_name="Empty Scope UAT", password_hash=hash_password(password), is_active=True, must_change_password=False, metadata_={})
        no_perm = User(external_subject=f"{prefix}-noperm", username=f"sa-noperm-{suffix}", display_name="No Permission UAT", password_hash=hash_password(password), is_active=True, must_change_password=False, metadata_={})
        db.add_all([scoped, empty, no_perm]); await db.flush()
        db.add_all([UserRole(user_id=scoped.id, role_id=admin_role.id), UserRole(user_id=empty.id, role_id=admin_role.id)])
        db.add_all([
            UserResourceScope(user_id=scoped.id, scope_type="NETWORK", network_id=net_a.id),
            UserResourceScope(user_id=scoped.id, scope_type="CITY", city_id=city_b.id),
        ])
        created_user_ids[:] = [scoped.id, empty.id, no_perm.id]
        created_network_ids[:] = [net_a.id, net_b.id]
        await db.commit()

    created_city_id: UUID | None = None
    try:
        async with httpx.AsyncClient(base_url=BASE_URL, timeout=20.0) as client:
            scoped_token = await _login(client, f"sa-scoped-{suffix}", password)
            empty_token = await _login(client, f"sa-empty-{suffix}", password)
            no_perm_token = await _login(client, f"sa-noperm-{suffix}", password)
            scoped_headers = {"Authorization": f"Bearer {scoped_token}"}
            empty_headers = {"Authorization": f"Bearer {empty_token}"}
            no_perm_headers = {"Authorization": f"Bearer {no_perm_token}"}

            response = await client.get("/api/networks", headers=scoped_headers)
            body = response.json() if response.status_code == 200 else []
            ids = {item["id"] for item in body} if isinstance(body, list) else set()
            checks.append(Check("network list filters before exposure", response.status_code == 200 and str(net_a.id) in ids and str(net_b.id) not in ids, f"HTTP {response.status_code}"))

            response = await client.get(f"/api/networks/{net_b.id}", headers=scoped_headers)
            checks.append(Check("out-of-scope detail is enumeration-safe", response.status_code == 404, f"HTTP {response.status_code}"))

            response = await client.get("/api/cities/page?page=1&page_size=50", headers=scoped_headers)
            data = response.json() if response.status_code == 200 else {}
            city_ids = {item["id"] for item in data.get("items", [])}
            checks.append(Check("multiple scopes form union", response.status_code == 200 and str(city_a.id) in city_ids and str(city_b.id) in city_ids, f"HTTP {response.status_code}"))

            response = await client.get("/api/geography/scope-options", headers=scoped_headers)
            data = response.json() if response.status_code == 200 else {}
            network_ids = {item["id"] for item in data.get("networks", [])}
            checks.append(Check("city scope does not leak parent network", response.status_code == 200 and str(net_a.id) in network_ids and str(net_b.id) not in network_ids, f"HTTP {response.status_code}"))

            payload = {"name": f"{prefix} API City", "code": f"SCI-{suffix}", "description": "synthetic scoped API UAT"}
            response = await client.post(f"/api/networks/{net_a.id}/cities", headers=scoped_headers, json=payload)
            if response.status_code == 201:
                created_city_id = UUID(response.json()["id"])
            checks.append(Check("in-scope mutation allowed", response.status_code == 201, f"HTTP {response.status_code}"))

            payload["code"] = f"SCO-{suffix}"
            response = await client.post(f"/api/networks/{net_b.id}/cities", headers=scoped_headers, json=payload)
            checks.append(Check("out-of-scope destination mutation denied", response.status_code == 404, f"HTTP {response.status_code}"))

            response = await client.get("/api/networks", headers=empty_headers)
            body = response.json() if response.status_code == 200 else None
            checks.append(Check("no resource scope fails closed", response.status_code == 200 and body == [], f"HTTP {response.status_code}"))

            response = await client.get("/api/networks", headers=no_perm_headers)
            checks.append(Check("WHAT permission still required inside WHERE model", response.status_code == 403, f"HTTP {response.status_code}"))

        failed = [check for check in checks if not check.passed]
        print(json.dumps({
            "gate": "SCOPED_ACCESS_API_UAT",
            "status": "PASS" if not failed else "FAIL",
            "pass": sum(1 for check in checks if check.passed),
            "fail": len(failed),
            "checks": [check.__dict__ for check in checks],
        }, indent=2))
        return 0 if not failed else 1
    finally:
        async with AsyncSessionLocal() as db:
            if created_city_id is not None:
                await db.execute(delete(City).where(City.id == created_city_id))
            # SQLAlchemy/DB FK cascades remove sessions, roles, and resource scopes.
            await db.execute(delete(User).where(User.id.in_(created_user_ids)))
            # Remove the synthetic hierarchy from leaves upward.
            await db.execute(delete(Sector).where(Sector.name.like(f"{prefix}%")))
            await db.execute(delete(Location).where(Location.name.like(f"{prefix}%")))
            await db.execute(delete(City).where(City.name.like(f"{prefix}%")))
            await db.execute(delete(Network).where(Network.id.in_(created_network_ids)))
            await db.commit()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
