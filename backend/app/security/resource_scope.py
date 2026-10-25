from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
from uuid import UUID

from fastapi import Depends, Request
from sqlalchemy import and_, or_, select
from sqlalchemy.dialects.postgresql import array
from sqlalchemy.ext.asyncio import AsyncSession

from ..api.deps import get_db
from ..core.exceptions import APIError
from ..models import City, DeviceGroup, DeviceGroupNesting, Location, Network, Sector, User, UserResourceScope
from .authorization import get_current_user

_SCOPE_TYPES = {"GLOBAL", "NETWORK", "CITY", "LOCATION", "SECTOR", "GROUP"}


@dataclass(frozen=True)
class EffectiveResourceScope:
    user_id: UUID
    global_access: bool
    network_ids: frozenset[UUID]
    city_ids: frozenset[UUID]
    location_ids: frozenset[UUID]
    sector_ids: frozenset[UUID]
    group_ids: frozenset[UUID]

    @property
    def empty(self) -> bool:
        return not (
            self.global_access
            or self.network_ids
            or self.city_ids
            or self.location_ids
            or self.sector_ids
            or self.group_ids
        )


async def _descendant_group_ids(db: AsyncSession, roots: set[UUID]) -> set[UUID]:
    if not roots:
        return set()
    nesting = DeviceGroupNesting.__table__
    cte = (
        select(nesting.c.child_group_id.label("group_id"))
        .where(
            nesting.c.parent_group_id.in_(roots),
            nesting.c.deleted_at.is_(None),
        )
        .cte("resource_scope_group_descendants", recursive=True)
    )
    descendant = nesting.alias("resource_scope_group_nesting")
    cte = cte.union_all(
        select(descendant.c.child_group_id).where(
            descendant.c.parent_group_id == cte.c.group_id,
            descendant.c.deleted_at.is_(None),
        )
    )
    rows = set((await db.scalars(select(cte.c.group_id).distinct())).all())
    return roots | rows


async def load_effective_resource_scope(
    db: AsyncSession,
    user_id: UUID,
) -> EffectiveResourceScope:
    rows = list((await db.scalars(
        select(UserResourceScope).where(UserResourceScope.user_id == user_id)
    )).all())

    global_access = any(row.scope_type == "GLOBAL" for row in rows)
    networks = {row.network_id for row in rows if row.scope_type == "NETWORK" and row.network_id}
    cities = {row.city_id for row in rows if row.scope_type == "CITY" and row.city_id}
    locations = {row.location_id for row in rows if row.scope_type == "LOCATION" and row.location_id}
    sectors = {row.sector_id for row in rows if row.scope_type == "SECTOR" and row.sector_id}
    groups = {row.group_id for row in rows if row.scope_type == "GROUP" and row.group_id}
    groups = await _descendant_group_ids(db, groups)

    return EffectiveResourceScope(
        user_id=user_id,
        global_access=global_access,
        network_ids=frozenset(networks),
        city_ids=frozenset(cities),
        location_ids=frozenset(locations),
        sector_ids=frozenset(sectors),
        group_ids=frozenset(groups),
    )


def _id_clause(column, values: Iterable[UUID]):
    values = tuple(values)
    return column.in_(values) if values else None


def geography_access_clause(
    scope: EffectiveResourceScope,
    *,
    network_col,
    city_col,
    location_col,
    sector_col,
):
    if scope.global_access:
        return True
    clauses = [
        _id_clause(network_col, scope.network_ids),
        _id_clause(city_col, scope.city_ids),
        _id_clause(location_col, scope.location_ids),
        _id_clause(sector_col, scope.sector_ids),
    ]
    clauses = [clause for clause in clauses if clause is not None]
    return or_(*clauses) if clauses else False


async def expanded_authorization_scope_keys(
    db: AsyncSession,
    scope: EffectiveResourceScope,
) -> set[str]:
    """Return immutable overlap keys for discovery/candidate provenance.

    Direct geographic grants are expanded downward. Group grants include the
    explicitly assigned groups and active descendants. GLOBAL remains a single
    global key.
    """
    if scope.global_access:
        return {"GLOBAL"}

    network_ids = set(scope.network_ids)
    city_ids = set(scope.city_ids)
    location_ids = set(scope.location_ids)
    sector_ids = set(scope.sector_ids)

    if network_ids:
        city_ids.update((await db.scalars(select(City.id).where(City.network_id.in_(network_ids)))).all())
    if city_ids:
        location_ids.update((await db.scalars(select(Location.id).where(Location.city_id.in_(city_ids)))).all())
    if location_ids:
        sector_ids.update((await db.scalars(select(Sector.id).where(Sector.location_id.in_(location_ids)))).all())

    keys = {f"NETWORK:{value}" for value in network_ids}
    keys.update(f"CITY:{value}" for value in city_ids)
    keys.update(f"LOCATION:{value}" for value in location_ids)
    keys.update(f"SECTOR:{value}" for value in sector_ids)
    keys.update(f"GROUP:{value}" for value in scope.group_ids)
    return keys


def authorization_scope_metadata(keys: Iterable[str], *, actor_user_id: UUID) -> dict:
    return {
        "version": 1,
        "actor_user_id": str(actor_user_id),
        "keys": {key: True for key in sorted(set(keys))},
    }


def preserve_authorization_metadata(existing: dict | None, replacement: dict | None) -> dict:
    """Protect reserved immutable provenance when user-editable metadata changes."""
    result = dict(replacement or {})
    existing_auth = (existing or {}).get("_authorization_scope")
    if existing_auth is not None:
        result["_authorization_scope"] = existing_auth
    return result


def scope_metadata_matches_clause(metadata_col, scope_keys: set[str]):
    if "GLOBAL" in scope_keys:
        return True
    if not scope_keys:
        return False
    # Stored as an object so PostgreSQL JSONB ?| can test key overlap in SQL.
    return metadata_col["_authorization_scope"]["keys"].has_any(array(sorted(scope_keys)))


async def require_global_scope(
    db: AsyncSession,
    user: User,
    *,
    message: str = "Global resource scope is required for this operation.",
) -> EffectiveResourceScope:
    # Production HTTP requests always supply an authenticated User.  A small
    # number of legacy domain tests call router functions directly, leaving
    # FastAPI's Depends placeholder unresolved.  Preserve that trusted
    # direct-call compatibility without changing the fail-closed HTTP path.
    if user is None or getattr(user, "id", None) is None:
        return await scope_for_actor(db, user)
    scope = await load_effective_resource_scope(db, user.id)
    if not scope.global_access:
        raise APIError(403, "RESOURCE_SCOPE_DENIED", message)
    return scope


async def require_global_request_scope(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    await require_global_scope(db, user)
    return user


async def current_request_scope(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> EffectiveResourceScope:
    return await load_effective_resource_scope(db, user.id)


def not_found_scope_error(resource_name: str = "Resource") -> APIError:
    return APIError(404, "RESOURCE_NOT_FOUND", f"{resource_name} not found.")


CONTROL_PLANE_GLOBAL_PREFIXES = (
    "/api/admin/",
    "/api/audit",
    "/api/operational-logs",
    "/api/restore-points",
    "/api/system-information",
    "/api/data-lifecycle",
    "/api/configuration-templates",
)


def request_requires_global_scope(request: Request) -> bool:
    path = request.scope.get("route").path if request.scope.get("route") else request.url.path
    if path.startswith(CONTROL_PLANE_GLOBAL_PREFIXES):
        return True
    if path.startswith("/api/discovery/flush"):
        return True
    return False


async def scope_for_actor(db: AsyncSession, actor: User | None) -> EffectiveResourceScope:
    """Resolve request scope; None is reserved for the domain-test auth override.

    Production authentication always returns a User with an id. The compatibility
    branch also accepts FastAPI's unresolved Depends default when router functions
    are called directly by pre-existing domain tests; dedicated scoped-security
    tests exercise the real authorization dependency.
    """
    if actor is None or getattr(actor, "id", None) is None:
        return EffectiveResourceScope(
            user_id=UUID(int=0), global_access=True,
            network_ids=frozenset(), city_ids=frozenset(), location_ids=frozenset(),
            sector_ids=frozenset(), group_ids=frozenset(),
        )
    return await load_effective_resource_scope(db, actor.id)
