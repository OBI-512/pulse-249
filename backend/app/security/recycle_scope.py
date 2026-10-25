from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import and_, false, func, literal, or_, select, true, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import (
    City, Customer, CustomerService, Device, DeviceGroup, DeviceGroupMembership,
    DeviceGroupNesting, DeviceHierarchyLink, DeviceIP, DeviceInterface,
    DevicePlacement, DeviceRelationship, Location, Network, RecycleBinBatch,
    Sector, UserResourceScope,
)
from .resource_scope import EffectiveResourceScope, expanded_authorization_scope_keys, load_effective_resource_scope
from .scope_queries import (
    city_scope_clause, customer_scope_clause, customer_service_scope_clause,
    device_scope_clause, group_scope_clause, location_scope_clause,
    network_scope_clause, relationship_scope_clause, sector_scope_clause,
)

_RESERVED_REQUIRED_GRANTS = "_authorization_required_grants"


def _scope_row_key(row: UserResourceScope) -> str | None:
    target = {
        "NETWORK": row.network_id,
        "CITY": row.city_id,
        "LOCATION": row.location_id,
        "SECTOR": row.sector_id,
        "GROUP": row.group_id,
    }.get(row.scope_type)
    if row.scope_type == "GLOBAL":
        return "GLOBAL"
    return f"{row.scope_type}:{target}" if target is not None else None


async def _device_authorization_keys(
    db: AsyncSession,
    scope: EffectiveResourceScope,
    device_id: UUID,
    actor_keys: set[str],
) -> set[str]:
    """Return stable keys that can represent this device's authorization path.

    Prefer the authoritative geographic leaf because ancestor grants expand to it.
    If the current non-GLOBAL actor reaches the device only through GROUP scope,
    select a matching group key instead. This prevents unrelated actor grants from
    becoming requirements on the recycle batch.
    """
    from ..services.group_effective import effective_group_context_subquery, direct_group_device_select

    context = effective_group_context_subquery()
    row = (await db.execute(
        select(
            context.c.network_id,
            context.c.city_id,
            context.c.location_id,
            context.c.sector_id,
        ).where(context.c.device_id == device_id)
    )).first()
    geo_candidates: list[str] = []
    if row is not None:
        for kind, value in (
            ("SECTOR", row.sector_id),
            ("LOCATION", row.location_id),
            ("CITY", row.city_id),
            ("NETWORK", row.network_id),
        ):
            if value is not None:
                geo_candidates.append(f"{kind}:{value}")

    # GLOBAL actors may record the most specific stable geography so a later
    # scoped operator covering the same resource can restore/purge it.
    if scope.global_access and geo_candidates:
        return {geo_candidates[0]}
    for key in geo_candidates:
        if key in actor_keys:
            return {key}

    if scope.group_ids:
        groups = list((await db.scalars(select(DeviceGroup).where(
            DeviceGroup.id.in_(tuple(scope.group_ids)),
            DeviceGroup.deleted_at.is_(None),
        ))).all())
        if groups:
            selects = [
                direct_group_device_select(group).add_columns(
                    literal(str(group.id)).label("scope_group_id")
                )
                for group in groups
            ]
            population = (union_all(*selects) if len(selects) > 1 else selects[0]).subquery("recycle_authorized_group_population")
            match = (await db.execute(
                select(population.c.scope_group_id).where(population.c.device_id == device_id).limit(1)
            )).first()
            if match is not None:
                return {f"GROUP:{match.scope_group_id}"}
    return set()


async def _group_authorization_keys(
    scope: EffectiveResourceScope,
    group: DeviceGroup,
    actor_keys: set[str],
) -> set[str]:
    anchored = {
        "NETWORK": group.network_id,
        "CITY": group.city_id,
        "LOCATION": group.location_id,
        "SECTOR": group.sector_id,
    }.get(group.scope_type)
    if anchored is not None:
        key = f"{group.scope_type}:{anchored}"
        if scope.global_access or key in actor_keys:
            return {key}
    group_key = f"GROUP:{group.id}"
    if scope.global_access or group_key in actor_keys:
        return {group_key}
    return set()


async def _row_required_keys(
    db: AsyncSession,
    scope: EffectiveResourceScope,
    actor_keys: set[str],
    entity_type: str,
    row: Any,
) -> set[str]:
    if entity_type == "NETWORK":
        return {f"NETWORK:{row.id}"}
    if entity_type == "CITY":
        return {f"CITY:{row.id}"}
    if entity_type == "LOCATION":
        return {f"LOCATION:{row.id}"}
    if entity_type == "SECTOR":
        return {f"SECTOR:{row.id}"}
    if entity_type == "DEVICE":
        return await _device_authorization_keys(db, scope, row.id, actor_keys)
    if entity_type == "CUSTOMER_SERVICE":
        return {f"SECTOR:{row.sector_id}"} if row.sector_id else set()
    if entity_type == "CUSTOMER":
        sector_ids = list((await db.scalars(select(CustomerService.sector_id).where(
            CustomerService.customer_id == row.id,
            CustomerService.deleted_at.is_(None),
            CustomerService.sector_id.is_not(None),
        ))).all())
        keys = [f"SECTOR:{value}" for value in sector_ids]
        if scope.global_access:
            return {keys[0]} if keys else {"GLOBAL"}
        matching = [key for key in keys if key in actor_keys]
        return {matching[0]} if matching else set()
    if entity_type == "DEVICE_GROUP":
        return await _group_authorization_keys(scope, row, actor_keys)
    if entity_type == "DEVICE_RELATIONSHIP":
        return (
            await _device_authorization_keys(db, scope, row.source_device_id, actor_keys)
            | await _device_authorization_keys(db, scope, row.target_device_id, actor_keys)
        )
    if entity_type in {"DEVICE_IP", "DEVICE_INTERFACE", "DEVICE_PLACEMENT"}:
        return await _device_authorization_keys(db, scope, row.device_id, actor_keys)
    if entity_type == "DEVICE_HIERARCHY_LINK":
        return (
            await _device_authorization_keys(db, scope, row.parent_device_id, actor_keys)
            | await _device_authorization_keys(db, scope, row.child_device_id, actor_keys)
        )
    if entity_type == "DEVICE_GROUP_MEMBERSHIP":
        group = await db.get(DeviceGroup, row.group_id)
        return (
            (await _group_authorization_keys(scope, group, actor_keys) if group else set())
            | await _device_authorization_keys(db, scope, row.device_id, actor_keys)
        )
    if entity_type == "DEVICE_GROUP_NESTING":
        parent = await db.get(DeviceGroup, row.parent_group_id)
        child = await db.get(DeviceGroup, row.child_group_id)
        keys: set[str] = set()
        if parent:
            keys |= await _group_authorization_keys(scope, parent, actor_keys)
        if child:
            keys |= await _group_authorization_keys(scope, child, actor_keys)
        return keys
    return {"GLOBAL"} if scope.global_access else set()


def add_required_grants_snapshot(snapshot: dict | None, grant_keys: set[str]) -> dict:
    result = dict(snapshot or {})
    result[_RESERVED_REQUIRED_GRANTS] = {key: True for key in sorted(grant_keys)}
    return result


async def recycle_batch_scope_clause(db: AsyncSession, scope: EffectiveResourceScope, snapshot_col=RecycleBinBatch.root_display_snapshot):
    if scope.global_access:
        return true()
    keys = await expanded_authorization_scope_keys(db, scope)
    if not keys:
        return false()
    required = snapshot_col[_RESERVED_REQUIRED_GRANTS]
    # New batches store only the authorization footprint of the bundled
    # resources, never every unrelated grant held by the deleting actor.
    # A broader current ancestor grant works because actor keys expand downward.
    # Legacy batches without a footprint remain GLOBAL-only.
    return and_(
        snapshot_col.has_key(_RESERVED_REQUIRED_GRANTS),  # noqa: W601 - PostgreSQL JSONB operator
        required.contained_by({key: True for key in sorted(keys)}),
    )


async def batch_is_in_scope(db: AsyncSession, scope: EffectiveResourceScope, batch_id: UUID) -> RecycleBinBatch | None:
    return await db.scalar(
        select(RecycleBinBatch).where(
            RecycleBinBatch.id == batch_id,
            await recycle_batch_scope_clause(db, scope),
        )
    )


async def _row_in_scope(db: AsyncSession, scope: EffectiveResourceScope, entity_type: str, row: Any) -> bool:
    if scope.global_access:
        return True
    if entity_type == "NETWORK":
        return bool(await db.scalar(select(Network.id).where(Network.id == row.id, network_scope_clause(scope))))
    if entity_type == "CITY":
        return bool(await db.scalar(select(City.id).where(City.id == row.id, city_scope_clause(scope))))
    if entity_type == "LOCATION":
        return bool(await db.scalar(select(Location.id).where(Location.id == row.id, location_scope_clause(scope))))
    if entity_type == "SECTOR":
        return bool(await db.scalar(select(Sector.id).where(Sector.id == row.id, sector_scope_clause(scope))))
    if entity_type == "DEVICE":
        clause = await device_scope_clause(db, scope, device_col=Device.id)
        return bool(await db.scalar(select(Device.id).where(Device.id == row.id, clause)))
    if entity_type == "CUSTOMER":
        return bool(await db.scalar(select(Customer.id).where(Customer.id == row.id, customer_scope_clause(scope))))
    if entity_type == "CUSTOMER_SERVICE":
        return bool(await db.scalar(select(CustomerService.id).where(CustomerService.id == row.id, customer_service_scope_clause(scope))))
    if entity_type == "DEVICE_GROUP":
        return bool(await db.scalar(select(DeviceGroup.id).where(DeviceGroup.id == row.id, group_scope_clause(scope))))
    if entity_type == "DEVICE_RELATIONSHIP":
        clause = await relationship_scope_clause(db, scope, relationship=DeviceRelationship)
        return bool(await db.scalar(select(DeviceRelationship.id).where(DeviceRelationship.id == row.id, clause)))
    if entity_type in {"DEVICE_IP", "DEVICE_INTERFACE", "DEVICE_PLACEMENT"}:
        clause = await device_scope_clause(db, scope, device_col=Device.id)
        return bool(await db.scalar(select(Device.id).where(Device.id == row.device_id, clause)))
    if entity_type == "DEVICE_HIERARCHY_LINK":
        clause = await device_scope_clause(db, scope, device_col=Device.id)
        parent_ok = bool(await db.scalar(select(Device.id).where(Device.id == row.parent_device_id, clause)))
        child_ok = bool(await db.scalar(select(Device.id).where(Device.id == row.child_device_id, clause)))
        return parent_ok and child_ok
    if entity_type == "DEVICE_GROUP_MEMBERSHIP":
        group_ok = bool(await db.scalar(select(DeviceGroup.id).where(DeviceGroup.id == row.group_id, group_scope_clause(scope))))
        clause = await device_scope_clause(db, scope, device_col=Device.id)
        device_ok = bool(await db.scalar(select(Device.id).where(Device.id == row.device_id, clause)))
        return group_ok and device_ok
    if entity_type == "DEVICE_GROUP_NESTING":
        parent_ok = bool(await db.scalar(select(DeviceGroup.id).where(DeviceGroup.id == row.parent_group_id, group_scope_clause(scope))))
        child_ok = bool(await db.scalar(select(DeviceGroup.id).where(DeviceGroup.id == row.child_group_id, group_scope_clause(scope))))
        return parent_ok and child_ok
    return False


async def _protected_scope_target_conflicts(
    db: AsyncSession,
    *,
    actor_user_id: UUID | None,
    scope: EffectiveResourceScope,
    typed_rows: list[tuple[Any, Any]],
) -> list[dict[str, str]]:
    if actor_user_id is None:
        return []
    targets = {
        "NETWORK": {row.id for item, row in typed_rows if item.entity_type == "NETWORK"},
        "CITY": {row.id for item, row in typed_rows if item.entity_type == "CITY"},
        "LOCATION": {row.id for item, row in typed_rows if item.entity_type == "LOCATION"},
        "SECTOR": {row.id for item, row in typed_rows if item.entity_type == "SECTOR"},
        "GROUP": {row.id for item, row in typed_rows if item.entity_type == "DEVICE_GROUP"},
    }
    clauses = []
    for kind, ids in targets.items():
        if not ids:
            continue
        column = {
            "NETWORK": UserResourceScope.network_id,
            "CITY": UserResourceScope.city_id,
            "LOCATION": UserResourceScope.location_id,
            "SECTOR": UserResourceScope.sector_id,
            "GROUP": UserResourceScope.group_id,
        }[kind]
        clauses.append(and_(UserResourceScope.scope_type == kind, column.in_(tuple(ids))))
    if not clauses:
        return []
    protected = int((await db.scalar(select(func.count()).select_from(UserResourceScope).where(or_(*clauses)))) or 0)
    if not protected:
        return []
    from .authorization import user_has_permission
    allowed = scope.global_access and await user_has_permission(
        db, user_id=actor_user_id, permission_code="user.scopes.manage"
    )
    if allowed:
        return []
    return [{
        "code": "SECURITY_SCOPE_TARGET_PROTECTED",
        "entity_type": "RESOURCE_SCOPE_TARGET",
        "entity_id": "multiple" if protected > 1 else "protected",
        "message": "Deleting a resource used directly as a security scope requires GLOBAL scope and user.scopes.manage.",
    }]


async def cross_scope_recycle_conflicts(
    db: AsyncSession,
    *,
    actor_user_id: UUID | None,
    typed_rows: list[tuple[Any, Any]],
) -> tuple[list[dict[str, str]], set[str]]:
    if actor_user_id is None:
        compatibility = EffectiveResourceScope(
            user_id=UUID(int=0), global_access=True,
            network_ids=frozenset(), city_ids=frozenset(), location_ids=frozenset(),
            sector_ids=frozenset(), group_ids=frozenset(),
        )
        required: set[str] = set()
        for item, row in typed_rows:
            required |= await _row_required_keys(db, compatibility, {"GLOBAL"}, item.entity_type, row)
        return [], required or {"GLOBAL"}

    scope = await load_effective_resource_scope(db, actor_user_id)
    actor_keys = await expanded_authorization_scope_keys(db, scope)
    conflicts = await _protected_scope_target_conflicts(
        db, actor_user_id=actor_user_id, scope=scope, typed_rows=typed_rows
    )
    required: set[str] = set()
    for item, row in typed_rows:
        if not await _row_in_scope(db, scope, item.entity_type, row):
            conflicts.append({
                "code": "RECYCLE_SCOPE_CROSS_BOUNDARY",
                "entity_type": item.entity_type,
                "entity_id": str(item.entity_id),
                "message": "The recycle bundle crosses the actor's resource scope.",
            })
            continue
        item_keys = await _row_required_keys(db, scope, actor_keys, item.entity_type, row)
        if not item_keys:
            conflicts.append({
                "code": "RECYCLE_SCOPE_UNRESOLVED",
                "entity_type": item.entity_type,
                "entity_id": str(item.entity_id),
                "message": "The resource authorization footprint could not be resolved safely.",
            })
            continue
        required |= item_keys
    return conflicts, required or ({"GLOBAL"} if scope.global_access else set())

async def preview_scope_conflicts(
    db: AsyncSession,
    *,
    actor_user_id: UUID | None,
    entity_type: str,
    entity_id: UUID,
    bundled_items: list[Any],
) -> list[dict[str, str]]:
    from types import SimpleNamespace
    from ..services.recycle_policies import ITEM_MODELS

    all_items = [SimpleNamespace(entity_type=entity_type, entity_id=entity_id), *bundled_items]
    typed_rows: list[tuple[Any, Any]] = []
    for item in all_items:
        model = ITEM_MODELS[item.entity_type]
        row = await db.scalar(select(model).where(model.id == item.entity_id))
        if row is None:
            return [{
                "code": "RECYCLE_SCOPE_CROSS_BOUNDARY",
                "entity_type": item.entity_type,
                "entity_id": str(item.entity_id),
                "message": "The resource is unavailable in the actor's scope.",
            }]
        typed_rows.append((item, row))
    conflicts, _ = await cross_scope_recycle_conflicts(db, actor_user_id=actor_user_id, typed_rows=typed_rows)
    return conflicts
