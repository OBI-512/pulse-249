from __future__ import annotations

from types import SimpleNamespace
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import String, and_, exists, func, literal, or_, select, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ..recycle_support import recycle_from_delete_endpoint
from ...security.authorization import authorize_request, user_has_permission
from ...security.resource_scope import require_global_scope, scope_for_actor
from ...security.scope_queries import (
    device_scope_clause, group_scope_clause, require_city, require_device, require_group,
    require_location, require_network, require_sector,
)
from ...models import (
    City,
    Device,
    DeviceGroup,
    DeviceGroupMembership,
    DeviceGroupNesting,
    DeviceHierarchyLink,
    DeviceIP,
    DevicePlacement,
    DeviceType,
    Location,
    Network,
    Sector,
    UserResourceScope,
)
from ...schemas.device import DeviceRead
from ...schemas.group import (
    DeviceGroupChildrenUpdate,
    DeviceGroupCreate,
    DeviceGroupListRow,
    DeviceGroupNestingRead,
    DeviceGroupRead,
    DeviceGroupScope as DeviceGroupScopeSchema,
    DeviceScope as DeviceScopeSchema,
    SectorRole as SectorRoleSchema,
    DeviceGroupUpdate,
    GroupDeviceItem,
    GroupItemsPage,
)
from ...schemas.pagination import PageResult
from ...services.audit import record_audit
from ...services.audit_summaries import business_summary, changed_summary, display_snapshot
from ...services.crud import get_active_for_update_or_404, get_or_404
from ...services.groups import (
    GroupMembershipConflict,
    add_child_group,
    add_membership,
    descendant_group_ids,
    direct_group_device_select,
    effective_group_context_subquery,
    move_membership,
    remove_child_group,
    replace_child_groups,
    remove_membership,
    validate_group_nesting,
    validate_membership,
)

router = APIRouter(
    prefix="/device-groups",
    tags=["Device Groups"],
    dependencies=[Depends(authorize_request)],
)

PAGE_SIZES = {50, 100, 200, 300, 400, 500}


def _bad_page(page: int, page_size: int, *, max_size: int = 500) -> None:
    if page < 1 or page_size < 1 or page_size > max_size:
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_PAGINATION", "message": f"Page size must be between 1 and {max_size}."},
        )


async def _validate_group_context(payload: DeviceGroupCreate, db: AsyncSession) -> None:
    scope = payload.scope_type
    if scope == DeviceGroupScopeSchema.GLOBAL:
        return
    pairs = {
        DeviceGroupScopeSchema.NETWORK: (Network, payload.network_id, "network_id"),
        DeviceGroupScopeSchema.CITY: (City, payload.city_id, "city_id"),
        DeviceGroupScopeSchema.LOCATION: (Location, payload.location_id, "location_id"),
        DeviceGroupScopeSchema.SECTOR: (Sector, payload.sector_id, "sector_id"),
    }
    model, entity_id, field = pairs[scope]
    if entity_id is None:
        raise HTTPException(
            status_code=422,
            detail={"code": "GROUP_CONTEXT_REQUIRED", "message": f"{scope.value} groups require {field}."},
        )
    await get_active_for_update_or_404(db, model, entity_id)


async def _validate_group_context_in_scope(payload: DeviceGroupCreate | DeviceGroupUpdate, db: AsyncSession, scope) -> None:
    scope_type = payload.scope_type
    if scope_type is None:
        return
    value = scope_type.value if hasattr(scope_type, "value") else str(scope_type)
    if value == "GLOBAL":
        if not scope.global_access:
            from ...security.resource_scope import not_found_scope_error
            raise not_found_scope_error("Group scope")
        return
    target_map = {
        "NETWORK": (payload.network_id, require_network),
        "CITY": (payload.city_id, require_city),
        "LOCATION": (payload.location_id, require_location),
        "SECTOR": (payload.sector_id, require_sector),
    }
    target_id, guard = target_map[value]
    if target_id is None:
        raise HTTPException(422, detail={"code": "GROUP_CONTEXT_REQUIRED", "message": f"{value} groups require a matching context id."})
    await guard(db, scope, target_id)


def _is_scoped_resource_not_found(exc: HTTPException) -> bool:
    detail = exc.detail
    return (
        exc.status_code == 404
        and isinstance(detail, dict)
        and detail.get("code") == "RESOURCE_NOT_FOUND"
    )


async def _require_membership_group(db: AsyncSession, scope, group_id: UUID):
    """Preserve the pre-scope group-membership 404 contract for GLOBAL actors.

    Restricted actors still receive generic RESOURCE_NOT_FOUND so scope boundaries
    cannot be enumerated.
    """
    try:
        return await require_group(db, scope, group_id)
    except HTTPException as exc:
        if scope.global_access and _is_scoped_resource_not_found(exc):
            raise HTTPException(
                status_code=404,
                detail={"code": "GROUP_NOT_FOUND", "message": "Device or group not found."},
            ) from exc
        raise


async def _require_membership_device(db: AsyncSession, scope, device_id: UUID):
    """Preserve the pre-scope device-membership 404 contract for GLOBAL actors."""
    try:
        return await require_device(db, scope, device_id)
    except HTTPException as exc:
        if scope.global_access and _is_scoped_resource_not_found(exc):
            raise HTTPException(
                status_code=404,
                detail={"code": "DEVICE_NOT_FOUND", "message": "Device or group not found."},
            ) from exc
        raise


async def _security_boundary_guard(db: AsyncSession, actor, scope, group_ids: set[UUID]) -> None:
    """Protect GROUP security scopes from organizational self-expansion.

    A GROUP grant includes active descendants, so changing a descendant group's
    population or nesting can change the effective boundary of any protected
    ancestor. Resolve the complete active ancestor closure before deciding
    whether the mutation is a security-boundary change.
    """
    if not group_ids:
        return
    nesting = DeviceGroupNesting.__table__
    ancestors = (
        select(nesting.c.parent_group_id.label("group_id"))
        .where(nesting.c.child_group_id.in_(tuple(group_ids)), nesting.c.deleted_at.is_(None))
        .cte("security_group_ancestors", recursive=True)
    )
    parent_link = nesting.alias("security_group_parent_link")
    ancestors = ancestors.union_all(
        select(parent_link.c.parent_group_id).where(
            parent_link.c.child_group_id == ancestors.c.group_id,
            parent_link.c.deleted_at.is_(None),
        )
    )
    protected_ids = select(UserResourceScope.group_id).where(
        UserResourceScope.scope_type == "GROUP",
        UserResourceScope.group_id.is_not(None),
    )
    directly_protected = await db.scalar(
        select(func.count()).select_from(UserResourceScope).where(
            UserResourceScope.scope_type == "GROUP",
            UserResourceScope.group_id.in_(tuple(group_ids)),
        )
    )
    ancestor_protected = await db.scalar(
        select(func.count()).select_from(ancestors).where(ancestors.c.group_id.in_(protected_ids))
    )
    if not directly_protected and not ancestor_protected:
        return
    actor_id = getattr(actor, "id", None)
    if actor_id is None:
        return
    if not scope.global_access or not await user_has_permission(db, user_id=actor_id, permission_code="user.scopes.manage"):
        raise HTTPException(403, detail={
            "code": "SECURITY_GROUP_BOUNDARY_PROTECTED",
            "message": "Changing a group used by a GROUP security scope requires GLOBAL scope and user.scopes.manage.",
        })


def _effective_group_context_subquery():
    return effective_group_context_subquery()


def _direct_device_select(group: DeviceGroup):
    return direct_group_device_select(group)


async def _load_groups(db: AsyncSession, ids: set[UUID]) -> list[DeviceGroup]:
    if not ids:
        return []
    return list((await db.scalars(select(DeviceGroup).where(DeviceGroup.id.in_(ids), DeviceGroup.deleted_at.is_(None)))).all())


async def _contributing_groups(db: AsyncSession, group: DeviceGroup, selected_direct_children: set[UUID] | None = None) -> list[DeviceGroup]:
    ids: set[UUID] = {group.id}
    if selected_direct_children:
        for child_id in selected_direct_children:
            ids.add(child_id)
            ids.update(await descendant_group_ids(db, child_id))
    return await _load_groups(db, ids)


async def _effective_device_count(db: AsyncSession, group: DeviceGroup) -> int:
    direct_children = set((await db.scalars(select(DeviceGroupNesting.child_group_id).where(
        DeviceGroupNesting.parent_group_id == group.id, DeviceGroupNesting.deleted_at.is_(None)
    ))).all())
    groups = await _contributing_groups(db, group, direct_children)
    selects = [_direct_device_select(item) for item in groups]
    if not selects:
        return 0
    population = union_all(*selects).subquery("group_population_count") if len(selects) > 1 else selects[0].subquery("group_population_count")
    return int((await db.scalar(select(func.count(func.distinct(population.c.device_id))))) or 0)


async def _context_names(db: AsyncSession, groups: list[DeviceGroup]) -> dict[UUID, str]:
    out: dict[UUID, str] = {}
    by_scope: dict[str, set[UUID]] = {"NETWORK": set(), "CITY": set(), "LOCATION": set(), "SECTOR": set()}
    for group in groups:
        value = {"NETWORK": group.network_id, "CITY": group.city_id, "LOCATION": group.location_id, "SECTOR": group.sector_id}.get(group.scope_type)
        if value is not None:
            by_scope[group.scope_type].add(value)
    for scope, model in (("NETWORK", Network), ("CITY", City), ("LOCATION", Location), ("SECTOR", Sector)):
        ids = by_scope[scope]
        if ids:
            for row in (await db.scalars(select(model).where(model.id.in_(ids)))).all():
                out[row.id] = row.name
    return out


@router.get("", response_model=list[DeviceGroupRead])
async def list_groups(
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    return list((await db.scalars(select(DeviceGroup).where(DeviceGroup.deleted_at.is_(None), group_scope_clause(scope)).order_by(DeviceGroup.name))).all())


@router.get("/page", response_model=PageResult[DeviceGroupListRow])
async def list_groups_page(
    db: AsyncSession = Depends(get_db),
    search: str | None = None,
    group_kind: str | None = None,
    membership_mode: str | None = None,
    scope_type: str | None = None,
    device_scope: str | None = None,
    sector_role: str | None = None,
    sort_by: str = "name",
    sort_direction: str = "asc",
    page: int = 1,
    page_size: int = 50,
    actor=Depends(authorize_request),
):
    _bad_page(page, page_size)
    if sort_direction not in {"asc", "desc"}:
        raise HTTPException(422, detail={"code": "INVALID_GROUP_SORT", "message": "Unsupported group sort direction."})
    scope = await scope_for_actor(db, actor)
    stmt = select(DeviceGroup).where(DeviceGroup.deleted_at.is_(None), group_scope_clause(scope))
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(or_(DeviceGroup.name.ilike(pattern), DeviceGroup.code.ilike(pattern), DeviceGroup.description.ilike(pattern)))
    if group_kind:
        stmt = stmt.where(DeviceGroup.group_kind == group_kind)
    if membership_mode:
        stmt = stmt.where(DeviceGroup.membership_mode == membership_mode)
    if scope_type:
        stmt = stmt.where(DeviceGroup.scope_type == scope_type)
    if device_scope:
        stmt = stmt.where(DeviceGroup.device_scope == device_scope)
    if sector_role:
        stmt = stmt.where(DeviceGroup.sector_role == sector_role)
    groups = list((await db.scalars(stmt)).all())
    contexts = await _context_names(db, groups)
    parent_rows = (await db.execute(
        select(DeviceGroupNesting.child_group_id, DeviceGroup.id, DeviceGroup.name)
        .join(DeviceGroup, DeviceGroup.id == DeviceGroupNesting.parent_group_id)
        .where(DeviceGroupNesting.deleted_at.is_(None), DeviceGroup.deleted_at.is_(None), group_scope_clause(scope))
    )).all()
    parents = {row[0]: (row[1], row[2]) for row in parent_rows}
    child_counts = dict((await db.execute(
        select(DeviceGroupNesting.parent_group_id, func.count()).where(DeviceGroupNesting.deleted_at.is_(None)).group_by(DeviceGroupNesting.parent_group_id)
    )).all())

    rows: list[DeviceGroupListRow] = []
    for group in groups:
        context_id = {"NETWORK": group.network_id, "CITY": group.city_id, "LOCATION": group.location_id, "SECTOR": group.sector_id}.get(group.scope_type)
        parent = parents.get(group.id)
        data = DeviceGroupRead.model_validate(group).model_dump()
        rows.append(DeviceGroupListRow(
            **data,
            context_name=contexts.get(context_id) if context_id else None,
            parent_group_id=parent[0] if parent else None,
            parent_group_name=parent[1] if parent else None,
            child_count=int(child_counts.get(group.id, 0)),
            device_count=await _effective_device_count(db, group),
        ))

    sort_map = {
        "name": lambda x: x.name.lower(), "code": lambda x: x.code.lower(), "group_kind": lambda x: x.group_kind.value,
        "membership_mode": lambda x: x.membership_mode.value, "scope_type": lambda x: x.scope_type.value,
        "device_scope": lambda x: x.device_scope.value, "sector_role": lambda x: x.sector_role.value if x.sector_role else "",
        "context_name": lambda x: (x.context_name or "").lower(), "parent_group_name": lambda x: (x.parent_group_name or "").lower(),
        "device_count": lambda x: x.device_count, "child_count": lambda x: x.child_count,
    }
    key = sort_map.get(sort_by)
    if key is None:
        raise HTTPException(422, detail={"code": "INVALID_GROUP_SORT", "message": "Unsupported group sort field."})
    rows.sort(key=key, reverse=sort_direction == "desc")
    total = len(rows)
    start = (page - 1) * page_size
    return PageResult(items=rows[start:start + page_size], total=total, page=page, page_size=page_size)


@router.get("/eligible-children/page", response_model=PageResult[DeviceGroupRead])
async def list_eligible_child_groups_page(
    db: AsyncSession = Depends(get_db),
    parent_group_id: UUID | None = None,
    scope_type: DeviceGroupScopeSchema = DeviceGroupScopeSchema.GLOBAL,
    network_id: UUID | None = None,
    city_id: UUID | None = None,
    location_id: UUID | None = None,
    sector_id: UUID | None = None,
    device_scope: DeviceScopeSchema = DeviceScopeSchema.ANY,
    sector_role: SectorRoleSchema | None = None,
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
    actor=Depends(authorize_request),
):
    """Return only groups valid as direct children for the draft/current parent.

    This is intentionally server-evaluated with the same nesting validator used
    by mutations. A candidate already parented elsewhere, a system group, a
    cycle, or an incompatible scope/context/device criterion is never offered.
    """
    _bad_page(page, page_size, max_size=50)
    scope = await scope_for_actor(db, actor)
    if parent_group_id is not None:
        existing_parent = await require_group(db, scope, parent_group_id)
        if existing_parent.group_kind == "SYSTEM":
            return PageResult(items=[], total=0, page=page, page_size=page_size)

    context_pairs = {
        DeviceGroupScopeSchema.NETWORK: (Network, network_id),
        DeviceGroupScopeSchema.CITY: (City, city_id),
        DeviceGroupScopeSchema.LOCATION: (Location, location_id),
        DeviceGroupScopeSchema.SECTOR: (Sector, sector_id),
    }
    if scope_type != DeviceGroupScopeSchema.GLOBAL:
        model, context_id = context_pairs[scope_type]
        if context_id is None:
            return PageResult(items=[], total=0, page=page, page_size=page_size)
        await {Network: require_network, City: require_city, Location: require_location, Sector: require_sector}[model](db, scope, context_id)

    parent = SimpleNamespace(
        id=parent_group_id or uuid4(),
        group_kind="CUSTOM",
        scope_type=scope_type.value,
        network_id=network_id if scope_type == DeviceGroupScopeSchema.NETWORK else None,
        city_id=city_id if scope_type == DeviceGroupScopeSchema.CITY else None,
        location_id=location_id if scope_type == DeviceGroupScopeSchema.LOCATION else None,
        sector_id=sector_id if scope_type == DeviceGroupScopeSchema.SECTOR else None,
        device_scope=device_scope.value,
        sector_role=sector_role.value if sector_role else None,
    )

    stmt = select(DeviceGroup).where(
        DeviceGroup.deleted_at.is_(None),
        DeviceGroup.group_kind == "CUSTOM",
        group_scope_clause(scope),
    )
    if parent_group_id is not None:
        stmt = stmt.where(DeviceGroup.id != parent_group_id)
    if search and search.strip():
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(or_(DeviceGroup.name.ilike(pattern), DeviceGroup.code.ilike(pattern)))
    candidates = list((await db.scalars(stmt.order_by(DeviceGroup.name, DeviceGroup.code))).all())
    if not candidates:
        return PageResult(items=[], total=0, page=page, page_size=page_size)

    parent_rows = (await db.execute(select(
        DeviceGroupNesting.child_group_id, DeviceGroupNesting.parent_group_id
    ).where(
        DeviceGroupNesting.child_group_id.in_([candidate.id for candidate in candidates]),
        DeviceGroupNesting.deleted_at.is_(None),
    ))).all()
    parent_by_child = {child_id: current_parent_id for child_id, current_parent_id in parent_rows}

    eligible: list[DeviceGroup] = []
    for candidate in candidates:
        current_parent_id = parent_by_child.get(candidate.id)
        if current_parent_id is not None and current_parent_id != parent_group_id:
            continue
        try:
            await validate_group_nesting(db, parent, candidate)
        except ValueError:
            continue
        eligible.append(candidate)

    total = len(eligible)
    start = (page - 1) * page_size
    return PageResult(items=eligible[start:start + page_size], total=total, page=page, page_size=page_size)


@router.post("", response_model=DeviceGroupRead, status_code=status.HTTP_201_CREATED)
async def create_group(payload: DeviceGroupCreate, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    scope = await scope_for_actor(db, actor)
    await _validate_group_context(payload, db)
    await _validate_group_context_in_scope(payload, db, scope)
    data = payload.model_dump()
    child_group_ids = data.pop("child_group_ids", [])
    actor_id = getattr(actor, "id", None)
    if child_group_ids and actor_id is not None and not await user_has_permission(db, user_id=actor_id, permission_code="group.membership.manage"):
        raise HTTPException(403, detail={"code": "PERMISSION_DENIED", "message": "Permission 'group.membership.manage' is required to assign child groups."})
    for child_group_id in child_group_ids:
        await require_group(db, scope, child_group_id)
    data["scope_type"] = payload.scope_type.value
    data["device_scope"] = payload.device_scope.value
    data["membership_mode"] = payload.membership_mode.value
    data["sector_role"] = payload.sector_role.value if payload.sector_role else None
    data["metadata_"] = data.pop("metadata")
    data.update(group_kind="CUSTOM", system_key=None)
    obj = DeviceGroup(**data)
    db.add(obj)
    try:
        await db.flush()
        if child_group_ids:
            await replace_child_groups(db, obj.id, child_group_ids)
        await record_audit(db, action="GROUP_CREATED", entity_type="DeviceGroup", entity_id=obj.id,
            description="Device group created.", entity_display_snapshot=display_snapshot(obj), after_summary=business_summary(obj))
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    await db.refresh(obj)
    return obj


@router.get("/{group_id}", response_model=DeviceGroupRead)
async def get_group(
    group_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    return await require_group(db, scope, group_id)


@router.patch("/{group_id}", response_model=DeviceGroupRead)
async def update_group(group_id: UUID, payload: DeviceGroupUpdate, db: AsyncSession = Depends(get_db), actor=Depends(authorize_request)):
    scope = await scope_for_actor(db, actor)
    obj = await require_group(db, scope, group_id, for_update=True)
    await _security_boundary_guard(db, actor, scope, {group_id})
    if obj.group_kind == "SYSTEM":
        raise HTTPException(409, detail={"code": "SYSTEM_GROUP_IMMUTABLE", "message": "Built-in system groups cannot be modified."})
    before = business_summary(obj)
    data = payload.model_dump(exclude_unset=True)
    # Any new organizational anchor must also be in the actor's geographic scope.
    if "scope_type" in data:
        await _validate_group_context_in_scope(payload, db, scope)
    for field, guard in (("network_id", require_network), ("city_id", require_city), ("location_id", require_location), ("sector_id", require_sector)):
        if field in data and data[field] is not None:
            await guard(db, scope, data[field])
    child_group_ids = data.pop("child_group_ids", None)
    actor_id = getattr(actor, "id", None)
    if child_group_ids is not None and actor_id is not None and not await user_has_permission(db, user_id=actor_id, permission_code="group.membership.manage"):
        raise HTTPException(403, detail={"code": "PERMISSION_DENIED", "message": "Permission 'group.membership.manage' is required to assign child groups."})
    reconcile = bool(data.pop("reconcile_memberships", False))
    metadata_requested = "metadata" in data
    if metadata_requested:
        obj.metadata_ = data.pop("metadata")
    for key in ("device_scope", "sector_role", "membership_mode"):
        if key in data and data[key] is not None and hasattr(data[key], "value"):
            data[key] = data[key].value
    for key, value in data.items():
        setattr(obj, key, value)
    if obj.sector_role is not None and obj.device_scope != "SECTOR":
        raise HTTPException(422, detail={"code": "GROUP_SECTOR_ROLE_REQUIRES_SECTOR_SCOPE", "message": "Sector role is valid only for SECTOR device scope."})

    memberships = list((await db.scalars(select(DeviceGroupMembership).where(
        DeviceGroupMembership.group_id == obj.id, DeviceGroupMembership.deleted_at.is_(None)
    ).order_by(DeviceGroupMembership.id).with_for_update())).all())
    if obj.membership_mode == "DYNAMIC" and memberships:
        if not reconcile:
            raise HTTPException(409, detail={"code": "GROUP_DYNAMIC_REQUIRES_RECONCILIATION", "message": "Switching to dynamic membership requires removal of stored manual memberships."})
        for membership in memberships:
            await record_audit(db, action="GROUP_MEMBERSHIP_RECONCILED", entity_type="DeviceGroupMembership", entity_id=membership.id,
                description="Manual membership removed while switching the group to dynamic membership.", entity_display_snapshot=display_snapshot(membership),
                metadata={"reason": "GROUP_MEMBERSHIP_MODE_DYNAMIC"}, before_summary=business_summary(membership))
            await db.delete(membership)
    elif obj.membership_mode == "MANUAL" and any(key in data for key in {"device_scope", "sector_role"}):
        invalid = []
        for membership in memberships:
            try:
                await validate_membership(db, membership.device_id, obj.id)
            except ValueError as exc:
                invalid.append((membership, str(exc)))
        if invalid and not reconcile:
            raise HTTPException(409, detail={"code": "GROUP_CRITERIA_HAS_INCOMPATIBLE_MEMBERS", "message": "Group criteria would invalidate existing memberships."})
        for membership, reason in invalid:
            await record_audit(db, action="GROUP_MEMBERSHIP_RECONCILED", entity_type="DeviceGroupMembership", entity_id=membership.id,
                description="Invalid membership removed during group-criteria reconciliation.", entity_display_snapshot=display_snapshot(membership),
                metadata={"reason": "GROUP_CRITERIA_UPDATE", "validation_code": reason}, before_summary=business_summary(membership))
            await db.delete(membership)

    parent_link = await db.scalar(select(DeviceGroupNesting).where(
        DeviceGroupNesting.child_group_id == obj.id,
        DeviceGroupNesting.deleted_at.is_(None),
    ))
    if parent_link is not None:
        parent_group = await get_or_404(db, DeviceGroup, parent_link.parent_group_id)
        try:
            await validate_group_nesting(db, parent_group, obj)
        except ValueError as exc:
            raise HTTPException(409, detail={
                "code": "GROUP_PARENT_INCOMPATIBLE_AFTER_UPDATE",
                "message": "This update would make the group incompatible with its current parent. Remove it from that parent first.",
                "validation_code": str(exc),
            }) from exc

    if child_group_ids is not None:
        try:
            await replace_child_groups(db, obj.id, child_group_ids)
        except ValueError as exc:
            raise HTTPException(409, detail={"code": str(exc), "message": "The requested child-group selection is not allowed."}) from exc

    after = business_summary(obj)
    before_changes, after_changes, changed_fields = changed_summary(before, after)
    if changed_fields or metadata_requested:
        await record_audit(db, action="GROUP_UPDATED", entity_type="DeviceGroup", entity_id=obj.id,
            description="Device group updated.", entity_display_snapshot=display_snapshot(obj),
            metadata={"changed_fields": [*changed_fields, *(["metadata"] if metadata_requested else [])]},
            before_summary=before_changes, after_summary=after_changes)
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    await db.refresh(obj)
    return obj


@router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(group_id: UUID, reason: str | None = None, confirmed: bool = False,
                       actor=Depends(authorize_request), db: AsyncSession = Depends(get_db)):
    scope = await scope_for_actor(db, actor)
    group = await require_group(db, scope, group_id)
    await _security_boundary_guard(db, actor, scope, {group_id})
    if group.group_kind == "SYSTEM":
        raise HTTPException(409, detail={"code": "SYSTEM_GROUP_IMMUTABLE", "message": "Built-in system groups cannot be recycled or deleted."})
    await recycle_from_delete_endpoint(db, entity_type="DEVICE_GROUP", entity_id=group_id, actor=actor, reason=reason, confirmed=confirmed)
    return None


@router.get("/{group_id}/devices/page", response_model=PageResult[DeviceRead])
async def list_group_devices_page(
    group_id: UUID,
    db: AsyncSession = Depends(get_db),
    search: str | None = None,
    sort_by: str = "display_name",
    sort_direction: str = "asc",
    page: int = 1,
    page_size: int = 50,
    actor=Depends(authorize_request),
):
    _bad_page(page, page_size)
    scope = await scope_for_actor(db, actor)
    group = await require_group(db, scope, group_id)
    pop = _direct_device_select(group).subquery("direct_group_devices")
    stmt = select(Device).join(pop, pop.c.device_id == Device.id).where(Device.deleted_at.is_(None), await device_scope_clause(db, scope, device_col=Device.id))
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(or_(Device.display_name.ilike(pattern), Device.hostname.ilike(pattern)))
    sort_map = {"display_name": Device.display_name, "lifecycle_state": Device.lifecycle_state, "operational_state": Device.operational_state}
    sort_expr = sort_map.get(sort_by)
    if sort_expr is None or sort_direction not in {"asc", "desc"}:
        raise HTTPException(422, detail={"code": "INVALID_GROUP_DEVICE_SORT", "message": "Unsupported group-device sort."})
    total = int((await db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery()))) or 0)
    order = sort_expr.desc() if sort_direction == "desc" else sort_expr.asc()
    rows = list((await db.scalars(stmt.order_by(order.nullslast(), Device.id.asc()).offset((page - 1) * page_size).limit(page_size))).all())
    return PageResult(items=rows, total=total, page=page, page_size=page_size)


@router.get("/{group_id}/items/page", response_model=GroupItemsPage)
async def list_group_items_page(
    group_id: UUID,
    db: AsyncSession = Depends(get_db),
    search: str | None = None,
    item_type: str | None = None,
    device_type: str | None = None,
    lifecycle_state: str | None = None,
    operational_state: str | None = None,
    child_group_ids: str | None = None,
    include_all_children: bool = True,
    sort_by: str = "display_name",
    sort_direction: str = "asc",
    page: int = 1,
    page_size: int = 50,
    actor=Depends(authorize_request),
):
    _bad_page(page, page_size)
    normalized_item_type = (item_type or "").strip().upper()
    if normalized_item_type not in {"", "GROUP", "DEVICE"}:
        raise HTTPException(422, detail={"code": "INVALID_GROUP_ITEM_TYPE", "message": "Item type must be GROUP or DEVICE."})

    scope = await scope_for_actor(db, actor)
    group = await require_group(db, scope, group_id)
    children = list((await db.scalars(
        select(DeviceGroup).join(DeviceGroupNesting, DeviceGroupNesting.child_group_id == DeviceGroup.id)
        .where(DeviceGroupNesting.parent_group_id == group.id, DeviceGroupNesting.deleted_at.is_(None), DeviceGroup.deleted_at.is_(None), group_scope_clause(scope))
        .order_by(DeviceGroup.name)
    )).all())
    direct_ids = {child.id for child in children}
    if include_all_children:
        selected = direct_ids
    else:
        selected = set()
        if child_group_ids:
            try:
                selected = {UUID(value.strip()) for value in child_group_ids.split(",") if value.strip()}
            except ValueError as exc:
                raise HTTPException(422, detail={"code": "INVALID_CHILD_GROUP_SELECTION", "message": "Child-group selection contains an invalid ID."}) from exc
        if not selected.issubset(direct_ids):
            raise HTTPException(422, detail={"code": "INVALID_CHILD_GROUP_SELECTION", "message": "Only direct child groups may be selected."})

    contributors = await _contributing_groups(db, group, selected)
    source_selects = [
        select(pop.c.device_id, literal(item.name).label("source_group"))
        for item in contributors
        for pop in [_direct_device_select(item).subquery(f"pop_{str(item.id).replace('-', '')}")]
    ]
    if source_selects:
        sources = union_all(*source_selects).subquery("group_item_sources") if len(source_selects) > 1 else source_selects[0].subquery("group_item_sources")
        ids = select(sources.c.device_id).distinct().subquery("group_item_ids")
    else:
        sources = None
        ids = select(Device.id.label("device_id")).where(literal(False)).subquery("group_item_ids")

    primary_ip = (
        select(DeviceIP.ip_address).where(DeviceIP.device_id == Device.id, DeviceIP.deleted_at.is_(None), DeviceIP.is_management.is_(True))
        .order_by(DeviceIP.is_primary.desc(), DeviceIP.id.asc()).limit(1).scalar_subquery()
    )
    null_text = lambda: literal(None).cast(String)

    device_stmt = (
        select(
            literal("DEVICE").label("item_type"),
            Device.id.label("id"),
            Device.display_name.label("display_name"),
            null_text().label("code"),
            Device.hostname.label("hostname"),
            DeviceType.code.label("device_type_code"),
            primary_ip.label("management_ip"),
            Device.lifecycle_state.label("lifecycle_state"),
            Device.operational_state.label("operational_state"),
        )
        .join(ids, ids.c.device_id == Device.id)
        .join(DeviceType, DeviceType.id == Device.device_type_id)
        .where(Device.deleted_at.is_(None), await device_scope_clause(db, scope, device_col=Device.id))
    )
    group_stmt = (
        select(
            literal("GROUP").label("item_type"),
            DeviceGroup.id.label("id"),
            DeviceGroup.name.label("display_name"),
            DeviceGroup.code.label("code"),
            null_text().label("hostname"),
            DeviceGroup.device_scope.label("device_type_code"),
            null_text().label("management_ip"),
            null_text().label("lifecycle_state"),
            null_text().label("operational_state"),
        )
        .join(DeviceGroupNesting, DeviceGroupNesting.child_group_id == DeviceGroup.id)
        .where(
            DeviceGroupNesting.parent_group_id == group.id,
            DeviceGroupNesting.deleted_at.is_(None),
            DeviceGroup.deleted_at.is_(None),
            group_scope_clause(scope),
        )
    )

    if search:
        pattern = f"%{search.strip()}%"
        device_stmt = device_stmt.where(or_(Device.display_name.ilike(pattern), Device.hostname.ilike(pattern), primary_ip.ilike(pattern)))
        group_stmt = group_stmt.where(or_(DeviceGroup.name.ilike(pattern), DeviceGroup.code.ilike(pattern), DeviceGroup.description.ilike(pattern)))
    if device_type:
        device_stmt = device_stmt.where(DeviceType.code == device_type)
        group_stmt = group_stmt.where(DeviceGroup.device_scope == device_type)
    if lifecycle_state:
        device_stmt = device_stmt.where(Device.lifecycle_state == lifecycle_state)
        group_stmt = group_stmt.where(literal(False))
    if operational_state:
        device_stmt = device_stmt.where(Device.operational_state == operational_state)
        group_stmt = group_stmt.where(literal(False))

    item_selects = []
    if normalized_item_type != "GROUP":
        item_selects.append(device_stmt)
    if normalized_item_type != "DEVICE":
        item_selects.append(group_stmt)
    if not item_selects:
        raise HTTPException(422, detail={"code": "INVALID_GROUP_ITEM_TYPE", "message": "No item type was selected."})
    combined = (union_all(*item_selects) if len(item_selects) > 1 else item_selects[0]).subquery("group_items")

    sort_map = {
        "item_type": combined.c.item_type,
        "display_name": combined.c.display_name,
        "device_type": combined.c.device_type_code,
        "lifecycle_state": combined.c.lifecycle_state,
        "operational_state": combined.c.operational_state,
    }
    sort_expr = sort_map.get(sort_by)
    if sort_expr is None or sort_direction not in {"asc", "desc"}:
        raise HTTPException(422, detail={"code": "INVALID_GROUP_ITEM_SORT", "message": "Unsupported Group Items sort."})

    total = int((await db.scalar(select(func.count()).select_from(combined))) or 0)
    order = sort_expr.desc() if sort_direction == "desc" else sort_expr.asc()
    page_rows = list((await db.execute(
        select(combined).order_by(order.nullslast(), combined.c.item_type.asc(), combined.c.display_name.asc(), combined.c.id.asc())
        .offset((page - 1) * page_size).limit(page_size)
    )).mappings().all())
    if not page_rows:
        return GroupItemsPage(child_groups=children, items=[], total=total, page=page, page_size=page_size)

    page_device_ids = [row["id"] for row in page_rows if row["item_type"] == "DEVICE"]
    source_map: dict[UUID, list[str]] = {device_id: [] for device_id in page_device_ids}
    if sources is not None and page_device_ids:
        for device_id, source_name in (await db.execute(
            select(sources.c.device_id, sources.c.source_group).where(sources.c.device_id.in_(page_device_ids)).distinct()
        )).all():
            source_map.setdefault(device_id, []).append(source_name)

    child_by_id = {child.id: child for child in children}
    group_counts: dict[UUID, int] = {}
    for row in page_rows:
        if row["item_type"] == "GROUP" and row["id"] in child_by_id:
            group_counts[row["id"]] = await _effective_device_count(db, child_by_id[row["id"]])

    items: list[GroupDeviceItem] = []
    for row in page_rows:
        is_group = row["item_type"] == "GROUP"
        items.append(GroupDeviceItem(
            item_type=row["item_type"],
            id=row["id"],
            display_name=row["display_name"],
            code=row["code"],
            hostname=row["hostname"],
            device_type_code=row["device_type_code"],
            management_ip=row["management_ip"],
            lifecycle_state=row["lifecycle_state"],
            operational_state=row["operational_state"],
            item_count=group_counts.get(row["id"]) if is_group else None,
            source_groups=[group.name] if is_group else sorted(set(source_map.get(row["id"], []))),
        ))
    return GroupItemsPage(child_groups=children, items=items, total=total, page=page, page_size=page_size)


@router.get("/{group_id}/eligible-devices/page", response_model=PageResult[DeviceRead])
async def list_eligible_group_devices_page(
    group_id: UUID,
    db: AsyncSession = Depends(get_db),
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
    actor=Depends(authorize_request),
):
    _bad_page(page, page_size, max_size=50)
    scope = await scope_for_actor(db, actor)
    group = await require_group(db, scope, group_id)
    if group.group_kind == "SYSTEM" or group.membership_mode != "MANUAL":
        raise HTTPException(409, detail={"code": "GROUP_MEMBERSHIP_NOT_MANUAL", "message": "Dynamic/system groups calculate membership automatically."})
    context = _effective_group_context_subquery()
    stmt = select(Device).join(DeviceType, DeviceType.id == Device.device_type_id).where(Device.deleted_at.is_(None), await device_scope_clause(db, scope, device_col=Device.id))
    if group.device_scope != "ANY":
        stmt = stmt.where(DeviceType.code == group.device_scope)
    if group.scope_type != "GLOBAL" or group.sector_role is not None:
        stmt = stmt.join(context, context.c.device_id == Device.id)
        if group.scope_type == "NETWORK": stmt = stmt.where(context.c.network_id == group.network_id)
        elif group.scope_type == "CITY": stmt = stmt.where(context.c.city_id == group.city_id)
        elif group.scope_type == "LOCATION": stmt = stmt.where(context.c.location_id == group.location_id)
        elif group.scope_type == "SECTOR": stmt = stmt.where(context.c.sector_id == group.sector_id)
        if group.sector_role is not None: stmt = stmt.where(context.c.sector_role == group.sector_role)
    direct_member = exists(select(DeviceGroupMembership.id).where(DeviceGroupMembership.device_id == Device.id,
        DeviceGroupMembership.group_id == group.id, DeviceGroupMembership.deleted_at.is_(None)))
    stmt = stmt.where(~direct_member)
    if group.scope_type != "GLOBAL":
        cg = DeviceGroup.__table__.alias("conflict_group")
        cm = DeviceGroupMembership.__table__.alias("conflict_membership")
        conditions = [cm.c.device_id == Device.id, cm.c.deleted_at.is_(None), cg.c.id == cm.c.group_id,
                      cg.c.deleted_at.is_(None), cg.c.id != group.id, cg.c.scope_type == group.scope_type]
        if group.scope_type == "NETWORK": conditions.append(cg.c.network_id == group.network_id)
        elif group.scope_type == "CITY": conditions.append(cg.c.city_id == group.city_id)
        elif group.scope_type == "LOCATION": conditions.append(cg.c.location_id == group.location_id)
        elif group.scope_type == "SECTOR": conditions.append(cg.c.sector_id == group.sector_id)
        stmt = stmt.where(~exists(select(literal(1)).select_from(cm.join(cg, cg.c.id == cm.c.group_id)).where(*conditions)))
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(or_(Device.display_name.ilike(pattern), Device.hostname.ilike(pattern)))
    total = int((await db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery()))) or 0)
    rows = list((await db.scalars(stmt.order_by(Device.display_name.asc(), Device.id.asc()).offset((page - 1) * page_size).limit(page_size))).all())
    return PageResult(items=rows, total=total, page=page, page_size=page_size)


@router.get("/{group_id}/devices")
async def list_group_devices(
    group_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    group = await require_group(db, scope, group_id)
    pop = _direct_device_select(group).subquery("group_direct_devices")
    return list((await db.scalars(select(Device).join(pop, pop.c.device_id == Device.id).where(await device_scope_clause(db, scope, device_col=Device.id)).order_by(Device.display_name))).all())


@router.post("/{group_id}/devices/{device_id}", status_code=status.HTTP_201_CREATED)
async def add_device_to_group(
    group_id: UUID,
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    await _require_membership_group(db, scope, group_id)
    await _require_membership_device(db, scope, device_id)
    await _security_boundary_guard(db, actor, scope, {group_id})
    try:
        membership = await add_membership(db, device_id, group_id)
    except ValueError as exc:
        code = str(exc)
        if code in {"DEVICE_NOT_FOUND", "GROUP_NOT_FOUND"}:
            raise HTTPException(404, detail={"code": code, "message": "Device or group not found."})
        if code == "MEMBERSHIP_EXISTS":
            raise HTTPException(409, detail={"code": code, "message": "The device is already a member of this group."})
        if code == "GROUP_MEMBERSHIP_NOT_MANUAL":
            raise HTTPException(409, detail={"code": code, "message": "Dynamic/system groups calculate membership automatically."})
        if code.startswith("GROUP_"):
            raise HTTPException(422, detail={"code": code, "message": "The device does not satisfy the group constraints."})
        raise
    except GroupMembershipConflict as exc:
        raise HTTPException(409, detail={"code": "GROUP_CONTEXT_MEMBERSHIP_EXISTS", "message": "The device already belongs to another group in this organizational context.", "existing_group_id": str(exc.existing_group.id)})
    await db.commit(); await db.refresh(membership); return membership


@router.post("/{group_id}/devices/{device_id}/move", status_code=status.HTTP_201_CREATED)
async def move_device_to_group(
    group_id: UUID,
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    await _require_membership_group(db, scope, group_id)
    await _require_membership_device(db, scope, device_id)
    source_group_ids = set((await db.scalars(
        select(DeviceGroupMembership.group_id).where(
            DeviceGroupMembership.device_id == device_id,
            DeviceGroupMembership.deleted_at.is_(None),
        )
    )).all())
    await _security_boundary_guard(db, actor, scope, {group_id, *source_group_ids})
    try:
        membership = await move_membership(db, device_id, group_id)
    except ValueError as exc:
        code = str(exc)
        if code in {"DEVICE_NOT_FOUND", "GROUP_NOT_FOUND"}: raise HTTPException(404, detail={"code": code, "message": "Device or group not found."})
        if code in {"MEMBERSHIP_EXISTS", "GROUP_MEMBERSHIP_NOT_MANUAL"}: raise HTTPException(409, detail={"code": code, "message": "The requested membership operation is not available."})
        if code.startswith("GROUP_"): raise HTTPException(422, detail={"code": code, "message": "The device does not satisfy the group constraints."})
        raise
    except GroupMembershipConflict as exc:
        raise HTTPException(409, detail={"code": "GROUP_CONTEXT_MEMBERSHIP_EXISTS", "message": "The destination conflicts with an existing organizational membership.", "existing_group_id": str(exc.existing_group.id)})
    await db.commit(); await db.refresh(membership); return membership


@router.delete("/{group_id}/devices/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_device_from_group(
    group_id: UUID,
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    group = await _require_membership_group(db, scope, group_id)
    await _require_membership_device(db, scope, device_id)
    await _security_boundary_guard(db, actor, scope, {group_id})
    if group.group_kind == "SYSTEM" or group.membership_mode != "MANUAL":
        raise HTTPException(409, detail={"code": "GROUP_MEMBERSHIP_NOT_MANUAL", "message": "Dynamic/system groups calculate membership automatically."})
    try:
        await remove_membership(db, device_id, group_id)
    except ValueError as exc:
        if str(exc) == "MEMBERSHIP_NOT_FOUND": raise HTTPException(404, detail={"code": "MEMBERSHIP_NOT_FOUND", "message": "The device is not a member of this group."})
        raise
    await db.commit(); return None


@router.get("/{group_id}/children", response_model=list[DeviceGroupRead])
async def list_child_groups(
    group_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    await require_group(db, scope, group_id)
    return list((await db.scalars(select(DeviceGroup).join(DeviceGroupNesting, DeviceGroupNesting.child_group_id == DeviceGroup.id)
        .where(DeviceGroupNesting.parent_group_id == group_id, DeviceGroupNesting.deleted_at.is_(None), DeviceGroup.deleted_at.is_(None), group_scope_clause(scope)).order_by(DeviceGroup.name))).all())


@router.get("/{group_id}/parent", response_model=DeviceGroupRead | None)
async def get_parent_group(
    group_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    await require_group(db, scope, group_id)
    return await db.scalar(select(DeviceGroup).join(DeviceGroupNesting, DeviceGroupNesting.parent_group_id == DeviceGroup.id)
        .where(DeviceGroupNesting.child_group_id == group_id, DeviceGroupNesting.deleted_at.is_(None), DeviceGroup.deleted_at.is_(None), group_scope_clause(scope)))


@router.put("/{group_id}/children", response_model=list[DeviceGroupRead])
async def replace_group_children(
    group_id: UUID,
    payload: DeviceGroupChildrenUpdate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    await require_group(db, scope, group_id)
    for child_id in payload.child_group_ids:
        await require_group(db, scope, child_id)
    await _security_boundary_guard(db, actor, scope, {group_id, *payload.child_group_ids})
    try:
        await replace_child_groups(db, group_id, payload.child_group_ids)
        await db.commit()
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(409, detail={"code": str(exc), "message": "The requested child-group selection is not allowed."}) from exc
    return list((await db.scalars(
        select(DeviceGroup)
        .join(DeviceGroupNesting, DeviceGroupNesting.child_group_id == DeviceGroup.id)
        .where(
            DeviceGroupNesting.parent_group_id == group_id,
            DeviceGroupNesting.deleted_at.is_(None),
            DeviceGroup.deleted_at.is_(None),
            group_scope_clause(scope),
        )
        .order_by(DeviceGroup.name)
    )).all())


@router.post("/{group_id}/children/{child_group_id}", response_model=DeviceGroupNestingRead, status_code=status.HTTP_201_CREATED)
async def add_group_child(
    group_id: UUID,
    child_group_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    await require_group(db, scope, group_id)
    await require_group(db, scope, child_group_id)
    await _security_boundary_guard(db, actor, scope, {group_id, child_group_id})
    try:
        link = await add_child_group(db, group_id, child_group_id); await db.commit(); await db.refresh(link); return link
    except ValueError as exc:
        await db.rollback(); raise HTTPException(409, detail={"code": str(exc), "message": "The requested group nesting is not allowed."}) from exc


@router.delete("/{group_id}/children/{child_group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_group_child(
    group_id: UUID,
    child_group_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    await require_group(db, scope, group_id)
    await require_group(db, scope, child_group_id)
    await _security_boundary_guard(db, actor, scope, {group_id, child_group_id})
    try:
        await remove_child_group(db, group_id, child_group_id); await db.commit(); return None
    except ValueError as exc:
        await db.rollback(); raise HTTPException(404, detail={"code": str(exc), "message": "Group nesting was not found."}) from exc


@router.get("/{group_id}/effective-devices")
async def list_effective_group_devices(
    group_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    group = await require_group(db, scope, group_id)
    direct_children = set((await db.scalars(select(DeviceGroupNesting.child_group_id).where(
        DeviceGroupNesting.parent_group_id == group.id, DeviceGroupNesting.deleted_at.is_(None)))).all())
    contributors = await _contributing_groups(db, group, direct_children)
    selects = [_direct_device_select(item) for item in contributors]
    if not selects: return []
    population = union_all(*selects).subquery("effective_group_devices") if len(selects) > 1 else selects[0].subquery("effective_group_devices")
    return list((await db.scalars(select(Device).join(population, population.c.device_id == Device.id).where(await device_scope_clause(db, scope, device_col=Device.id)).distinct().order_by(Device.display_name))).all())


@router.get("/{group_id}/eligible-devices")
async def list_eligible_group_devices(
    group_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    page = await list_eligible_group_devices_page(group_id=group_id, actor=actor, db=db, page=1, page_size=50)
    return page.items
