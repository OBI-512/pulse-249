from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...core.exceptions import APIError
from ...models import (
    AuthSession, City, DeviceGroup, Location, Network, Permission, Role, RolePermission,
    Sector, SystemSetting, User, UserPermission, UserResourceScope, UserRole,
)
from ...schemas.admin import (
    AdminSessionRead, OnlineSessionRead, PasswordReset, ResourceScopeOptionRead,
    ResourceScopeRead, SecurityOptionRead, SecurityOptionsRead, SessionRevokeResponse,
    SettingRead, SettingWrite, UserCreate, UserRead, UserResourceScopesRead,
    UserResourceScopesWrite, UserUpdate,
)
from ...schemas.pagination import PageResult
from ...security.authorization import get_current_user, user_has_permission
from ...security.resource_scope import (
    expanded_authorization_scope_keys, load_effective_resource_scope, require_global_request_scope,
)
from ...security.password_policy import apply_password_change, validate_password_policy
from ...security.permission_dependencies import prerequisites_for
from ...security.passwords import hash_password
from ...security.sessions import SESSION_IDLE_TIMEOUT_MINUTES, list_user_sessions, revoke_session_by_id, revoke_user_sessions, session_state
from ...services.audit import record_audit
from ...services.user_security import (
    enforce_user_safety,
    get_user_for_update,
    resolve_permission_assignment,
    resolve_permissions_or_error,
    resolve_roles_or_error,
)
from ...services.settings_registry import (
    SETTINGS_REGISTRY,
    list_typed_settings,
    validate_setting_value,
    get_typed_setting,
)


router = APIRouter(prefix="/admin", tags=["Administration"], dependencies=[Depends(require_global_request_scope)])


async def _require_permissions(db: AsyncSession, actor: User, *codes: str) -> None:
    for code in codes:
        if not await user_has_permission(db, user_id=actor.id, permission_code=code):
            raise APIError(403, "PERMISSION_DENIED", f"Permission '{code}' is required.")


async def _role_codes(db: AsyncSession, user_id: UUID) -> list[str]:
    return sorted(set(await db.scalars(
        select(Role.code).join(UserRole, UserRole.role_id == Role.id).where(UserRole.user_id == user_id)
    )))


async def _direct_permission_codes(db: AsyncSession, user_id: UUID) -> list[str]:
    return sorted(set(await db.scalars(
        select(Permission.code).join(UserPermission, UserPermission.permission_id == Permission.id).where(UserPermission.user_id == user_id)
    )))


async def _user_summary(db: AsyncSession, user: User) -> dict[str, Any]:
    return {
        "username": user.username,
        "display_name": user.display_name,
        "is_active": user.is_active,
        "roles": await _role_codes(db, user.id),
        "direct_permissions": await _direct_permission_codes(db, user.id),
        "password_configured": bool(user.password_hash),
        "must_change_password": user.must_change_password,
        "password_change_reason": user.password_change_reason,
    }


def _user_display(user: User) -> dict[str, Any]:
    return {"username": user.username, "display_name": user.display_name}


def _scope_target_id(row: UserResourceScope) -> UUID | None:
    return {
        "NETWORK": row.network_id,
        "CITY": row.city_id,
        "LOCATION": row.location_id,
        "SECTOR": row.sector_id,
        "GROUP": row.group_id,
    }.get(row.scope_type)


async def _scope_label(db: AsyncSession, row: UserResourceScope) -> tuple[str, str | None]:
    if row.scope_type == "GLOBAL":
        return "Global", "All resources"
    model = {
        "NETWORK": Network, "CITY": City, "LOCATION": Location,
        "SECTOR": Sector, "GROUP": DeviceGroup,
    }.get(row.scope_type)
    target_id = _scope_target_id(row)
    target = await db.get(model, target_id) if model is not None and target_id is not None else None
    if target is None:
        return f"{row.scope_type} · missing", str(target_id) if target_id else None
    label = getattr(target, "name", None) or getattr(target, "code", None) or str(target.id)
    code = getattr(target, "code", None)
    context = f"{code}" if code and code != label else None
    return str(label), context


async def _scope_read(db: AsyncSession, row: UserResourceScope) -> ResourceScopeRead:
    label, context = await _scope_label(db, row)
    return ResourceScopeRead(
        id=row.id, scope_type=row.scope_type, resource_id=_scope_target_id(row),
        label=label, context=context, assigned_by_user_id=row.assigned_by_user_id,
        created_at=row.created_at,
    )


async def _validate_scope_assignment(db: AsyncSession, scope_type: str, resource_id: UUID | None):
    if scope_type == "GLOBAL":
        if resource_id is not None:
            raise APIError(422, "INVALID_RESOURCE_SCOPE", "GLOBAL scope cannot have a resource_id.")
        return None
    if resource_id is None:
        raise APIError(422, "INVALID_RESOURCE_SCOPE", f"{scope_type} scope requires resource_id.")
    model = {
        "NETWORK": Network, "CITY": City, "LOCATION": Location,
        "SECTOR": Sector, "GROUP": DeviceGroup,
    }.get(scope_type)
    if model is None:
        raise APIError(422, "INVALID_RESOURCE_SCOPE", "Unsupported resource scope type.")
    target = await db.get(model, resource_id)
    if target is None or getattr(target, "deleted_at", None) is not None:
        raise APIError(404, "RESOURCE_SCOPE_TARGET_NOT_FOUND", "Scope target not found.")
    return target


def _setting_summary(setting: SystemSetting | None, *, mask_value: bool = False) -> dict[str, Any] | None:
    if setting is None:
        return None
    return {
        "key": setting.key,
        "description": setting.description,
        "is_secret": setting.is_secret,
        "value": "[REDACTED]" if mask_value or setting.is_secret else setting.value,
    }


async def user_read(db: AsyncSession, user: User) -> UserRead:
    roles = await _role_codes(db, user.id)
    role_permissions = (await db.scalars(
        select(Permission.code)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(UserRole, UserRole.role_id == RolePermission.role_id)
        .where(UserRole.user_id == user.id)
    )).all()
    direct_permissions = await _direct_permission_codes(db, user.id)
    return UserRead(
        id=user.id, username=user.username, display_name=user.display_name,
        is_active=user.is_active, must_change_password=user.must_change_password,
        password_change_reason=user.password_change_reason, password_changed_at=user.password_changed_at, roles=roles,
        permissions=sorted(set(role_permissions) | set(direct_permissions)),
        direct_permissions=direct_permissions,
    )


async def _replace_roles(db: AsyncSession, user_id: UUID, roles: list[Role]) -> None:
    await db.execute(delete(UserRole).where(UserRole.user_id == user_id))
    for role in roles:
        db.add(UserRole(user_id=user_id, role_id=role.id))


async def _replace_permissions(db: AsyncSession, user_id: UUID, permissions: list[Permission]) -> None:
    await db.execute(delete(UserPermission).where(UserPermission.user_id == user_id))
    for permission in permissions:
        db.add(UserPermission(user_id=user_id, permission_id=permission.id))


async def _record_session_revocation(db: AsyncSession, *, user: User, reason: str) -> int:
    revoked_count = await revoke_user_sessions(db, user_id=user.id, reason=reason)
    if revoked_count:
        await record_audit(
            db, action="SESSION_REVOKED", entity_type="User", entity_id=user.id,
            entity_display_snapshot=_user_display(user),
            description="All active sessions were revoked after a security-relevant user change.",
            metadata={"reason": reason, "revoked_session_count": revoked_count},
        )
    return revoked_count


async def _authorize_create_payload(db: AsyncSession, actor: User, payload: UserCreate) -> tuple[list[Role], list[Permission]]:
    await _require_permissions(db, actor, "user.create")
    roles = await resolve_roles_or_error(db, payload.role_codes)
    permissions = await resolve_permission_assignment(db, payload.permission_codes, roles)
    if payload.role_codes:
        await _require_permissions(db, actor, "user.roles.manage")
    if payload.permission_codes:
        await _require_permissions(db, actor, "user.permissions.manage")
    return roles, permissions


@router.get("/resource-scope-options", response_model=list[ResourceScopeOptionRead])
async def list_resource_scope_options(
    scope_type: str = Query(pattern="^(GLOBAL|NETWORK|CITY|LOCATION|SECTOR|GROUP)$"),
    search: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=100, ge=1, le=500),
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_permissions(db, actor, "user.scopes.read")
    if scope_type == "GLOBAL":
        return [ResourceScopeOptionRead(scope_type="GLOBAL", resource_id=None, label="Global", context="All resources")]
    model = {
        "NETWORK": Network, "CITY": City, "LOCATION": Location,
        "SECTOR": Sector, "GROUP": DeviceGroup,
    }[scope_type]
    stmt = select(model).where(model.deleted_at.is_(None))
    if search and search.strip():
        term = f"%{search.strip()}%"
        stmt = stmt.where(or_(model.name.ilike(term), model.code.ilike(term)))
    rows = list((await db.scalars(stmt.order_by(model.name, model.code).limit(limit))).all())
    return [
        ResourceScopeOptionRead(
            scope_type=scope_type, resource_id=row.id, label=row.name,
            context=getattr(row, "code", None),
        )
        for row in rows
    ]


@router.get("/users/{user_id}/resource-scopes", response_model=UserResourceScopesRead)
async def get_user_resource_scopes(
    user_id: UUID, actor: User = Depends(get_current_user), db: AsyncSession = Depends(get_db),
):
    await _require_permissions(db, actor, "user.scopes.read")
    user = await db.get(User, user_id)
    if user is None:
        raise APIError(404, "USER_NOT_FOUND", "User not found.")
    rows = list((await db.scalars(
        select(UserResourceScope).where(UserResourceScope.user_id == user_id).order_by(UserResourceScope.scope_type, UserResourceScope.created_at)
    )).all())
    effective = await load_effective_resource_scope(db, user_id)
    coverage_keys = await expanded_authorization_scope_keys(db, effective)
    return UserResourceScopesRead(
        user_id=user.id, username=user.username,
        direct_scopes=[await _scope_read(db, row) for row in rows],
        effective_summary={
            "global": effective.global_access,
            "direct_networks": sum(1 for row in rows if row.scope_type == "NETWORK"),
            "direct_cities": sum(1 for row in rows if row.scope_type == "CITY"),
            "direct_locations": sum(1 for row in rows if row.scope_type == "LOCATION"),
            "direct_sectors": sum(1 for row in rows if row.scope_type == "SECTOR"),
            "direct_groups": sum(1 for row in rows if row.scope_type == "GROUP"),
            "effective_networks": sum(1 for key in coverage_keys if key.startswith("NETWORK:")),
            "effective_cities": sum(1 for key in coverage_keys if key.startswith("CITY:")),
            "effective_locations": sum(1 for key in coverage_keys if key.startswith("LOCATION:")),
            "effective_sectors": sum(1 for key in coverage_keys if key.startswith("SECTOR:")),
            "effective_groups": sum(1 for key in coverage_keys if key.startswith("GROUP:")),
        },
    )


@router.put("/users/{user_id}/resource-scopes", response_model=UserResourceScopesRead)
async def replace_user_resource_scopes(
    user_id: UUID, payload: UserResourceScopesWrite,
    actor: User = Depends(get_current_user), db: AsyncSession = Depends(get_db),
):
    await _require_permissions(db, actor, "user.scopes.manage")
    user = await get_user_for_update(db, user_id)
    before_rows = list((await db.scalars(select(UserResourceScope).where(UserResourceScope.user_id == user_id))).all())
    before = [{"scope_type": row.scope_type, "resource_id": str(_scope_target_id(row)) if _scope_target_id(row) else None} for row in before_rows]

    normalized: list[tuple[str, UUID | None]] = []
    seen: set[tuple[str, UUID | None]] = set()
    for requested in payload.scopes:
        scope_type = requested.scope_type.upper()
        await _validate_scope_assignment(db, scope_type, requested.resource_id)
        key = (scope_type, requested.resource_id)
        if key not in seen:
            seen.add(key); normalized.append(key)

    # Prevent the last active GLOBAL scope administrator from removing the
    # control-plane boundary that permits scope administration.
    removes_actor_global = user.id == actor.id and ("GLOBAL", None) not in seen
    if removes_actor_global:
        other_global_scope_managers = await db.scalar(select(func.count()).select_from(User).where(
            User.id != actor.id, User.is_active.is_(True),
            select(UserResourceScope.id).where(UserResourceScope.user_id == User.id, UserResourceScope.scope_type == "GLOBAL").exists(),
            or_(
                select(UserRole.id).join(Role, Role.id == UserRole.role_id).join(RolePermission, RolePermission.role_id == Role.id).join(Permission, Permission.id == RolePermission.permission_id).where(UserRole.user_id == User.id, Permission.code == "user.scopes.manage").exists(),
                select(UserPermission.id).join(Permission, Permission.id == UserPermission.permission_id).where(UserPermission.user_id == User.id, Permission.code == "user.scopes.manage").exists(),
            ),
        ))
        if not other_global_scope_managers:
            raise APIError(409, "LAST_GLOBAL_SCOPE_ADMIN", "Cannot remove GLOBAL scope from the last active scope administrator.")

    await db.execute(delete(UserResourceScope).where(UserResourceScope.user_id == user_id))
    for scope_type, resource_id in normalized:
        values = {
            "network_id": None, "city_id": None, "location_id": None,
            "sector_id": None, "group_id": None,
        }
        if scope_type != "GLOBAL":
            values[{"NETWORK":"network_id","CITY":"city_id","LOCATION":"location_id","SECTOR":"sector_id","GROUP":"group_id"}[scope_type]] = resource_id
        db.add(UserResourceScope(
            user_id=user_id, scope_type=scope_type, assigned_by_user_id=actor.id, **values
        ))
    await db.flush()
    after_rows = list((await db.scalars(select(UserResourceScope).where(UserResourceScope.user_id == user_id))).all())
    after = [{"scope_type": row.scope_type, "resource_id": str(_scope_target_id(row)) if _scope_target_id(row) else None} for row in after_rows]
    await record_audit(
        db, action="USER_RESOURCE_SCOPE_CHANGED", entity_type="User", entity_id=user.id,
        entity_display_snapshot=_user_display(user), description="Administrative user resource scopes replaced.",
        before_summary={"resource_scopes": before}, after_summary={"resource_scopes": after},
    )
    await _record_session_revocation(db, user=user, reason="RESOURCE_SCOPE_CHANGED")
    await db.commit()
    return await get_user_resource_scopes(user_id, actor, db)


@router.get("/security-options", response_model=SecurityOptionsRead)
async def list_security_options(actor: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_permissions(db, actor, "user.read")
    roles = (await db.scalars(select(Role).order_by(Role.name, Role.code))).all()
    permissions = (await db.scalars(select(Permission).order_by(Permission.name, Permission.code))).all()
    return SecurityOptionsRead(
        roles=[SecurityOptionRead(code=row.code, name=row.name, description=row.description) for row in roles],
        permissions=[
            SecurityOptionRead(
                code=row.code,
                name=row.name,
                description=row.description,
                requires=list(prerequisites_for(row.code)),
            )
            for row in permissions
        ],
    )


@router.get("/users/page", response_model=PageResult[UserRead])
async def list_users_page(
    search: str | None = Query(default=None, max_length=200),
    status: str | None = Query(default=None, pattern="^(ACTIVE|DISABLED)$"),
    role: str | None = Query(default=None, max_length=80),
    sort_by: str = Query(default="username", pattern="^(username|display_name|is_active|role)$"),
    sort_dir: str = Query(default="asc", pattern="^(asc|desc)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Server-paged user directory used by the administrative table.

    Role filtering/searching is evaluated in SQL so the browser never needs to
    download the complete account population simply to search or paginate it.
    """
    await _require_permissions(db, actor, "user.read")

    role_code = (
        select(func.min(Role.code))
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == User.id)
        .correlate(User)
        .scalar_subquery()
    )
    filters = []
    if search and search.strip():
        term = f"%{search.strip()}%"
        role_match = (
            select(UserRole.id)
            .join(Role, Role.id == UserRole.role_id)
            .where(UserRole.user_id == User.id, Role.code.ilike(term))
            .exists()
        )
        filters.append(or_(User.username.ilike(term), User.display_name.ilike(term), role_match))
    if status == "ACTIVE":
        filters.append(User.is_active.is_(True))
    elif status == "DISABLED":
        filters.append(User.is_active.is_(False))
    if role:
        filters.append(
            select(UserRole.id)
            .join(Role, Role.id == UserRole.role_id)
            .where(UserRole.user_id == User.id, Role.code == role)
            .exists()
        )

    filtered = select(User).where(*filters)
    total = int(await db.scalar(select(func.count()).select_from(filtered.subquery())) or 0)

    sort_expr = {
        "username": User.username,
        "display_name": func.coalesce(User.display_name, ""),
        "is_active": User.is_active,
        "role": func.coalesce(role_code, ""),
    }[sort_by]
    direction = sort_expr.desc() if sort_dir == "desc" else sort_expr.asc()
    rows = (await db.scalars(
        filtered.order_by(direction, User.username.asc(), User.id.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )).all()
    return PageResult(
        items=[await user_read(db, user) for user in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/users", response_model=list[UserRead])
async def list_users(actor: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Compatibility list endpoint; new administrative tables use /users/page."""
    await _require_permissions(db, actor, "user.read")
    return [await user_read(db, user) for user in (await db.scalars(select(User).order_by(User.username))).all()]


@router.post("/users", response_model=UserRead, status_code=201)
async def create_user(payload: UserCreate, actor: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    roles, permissions = await _authorize_create_payload(db, actor, payload)
    if await db.scalar(select(User).where(User.username == payload.username)):
        raise APIError(409, "USERNAME_EXISTS", "Username already exists.")
    await validate_password_policy(db, payload.password)
    user = User(
        external_subject=f"local:{payload.username}", username=payload.username,
        display_name=payload.display_name, password_hash=hash_password(payload.password),
        is_active=True, must_change_password=True, password_change_reason="FIRST_LOGIN",
        password_changed_at=datetime.now(timezone.utc), metadata_={},
    )
    db.add(user)
    await db.flush()
    for role in roles:
        db.add(UserRole(user_id=user.id, role_id=role.id))
    for permission in permissions:
        db.add(UserPermission(user_id=user.id, permission_id=permission.id))
    await db.flush()
    await record_audit(
        db, action="USER_CREATED", entity_type="User", entity_id=user.id,
        entity_display_snapshot=_user_display(user), description="Administrative user account created.",
        after_summary=await _user_summary(db, user),
        metadata={"changed_fields": ["account", "roles", "direct_permissions"]},
    )
    await db.commit()
    await db.refresh(user)
    return await user_read(db, user)


@router.patch("/users/{user_id}", response_model=UserRead)
async def update_user(user_id: UUID, payload: UserUpdate, actor: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    # Validation happens before assignment replacement: unknown entries are
    # rejected and no requested RBAC change is silently ignored.
    supplied_roles = await resolve_roles_or_error(db, payload.role_codes) if payload.role_codes is not None else None
    # Validate unknown permission codes before taking mutation locks. The final
    # direct grant set is normalized against the proposed role below.
    supplied_permissions = await resolve_permissions_or_error(db, payload.permission_codes) if payload.permission_codes is not None else None
    required: list[str] = []
    if payload.display_name is not None:
        required.append("user.update")
    if payload.is_active is not None:
        required.append("user.deactivate")
    if supplied_roles is not None:
        required.append("user.roles.manage")
    if supplied_permissions is not None:
        required.append("user.permissions.manage")
    if payload.password is not None:  # compatibility payload; same reset control
        required.append("user.password.reset")
    await _require_permissions(db, actor, *(required or ["user.update"]))

    user = await get_user_for_update(db, user_id)
    before = await _user_summary(db, user)
    proposed_roles = [role.code for role in supplied_roles] if supplied_roles is not None else before["roles"]
    proposed_role_rows = supplied_roles if supplied_roles is not None else await resolve_roles_or_error(db, proposed_roles)
    requested_direct_codes = payload.permission_codes if payload.permission_codes is not None else before["direct_permissions"]
    normalized_permissions = await resolve_permission_assignment(db, requested_direct_codes, proposed_role_rows)
    normalized_permission_codes = sorted(permission.code for permission in normalized_permissions)
    auto_direct_change = payload.permission_codes is None and normalized_permission_codes != sorted(before["direct_permissions"])
    if auto_direct_change:
        # A role change can expose a prerequisite previously supplied by that
        # role. Preserve the dependent direct grant safely by adding the missing
        # prerequisite, but only for an actor allowed to manage permissions.
        await _require_permissions(db, actor, "user.permissions.manage")

    proposed_active = payload.is_active if payload.is_active is not None else user.is_active
    await enforce_user_safety(
        db, actor_user_id=actor.id, target=user, proposed_active=proposed_active,
        proposed_role_codes=proposed_roles,
    )
    if payload.password is not None:
        await apply_password_change(
            db, user=user, new_password=payload.password,
            must_change_password=True, change_reason="ADMIN_RESET",
        )

    changed_fields: list[str] = []
    if payload.display_name is not None:
        user.display_name = payload.display_name; changed_fields.append("display_name")
    if payload.is_active is not None:
        user.is_active = payload.is_active; changed_fields.append("is_active")
    if supplied_roles is not None:
        await _replace_roles(db, user.id, supplied_roles); changed_fields.append("roles")
    if supplied_permissions is not None or auto_direct_change:
        await _replace_permissions(db, user.id, normalized_permissions); changed_fields.append("direct_permissions")
    if payload.password is not None:
        changed_fields.append("password")
    await db.flush()
    after = await _user_summary(db, user)
    common = {"entity_type": "User", "entity_id": user.id, "entity_display_snapshot": _user_display(user), "before_summary": before, "after_summary": after}
    await record_audit(db, action="USER_UPDATED", description="Administrative user account updated.", metadata={"changed_fields": changed_fields}, **common)
    if before["is_active"] and not after["is_active"]:
        await record_audit(db, action="USER_DEACTIVATED", description="Administrative user account deactivated.", **common)
    elif not before["is_active"] and after["is_active"]:
        await record_audit(db, action="USER_REACTIVATED", description="Administrative user account reactivated.", **common)
    if before["roles"] != after["roles"]:
        await record_audit(db, action="USER_ROLE_CHANGED", description="Administrative user role assignments changed.", **common)
    if before["direct_permissions"] != after["direct_permissions"]:
        await record_audit(db, action="USER_PERMISSION_CHANGED", description="Administrative user direct permissions changed.", **common)
    if "password" in changed_fields:
        await record_audit(db, action="PASSWORD_RESET", description="Administrator reset an account password.", metadata={"password_value_logged": False}, **common)
    reasons = []
    if "password" in changed_fields: reasons.append("PASSWORD_RESET")
    if before["is_active"] != after["is_active"]: reasons.append("ACCOUNT_STATUS_CHANGED")
    if before["roles"] != after["roles"]: reasons.append("ROLE_CHANGED")
    if before["direct_permissions"] != after["direct_permissions"]: reasons.append("DIRECT_PERMISSION_CHANGED")
    if reasons:
        await _record_session_revocation(db, user=user, reason="+".join(reasons))
    await db.commit()
    await db.refresh(user)
    return await user_read(db, user)


@router.post("/users/{user_id}/password-reset", status_code=204)
async def reset_user_password(user_id: UUID, payload: PasswordReset, actor: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_permissions(db, actor, "user.password.reset")
    user = await get_user_for_update(db, user_id)
    await apply_password_change(
        db, user=user, new_password=payload.new_password,
        must_change_password=True, change_reason="ADMIN_RESET",
    )
    await record_audit(
        db, action="PASSWORD_RESET", entity_type="User", entity_id=user.id,
        entity_display_snapshot=_user_display(user), description="Administrator reset an account password.",
        metadata={"password_value_logged": False},
    )
    await _record_session_revocation(db, user=user, reason="PASSWORD_RESET")
    await db.commit()
    return None


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(user_id: UUID, actor: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    # This endpoint deliberately deactivates; no normal user hard-delete is exposed.
    await _require_permissions(db, actor, "user.deactivate")
    user = await get_user_for_update(db, user_id)
    before = await _user_summary(db, user)
    await enforce_user_safety(db, actor_user_id=actor.id, target=user, proposed_active=False, proposed_role_codes=before["roles"])
    user.is_active = False
    await db.flush()
    after = await _user_summary(db, user)
    await record_audit(
        db, action="USER_DEACTIVATED", entity_type="User", entity_id=user.id,
        entity_display_snapshot=_user_display(user), description="Administrative user account deactivated.",
        before_summary=before, after_summary=after,
    )
    await _record_session_revocation(db, user=user, reason="ACCOUNT_DEACTIVATED")
    await db.commit()
    return None


@router.get("/users/{user_id}/sessions", response_model=list[AdminSessionRead])
async def list_account_sessions(
    user_id: UUID,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_permissions(db, actor, "user.sessions.read")
    user = await db.get(User, user_id)
    if user is None:
        raise APIError(404, "USER_NOT_FOUND", "User not found.")
    sessions = await list_user_sessions(db, user_id=user_id, include_revoked=True)
    online_window = int((await get_typed_setting(db, "auth.session_online_window_minutes"))["value"])
    return [
        AdminSessionRead(
            id=session.id, user_id=session.user_id, created_at=session.created_at,
            last_seen_at=session.last_seen_at, last_user_activity_at=session.last_user_activity_at, expires_at=session.expires_at,
            revoked_at=session.revoked_at, revoked_reason=session.revoked_reason,
            status=session_state(session, online_window_minutes=online_window),
            login_ip=session.login_ip, last_ip=session.last_ip,
            browser_name=session.browser_name, browser_version=session.browser_version,
            os_name=session.os_name, os_version=session.os_version,
            device_type=session.device_type, user_agent=session.user_agent,
        )
        for session in sessions
    ]


@router.delete("/users/{user_id}/sessions/{session_id}", response_model=SessionRevokeResponse)
async def revoke_account_session(
    user_id: UUID,
    session_id: UUID,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_permissions(db, actor, "user.sessions.manage")
    user = await db.get(User, user_id)
    if user is None:
        raise APIError(404, "USER_NOT_FOUND", "User not found.")
    revoked = await revoke_session_by_id(db, user_id=user_id, session_id=session_id, reason="ADMIN_SESSION_REVOKE")
    if not revoked:
        raise APIError(404, "SESSION_NOT_FOUND", "Active session not found.")
    await record_audit(
        db, action="SESSION_REVOKED", entity_type="AuthSession", entity_id=session_id,
        entity_display_snapshot={"user_id": str(user_id), "username": user.username},
        description="Administrator revoked an authentication session.",
        metadata={"reason": "ADMIN_SESSION_REVOKE"},
    )
    await db.commit()
    return SessionRevokeResponse(revoked_count=1)


@router.post("/users/{user_id}/sessions/revoke-all", response_model=SessionRevokeResponse)
async def revoke_all_account_sessions(
    user_id: UUID,
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_permissions(db, actor, "user.sessions.manage")
    user = await db.get(User, user_id)
    if user is None:
        raise APIError(404, "USER_NOT_FOUND", "User not found.")
    count = await revoke_user_sessions(db, user_id=user_id, reason="ADMIN_REVOKE_ALL")
    await record_audit(
        db, action="SESSION_REVOKED", entity_type="User", entity_id=user_id,
        entity_display_snapshot={"username": user.username, "display_name": user.display_name},
        description="Administrator revoked all active sessions for an account.",
        metadata={"reason": "ADMIN_REVOKE_ALL", "revoked_session_count": count},
    )
    await db.commit()
    return SessionRevokeResponse(revoked_count=count)


@router.get("/sessions/online", response_model=PageResult[OnlineSessionRead])
async def list_online_sessions(
    search: str | None = Query(default=None, max_length=200),
    status: str | None = Query(default=None, pattern="^(ACTIVE|ONLINE|IDLE)$"),
    browser: str | None = Query(default=None, max_length=100),
    operating_system: str | None = Query(default=None, max_length=100),
    device_type: str | None = Query(default=None, pattern="^(DESKTOP|MOBILE|TABLET|UNKNOWN)$"),
    sort_by: str = Query(default="last_user_activity_at", pattern="^(username|display_name|created_at|last_seen_at|last_user_activity_at|duration|login_ip|browser|operating_system|device_type)$"),
    sort_dir: str = Query(default="desc", pattern="^(asc|desc)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    actor: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_permissions(db, actor, "user.sessions.read")
    now = datetime.now(timezone.utc)
    online_window = int((await get_typed_setting(db, "auth.session_online_window_minutes"))["value"])
    cutoff = now - timedelta(minutes=online_window)
    idle_expiry_cutoff = now - timedelta(minutes=SESSION_IDLE_TIMEOUT_MINUTES)

    effective_user_activity = func.coalesce(AuthSession.last_user_activity_at, AuthSession.created_at)
    filters = [
        AuthSession.revoked_at.is_(None),
        AuthSession.expires_at > now,
        effective_user_activity > idle_expiry_cutoff,
        User.is_active.is_(True),
    ]
    if search and search.strip():
        term = f"%{search.strip()}%"
        filters.append(or_(
            User.username.ilike(term), User.display_name.ilike(term),
            AuthSession.login_ip.ilike(term), AuthSession.last_ip.ilike(term),
            AuthSession.browser_name.ilike(term), AuthSession.os_name.ilike(term),
            AuthSession.device_type.ilike(term),
        ))
    if status in {"ACTIVE", "ONLINE"}:
        filters.append(effective_user_activity >= cutoff)
    elif status == "IDLE":
        filters.append(effective_user_activity < cutoff)
    if browser and browser.strip():
        filters.append(AuthSession.browser_name.ilike(f"%{browser.strip()}%"))
    if operating_system and operating_system.strip():
        filters.append(AuthSession.os_name.ilike(f"%{operating_system.strip()}%"))
    if device_type:
        filters.append(AuthSession.device_type == device_type)

    base = select(AuthSession.id).join(User, User.id == AuthSession.user_id).where(*filters)
    total = int(await db.scalar(select(func.count()).select_from(base.subquery())) or 0)

    sort_expr = {
        "username": User.username,
        "display_name": func.coalesce(User.display_name, ""),
        "created_at": AuthSession.created_at,
        "last_seen_at": effective_user_activity,
        "last_user_activity_at": effective_user_activity,
        "duration": AuthSession.created_at,
        "login_ip": func.coalesce(AuthSession.login_ip, ""),
        "browser": func.coalesce(AuthSession.browser_name, ""),
        "operating_system": func.coalesce(AuthSession.os_name, ""),
        "device_type": func.coalesce(AuthSession.device_type, ""),
    }[sort_by]
    # Longer duration means earlier creation, so invert duration direction.
    if sort_by == "duration":
        direction = sort_expr.asc() if sort_dir == "desc" else sort_expr.desc()
    else:
        direction = sort_expr.desc() if sort_dir == "desc" else sort_expr.asc()

    statement = (
        select(AuthSession, User)
        .join(User, User.id == AuthSession.user_id)
        .where(*filters)
        .order_by(direction, AuthSession.id.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = (await db.execute(statement)).all()
    page_user_ids = {session_user.id for _, session_user in rows}
    roles_by_user: dict[UUID, list[str]] = {user_id: [] for user_id in page_user_ids}
    if page_user_ids:
        role_rows = (
            await db.execute(
                select(UserRole.user_id, Role.code)
                .join(Role, Role.id == UserRole.role_id)
                .where(UserRole.user_id.in_(page_user_ids))
                .order_by(Role.code.asc())
            )
        ).all()
        for role_user_id, role_code in role_rows:
            roles_by_user.setdefault(role_user_id, []).append(role_code)

    items: list[OnlineSessionRead] = []
    for session, session_user in rows:
        last_activity = session.last_user_activity_at or session.created_at
        items.append(OnlineSessionRead(
            id=session.id, user_id=session.user_id, username=session_user.username,
            display_name=session_user.display_name, roles=roles_by_user.get(session_user.id, []),
            created_at=session.created_at, last_seen_at=session.last_seen_at, last_user_activity_at=session.last_user_activity_at, expires_at=session.expires_at,
            revoked_at=session.revoked_at, revoked_reason=session.revoked_reason,
            status=session_state(session, online_window_minutes=online_window, now=now),
            login_ip=session.login_ip, last_ip=session.last_ip,
            browser_name=session.browser_name, browser_version=session.browser_version,
            os_name=session.os_name, os_version=session.os_version,
            device_type=session.device_type, user_agent=session.user_agent,
            duration_seconds=max(0, int((now - session.created_at).total_seconds())),
            idle_seconds=max(0, int((now - last_activity).total_seconds())),
            time_remaining_seconds=max(0, int((session.expires_at - now).total_seconds())),
        ))
    return PageResult(items=items, total=total, page=page, page_size=page_size)


@router.get("/settings", response_model=list[SettingRead])
async def list_settings(actor: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_permissions(db, actor, "settings.read")
    can_read_secret = await user_has_permission(db, user_id=actor.id, permission_code="settings.secret.read")
    typed = await list_typed_settings(db)
    response = [
        SettingRead(
            key=definition.key,
            value=value if can_read_secret or not definition.is_secret else {"value": "[REDACTED]"},
            description=definition.description,
            is_secret=definition.is_secret,
            category=definition.category,
            is_configured=is_configured,
        )
        for definition, value, is_configured in typed
    ]
    # Preserve read-only visibility of historic secret rows while migrating to
    # the typed registry.  Internal implementation markers never cross this
    # API boundary and unknown rows cannot be updated through it.
    legacy_secret_rows = await db.scalars(
        select(SystemSetting)
        .where(SystemSetting.is_secret.is_(True), ~SystemSetting.key.in_(SETTINGS_REGISTRY), ~SystemSetting.key.startswith("internal."))
        .order_by(SystemSetting.key)
    )
    response.extend(
        SettingRead(
            key=row.key,
            value=row.value if can_read_secret else {"value": "[REDACTED]"},
            description=row.description,
            is_secret=True,
            category="legacy",
            is_configured=True,
        )
        for row in legacy_secret_rows
    )
    return response


@router.put("/settings/{key}", response_model=SettingRead)
async def put_setting(key: str, payload: SettingWrite, actor: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_permissions(db, actor, "settings.manage")
    obj = await db.scalar(select(SystemSetting).where(SystemSetting.key == key).with_for_update().execution_options(populate_existing=True))
    if key in SETTINGS_REGISTRY:
        definition, value = validate_setting_value(key, payload.value, supplied_secret=payload.is_secret)
        description = definition.description
        is_secret = definition.is_secret
        category = definition.category
    else:
        # Existing legacy settings may be corrected/migrated, but the typed
        # endpoint never creates a new arbitrary configuration key.
        if obj is None:
            validate_setting_value(key, payload.value, supplied_secret=payload.is_secret)
            raise AssertionError("unreachable")
        if not isinstance(payload.value, dict):
            raise APIError(422, "SETTING_VALUE_INVALID", "Legacy setting values must be JSON objects.")
        value = payload.value
        description = payload.description if payload.description is not None else obj.description
        is_secret = obj.is_secret if payload.is_secret is None else payload.is_secret
        category = "legacy"
    must_mask = bool(getattr(obj, "is_secret", False) or is_secret)
    before = _setting_summary(obj, mask_value=must_mask)
    if obj is None:
        obj = SystemSetting(key=key, value=value, description=description, is_secret=is_secret)
        db.add(obj)
    else:
        obj.value = value; obj.description = description; obj.is_secret = is_secret
    await db.flush()
    await record_audit(
        db, action="SETTING_CHANGED", entity_type="SystemSetting", entity_id=obj.id,
        entity_display_snapshot={"key": obj.key}, description="System setting changed.",
        before_summary=before, after_summary=_setting_summary(obj, mask_value=must_mask),
        metadata={"key": obj.key, "value_changed": True},
    )
    await db.commit()
    await db.refresh(obj)
    can_read_secret = await user_has_permission(db, user_id=actor.id, permission_code="settings.secret.read")
    return SettingRead(key=obj.key, value=obj.value if can_read_secret or not obj.is_secret else {"value": "[REDACTED]"}, description=obj.description, is_secret=obj.is_secret, category=category, is_configured=True)
