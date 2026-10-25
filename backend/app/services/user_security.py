"""Transactional user, RBAC, and session safety invariants."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import APIError
from ..models import Permission, Role, RolePermission, User, UserRole
from ..security.permission_dependencies import expand_permission_codes


ADMINISTRATOR_ROLE_CODE = "administrator"


async def get_user_for_update(db: AsyncSession, user_id: UUID) -> User:
    # Every administration mutation observes the same lock order: the role
    # configuration, active administrators ordered by UUID, then the target.
    # That avoids two concurrent last-admin operations taking target locks in
    # opposite order before either can count the administrators.
    administrator_role = await db.scalar(
        select(Role)
        .where(Role.code == ADMINISTRATOR_ROLE_CODE)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if administrator_role is not None:
        await db.scalars(
            select(User)
            .join(UserRole, UserRole.user_id == User.id)
            .where(UserRole.role_id == administrator_role.id, User.is_active.is_(True))
            .order_by(User.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    user = await db.scalar(
        select(User)
        .where(User.id == user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if user is None:
        raise APIError(404, "USER_NOT_FOUND", "User not found.")
    return user


async def resolve_roles_or_error(db: AsyncSession, codes: list[str]) -> list[Role]:
    requested = list(dict.fromkeys(codes))
    roles = list((await db.scalars(select(Role).where(Role.code.in_(requested)))).all()) if requested else []
    found = {role.code for role in roles}
    unknown = sorted(set(requested) - found)
    if unknown:
        raise APIError(422, "UNKNOWN_ROLE_CODE", f"Unknown role code: {unknown[0]}.")
    return roles


async def resolve_permissions_or_error(
    db: AsyncSession, codes: list[str]
) -> list[Permission]:
    requested = list(dict.fromkeys(codes))
    permissions = list(
        (await db.scalars(select(Permission).where(Permission.code.in_(requested)))).all()
    ) if requested else []
    found = {permission.code for permission in permissions}
    unknown = sorted(set(requested) - found)
    if unknown:
        raise APIError(
            422, "UNKNOWN_PERMISSION_CODE", f"Unknown permission code: {unknown[0]}."
        )
    return permissions


async def role_permission_codes(db: AsyncSession, roles: list[Role]) -> set[str]:
    if not roles:
        return set()
    role_ids = [role.id for role in roles]
    return set((await db.scalars(
        select(Permission.code)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .where(RolePermission.role_id.in_(role_ids))
    )).all())


async def resolve_permission_assignment(
    db: AsyncSession,
    direct_codes: list[str],
    roles: list[Role],
) -> list[Permission]:
    """Resolve direct grants and automatically add missing RBAC prerequisites.

    Role-derived grants satisfy prerequisites without being duplicated as direct
    user permissions. Unknown requested codes are still rejected before any
    assignment is changed.
    """
    requested = await resolve_permissions_or_error(db, direct_codes)
    role_codes = await role_permission_codes(db, roles)
    normalized_codes = expand_permission_codes(
        [permission.code for permission in requested],
        satisfied_codes=role_codes,
    )
    if set(normalized_codes) == {permission.code for permission in requested}:
        return requested
    return await resolve_permissions_or_error(db, normalized_codes)


async def enforce_user_safety(
    db: AsyncSession,
    *,
    actor_user_id: UUID,
    target: User,
    proposed_active: bool,
    proposed_role_codes: list[str],
) -> None:
    """Protect self-deactivation and the final active administrator atomically.

    Administrator-capable has one explicit authoritative definition in this
    system: an active account holding the seeded ``administrator`` role.  This
    keeps the invariant deterministic even when direct permissions are used for
    narrowly scoped access.
    """

    if target.id == actor_user_id and not proposed_active:
        raise APIError(409, "SELF_DEACTIVATION_PROHIBITED", "You cannot deactivate your own account.")

    administrator_role = await db.scalar(
        select(Role)
        .where(Role.code == ADMINISTRATOR_ROLE_CODE)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if administrator_role is None:  # configuration corruption must fail safely
        raise APIError(409, "ADMINISTRATOR_ROLE_NOT_CONFIGURED", "Administrator role is not configured.")

    current_is_admin = await db.scalar(
        select(UserRole.id).where(
            UserRole.user_id == target.id,
            UserRole.role_id == administrator_role.id,
        )
    ) is not None
    proposed_is_admin = ADMINISTRATOR_ROLE_CODE in proposed_role_codes
    if not (current_is_admin and (not proposed_active or not proposed_is_admin)):
        return

    # Lock all active administrator accounts under the same role before the
    # count. Concurrent demotion/deactivation attempts serialize here.
    active_admins = list(
        (
            await db.scalars(
                select(User)
                .join(UserRole, UserRole.user_id == User.id)
                .where(UserRole.role_id == administrator_role.id, User.is_active.is_(True))
                .order_by(User.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).all()
    )
    remaining = len(active_admins) - 1
    if remaining < 1:
        raise APIError(
            409,
            "LAST_ADMINISTRATOR_PROTECTED",
            "At least one active administrator account must remain.",
        )
