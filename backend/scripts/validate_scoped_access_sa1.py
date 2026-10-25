"""Validate SA1 authoritative scope schema against the active database."""
from __future__ import annotations

import asyncio
import json

from sqlalchemy import text

from app.db.session import engine


async def main() -> None:
    async with engine.connect() as db:
        revision = await db.scalar(text("SELECT version_num FROM alembic_version"))
        if revision != "0020_user_resource_scopes":
            raise RuntimeError(f"Unexpected Alembic revision: {revision}")

        users = int(await db.scalar(text("SELECT COUNT(*) FROM users")) or 0)
        global_users = int(await db.scalar(text(
            "SELECT COUNT(DISTINCT user_id) FROM user_resource_scopes WHERE scope_type='GLOBAL'"
        )) or 0)
        non_global = int(await db.scalar(text(
            "SELECT COUNT(*) FROM user_resource_scopes WHERE scope_type <> 'GLOBAL'"
        )) or 0)
        duplicate_global = int(await db.scalar(text(
            """
            SELECT COUNT(*) FROM (
                SELECT user_id FROM user_resource_scopes
                WHERE scope_type='GLOBAL'
                GROUP BY user_id HAVING COUNT(*) <> 1
            ) q
            """
        )) or 0)
        missing_global = int(await db.scalar(text(
            """
            SELECT COUNT(*) FROM users u
            WHERE NOT EXISTS (
                SELECT 1 FROM user_resource_scopes s
                WHERE s.user_id=u.id AND s.scope_type='GLOBAL'
            )
            """
        )) or 0)

        permission_codes = set((await db.scalars(text(
            "SELECT code FROM permissions WHERE code IN ('user.scopes.read','user.scopes.manage')"
        ))).all())
        admin_grants = int(await db.scalar(text(
            """
            SELECT COUNT(*) FROM role_permissions rp
            JOIN roles r ON r.id=rp.role_id
            JOIN permissions p ON p.id=rp.permission_id
            WHERE r.code='administrator'
              AND p.code IN ('user.scopes.read','user.scopes.manage')
            """
        )) or 0)
        restricted_grants = int(await db.scalar(text(
            """
            SELECT COUNT(*) FROM role_permissions rp
            JOIN roles r ON r.id=rp.role_id
            JOIN permissions p ON p.id=rp.permission_id
            WHERE r.code='restricted'
              AND p.code IN ('user.scopes.read','user.scopes.manage')
            """
        )) or 0)

    if permission_codes != {"user.scopes.read", "user.scopes.manage"}:
        raise RuntimeError(f"Scope permissions missing: {sorted(permission_codes)}")
    if admin_grants != 2 or restricted_grants != 0:
        raise RuntimeError(
            f"Unexpected scope permission grants admin={admin_grants} restricted={restricted_grants}"
        )
    if global_users != users or missing_global or duplicate_global or non_global:
        raise RuntimeError(
            "Existing-user GLOBAL compatibility backfill is inconsistent: "
            f"users={users} global_users={global_users} missing={missing_global} "
            f"duplicates={duplicate_global} non_global={non_global}"
        )

    print(json.dumps({
        "revision": revision,
        "users": users,
        "global_scope_users": global_users,
        "non_global_scopes": non_global,
        "scope_permissions": sorted(permission_codes),
        "administrator_scope_grants": admin_grants,
        "restricted_scope_grants": restricted_grants,
        "status": "PASS",
    }, sort_keys=True))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        asyncio.run(engine.dispose())
