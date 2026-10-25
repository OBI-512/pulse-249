"""Reconcile TP3 Web TLS trust permission into seeded administrator RBAC."""
from __future__ import annotations

import uuid

from sqlalchemy import select

from app.db.session import AsyncSessionLocal
from app.models import Permission, Role, RolePermission


SEED_NAMESPACE = uuid.UUID("8d3a2d89-4e70-4e36-9b1a-4d0f6e1c1f55")
PERMISSION_CODE = "device.remote_access.web.trust"


def did(key: str) -> uuid.UUID:
    return uuid.uuid5(SEED_NAMESPACE, key)


async def reconcile_tp3_seed_permissions() -> None:
    """Grant the migration-seeded TP3 permission after demo roles exist.

    Migration 0045 may run before deterministic demo roles are seeded on a
    pristine database. Incremental databases already have the administrator
    role and receive the grant inside the migration. This reconciliation keeps
    both paths equivalent without changing operator/viewer authority.
    """

    async with AsyncSessionLocal() as db:
        permission = await db.scalar(
            select(Permission).where(Permission.code == PERMISSION_CODE)
        )
        administrator = await db.scalar(
            select(Role).where(Role.code == "administrator")
        )
        if permission is None or administrator is None:
            return

        existing = await db.scalar(
            select(RolePermission).where(
                RolePermission.role_id == administrator.id,
                RolePermission.permission_id == permission.id,
            )
        )
        if existing is None:
            db.add(
                RolePermission(
                    id=did(f"roleperm:administrator:{PERMISSION_CODE}"),
                    role_id=administrator.id,
                    permission_id=permission.id,
                )
            )
            await db.commit()
