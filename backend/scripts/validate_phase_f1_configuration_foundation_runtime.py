from __future__ import annotations

import asyncio
import json

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.settings import settings


TABLES = {
    "configuration_templates",
    "configuration_template_versions",
    "configuration_functions",
    "device_configuration_bindings",
    "configuration_snapshots",
    "configuration_operations",
    "configuration_operation_steps",
    "device_configuration_states",
}
PERMISSIONS = {
    "device.configuration.read",
    "device.configuration.capture",
    "device.configuration.apply",
    "device.configuration.restore",
    "device.configuration.template.read",
    "device.configuration.template.manage",
}
INDEXES = {
    "uq_configuration_operations_active_device",
    "uq_configuration_operations_actor_idempotency",
    "ix_configuration_snapshots_device_created",
    "ix_configuration_functions_version_order",
    "uq_configuration_template_versions_published",
}
CONSTRAINTS = {
    "ck_configuration_template_versions_status",
    "ck_configuration_template_versions_publish_ready",
    "ck_device_configuration_bindings_credential_reference",
    "ck_configuration_snapshots_ready_artifact",
    "ck_configuration_snapshots_encryption_scheme",
    "ck_configuration_snapshots_encryption_key_reference",
    "ck_configuration_operations_status",
    "ck_device_configuration_states_drift_status",
}


async def _run() -> dict[str, object]:
    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    try:
        async with engine.connect() as db:
            revision = await db.scalar(text("SELECT version_num FROM alembic_version LIMIT 1"))
            if revision != "0036_config_foundation":
                raise RuntimeError(f"F1 migration head mismatch: {revision}")

            tables = set((await db.scalars(text(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
            ))).all())
            missing_tables = sorted(TABLES - tables)
            if missing_tables:
                raise RuntimeError(f"F1 runtime tables missing: {missing_tables}")

            permission_codes = set((await db.scalars(text(
                "SELECT code FROM permissions WHERE code = ANY(CAST(:codes AS text[]))"
            ), {"codes": sorted(PERMISSIONS)})).all())
            missing_permissions = sorted(PERMISSIONS - permission_codes)
            if missing_permissions:
                raise RuntimeError(f"F1 runtime permissions missing: {missing_permissions}")

            admin_count = int(await db.scalar(text(
                "SELECT COUNT(*) FROM role_permissions rp "
                "JOIN roles r ON r.id = rp.role_id "
                "JOIN permissions p ON p.id = rp.permission_id "
                "WHERE r.code = 'administrator' AND p.code = ANY(CAST(:codes AS text[]))"
            ), {"codes": sorted(PERMISSIONS)}) or 0)
            if admin_count != len(PERMISSIONS):
                raise RuntimeError(f"F1 administrator permission grant mismatch: {admin_count}")

            non_admin_count = int(await db.scalar(text(
                "SELECT COUNT(*) FROM role_permissions rp "
                "JOIN roles r ON r.id = rp.role_id "
                "JOIN permissions p ON p.id = rp.permission_id "
                "WHERE r.code <> 'administrator' AND p.code = ANY(CAST(:codes AS text[]))"
            ), {"codes": sorted(PERMISSIONS)}) or 0)
            if non_admin_count != 0:
                raise RuntimeError(f"F1 new permissions were granted to non-admin roles by default: {non_admin_count}")

            indexes = set((await db.scalars(text(
                "SELECT indexname FROM pg_indexes WHERE schemaname = 'public'"
            ))).all())
            missing_indexes = sorted(INDEXES - indexes)
            if missing_indexes:
                raise RuntimeError(f"F1 runtime indexes missing: {missing_indexes}")

            constraints = set((await db.scalars(text(
                "SELECT conname FROM pg_constraint WHERE connamespace = 'public'::regnamespace"
            ))).all())
            missing_constraints = sorted(CONSTRAINTS - constraints)
            if missing_constraints:
                raise RuntimeError(f"F1 runtime constraints missing: {missing_constraints}")

            return {
                "phase": "F1",
                "runtime_foundation": "PASS",
                "migration": revision,
                "tables": len(TABLES),
                "permissions": len(PERMISSIONS),
                "administrator_default_grants": admin_count,
                "non_administrator_default_grants": non_admin_count,
            }
    finally:
        await engine.dispose()


if __name__ == "__main__":
    print(json.dumps(asyncio.run(_run()), sort_keys=True))
