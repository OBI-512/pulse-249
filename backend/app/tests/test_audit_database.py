from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.models import AuditLog, Permission, Role, RolePermission
from app.services.audit import enable_audit_maintenance, record_audit
from app.settings import settings


def test_audit_schema_has_required_columns_indexes_constraint_and_triggers():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        try:
            async with engine.connect() as connection:
                def inspect_schema(sync_connection):
                    inspector = sa.inspect(sync_connection)
                    return (
                        {column["name"] for column in inspector.get_columns("audit_logs")},
                        {index["name"] for index in inspector.get_indexes("audit_logs")},
                        {check["name"] for check in inspector.get_check_constraints("audit_logs")},
                    )

                columns, indexes, checks = await connection.run_sync(inspect_schema)
                triggers = set(
                    await connection.scalars(
                        text(
                            """
                            SELECT tgname
                            FROM pg_trigger
                            WHERE tgrelid = 'audit_logs'::regclass
                              AND NOT tgisinternal
                            """
                        )
                    )
                )
            assert {
                "occurred_at",
                "actor_user_id",
                "actor_username_snapshot",
                "action",
                "entity_type",
                "entity_id",
                "entity_display_snapshot",
                "result",
                "request_id",
                "source_ip",
                "before_summary",
                "after_summary",
                "metadata",
            } <= columns
            assert {
                "ix_audit_logs_occurred_at",
                "ix_audit_logs_actor_occurred_at",
                "ix_audit_logs_entity_occurred_at",
                "ix_audit_logs_action_occurred_at",
                "ix_audit_logs_result_occurred_at",
                "ix_audit_logs_request_id",
            } <= indexes
            assert "ck_audit_logs_result" in checks
            assert {
                "trg_audit_logs_append_only",
                "trg_audit_logs_append_only_truncate",
            } <= triggers
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_audit_permissions_default_only_to_administrator():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with factory() as db:
                rows = (
                    await db.execute(
                        select(Role.code, Permission.code)
                        .join(RolePermission, RolePermission.role_id == Role.id)
                        .join(Permission, Permission.id == RolePermission.permission_id)
                        .where(
                            Role.code.in_(
                                {
                                    "administrator",
                                    "operator",
                                    "administrative_viewer",
                                    "viewer",
                                }
                            ),
                            Permission.code.in_({"audit.read", "audit.export"}),
                        )
                    )
                ).all()
            grants: dict[str, set[str]] = {}
            for role_code, permission_code in rows:
                grants.setdefault(role_code, set()).add(permission_code)
            assert grants.get("administrator") == {"audit.read", "audit.export"}
            assert grants.get("operator", set()) == set()
            assert grants.get("administrative_viewer", set()) == set()
            assert grants.get("viewer", set()) == set()
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_audit_table_rejects_update_delete_and_truncate_except_explicit_maintenance():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        audit_id = None
        try:
            async with factory() as db:
                row = await record_audit(
                    db,
                    action="APPEND_ONLY_TEST",
                    entity_type="AuditTest",
                    entity_id=uuid4(),
                    description="Append-only database trigger test.",
                )
                await db.commit()
                await db.refresh(row)
                audit_id = row.id

            async with factory() as db:
                with pytest.raises(DBAPIError):
                    await db.execute(
                        update(AuditLog)
                        .where(AuditLog.id == audit_id)
                        .values(description="forbidden update")
                    )
                await db.rollback()

            async with factory() as db:
                with pytest.raises(DBAPIError):
                    await db.execute(delete(AuditLog).where(AuditLog.id == audit_id))
                await db.rollback()

            async with engine.connect() as connection:
                transaction = await connection.begin()
                try:
                    with pytest.raises(DBAPIError):
                        await connection.execute(text("TRUNCATE TABLE audit_logs"))
                finally:
                    if transaction.is_active:
                        await transaction.rollback()

            # The maintenance TRUNCATE path is tested only inside a transaction
            # that is always rolled back, so no live evidence can be erased.
            async with engine.connect() as connection:
                transaction = await connection.begin()
                try:
                    await connection.execute(
                        text("SET LOCAL fttw.audit_maintenance = 'on'")
                    )
                    await connection.execute(text("TRUNCATE TABLE audit_logs"))
                    assert await connection.scalar(
                        select(sa.func.count(AuditLog.id))
                    ) == 0
                finally:
                    if transaction.is_active:
                        await transaction.rollback()

            async with factory() as db:
                retained = await db.get(AuditLog, audit_id)
                assert retained is not None
                assert retained.description == "Append-only database trigger test."

                await enable_audit_maintenance(db)
                await db.execute(
                    update(AuditLog)
                    .where(AuditLog.id == audit_id)
                    .values(description="authorized maintenance")
                )
                await db.commit()

            async with factory() as db:
                assert (await db.get(AuditLog, audit_id)).description == "authorized maintenance"
                await enable_audit_maintenance(db)
                await db.execute(delete(AuditLog).where(AuditLog.id == audit_id))
                await db.commit()
                audit_id = None
        finally:
            if audit_id is not None:
                async with factory() as cleanup:
                    await enable_audit_maintenance(cleanup)
                    await cleanup.execute(delete(AuditLog).where(AuditLog.id == audit_id))
                    await cleanup.commit()
            await engine.dispose()

    asyncio.run(scenario())
