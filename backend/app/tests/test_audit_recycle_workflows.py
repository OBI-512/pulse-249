from __future__ import annotations

import asyncio
from uuid import uuid4

from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.deps import get_db
from app.main import app
from app.models import AuditLog, Network, RecycleBinBatch, RecycleBinItem
from app.services.audit import enable_audit_maintenance
from app.services.recycle_bin import recycle_entity
from app.settings import settings


def test_recycle_restore_and_purge_workflows_record_started_completed_failed_and_canonical_events():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        async def override_get_db():
            async with factory() as db:
                yield db

        previous_db = app.dependency_overrides.get(get_db)
        app.dependency_overrides[get_db] = override_get_db
        marker = uuid4().hex[:12]
        request_prefix = f"audit-recycle-{marker}"
        network_id = first_batch_id = second_batch_id = None
        try:
            async with factory() as db:
                network = Network(
                    name=f"Audit recycle {marker}",
                    code=f"AUD-R-{marker}",
                    status="ACTIVE",
                )
                db.add(network)
                await db.flush()
                network_id = network.id
                first_batch = await recycle_entity(
                    db,
                    entity_type="NETWORK",
                    entity_id=network.id,
                    actor_user_id=None,
                )
                first_batch_id = first_batch.id
                await db.commit()

            async with AsyncClient(
                transport=ASGITransport(app=app, raise_app_exceptions=False),
                base_url="http://test",
            ) as client:
                restored = await client.post(
                    f"/api/recycle-bin/{first_batch_id}/restore",
                    headers={"X-Request-ID": f"{request_prefix}-restore-success"},
                )
                assert restored.status_code == 200, restored.text

                restore_failed = await client.post(
                    f"/api/recycle-bin/{first_batch_id}/restore",
                    headers={"X-Request-ID": f"{request_prefix}-restore-failed"},
                )
                assert restore_failed.status_code == 409

            async with factory() as db:
                second_batch = await recycle_entity(
                    db,
                    entity_type="NETWORK",
                    entity_id=network_id,
                    actor_user_id=None,
                )
                second_batch_id = second_batch.id
                await db.commit()

            async with AsyncClient(
                transport=ASGITransport(app=app, raise_app_exceptions=False),
                base_url="http://test",
            ) as client:
                purge_failed = await client.delete(
                    f"/api/recycle-bin/{second_batch_id}",
                    headers={"X-Request-ID": f"{request_prefix}-purge-failed"},
                )
                assert purge_failed.status_code == 409

                purged = await client.delete(
                    f"/api/recycle-bin/{second_batch_id}",
                    params={"force": "true", "confirmation": str(second_batch_id)},
                    headers={"X-Request-ID": f"{request_prefix}-purge-success"},
                )
                assert purged.status_code == 204, purged.text

            async with factory() as db:
                rows = list(
                    (
                        await db.scalars(
                            select(AuditLog).where(
                                or_(
                                    AuditLog.request_id.like(f"{request_prefix}%"),
                                    AuditLog.entity_id == network_id,
                                )
                            )
                        )
                    ).all()
                )
                actions = {row.action for row in rows}
                assert {
                    "RECYCLE_RESTORE_STARTED",
                    "RECYCLE_RESTORE_COMPLETED",
                    "RECYCLE_RESTORE_FAILED",
                    "RECYCLE_PURGE_STARTED",
                    "RECYCLE_PURGE_COMPLETED",
                    "RECYCLE_PURGE_FAILED",
                    "NETWORK_RESTORED",
                    "NETWORK_PURGED",
                } <= actions
                restore_failure = next(
                    row
                    for row in rows
                    if row.action == "RECYCLE_RESTORE_FAILED"
                    and row.request_id == f"{request_prefix}-restore-failed"
                )
                purge_failure = next(
                    row
                    for row in rows
                    if row.action == "RECYCLE_PURGE_FAILED"
                    and row.request_id == f"{request_prefix}-purge-failed"
                )
                assert restore_failure.result == "FAILURE"
                assert purge_failure.result == "FAILURE"
                assert restore_failure.metadata_["error_code"] == "RECYCLE_BATCH_ALREADY_RESTORED"
                assert purge_failure.metadata_["error_code"] == "RECYCLE_RETENTION_NOT_EXPIRED"
                assert restore_failure.source_ip is not None
                assert purge_failure.source_ip is not None

                restore_completed = next(
                    row
                    for row in rows
                    if row.action == "RECYCLE_RESTORE_COMPLETED"
                )
                purge_completed = next(
                    row for row in rows if row.action == "RECYCLE_PURGE_COMPLETED"
                )
                assert restore_completed.result == "SUCCESS"
                assert restore_completed.after_summary == {"status": "RESTORED"}
                assert purge_completed.result == "SUCCESS"
                assert purge_completed.after_summary == {"status": "PURGED"}
        finally:
            async with factory() as db:
                await enable_audit_maintenance(db)
                if network_id is not None:
                    await db.execute(delete(AuditLog).where(AuditLog.entity_id == network_id))
                batch_ids = [
                    batch_id
                    for batch_id in (first_batch_id, second_batch_id)
                    if batch_id is not None
                ]
                if batch_ids:
                    await db.execute(
                        delete(AuditLog).where(AuditLog.entity_id.in_(batch_ids))
                    )
                    await db.execute(
                        delete(RecycleBinItem).where(RecycleBinItem.batch_id.in_(batch_ids))
                    )
                    await db.execute(delete(RecycleBinBatch).where(RecycleBinBatch.id.in_(batch_ids)))
                if network_id is not None:
                    await db.execute(delete(Network).where(Network.id == network_id))
                await db.commit()
            if previous_db is None:
                app.dependency_overrides.pop(get_db, None)
            else:
                app.dependency_overrides[get_db] = previous_db
            await engine.dispose()

    asyncio.run(scenario())
