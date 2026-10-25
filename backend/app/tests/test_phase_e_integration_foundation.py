from __future__ import annotations

import asyncio
from uuid import uuid4

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api_v1 import integration_app
from app.integrations.schemas import ExternalCustomerRecord, CustomerSyncEvent
from app.integrations.sync import process_event, run_connector_sync, upsert_customer_snapshot
from app.models import Customer, ExternalCustomerSnapshot, IntegrationConnector
from app.settings import settings


def _run(coro):
    async def wrapped():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with Session() as db:
                return await coro(db)
        finally:
            await engine.dispose()
    return asyncio.run(wrapped())


def test_external_v1_surface_is_deliberately_small():
    paths = {route.path for route in integration_app.routes}
    assert "/oauth/token" in paths
    assert "/customer-sync/events" in paths
    assert "/health" in paths
    assert not any(path.startswith("/devices") for path in paths)
    assert not any(path.startswith("/admin") for path in paths)


def test_unmapped_external_customer_is_staged_not_created_in_core():
    marker = uuid4().hex[:10]
    async def case(db):
        connector = IntegrationConnector(code=f"TEST-{marker}", name="test", base_url="https://example.invalid", enabled=False, config={})
        db.add(connector); await db.flush()
        record = ExternalCustomerRecord(external_customer_id=f"EXT-{marker}", customer_code=f"EXT-{marker}", name="External", status="ACTIVE")
        assert await upsert_customer_snapshot(db, connector, record) is True
        await db.flush()
        snap = await db.scalar(select(ExternalCustomerSnapshot).where(ExternalCustomerSnapshot.connector_id == connector.id))
        assert snap is not None and snap.sync_state == "UNMAPPED" and snap.mapped_customer_id is None
        assert await db.scalar(select(Customer.id).where(Customer.customer_code == f"EXT-{marker}")) is None
        await db.rollback()
    _run(case)


def test_mapping_updates_only_explicitly_managed_customer_fields():
    marker = uuid4().hex[:10]
    async def case(db):
        customer = Customer(customer_code=f"LOCAL-{marker}", name="Local Name", status="ACTIVE", metadata_={})
        connector = IntegrationConnector(code=f"TEST-{marker}", name="test", base_url="https://example.invalid", enabled=False, config={})
        db.add_all([customer, connector]); await db.flush()
        first = ExternalCustomerRecord(external_customer_id=f"EXT-{marker}", name="External Name", status="ACTIVE")
        await upsert_customer_snapshot(db, connector, first); await db.flush()
        snap = await db.scalar(select(ExternalCustomerSnapshot).where(ExternalCustomerSnapshot.connector_id == connector.id))
        snap.mapped_customer_id = customer.id; snap.managed_fields = ["status"]; snap.sync_state = "MAPPED"
        changed = ExternalCustomerRecord(external_customer_id=f"EXT-{marker}", name="Should Not Replace", status="SUSPENDED")
        await upsert_customer_snapshot(db, connector, changed); await db.flush()
        assert customer.name == "Local Name"
        assert customer.status == "SUSPENDED"
        await db.rollback()
    _run(case)


def test_event_idempotency_returns_duplicate_without_second_apply():
    marker = uuid4().hex[:10]
    async def case(db):
        connector = IntegrationConnector(code=f"TEST-{marker}", name="test", base_url="https://example.invalid", enabled=True, config={})
        db.add(connector); await db.flush()
        event = CustomerSyncEvent(event_id=f"EV-{marker}", event_type="CUSTOMER_UPSERT", customer={"external_customer_id": f"EXT-{marker}", "name": "A", "status": "ACTIVE"})
        first = await process_event(db, connector, event)
        second = await process_event(db, connector, event)
        assert first == ("PROCESSED", True)
        assert second == ("DUPLICATE", False)
        await db.rollback()
    _run(case)


def test_outbound_connector_failure_is_contained_as_failed_sync_run():
    marker = uuid4().hex[:10]
    async def case(db):
        connector = IntegrationConnector(code=f"TEST-{marker}", name="test", base_url="https://127.0.0.1:1", enabled=True, config={"timeout_seconds": 0.2, "allowed_hosts": ["127.0.0.1"]})
        db.add(connector); await db.flush()
        run = await run_connector_sync(db, connector, mode="FULL")
        assert run.status == "FAILED"
        assert connector.last_error_at is not None
        await db.rollback()
    _run(case)
