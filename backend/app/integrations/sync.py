from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Customer,
    CustomerService,
    ExternalCustomerSnapshot,
    ExternalServiceSnapshot,
    IntegrationConnector,
    IntegrationEventReceipt,
    IntegrationSyncRun,
)
from app.services.audit import record_audit
from app.services.customer_services import _validate_customer_vlan, CustomerServiceValidationError
from .connector import RestCustomerSourceAdapter
from .fingerprint import canonical_fingerprint
from .schemas import CustomerSyncBatch, CustomerSyncEvent, ExternalCustomerRecord, ExternalServiceRecord


@dataclass
class SyncCounts:
    received: int = 0
    changed: int = 0
    unchanged: int = 0
    failed: int = 0


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _customer_payload(record: ExternalCustomerRecord) -> dict:
    return record.model_dump(mode="json")


def _service_payload(record: ExternalServiceRecord) -> dict:
    return record.model_dump(mode="json")


async def upsert_customer_snapshot(db: AsyncSession, connector: IntegrationConnector, record: ExternalCustomerRecord) -> bool:
    fingerprint = canonical_fingerprint(_customer_payload(record))
    row = await db.scalar(
        select(ExternalCustomerSnapshot).where(
            ExternalCustomerSnapshot.connector_id == connector.id,
            ExternalCustomerSnapshot.external_customer_id == record.external_customer_id,
        ).with_for_update()
    )
    if row is not None and row.payload_fingerprint == fingerprint:
        row.received_at = utcnow()
        return False
    if row is None:
        row = ExternalCustomerSnapshot(
            connector_id=connector.id,
            external_customer_id=record.external_customer_id,
            received_at=utcnow(),
            payload_fingerprint=fingerprint,
            managed_fields=[],
            sync_state="UNMAPPED",
            attributes={},
        )
        db.add(row)
    row.customer_code = record.customer_code
    row.name = record.name
    row.status = record.status
    row.source_updated_at = record.source_updated_at
    row.received_at = utcnow()
    row.payload_fingerprint = fingerprint
    row.attributes = record.attributes

    if row.mapped_customer_id is not None:
        customer = await db.get(Customer, row.mapped_customer_id)
        if customer is None:
            row.mapped_customer_id = None
            row.managed_fields = []
            row.sync_state = "UNMAPPED"
        else:
            before = {"name": customer.name, "status": customer.status}
            fields = set(row.managed_fields or [])
            if "name" in fields and record.name is not None:
                customer.name = record.name
            if "status" in fields and record.status is not None:
                customer.status = record.status
            row.sync_state = "MAPPED"
            after = {"name": customer.name, "status": customer.status}
            if before != after:
                await record_audit(
                    db,
                    action="EXTERNAL_CUSTOMER_SYNC_APPLIED",
                    entity_type="Customer",
                    entity_id=customer.id,
                    description="Externally owned customer fields synchronized into FTTW.",
                    before_summary=before,
                    after_summary=after,
                    metadata={"connector_code": connector.code, "external_customer_id": record.external_customer_id},
                )
    return True


async def upsert_service_snapshot(db: AsyncSession, connector: IntegrationConnector, record: ExternalServiceRecord) -> bool:
    fingerprint = canonical_fingerprint(_service_payload(record))
    row = await db.scalar(
        select(ExternalServiceSnapshot).where(
            ExternalServiceSnapshot.connector_id == connector.id,
            ExternalServiceSnapshot.external_service_id == record.external_service_id,
        ).with_for_update()
    )
    if row is not None and row.payload_fingerprint == fingerprint:
        row.received_at = utcnow()
        return False
    if row is None:
        row = ExternalServiceSnapshot(
            connector_id=connector.id,
            external_service_id=record.external_service_id,
            external_customer_id=record.external_customer_id,
            received_at=utcnow(),
            payload_fingerprint=fingerprint,
            managed_fields=[],
            sync_state="UNMAPPED",
            attributes={},
        )
        db.add(row)
    row.external_customer_id = record.external_customer_id
    row.service_code = record.service_code
    row.status = record.status
    row.customer_vlan_id = record.customer_vlan_id
    row.source_updated_at = record.source_updated_at
    row.received_at = utcnow()
    row.payload_fingerprint = fingerprint
    row.attributes = record.attributes

    if row.mapped_customer_service_id is not None:
        service = await db.get(CustomerService, row.mapped_customer_service_id)
        if service is None:
            row.mapped_customer_service_id = None
            row.managed_fields = []
            row.sync_state = "UNMAPPED"
        else:
            before = {"status": service.status, "customer_vlan_id": service.customer_vlan_id}
            fields = set(row.managed_fields or [])
            if "status" in fields and record.status is not None:
                service.status = record.status
            if "customer_vlan_id" in fields and record.customer_vlan_id is not None and record.customer_vlan_id != service.customer_vlan_id:
                await _validate_customer_vlan(
                    db,
                    sector_id=service.sector_id,
                    customer_vlan_id=record.customer_vlan_id,
                    exclude_service_id=service.id,
                )
                service.customer_vlan_id = record.customer_vlan_id
            row.sync_state = "MAPPED"
            after = {"status": service.status, "customer_vlan_id": service.customer_vlan_id}
            if before != after:
                await record_audit(
                    db,
                    action="EXTERNAL_CUSTOMER_SERVICE_SYNC_APPLIED",
                    entity_type="CustomerService",
                    entity_id=service.id,
                    description="Externally owned service fields synchronized into FTTW.",
                    before_summary=before,
                    after_summary=after,
                    metadata={"connector_code": connector.code, "external_service_id": record.external_service_id},
                )
    return True


async def ingest_batch(db: AsyncSession, connector: IntegrationConnector, batch: CustomerSyncBatch) -> SyncCounts:
    counts = SyncCounts()
    for customer in batch.customers:
        counts.received += 1
        try:
            counts.changed += int(await upsert_customer_snapshot(db, connector, customer))
        except Exception:
            counts.failed += 1
            raise
    for service in batch.services:
        counts.received += 1
        try:
            counts.changed += int(await upsert_service_snapshot(db, connector, service))
        except Exception:
            counts.failed += 1
            raise
    counts.unchanged = counts.received - counts.changed - counts.failed
    return counts


async def process_event(db: AsyncSession, connector: IntegrationConnector, event: CustomerSyncEvent) -> tuple[str, bool]:
    lock_key = f"{connector.id}:{event.event_id}"
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": lock_key})
    existing = await db.scalar(select(IntegrationEventReceipt).where(
        IntegrationEventReceipt.connector_id == connector.id,
        IntegrationEventReceipt.event_id == event.event_id,
    ))
    if existing is not None:
        return "DUPLICATE", False

    if event.event_type.startswith("CUSTOMER_"):
        if event.customer is None:
            raise ValueError("CUSTOMER_EVENT_PAYLOAD_REQUIRED")
        record = event.customer
        if event.event_type == "CUSTOMER_DEACTIVATED":
            record = record.model_copy(update={"status": "INACTIVE"})
        changed = await upsert_customer_snapshot(db, connector, record)
    else:
        if event.service is None:
            raise ValueError("SERVICE_EVENT_PAYLOAD_REQUIRED")
        record = event.service
        if event.event_type == "SERVICE_DEACTIVATED":
            record = record.model_copy(update={"status": "INACTIVE"})
        changed = await upsert_service_snapshot(db, connector, record)

    db.add(IntegrationEventReceipt(
        connector_id=connector.id,
        event_id=event.event_id,
        event_type=event.event_type,
        received_at=utcnow(),
        source_updated_at=event.occurred_at,
        payload_hash=canonical_fingerprint(event.model_dump(mode="json")),
        status="PROCESSED",
    ))
    await record_audit(
        db,
        action="INTEGRATION_EVENT_PROCESSED",
        entity_type="IntegrationConnector",
        entity_id=connector.id,
        description="Customer/service synchronization event processed.",
        metadata={"connector_code": connector.code, "event_id": event.event_id, "event_type": event.event_type, "changed": changed},
    )
    return "PROCESSED", changed


async def run_connector_sync(db: AsyncSession, connector: IntegrationConnector, *, mode: str) -> IntegrationSyncRun:
    started = utcnow()
    run = IntegrationSyncRun(
        connector_id=connector.id,
        mode=mode,
        status="STARTED",
        started_at=started,
        metadata_={},
    )
    db.add(run)
    await db.flush()
    adapter = RestCustomerSourceAdapter(connector)
    total = SyncCounts()
    cursor: str | None = None
    try:
        for _ in range(100):
            if mode == "FULL":
                batch = await adapter.fetch_full(cursor=cursor)
            else:
                since = connector.last_reconciled_at.isoformat() if connector.last_reconciled_at else None
                batch = await adapter.fetch_changes(since=since, cursor=cursor)
            counts = await ingest_batch(db, connector, batch)
            total.received += counts.received
            total.changed += counts.changed
            total.unchanged += counts.unchanged
            total.failed += counts.failed
            cursor = batch.next_cursor
            if not batch.has_more:
                break
        else:
            raise RuntimeError("INTEGRATION_PAGINATION_LIMIT_EXCEEDED")
        now = utcnow()
        connector.last_reconciled_at = now
        connector.last_success_at = now
        connector.last_error_at = None
        connector.last_error_message = None
        run.status = "SUCCESS"
        run.finished_at = now
        run.records_received = total.received
        run.records_changed = total.changed
        run.records_unchanged = total.unchanged
        run.records_failed = total.failed
        run.cursor_after = cursor
        await record_audit(
            db,
            action="INTEGRATION_SYNC_COMPLETED",
            entity_type="IntegrationConnector",
            entity_id=connector.id,
            description="External customer/service reconciliation completed.",
            metadata={"connector_code": connector.code, "mode": mode, "received": total.received, "changed": total.changed},
        )
    except Exception as exc:
        now = utcnow()
        connector.last_error_at = now
        connector.last_error_message = str(exc)[:1000]
        run.status = "FAILED"
        run.finished_at = now
        run.records_received = total.received
        run.records_changed = total.changed
        run.records_unchanged = total.unchanged
        run.records_failed = total.failed + 1
        run.error_message = str(exc)[:1000]
        await record_audit(
            db,
            action="INTEGRATION_SYNC_FAILED",
            entity_type="IntegrationConnector",
            entity_id=connector.id,
            description="External customer/service reconciliation failed without affecting core FTTW operation.",
            result="FAILURE",
            metadata={"connector_code": connector.code, "mode": mode},
        )
    return run
