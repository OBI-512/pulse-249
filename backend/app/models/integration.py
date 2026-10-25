from __future__ import annotations

from datetime import datetime
from typing import Any
import uuid

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .core import Common


class IntegrationConnector(Common):
    __tablename__ = "integration_connectors"
    __table_args__ = (
        UniqueConstraint("code", name="uq_integration_connectors_code"),
        CheckConstraint("connector_type IN ('REST_CUSTOMER_SOURCE')", name="ck_integration_connectors_type"),
        CheckConstraint("auth_mode IN ('NONE','BEARER','BASIC','OAUTH2_CLIENT_CREDENTIALS')", name="ck_integration_connectors_auth_mode"),
        CheckConstraint("reconciliation_interval_seconds >= 60", name="ck_integration_connectors_reconcile_interval"),
    )

    code: Mapped[str] = mapped_column(String(80), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    connector_type: Mapped[str] = mapped_column(String(40), default="REST_CUSTOMER_SOURCE", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    base_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    auth_mode: Mapped[str] = mapped_column(String(40), default="NONE", nullable=False)
    credential_reference: Mapped[str | None] = mapped_column(String(255))
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    reconciliation_interval_seconds: Mapped[int] = mapped_column(Integer, default=3600, nullable=False)
    last_reconciled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_message: Mapped[str | None] = mapped_column(Text)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


class IntegrationClient(Common):
    __tablename__ = "integration_clients"
    __table_args__ = (
        UniqueConstraint("client_id", name="uq_integration_clients_client_id"),
        Index("ix_integration_clients_active", "is_active"),
    )

    name: Mapped[str] = mapped_column(String(160), nullable=False)
    client_id: Mapped[str] = mapped_column(String(160), nullable=False)
    client_secret_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    connector_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("integration_connectors.id", ondelete="SET NULL"))
    scopes: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    token_ttl_seconds: Mapped[int] = mapped_column(Integer, default=900, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)


class IntegrationAccessToken(Common):
    __tablename__ = "integration_access_tokens"
    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_integration_access_tokens_hash"),
        Index("ix_integration_access_tokens_client_expiry", "client_id", "expires_at"),
    )

    client_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("integration_clients.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_ip: Mapped[str | None] = mapped_column(String(64))


class ExternalCustomerSnapshot(Common):
    __tablename__ = "external_customer_snapshots"
    __table_args__ = (
        UniqueConstraint("connector_id", "external_customer_id", name="uq_external_customer_snapshot_identity"),
        Index("ix_external_customer_snapshots_mapping", "mapped_customer_id"),
        Index("ix_external_customer_snapshots_state", "sync_state"),
        CheckConstraint("sync_state IN ('UNMAPPED','MAPPED','ERROR')", name="ck_external_customer_snapshots_state"),
    )

    connector_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("integration_connectors.id", ondelete="CASCADE"), nullable=False)
    external_customer_id: Mapped[str] = mapped_column(String(200), nullable=False)
    customer_code: Mapped[str | None] = mapped_column(String(100))
    name: Mapped[str | None] = mapped_column(String(200))
    status: Mapped[str | None] = mapped_column(String(40))
    source_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    mapped_customer_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("customers.id", ondelete="SET NULL"))
    managed_fields: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    sync_state: Mapped[str] = mapped_column(String(20), default="UNMAPPED", nullable=False)
    payload_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


class ExternalServiceSnapshot(Common):
    __tablename__ = "external_service_snapshots"
    __table_args__ = (
        UniqueConstraint("connector_id", "external_service_id", name="uq_external_service_snapshot_identity"),
        Index("ix_external_service_snapshots_mapping", "mapped_customer_service_id"),
        Index("ix_external_service_snapshots_customer", "connector_id", "external_customer_id"),
        Index("ix_external_service_snapshots_state", "sync_state"),
        CheckConstraint("sync_state IN ('UNMAPPED','MAPPED','ERROR')", name="ck_external_service_snapshots_state"),
        CheckConstraint("customer_vlan_id IS NULL OR customer_vlan_id BETWEEN 2 AND 4094", name="ck_external_service_snapshots_vlan"),
    )

    connector_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("integration_connectors.id", ondelete="CASCADE"), nullable=False)
    external_service_id: Mapped[str] = mapped_column(String(200), nullable=False)
    external_customer_id: Mapped[str] = mapped_column(String(200), nullable=False)
    service_code: Mapped[str | None] = mapped_column(String(100))
    status: Mapped[str | None] = mapped_column(String(40))
    customer_vlan_id: Mapped[int | None] = mapped_column(Integer)
    source_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    mapped_customer_service_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("customer_services.id", ondelete="SET NULL"))
    managed_fields: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    sync_state: Mapped[str] = mapped_column(String(20), default="UNMAPPED", nullable=False)
    payload_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


class IntegrationEventReceipt(Common):
    __tablename__ = "integration_event_receipts"
    __table_args__ = (
        UniqueConstraint("connector_id", "event_id", name="uq_integration_event_receipts_identity"),
        Index("ix_integration_event_receipts_received", "received_at"),
        CheckConstraint("status IN ('PROCESSED','DUPLICATE','FAILED')", name="ck_integration_event_receipts_status"),
    )

    connector_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("integration_connectors.id", ondelete="CASCADE"), nullable=False)
    event_id: Mapped[str] = mapped_column(String(200), nullable=False)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)


class IntegrationSyncRun(Common):
    __tablename__ = "integration_sync_runs"
    __table_args__ = (
        Index("ix_integration_sync_runs_connector_started", "connector_id", "started_at"),
        CheckConstraint("mode IN ('FULL','INCREMENTAL','EVENT')", name="ck_integration_sync_runs_mode"),
        CheckConstraint("status IN ('STARTED','SUCCESS','PARTIAL','FAILED')", name="ck_integration_sync_runs_status"),
    )

    connector_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("integration_connectors.id", ondelete="CASCADE"), nullable=False)
    mode: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    records_received: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_changed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_unchanged: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_failed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    cursor_before: Mapped[str | None] = mapped_column(String(512))
    cursor_after: Mapped[str | None] = mapped_column(String(512))
    error_message: Mapped[str | None] = mapped_column(Text)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)
