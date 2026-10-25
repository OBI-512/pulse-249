"""Phase E integration foundation.

Revision ID: 0028_integration_foundation
Revises: 0027_report_config_trash
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0028_integration_foundation"
down_revision = "0027_report_config_trash"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Migration 0001 intentionally materializes current SQLAlchemy metadata on
    # a fresh installation. When that happens, Phase-E tables already exist
    # before Alembic reaches this historical incremental revision.
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("integration_connectors"):
        return
    op.create_table(
        "integration_connectors",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("code", sa.String(80), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("connector_type", sa.String(40), nullable=False, server_default="REST_CUSTOMER_SOURCE"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("base_url", sa.String(1024), nullable=False),
        sa.Column("auth_mode", sa.String(40), nullable=False, server_default="NONE"),
        sa.Column("credential_reference", sa.String(255)),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("reconciliation_interval_seconds", sa.Integer(), nullable=False, server_default="3600"),
        sa.Column("last_reconciled_at", sa.DateTime(timezone=True)),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("last_error_at", sa.DateTime(timezone=True)),
        sa.Column("last_error_message", sa.Text()),
        sa.Column("config", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.UniqueConstraint("code", name="uq_integration_connectors_code"),
        sa.CheckConstraint("connector_type IN ('REST_CUSTOMER_SOURCE')", name="ck_integration_connectors_type"),
        sa.CheckConstraint("auth_mode IN ('NONE','BEARER','BASIC','OAUTH2_CLIENT_CREDENTIALS')", name="ck_integration_connectors_auth_mode"),
        sa.CheckConstraint("reconciliation_interval_seconds >= 60", name="ck_integration_connectors_reconcile_interval"),
    )

    op.create_table(
        "integration_clients",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("client_id", sa.String(160), nullable=False),
        sa.Column("client_secret_hash", sa.String(512), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("connector_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("integration_connectors.id", ondelete="SET NULL")),
        sa.Column("scopes", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("token_ttl_seconds", sa.Integer(), nullable=False, server_default="900"),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.UniqueConstraint("client_id", name="uq_integration_clients_client_id"),
    )
    op.create_index("ix_integration_clients_active", "integration_clients", ["is_active"])

    op.create_table(
        "integration_access_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("client_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("integration_clients.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("scopes", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("source_ip", sa.String(64)),
        sa.UniqueConstraint("token_hash", name="uq_integration_access_tokens_hash"),
    )
    op.create_index("ix_integration_access_tokens_client_expiry", "integration_access_tokens", ["client_id", "expires_at"])

    op.create_table(
        "external_customer_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("connector_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("integration_connectors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("external_customer_id", sa.String(200), nullable=False),
        sa.Column("customer_code", sa.String(100)),
        sa.Column("name", sa.String(200)),
        sa.Column("status", sa.String(40)),
        sa.Column("source_updated_at", sa.DateTime(timezone=True)),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("mapped_customer_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("customers.id", ondelete="SET NULL")),
        sa.Column("managed_fields", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("sync_state", sa.String(20), nullable=False, server_default="UNMAPPED"),
        sa.Column("payload_fingerprint", sa.String(64), nullable=False),
        sa.Column("attributes", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.UniqueConstraint("connector_id", "external_customer_id", name="uq_external_customer_snapshot_identity"),
        sa.CheckConstraint("sync_state IN ('UNMAPPED','MAPPED','ERROR')", name="ck_external_customer_snapshots_state"),
    )
    op.create_index("ix_external_customer_snapshots_mapping", "external_customer_snapshots", ["mapped_customer_id"])
    op.create_index("ix_external_customer_snapshots_state", "external_customer_snapshots", ["sync_state"])

    op.create_table(
        "external_service_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("connector_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("integration_connectors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("external_service_id", sa.String(200), nullable=False),
        sa.Column("external_customer_id", sa.String(200), nullable=False),
        sa.Column("service_code", sa.String(100)),
        sa.Column("status", sa.String(40)),
        sa.Column("customer_vlan_id", sa.Integer()),
        sa.Column("source_updated_at", sa.DateTime(timezone=True)),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("mapped_customer_service_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("customer_services.id", ondelete="SET NULL")),
        sa.Column("managed_fields", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("sync_state", sa.String(20), nullable=False, server_default="UNMAPPED"),
        sa.Column("payload_fingerprint", sa.String(64), nullable=False),
        sa.Column("attributes", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.UniqueConstraint("connector_id", "external_service_id", name="uq_external_service_snapshot_identity"),
        sa.CheckConstraint("sync_state IN ('UNMAPPED','MAPPED','ERROR')", name="ck_external_service_snapshots_state"),
        sa.CheckConstraint("customer_vlan_id IS NULL OR customer_vlan_id BETWEEN 2 AND 4094", name="ck_external_service_snapshots_vlan"),
    )
    op.create_index("ix_external_service_snapshots_mapping", "external_service_snapshots", ["mapped_customer_service_id"])
    op.create_index("ix_external_service_snapshots_customer", "external_service_snapshots", ["connector_id", "external_customer_id"])
    op.create_index("ix_external_service_snapshots_state", "external_service_snapshots", ["sync_state"])

    op.create_table(
        "integration_event_receipts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("connector_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("integration_connectors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_id", sa.String(200), nullable=False),
        sa.Column("event_type", sa.String(80), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_updated_at", sa.DateTime(timezone=True)),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("error_message", sa.Text()),
        sa.UniqueConstraint("connector_id", "event_id", name="uq_integration_event_receipts_identity"),
        sa.CheckConstraint("status IN ('PROCESSED','DUPLICATE','FAILED')", name="ck_integration_event_receipts_status"),
    )
    op.create_index("ix_integration_event_receipts_received", "integration_event_receipts", ["received_at"])

    op.create_table(
        "integration_sync_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("connector_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("integration_connectors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("mode", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("records_received", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_changed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_unchanged", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_failed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cursor_before", sa.String(512)),
        sa.Column("cursor_after", sa.String(512)),
        sa.Column("error_message", sa.Text()),
        sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.CheckConstraint("mode IN ('FULL','INCREMENTAL','EVENT')", name="ck_integration_sync_runs_mode"),
        sa.CheckConstraint("status IN ('STARTED','SUCCESS','PARTIAL','FAILED')", name="ck_integration_sync_runs_status"),
    )
    op.create_index("ix_integration_sync_runs_connector_started", "integration_sync_runs", ["connector_id", "started_at"])


def downgrade() -> None:
    op.drop_index("ix_integration_sync_runs_connector_started", table_name="integration_sync_runs")
    op.drop_table("integration_sync_runs")
    op.drop_index("ix_integration_event_receipts_received", table_name="integration_event_receipts")
    op.drop_table("integration_event_receipts")
    op.drop_index("ix_external_service_snapshots_state", table_name="external_service_snapshots")
    op.drop_index("ix_external_service_snapshots_customer", table_name="external_service_snapshots")
    op.drop_index("ix_external_service_snapshots_mapping", table_name="external_service_snapshots")
    op.drop_table("external_service_snapshots")
    op.drop_index("ix_external_customer_snapshots_state", table_name="external_customer_snapshots")
    op.drop_index("ix_external_customer_snapshots_mapping", table_name="external_customer_snapshots")
    op.drop_table("external_customer_snapshots")
    op.drop_index("ix_integration_access_tokens_client_expiry", table_name="integration_access_tokens")
    op.drop_table("integration_access_tokens")
    op.drop_index("ix_integration_clients_active", table_name="integration_clients")
    op.drop_table("integration_clients")
    op.drop_table("integration_connectors")
