from __future__ import annotations

import argparse
import asyncio
import secrets
from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.integrations.sync import run_connector_sync
from app.models import Customer, CustomerService, ExternalCustomerSnapshot, ExternalServiceSnapshot, IntegrationClient, IntegrationConnector
from app.security.passwords import hash_password
from app.settings import settings


async def main_async(args) -> int:
    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with SessionLocal() as db:
            if args.command == "create-connector":
                parsed = urlparse(args.base_url)
                if parsed.scheme not in {"https", "http"} or not parsed.hostname:
                    raise SystemExit("Invalid base URL")
                if await db.scalar(select(IntegrationConnector.id).where(IntegrationConnector.code == args.code)):
                    raise SystemExit("Connector code already exists")
                row = IntegrationConnector(
                    code=args.code,
                    name=args.name,
                    base_url=args.base_url,
                    enabled=args.enable,
                    auth_mode=args.auth_mode,
                    credential_reference=args.credential_reference,
                    verify_tls=not args.no_verify_tls,
                    reconciliation_interval_seconds=args.reconcile_seconds,
                    config={
                        "full_sync_path": args.full_sync_path,
                        "changes_path": args.changes_path,
                        "timeout_seconds": args.timeout_seconds,
                        "retry_attempts": args.retry_attempts,
                        "retry_base_seconds": args.retry_base_seconds,
                        "circuit_breaker_seconds": args.circuit_breaker_seconds,
                        "allowed_hosts": [parsed.hostname],
                    },
                )
                db.add(row)
                await db.commit()
                print(f"connector_id={row.id} code={row.code} enabled={row.enabled}")
                return 0
            if args.command == "create-client":
                connector = await db.scalar(select(IntegrationConnector).where(IntegrationConnector.code == args.connector_code))
                if connector is None:
                    raise SystemExit("Connector not found")
                client_id = "fttw_" + secrets.token_urlsafe(12)
                secret = secrets.token_urlsafe(32)
                row = IntegrationClient(
                    name=args.name,
                    client_id=client_id,
                    client_secret_hash=hash_password(secret),
                    connector_id=connector.id,
                    scopes=args.scopes,
                    token_ttl_seconds=args.token_ttl_seconds,
                    metadata_={},
                )
                db.add(row)
                await db.commit()
                print(f"client_id={client_id}")
                print(f"client_secret={secret}")
                print("Store the secret securely; it is not retrievable from FTTW.")
                return 0
            if args.command == "map-customer":
                connector = await db.scalar(select(IntegrationConnector).where(IntegrationConnector.code == args.connector_code))
                snapshot = None if connector is None else await db.scalar(select(ExternalCustomerSnapshot).where(ExternalCustomerSnapshot.connector_id == connector.id, ExternalCustomerSnapshot.external_customer_id == args.external_id).with_for_update())
                customer = await db.get(Customer, UUID(args.customer_id))
                if connector is None or snapshot is None or customer is None:
                    raise SystemExit("Connector, external snapshot, or local customer not found")
                allowed = {"name", "status"}
                fields = set(args.managed_fields)
                if not fields.issubset(allowed):
                    raise SystemExit(f"Customer managed fields must be within {sorted(allowed)}")
                snapshot.mapped_customer_id = customer.id
                snapshot.managed_fields = sorted(fields)
                snapshot.sync_state = "MAPPED"
                await db.commit()
                print(f"mapped external customer {args.external_id} -> {customer.id}; managed_fields={sorted(fields)}")
                return 0
            if args.command == "map-service":
                connector = await db.scalar(select(IntegrationConnector).where(IntegrationConnector.code == args.connector_code))
                snapshot = None if connector is None else await db.scalar(select(ExternalServiceSnapshot).where(ExternalServiceSnapshot.connector_id == connector.id, ExternalServiceSnapshot.external_service_id == args.external_id).with_for_update())
                service = await db.get(CustomerService, UUID(args.service_id))
                if connector is None or snapshot is None or service is None:
                    raise SystemExit("Connector, external snapshot, or local service not found")
                allowed = {"status", "customer_vlan_id"}
                fields = set(args.managed_fields)
                if not fields.issubset(allowed):
                    raise SystemExit(f"Service managed fields must be within {sorted(allowed)}")
                snapshot.mapped_customer_service_id = service.id
                snapshot.managed_fields = sorted(fields)
                snapshot.sync_state = "MAPPED"
                await db.commit()
                print(f"mapped external service {args.external_id} -> {service.id}; managed_fields={sorted(fields)}")
                return 0
            if args.command == "sync":
                connector = await db.scalar(select(IntegrationConnector).where(IntegrationConnector.code == args.connector_code).with_for_update())
                if connector is None:
                    raise SystemExit("Connector not found")
                run = await run_connector_sync(db, connector, mode=args.mode)
                await db.commit()
                print(f"sync_run={run.id} status={run.status} received={run.records_received} changed={run.records_changed}")
                return 0 if run.status == "SUCCESS" else 1
        return 2
    finally:
        await engine.dispose()


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="FTTW optional external integration administration")
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("create-connector")
    c.add_argument("--code", required=True); c.add_argument("--name", required=True); c.add_argument("--base-url", required=True)
    c.add_argument("--auth-mode", choices=["NONE", "BEARER", "BASIC", "OAUTH2_CLIENT_CREDENTIALS"], default="NONE")
    c.add_argument("--credential-reference"); c.add_argument("--full-sync-path", default="/customers"); c.add_argument("--changes-path", default="/changes")
    c.add_argument("--timeout-seconds", type=float, default=10); c.add_argument("--reconcile-seconds", type=int, default=3600)
    c.add_argument("--retry-attempts", type=int, default=3); c.add_argument("--retry-base-seconds", type=float, default=0.5); c.add_argument("--circuit-breaker-seconds", type=int, default=60)
    c.add_argument("--enable", action="store_true"); c.add_argument("--no-verify-tls", action="store_true")
    c = sub.add_parser("create-client")
    c.add_argument("--name", required=True); c.add_argument("--connector-code", required=True); c.add_argument("--scopes", nargs="+", default=["customer-sync.write"]); c.add_argument("--token-ttl-seconds", type=int, default=900)
    c = sub.add_parser("map-customer")
    c.add_argument("--connector-code", required=True); c.add_argument("--external-id", required=True); c.add_argument("--customer-id", required=True); c.add_argument("--managed-fields", nargs="*", default=[])
    c = sub.add_parser("map-service")
    c.add_argument("--connector-code", required=True); c.add_argument("--external-id", required=True); c.add_argument("--service-id", required=True); c.add_argument("--managed-fields", nargs="*", default=[])
    c = sub.add_parser("sync")
    c.add_argument("--connector-code", required=True); c.add_argument("--mode", choices=["FULL", "INCREMENTAL"], default="FULL")
    return p


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main_async(parser().parse_args())))
