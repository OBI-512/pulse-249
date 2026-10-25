from __future__ import annotations

import asyncio
import base64
import secrets
from uuid import uuid4

import httpx
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.integrations.sync import run_connector_sync
from app.models import ExternalCustomerSnapshot, IntegrationClient, IntegrationConnector
from app.security.passwords import hash_password
from app.settings import settings


async def _wait_http_ready(url: str, label: str, timeout_seconds: float = 60.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    last_error: Exception | None = None
    async with httpx.AsyncClient(timeout=2.0) as client:
        while asyncio.get_running_loop().time() < deadline:
            try:
                response = await client.get(url)
                if response.status_code < 500:
                    return
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as exc:
                last_error = exc
            await asyncio.sleep(0.5)
    raise RuntimeError(f"{label} did not become ready within {timeout_seconds:.0f}s: {last_error}")


async def main() -> int:
    if not settings.integrations_enabled or not settings.integration_allow_insecure_http:
        raise RuntimeError("Runtime qualification requires integrations enabled and HTTP allowed only in the isolated mock harness.")
    await _wait_http_ready("http://localhost:8000/api/health", "FTTW backend")
    await _wait_http_ready("http://mock-oss:8090/customers", "Mock OSS")
    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    marker = uuid4().hex[:10]
    code = f"RUNTIME-{marker}"
    secret = secrets.token_urlsafe(24)
    client_id = f"runtime_{marker}"
    connector_id = client_row_id = None
    try:
        async with Session() as db:
            connector = IntegrationConnector(code=code, name="Runtime Mock OSS", base_url="http://mock-oss:8090", enabled=True, auth_mode="NONE", verify_tls=False, reconciliation_interval_seconds=3600, config={"full_sync_path": "/customers", "changes_path": "/changes", "timeout_seconds": 1.0, "allowed_hosts": ["mock-oss"]})
            db.add(connector); await db.flush(); connector_id = connector.id
            client = IntegrationClient(name="Runtime Mock Client", client_id=client_id, client_secret_hash=hash_password(secret), is_active=True, connector_id=connector.id, scopes=["customer-sync.write"], token_ttl_seconds=300, metadata_={})
            db.add(client); await db.flush(); client_row_id = client.id
            run = await run_connector_sync(db, connector, mode="FULL")
            if run.status != "SUCCESS" or run.records_received < 3:
                raise RuntimeError(f"Full sync failed: status={run.status} received={run.records_received}")
            staged = int((await db.scalar(select(func.count(ExternalCustomerSnapshot.id)).where(ExternalCustomerSnapshot.connector_id == connector.id))) or 0)
            if staged < 2:
                raise RuntimeError("Expected staged customer snapshots were not created.")
            await db.commit()

        basic = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
        async with httpx.AsyncClient(timeout=5.0) as client:
            token = await client.post("http://localhost:8000/api/v1/oauth/token", headers={"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"}, content="grant_type=client_credentials&scope=customer-sync.write")
            token.raise_for_status()
            bearer = token.json()["access_token"]
            payload = {"event_id": f"EVENT-{marker}", "event_type": "CUSTOMER_UPSERT", "customer": {"external_customer_id": f"PUSH-{marker}", "customer_code": f"PUSH-{marker}", "name": "Pushed Customer", "status": "ACTIVE", "attributes": {}}}
            first = await client.post("http://localhost:8000/api/v1/customer-sync/events", headers={"Authorization": f"Bearer {bearer}"}, json=payload)
            first.raise_for_status()
            second = await client.post("http://localhost:8000/api/v1/customer-sync/events", headers={"Authorization": f"Bearer {bearer}"}, json=payload)
            second.raise_for_status()
            if first.json()["status"] != "PROCESSED" or second.json()["status"] != "DUPLICATE":
                raise RuntimeError("Inbound event idempotency contract failed.")
            await client.post("http://mock-oss:8090/control/error")

        async with Session() as db:
            connector = await db.get(IntegrationConnector, connector_id)
            failed = await run_connector_sync(db, connector, mode="INCREMENTAL")
            if failed.status != "FAILED":
                raise RuntimeError("Mock OSS failure was not contained as FAILED sync evidence.")
            await db.commit()

        async with httpx.AsyncClient(timeout=5.0) as client:
            health = await client.get("http://localhost:8000/api/health")
            health.raise_for_status()
            if health.json().get("status") not in {"online", "degraded"}:
                raise RuntimeError("Core FTTW health failed during external OSS failure.")
            await client.post("http://mock-oss:8090/control/normal")
        print("[PASS] Phase E integration runtime: initial pull, inbound update, idempotency, failure isolation, core independence.")
        return 0
    finally:
        async with Session() as db:
            if client_row_id is not None:
                client = await db.get(IntegrationClient, client_row_id)
                if client is not None:
                    await db.delete(client)
                    await db.flush()
            if connector_id is not None:
                connector = await db.get(IntegrationConnector, connector_id)
                if connector is not None:
                    await db.delete(connector)
            await db.commit()
        await engine.dispose()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
