from __future__ import annotations

import asyncio
import json
from pathlib import Path
from uuid import uuid4

from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.deps import get_db
from app.main import app
from app.models import AuthSession, Permission, User, UserPermission, UserResourceScope
from app.observability.logging import sanitize_operational_event, service_log_path
from app.security.authorization import authorize_request
from app.security.passwords import hash_password
from app.security.sessions import create_session
from app.settings import settings


def test_operational_log_redaction_and_bounded_authorized_viewer(monkeypatch, tmp_path: Path):
    async def scenario():
        original_root = settings.data_root
        settings.data_root = str(tmp_path)
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        async def override_get_db():
            async with factory() as db:
                yield db

        previous_db = app.dependency_overrides.get(get_db)
        previous_auth = app.dependency_overrides.pop(authorize_request, None)
        app.dependency_overrides[get_db] = override_get_db
        user_id = None
        try:
            event = sanitize_operational_event({
                "timestamp": "2030-01-01T00:00:00+00:00", "level": "ERROR", "service": "backend",
                "logger": "test", "message": "request failed", "request_id": "req-log-test",
                "password": "must-not-leak", "database_url": "postgresql://user:secret@host/db",
            })
            assert "must-not-leak" not in json.dumps(event)
            path = service_log_path("backend")
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")
            worker_event = sanitize_operational_event({
                "timestamp": "2030-01-01T00:00:01+00:00", "level": "INFO", "service": "worker",
                "logger": "test.worker", "message": "worker event", "request_id": "req-worker-test",
            })
            service_log_path("worker").write_text(json.dumps(worker_event) + "\n", encoding="utf-8")
            configuration_worker_event = sanitize_operational_event({
                "timestamp": "2030-01-01T00:00:02+00:00", "level": "INFO", "service": "configuration-worker",
                "logger": "test.configuration", "message": "configuration worker event", "request_id": "req-configuration-worker-test",
            })
            service_log_path("configuration-worker").write_text(
                json.dumps(configuration_worker_event) + "\n", encoding="utf-8"
            )

            async with factory() as db:
                marker = uuid4().hex[:12]
                user = User(
                    external_subject=f"logs:{marker}", username=f"logs-{marker}", display_name="Log Reader",
                    password_hash=hash_password(f"Logs-{marker}-Password!"), is_active=True, metadata_={},
                )
                db.add(user)
                await db.flush()
                db.add(UserResourceScope(user_id=user.id, scope_type="GLOBAL"))
                for code in ("logs.read", "logs.export"):
                    permission = await db.scalar(select(Permission).where(Permission.code == code))
                    assert permission is not None
                    db.add(UserPermission(user_id=user.id, permission_id=permission.id))
                token, _ = await create_session(db, user_id=user.id)
                await db.commit()
                user_id = user.id

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                headers = {"Authorization": f"Bearer {token}"}
                viewed = await client.get("/api/operational-logs", headers=headers, params={"service": "backend", "request_id": "req-log-test"})
                assert viewed.status_code == 200, viewed.text
                assert len(viewed.json()) == 1
                assert "must-not-leak" not in viewed.text
                combined = await client.get("/api/operational-logs/page", headers=headers, params={"service": "all", "page": 1, "page_size": 50})
                assert combined.status_code == 200, combined.text
                services = {item["service"] for item in combined.json()["items"]}
                assert {"backend", "worker", "configuration-worker"} <= services
                configuration_view = await client.get(
                    "/api/operational-logs",
                    headers=headers,
                    params={"service": "configuration-worker", "request_id": "req-configuration-worker-test"},
                )
                assert configuration_view.status_code == 200, configuration_view.text
                assert len(configuration_view.json()) == 1
                assert configuration_view.json()[0]["service"] == "configuration-worker"

                exported = await client.get("/api/operational-logs/export", headers=headers, params={"service": "backend"})
                assert exported.status_code == 200
                assert "must-not-leak" not in exported.text
        finally:
            if user_id is not None:
                async with factory() as db:
                    await db.execute(delete(AuthSession).where(AuthSession.user_id == user_id))
                    await db.execute(delete(User).where(User.id == user_id))
                    await db.commit()
            if previous_db is None:
                app.dependency_overrides.pop(get_db, None)
            else:
                app.dependency_overrides[get_db] = previous_db
            if previous_auth is not None:
                app.dependency_overrides[authorize_request] = previous_auth
            settings.data_root = original_root
            await engine.dispose()

    asyncio.run(scenario())
