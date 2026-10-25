from __future__ import annotations

import asyncio
import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.core.audit_context import (
    REQUEST_ID_HEADER,
    bind_audit_actor,
    bind_request_context,
    reset_audit_context,
    resolve_request_id,
    valid_request_id,
)
from app.core.audit_redaction import REDACTED, redact_audit_value
from app.main import app
from app.services import audit as audit_service


def test_recursive_redaction_covers_all_required_secret_classes():
    current_hash = "pbkdf2_sha256$600000$c2FsdA==$c2VjcmV0a2V5"
    payload = {
        "password": "plain-password",
        "nested": {
            "password_hash": current_hash,
            "access_token": "access-secret",
            "session_token": "session-secret",
            "session_hash": "session-hash-secret",
            "device_credentials": {"username": "device", "password": "device-secret"},
            "credential_reference": "vault://secret/device",
            "benign_reference_label": "vault://secret/device/credential",
            "private_key": "-----BEGIN PRIVATE KEY-----\nprivate-material",
            "connection": "postgresql://dbuser:db-secret@db.example/fttw?token=query-secret",
            "benign_connection_note": "host=db password=dsn-secret user=fttw",
            "setting": {"is_secret": True, "value": "setting-secret"},
            "items": [{"authorization": "Bearer bearer-secret"}],
            # Defense in depth must identify the application's hash even when
            # a caller gives it a non-sensitive key.
            "opaque_value": current_hash,
        },
        "safe": {"device_id": str(uuid4()), "status": "ACTIVE"},
    }

    redacted = redact_audit_value(payload)
    evidence = json.dumps(redacted, sort_keys=True)
    for secret in (
        "plain-password",
        current_hash,
        "access-secret",
        "session-secret",
        "session-hash-secret",
        "device-secret",
        "vault://secret/device",
        "private-material",
        "db-secret",
        "query-secret",
        "dsn-secret",
        "setting-secret",
        "bearer-secret",
    ):
        assert secret not in evidence
    assert redacted["password"] == REDACTED
    assert redacted["nested"]["setting"] == {
        "is_secret": True,
        "value": REDACTED,
    }
    assert redacted["safe"]["status"] == "ACTIVE"


def test_redaction_of_malformed_connection_uri_never_raises():
    assert redact_audit_value("postgresql://db.example:not-a-port/fttw") == REDACTED


def test_request_id_validation_accepts_safe_ids_and_replaces_unsafe_values():
    supplied = "client-correlation_123:child"
    assert valid_request_id(supplied)
    assert resolve_request_id(supplied) == supplied

    for unsafe in ("", "contains spaces", "line\nbreak", "x" * 129):
        generated = resolve_request_id(unsafe)
        assert generated != unsafe
        assert valid_request_id(generated)


class _StagingSession:
    def __init__(self, *, fail_add: bool = False):
        self.rows = []
        self.committed = False
        self.rolled_back = False
        self.fail_add = fail_add

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    def add(self, row):
        if self.fail_add:
            raise RuntimeError("simulated audit database failure")
        self.rows.append(row)

    async def commit(self):
        self.committed = True

    async def rollback(self):
        self.rolled_back = True


def test_record_audit_uses_context_redacts_and_does_not_commit():
    async def scenario():
        session = _StagingSession()
        user_id = uuid4()
        request_token = bind_request_context(
            request_id="request-core-123",
            source_ip="192.0.2.40",
        )
        actor_token = bind_audit_actor(user_id, "audit-user")
        try:
            row = await audit_service.record_audit(
                session,  # type: ignore[arg-type]
                action="device_updated",
                entity_type="Device",
                entity_id=uuid4(),
                entity_display_snapshot={"name": "Switch 1"},
                before_summary={"password": "before-secret"},
                after_summary={"status": "ACTIVE"},
                metadata={"token": "metadata-secret"},
            )
        finally:
            reset_audit_context(actor_token)
            reset_audit_context(request_token)

        assert session.rows == [row]
        assert not session.committed
        assert row.action == "DEVICE_UPDATED"
        assert row.result == "SUCCESS"
        assert row.actor_user_id == user_id
        assert row.actor_username_snapshot == "audit-user"
        assert row.request_id == "request-core-123"
        assert row.source_ip == "192.0.2.40"
        assert row.before_summary == {"password": REDACTED}
        assert row.metadata_ == {"token": REDACTED}

    asyncio.run(scenario())


def test_record_audit_rejects_unknown_result():
    async def scenario():
        with pytest.raises(ValueError, match="Unsupported audit result"):
            await audit_service.record_audit(
                _StagingSession(),  # type: ignore[arg-type]
                action="TEST_EVENT",
                result="UNKNOWN",
            )

    asyncio.run(scenario())


def test_failure_writer_uses_independent_commit_and_never_raises(monkeypatch):
    async def success_scenario():
        session = _StagingSession()
        monkeypatch.setattr(audit_service, "AsyncSessionLocal", lambda: session)
        assert await audit_service.record_failure_audit(
            action="LOGIN_FAILED",
            metadata={"password": "never-store-this"},
        )
        assert session.committed
        assert not session.rolled_back
        assert session.rows[0].result == "FAILURE"
        assert session.rows[0].metadata_ == {"password": REDACTED}

    asyncio.run(success_scenario())

    async def failure_scenario():
        session = _StagingSession(fail_add=True)
        monkeypatch.setattr(audit_service, "AsyncSessionLocal", lambda: session)
        assert not await audit_service.record_failure_audit(action="LOGIN_FAILED")
        assert session.rolled_back
        assert not session.committed

    asyncio.run(failure_scenario())


def test_request_id_middleware_echoes_valid_and_replaces_invalid_headers():
    with TestClient(app) as client:
        response = client.get("/api", headers={REQUEST_ID_HEADER: "client-request-42"})
        assert response.status_code == 200
        assert response.headers[REQUEST_ID_HEADER] == "client-request-42"

        response = client.get("/api", headers={REQUEST_ID_HEADER: "unsafe request id"})
        assert response.status_code == 200
        assert response.headers[REQUEST_ID_HEADER] != "unsafe request id"
        assert valid_request_id(response.headers[REQUEST_ID_HEADER])

        response = client.get("/api")
        assert response.status_code == 200
        assert valid_request_id(response.headers[REQUEST_ID_HEADER])


def test_request_id_header_is_exposed_to_cross_origin_frontends():
    with TestClient(app) as client:
        response = client.get(
            "/api",
            headers={
                "Origin": "http://localhost:3000",
            },
        )
    assert response.status_code == 200
    exposed = response.headers.get("access-control-expose-headers", "").lower()
    assert REQUEST_ID_HEADER.lower() in exposed
