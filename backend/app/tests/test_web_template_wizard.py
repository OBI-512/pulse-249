from __future__ import annotations

import asyncio
import inspect
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import httpx
import pytest

from app.api.routers import access_template_web_wizard as wizard
from app.core.exceptions import APIError
from app.models import AccessTemplate, AccessTemplateRevision, AccessTemplateTestResult
from app.remote_gateway import web_template_bootstrap as gateway_bootstrap
from app.schemas.access_templates import AccessTemplateRead
from app.services.web_template_discovery import _candidate_form
from scripts.validate_ci_route_permission_contract import current_manifest, expected_manifest


ROOT = Path(__file__).resolve().parents[2]


class _FakeDb:
    def __init__(self, *, scalar_result=None):
        self.scalar = AsyncMock(return_value=scalar_result)
        self.commit = AsyncMock()
        self.rollback = AsyncMock()
        self.refresh = AsyncMock()
        self.add = Mock()


def _family(*, active: bool = False) -> AccessTemplate:
    return AccessTemplate(
        id=uuid4(),
        name="Wizard WEB family",
        description="Lifecycle bridge test",
        protocol="WEB",
        protocol_variant="FORM_POST",
        visibility="PRIVATE",
        owner_user_id=uuid4(),
        is_active=active,
        settings_json={"credential_mode": "USERNAME_PASSWORD"},
    )


def _revision(template: AccessTemplate, *, status: str = "DRAFT") -> AccessTemplateRevision:
    return AccessTemplateRevision(
        id=uuid4(),
        template_id=template.id,
        revision_number=1,
        lifecycle_status=status,
        protocol_variant="FORM_POST",
        settings_json={"credential_mode": "USERNAME_PASSWORD"},
        definition_sha256="a" * 64 if status in {"TESTED", "APPROVED"} else None,
        legacy_backfill=False,
    )


def _template_read(template: AccessTemplate) -> AccessTemplateRead:
    now = datetime.now(timezone.utc)
    return AccessTemplateRead(
        id=template.id,
        name=template.name,
        description=template.description,
        protocol=template.protocol,
        protocol_variant=template.protocol_variant,
        visibility=template.visibility,
        owner_user_id=template.owner_user_id,
        is_active=template.is_active,
        settings=dict(template.settings_json or {}),
        secret_providers={},
        created_at=now,
        updated_at=now,
    )


def _response(html: str) -> httpx.Response:
    request = httpx.Request("GET", "http://192.0.2.10/login")
    return httpx.Response(200, text=html, request=request)


def test_discovery_extracts_username_password_form_without_credentials():
    form = _candidate_form(
        _response(
            '<form action="/session" method="post" enctype="multipart/form-data">'
            '<input type="hidden" name="csrf" value="token">'
            '<input type="text" name="login_name">'
            '<input type="password" name="secret_value">'
            '</form>'
        ),
        "USERNAME_PASSWORD",
    )
    assert form is not None
    assert form["action"] == "/session"
    assert form["enctype"] == "multipart/form-data"
    assert form["username_field"] == "login_name"
    assert form["password_field"] == "secret_value"
    assert "token" not in repr(form)


def test_discovery_accepts_password_only_form_and_does_not_invent_username():
    form = _candidate_form(
        _response(
            '<form action="/unlock" method="post">'
            '<input type="password" name="passcode">'
            '</form>'
        ),
        "PASSWORD_ONLY",
    )
    assert form is not None
    assert form["username_field"] is None
    assert form["password_field"] == "passcode"


def test_username_password_discovery_rejects_form_without_username_candidate():
    form = _candidate_form(
        _response('<form method="post"><input type="password" name="passcode"></form>'),
        "USERNAME_PASSWORD",
    )
    assert form is None


def test_wizard_routes_require_registered_device_and_three_acceptance_gates_by_contract():
    source = (ROOT / "app" / "api" / "routers" / "access_template_web_wizard.py").read_text(encoding="utf-8")
    assert "WEB_WIZARD_REFERENCE_DEVICE_NOT_FOUND" in source
    assert 'DeviceIP.is_management.is_(True)' in source
    assert '@router.post("/{template_id}/test"' in source
    assert '@router.post("/{template_id}/preview"' in source
    assert '@router.post("/{template_id}/confirm"' in source
    assert "WEB_WIZARD_CONNECTION_TEST_REQUIRED" in source
    assert "WEB_WIZARD_PREVIEW_CONFIRMATION_REQUIRED" in source
    assert "access_template_id=template.id" in source


def test_gateway_bootstrap_honors_template_bound_to_issued_web_session():
    source = (ROOT / "app" / "remote_gateway" / "web_template_bootstrap.py").read_text(encoding="utf-8")
    assert 'getattr(context["session"], "access_template_id", None)' in source
    assert "build_web_runtime_access(template, secrets)" in source
    assert '"browser_received_device_credentials": False' in source


def test_wizard_routes_are_lifecycle_native_without_changing_paths():
    source = inspect.getsource(wizard)
    start = inspect.getsource(wizard.start_web_template_wizard)
    test = inspect.getsource(wizard.test_web_template_draft)
    preview = inspect.getsource(wizard.preview_web_template)
    confirm = inspect.getsource(wizard.confirm_web_template)

    assert 'router.post("/start"' in source
    assert 'router.post("/{template_id}/test"' in source
    assert 'router.post("/{template_id}/preview"' in source
    assert 'router.post("/{template_id}/confirm"' in source
    assert "create_template_family(" in start
    assert "AccessTemplate(" not in start
    assert "apply_secret_inputs" not in start
    assert "AccessTemplateSecret(" not in start
    assert "test_revision_connection(" in test
    assert "runtime_template_for_revision(" in preview
    assert "resolved_revision_secrets(" in preview
    assert "approve_revision(" in confirm
    assert "activate_revision(" in confirm
    assert 'if revision.lifecycle_status == "TESTED"' in confirm
    assert 'elif revision.lifecycle_status != "APPROVED"' in confirm
    assert "template.is_active = True" not in confirm
    assert "ConfigurationOperation" not in source


def test_ambiguous_wizard_revision_resolution_fails_closed(monkeypatch):
    template = _family()
    actor_id = template.owner_user_id
    monkeypatch.setattr(wizard, "_owned_web_template", AsyncMock(return_value=template))
    monkeypatch.setattr(
        wizard,
        "list_revisions",
        AsyncMock(return_value=[_revision(template), _revision(template)]),
    )

    with pytest.raises(APIError) as caught:
        asyncio.run(wizard._wizard_lifecycle_revision(_FakeDb(), template.id, actor_id))

    assert caught.value.detail["code"] == "WEB_WIZARD_REVISION_AMBIGUOUS"


def test_current_revision_evidence_is_revision_bound_and_stale_safe(monkeypatch):
    template = _family()
    revision = _revision(template, status="TESTED")
    device_id = uuid4()
    monkeypatch.setattr(wizard, "revision_definition_sha256", AsyncMock(return_value="b" * 64))

    with pytest.raises(APIError) as caught:
        asyncio.run(
            wizard._require_successful_test(
                _FakeDb(), template=template, revision=revision, device_id=device_id
            )
        )

    assert caught.value.detail["code"] == "WEB_WIZARD_CONNECTION_TEST_STALE"


def test_inactive_gateway_preview_uses_revision_runtime_and_secrets(monkeypatch):
    template = _family()
    revision = _revision(template, status="TESTED")
    device_id = uuid4()
    evidence = AccessTemplateTestResult(
        id=uuid4(),
        template_id=template.id,
        revision_id=revision.id,
        device_id=device_id,
        status="SUCCESS",
        sanitized_message="Connection successful.",
        tested_at=datetime.now(timezone.utc),
        tested_by_user_id=template.owner_user_id,
    )
    runtime = SimpleNamespace(id=template.id)
    expected = SimpleNamespace(base_url="https://192.0.2.1")
    db = _FakeDb(scalar_result=evidence)
    monkeypatch.setattr(gateway_bootstrap, "list_revisions", AsyncMock(return_value=[revision]))
    monkeypatch.setattr(
        gateway_bootstrap,
        "revision_definition_sha256",
        AsyncMock(return_value=revision.definition_sha256),
    )
    runtime_mock = Mock(return_value=runtime)
    secrets_mock = AsyncMock(return_value={"username": "operator", "password": "secret"})
    build_mock = Mock(return_value=expected)
    monkeypatch.setattr(gateway_bootstrap, "runtime_template_for_revision", runtime_mock)
    monkeypatch.setattr(gateway_bootstrap, "resolved_revision_secrets", secrets_mock)
    monkeypatch.setattr(gateway_bootstrap, "build_web_runtime_access", build_mock)

    actual = asyncio.run(
        gateway_bootstrap._inactive_web_revision_runtime(
            db, template=template, device_id=device_id
        )
    )

    assert actual is expected
    runtime_mock.assert_called_once_with(template, revision)
    secrets_mock.assert_awaited_once_with(
        db, template_id=template.id, revision_id=revision.id
    )
    build_mock.assert_called_once_with(
        runtime, {"username": "operator", "password": "secret"}
    )


def test_route_permission_manifest_remains_307_operations():
    current = current_manifest()
    assert current == expected_manifest()
    assert current["route_count"] == 307
