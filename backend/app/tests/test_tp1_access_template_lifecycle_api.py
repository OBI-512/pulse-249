from __future__ import annotations

import asyncio
import inspect
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.api.routers import access_template_lifecycle as lifecycle_router
from app.core.exceptions import APIError
from app.models import AccessTemplate, AccessTemplateRevision, AccessTemplateRevisionSecret
from app.schemas.access_template_lifecycle import (
    AccessTemplateFamilyCreate,
    AccessTemplateRevisionUpdate,
)
from app.schemas.access_templates import AccessTemplateSecretInput
from app.services import access_template_lifecycle as lifecycle_service
from app.services.access_template_lifecycle import (
    revision_definition_sha256_from_parts,
    runtime_template_for_revision,
)
from scripts.validate_ci_route_permission_contract import current_manifest, expected_manifest


EXPECTED_LIFECYCLE_ROUTES = {
    ("POST", "/api/access-templates/families", "access_template.manage"),
    ("POST", "/api/access-templates/{template_id}/clone", "access_template.manage"),
    ("GET", "/api/access-templates/{template_id}/revisions", "access_template.read"),
    ("POST", "/api/access-templates/{template_id}/revisions", "access_template.manage"),
    ("PATCH", "/api/access-templates/{template_id}/revisions/{revision_id}", "access_template.manage"),
    ("POST", "/api/access-templates/{template_id}/revisions/{revision_id}/activate", "access_template.manage"),
    ("POST", "/api/access-templates/{template_id}/revisions/{revision_id}/approve", "access_template.manage"),
    ("POST", "/api/access-templates/{template_id}/revisions/{revision_id}/test", "access_template.test"),
}


class _FakeLifecycleDb:
    def __init__(self, *, scalar_result=None):
        self.pending = []
        self.scalar = AsyncMock(return_value=scalar_result)
        self.flush = AsyncMock()
        self.commit = AsyncMock()
        self.refresh = AsyncMock()
        self.rollback = AsyncMock(side_effect=self.pending.clear)

    def add(self, row):
        if getattr(row, "id", None) is None:
            row.id = uuid4()
        self.pending.append(row)


def _secret(*, key: str, payload: str) -> AccessTemplateRevisionSecret:
    return AccessTemplateRevisionSecret(
        revision_id=uuid4(),
        template_id=uuid4(),
        secret_key=key,
        provider="ENCRYPTED_DATABASE",
        encrypted_payload=payload,
        reference=None,
        key_version=1,
    )


def test_lifecycle_routes_are_closed_by_ci_contract():
    current = current_manifest()
    expected = expected_manifest()
    assert current == expected
    assert current["route_count"] == 319
    rows = {
        (row["method"], row["path"], row.get("permission"))
        for row in current["routes"]
    }
    assert EXPECTED_LIFECYCLE_ROUTES <= rows


def _family_payload() -> AccessTemplateFamilyCreate:
    return AccessTemplateFamilyCreate(
        name="  New SSH family  ",
        description="Lifecycle-native family",
        protocol="SSH",
        protocol_variant="PASSWORD_OR_KEY",
        visibility="PRIVATE",
        settings={"port": 22, "timeout_seconds": 10},
        secrets={
            "password": AccessTemplateSecretInput(
                provider="ENCRYPTED_DATABASE",
                value="not-persisted-by-this-test",
            )
        },
        change_note="Initial lifecycle draft",
    )


async def _lifecycle_family_bootstrap_creates_inactive_family_and_initial_draft(
    monkeypatch,
):
    db = _FakeLifecycleDb()
    payload = _family_payload()
    captured = {}

    def fake_transition(**kwargs):
        captured["transition"] = kwargs
        return {"password"}, set()

    def fake_validate(**kwargs):
        captured["validation"] = kwargs
        return "SSH", "PASSWORD_OR_KEY", dict(kwargs["template_settings"])

    async def fake_apply_revision_secrets(_db, **kwargs):
        captured["secret_inputs"] = kwargs["secret_inputs"]

    async def fake_record_audit(_db, **kwargs):
        captured["audit"] = kwargs

    monkeypatch.setattr(lifecycle_service, "calculate_secret_key_transition", fake_transition)
    monkeypatch.setattr(lifecycle_service, "validate_template_definition", fake_validate)
    monkeypatch.setattr(lifecycle_service, "_apply_revision_secret_inputs", fake_apply_revision_secrets)
    monkeypatch.setattr(lifecycle_service, "record_audit", fake_record_audit)

    family, revision = await lifecycle_service.create_template_family(
        db,
        name=payload.name,
        description=payload.description,
        protocol=payload.protocol,
        protocol_variant=payload.protocol_variant,
        visibility=payload.visibility,
        settings=payload.settings,
        secrets=payload.secrets,
        change_note=payload.change_note,
        actor_user_id=uuid4(),
    )

    assert db.pending == [family, revision]
    assert family.name == "New SSH family"
    assert family.is_active is False
    assert family.settings_json == payload.settings
    assert revision.template_id == family.id
    assert revision.revision_number == 1
    assert revision.lifecycle_status == "DRAFT"
    assert revision.protocol_variant == payload.protocol_variant
    assert revision.settings_json == payload.settings
    assert revision.source_revision_id is None
    assert revision.definition_sha256 is None
    assert revision.tested_at is None
    assert revision.approved_at is None
    assert revision.activated_at is None
    assert captured["validation"]["is_active"] is False
    assert captured["secret_inputs"] == payload.secrets
    assert captured["audit"]["after_summary"]["initial_revision_status"] == "DRAFT"
    assert captured["audit"]["after_summary"]["device_bindings_created"] == 0
    assert captured["audit"]["after_summary"]["configuration_operations_created"] == 0


def test_lifecycle_family_bootstrap_creates_inactive_family_and_initial_draft(
    monkeypatch,
):
    asyncio.run(
        _lifecycle_family_bootstrap_creates_inactive_family_and_initial_draft(
            monkeypatch
        )
    )


async def _lifecycle_family_bootstrap_rolls_back_orphan_on_revision_failure(
    monkeypatch,
):
    db = _FakeLifecycleDb()
    payload = _family_payload()

    monkeypatch.setattr(
        lifecycle_service,
        "calculate_secret_key_transition",
        lambda **_kwargs: ({"password"}, set()),
    )
    monkeypatch.setattr(
        lifecycle_service,
        "validate_template_definition",
        lambda **kwargs: ("SSH", "PASSWORD_OR_KEY", dict(kwargs["template_settings"])),
    )

    async def fail_revision_secrets(_db, **_kwargs):
        raise RuntimeError("induced revision bootstrap failure")

    monkeypatch.setattr(
        lifecycle_service,
        "_apply_revision_secret_inputs",
        fail_revision_secrets,
    )

    with pytest.raises(RuntimeError, match="induced revision bootstrap failure"):
        await lifecycle_router.create_access_template_family(
            payload=payload,
            db=db,
            actor=SimpleNamespace(id=uuid4()),
        )

    db.commit.assert_not_awaited()
    db.rollback.assert_awaited_once()
    assert db.pending == []


def test_lifecycle_family_bootstrap_rolls_back_orphan_on_revision_failure(
    monkeypatch,
):
    asyncio.run(
        _lifecycle_family_bootstrap_rolls_back_orphan_on_revision_failure(
            monkeypatch
        )
    )


async def _lifecycle_family_bootstrap_rejects_duplicate_identity(monkeypatch):
    db = _FakeLifecycleDb(scalar_result=uuid4())
    payload = _family_payload()

    with pytest.raises(APIError):
        await lifecycle_service.create_template_family(
            db,
            name=payload.name,
            description=payload.description,
            protocol=payload.protocol,
            protocol_variant=payload.protocol_variant,
            visibility=payload.visibility,
            settings=payload.settings,
            secrets=payload.secrets,
            change_note=payload.change_note,
            actor_user_id=uuid4(),
        )

    assert db.pending == []


def test_lifecycle_family_bootstrap_rejects_duplicate_identity(monkeypatch):
    asyncio.run(_lifecycle_family_bootstrap_rejects_duplicate_identity(monkeypatch))


def test_lifecycle_family_bootstrap_is_inactive_only_and_non_executing():
    with pytest.raises(ValidationError):
        AccessTemplateFamilyCreate(name="Invalid active family", protocol="SSH", is_active=True)

    route_source = inspect.getsource(lifecycle_router.create_access_template_family)
    service_source = inspect.getsource(lifecycle_service.create_template_family)
    assert "require_permission(MANAGE_PERMISSION)" in route_source
    assert route_source.count("await db.commit()") == 1
    assert "await db.rollback()" in route_source
    for forbidden in (
        "AccessTemplateAssignment(",
        "ConfigurationOperation(",
        "queue_operation(",
        "test_revision_connection(",
        "require_device(",
        "scope_for_actor(",
    ):
        assert forbidden not in service_source


def test_definition_fingerprint_changes_when_settings_change():
    secret = _secret(key="password", payload="v1:nonce:ciphertext")
    first = revision_definition_sha256_from_parts(
        protocol="SSH",
        protocol_variant="PASSWORD_OR_KEY",
        settings={"port": 22, "timeout_seconds": 10},
        secret_rows=[secret],
    )
    second = revision_definition_sha256_from_parts(
        protocol="SSH",
        protocol_variant="PASSWORD_OR_KEY",
        settings={"port": 2222, "timeout_seconds": 10},
        secret_rows=[secret],
    )
    assert len(first) == 64
    assert first != second


def test_definition_fingerprint_changes_when_secret_snapshot_changes():
    first = revision_definition_sha256_from_parts(
        protocol="SSH",
        protocol_variant="PASSWORD_OR_KEY",
        settings={"port": 22},
        secret_rows=[_secret(key="password", payload="v1:n1:c1")],
    )
    second = revision_definition_sha256_from_parts(
        protocol="SSH",
        protocol_variant="PASSWORD_OR_KEY",
        settings={"port": 22},
        secret_rows=[_secret(key="password", payload="v1:n2:c2")],
    )
    assert first != second


def test_runtime_template_uses_revision_definition_without_mutating_family():
    template_id = uuid4()
    family = AccessTemplate(
        id=template_id,
        name="SSH Access",
        description=None,
        protocol="SSH",
        protocol_variant="PASSWORD_OR_KEY",
        visibility="PRIVATE",
        owner_user_id=uuid4(),
        is_active=True,
        settings_json={"port": 22},
    )
    revision = AccessTemplateRevision(
        id=uuid4(),
        template_id=template_id,
        revision_number=2,
        lifecycle_status="DRAFT",
        protocol_variant="PASSWORD_OR_KEY",
        settings_json={"port": 2222, "timeout_seconds": 15},
        legacy_backfill=False,
    )
    runtime = runtime_template_for_revision(family, revision)
    assert runtime.id == family.id
    assert runtime.protocol == family.protocol
    assert runtime.settings_json["port"] == 2222
    assert family.settings_json["port"] == 22


def test_revision_update_requires_an_actual_field():
    with pytest.raises(ValidationError):
        AccessTemplateRevisionUpdate()


def test_revision_update_accepts_change_note_without_definition_change():
    payload = AccessTemplateRevisionUpdate(change_note="Documentation only")
    assert payload.change_note == "Documentation only"
    assert payload.settings is None
    assert payload.secrets is None
