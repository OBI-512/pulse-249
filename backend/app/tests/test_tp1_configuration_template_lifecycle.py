from __future__ import annotations

import inspect
import json
from pathlib import Path

from app.api.routers import configuration
from app.models import ConfigurationTemplateVersion
from app.schemas.configuration import ConfigurationTemplateVersionRead
from app.schemas.configuration_template_lifecycle import ConfigurationTemplateVersionLifecycleRead
from app.security.authorization import permission_for_request
from app.services import configuration_template_lifecycle
from starlette.requests import Request


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations" / "versions" / "0043_configuration_template_lifecycle.py"
EXTENSION = ROOT / "scripts" / "ci_route_permission_contract_0043_extension.json"


def _request(path: str, method: str) -> Request:
    class Route:
        pass

    route = Route()
    route.path = path
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("utf-8"),
            "query_string": b"",
            "headers": [],
            "client": ("tp1-test", 0),
            "server": ("tp1-test", 80),
            "route": route,
        }
    )


def test_configuration_template_model_exposes_five_state_lifecycle():
    constraints = {
        item.name: str(item.sqltext)
        for item in ConfigurationTemplateVersion.__table__.constraints
        if getattr(item, "name", None) and hasattr(item, "sqltext")
    }
    status = constraints["ck_configuration_template_versions_status"]
    for value in ("DRAFT", "TESTED", "APPROVED", "PUBLISHED", "RETIRED"):
        assert value in status
    assert "source_version_id" in ConfigurationTemplateVersion.__table__.c
    assert "tested_definition_sha256" in ConfigurationTemplateVersion.__table__.c
    assert "tested_at" in ConfigurationTemplateVersion.__table__.c
    assert "tested_by_user_id" in ConfigurationTemplateVersion.__table__.c
    assert "approved_at" in ConfigurationTemplateVersion.__table__.c
    assert "approved_by_user_id" in ConfigurationTemplateVersion.__table__.c


def test_normal_version_read_exposes_lifecycle_metadata():
    fields = set(ConfigurationTemplateVersionRead.model_fields)
    assert {
        "source_version_id",
        "tested_definition_sha256",
        "tested_at",
        "tested_by_user_id",
        "approved_at",
        "approved_by_user_id",
        "published_by_user_id",
    }.issubset(fields)
    assert "tested_definition_sha256" in ConfigurationTemplateVersionLifecycleRead.model_fields


def test_lifecycle_routes_are_registered_once():
    rows = []
    for route in configuration.template_router.routes:
        for method in sorted(getattr(route, "methods", []) or []):
            if method in {"HEAD", "OPTIONS"}:
                continue
            rows.append((method, route.path))
    expected = {
        ("GET", "/configuration-templates/{template_id}/versions/{version_id}/lifecycle"),
        ("POST", "/configuration-templates/{template_id}/versions/{version_id}/clone"),
        ("POST", "/configuration-templates/{template_id}/versions/{version_id}/clone-family"),
        ("POST", "/configuration-templates/{template_id}/versions/{version_id}/test"),
        ("POST", "/configuration-templates/{template_id}/versions/{version_id}/approve"),
        ("POST", "/configuration-templates/{template_id}/versions/{version_id}/activate"),
    }
    assert expected.issubset(set(rows))
    for item in expected:
        assert rows.count(item) == 1


def test_publish_route_is_approved_only_activation_alias():
    source = inspect.getsource(configuration.publish_configuration_template_version)
    assert "activate_configuration_template_version" in source
    assert "publish_template_version" not in source


def test_lifecycle_permissions_reuse_existing_global_configuration_boundary():
    read_path = "/api/configuration-templates/{template_id}/versions/{version_id}/lifecycle"
    write_path = "/api/configuration-templates/{template_id}/versions/{version_id}/activate"
    assert permission_for_request(_request(read_path, "GET")) == "device.configuration.template.read"
    assert permission_for_request(_request(write_path, "POST")) == "device.configuration.template.manage"


def test_0043_route_contract_extension_is_exact_six_routes():
    payload = json.loads(EXTENSION.read_text(encoding="utf-8"))
    assert payload["schema"] == 1
    rows = payload["routes"]
    assert len(rows) == 6
    assert all(row.get("global_scope") is True for row in rows)
    assert sum(1 for row in rows if row["method"] == "GET") == 1
    assert sum(1 for row in rows if row["method"] == "POST") == 5


def test_migration_0043_is_additive_and_grandfathers_existing_publication_evidence():
    source = MIGRATION.read_text(encoding="utf-8")
    revision_id = "0043_config_template_lifecycle"
    assert len(revision_id) <= 32
    assert f'revision = "{revision_id}"' in source
    assert 'down_revision = "0042_access_template_revisions"' in source
    for column in (
        "source_version_id",
        "tested_definition_sha256",
        "tested_at",
        "tested_by_user_id",
        "approved_at",
        "approved_by_user_id",
    ):
        assert column in source
    assert "COALESCE(tested_definition_sha256, content_sha256)" in source
    assert "status IN ('PUBLISHED', 'RETIRED')" in source


def test_migration_0043_does_not_rebind_or_rewrite_configuration_history():
    source = MIGRATION.read_text(encoding="utf-8").lower()
    forbidden_mutations = (
        "update device_configuration_bindings",
        "delete from device_configuration_bindings",
        "update configuration_snapshots",
        "delete from configuration_snapshots",
        "update configuration_operations",
        "delete from configuration_operations",
    )
    for statement in forbidden_mutations:
        assert statement not in source


def test_lifecycle_service_has_no_device_execution_or_dispatch_path():
    source = inspect.getsource(configuration_template_lifecycle)
    assert "queue_operation" not in source
    assert "celery_app" not in source
    assert "send_task" not in source
    assert "ConfigurationOperation(" not in source
    assert '"device_rebinding": False' in source
    assert '"configuration_execution": False' in source


def test_update_path_invalidates_test_and_approval_evidence():
    source = inspect.getsource(
        configuration_template_lifecycle.update_configuration_template_version_lifecycle
    )
    assert "tested_definition_sha256 = NULL" in source
    assert "tested_at = NULL" in source
    assert "approved_at = NULL" in source
    assert "status = 'DRAFT'" in source


def test_activation_requires_approved_state_and_matching_test_hash():
    source = inspect.getsource(
        configuration_template_lifecycle.activate_configuration_template_version
    )
    assert 'target.status != "APPROVED"' in source
    assert 'lifecycle["tested_definition_sha256"] != current_hash' in source
    assert 'row.status = "RETIRED"' in source
    assert 'target.status = "PUBLISHED"' in source
    retire_index = source.index('row.status = "RETIRED"')
    publish_index = source.index('target.status = "PUBLISHED"')
    assert "await db.flush()" in source[retire_index:publish_index]
