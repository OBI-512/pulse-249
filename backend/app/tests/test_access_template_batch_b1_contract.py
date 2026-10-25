from pathlib import Path
from types import SimpleNamespace

from starlette.requests import Request

from app.security.authorization import permission_for_request
from app.security.permissions import Permission as P


ROOT = Path(__file__).resolve().parents[1]


def _request(method: str, path: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "raw_path": path.encode(),
            "root_path": "",
            "scheme": "http",
            "query_string": b"",
            "headers": [],
            "client": ("test", 1),
            "server": ("test", 80),
            "route": SimpleNamespace(path=path),
        }
    )


def test_batch_b1_access_template_routes_keep_explicit_permissions():
    assert permission_for_request(_request("GET", "/api/access-templates/deleted")) == P.ACCESS_TEMPLATE_READ
    assert permission_for_request(_request("POST", "/api/access-templates/{template_id}/restore")) == P.ACCESS_TEMPLATE_MANAGE
    assert permission_for_request(_request("POST", "/api/access-templates/{template_id}/test")) == P.ACCESS_TEMPLATE_TEST


def test_batch_b1_restore_is_inactive_and_assignment_safe_by_contract():
    source = (ROOT / "api" / "routers" / "access_templates.py").read_text(encoding="utf-8")
    assert '@router.get("/deleted"' in source
    assert '@router.post("/{template_id}/restore"' in source
    assert "execution_options(include_recycled=True)" in source
    assert '"ACCESS_TEMPLATE_RESTORE_IDENTITY_CONFLICT"' in source
    assert "row.deleted_at = None" in source
    assert "row.is_active = False" in source
    assert ".values(enabled=False)" in source
    assert 'action="ACCESS_TEMPLATE_RESTORE"' in source


def test_batch_b1_deactivation_disables_assignments_and_invalidates_old_tests():
    source = (ROOT / "api" / "routers" / "access_templates.py").read_text(encoding="utf-8")
    assert "was_active = row.is_active" in source
    assert "if was_active and not next_active:" in source
    assert "row.updated_at = datetime.now(timezone.utc)" in source
    assert '"assignments_disabled": bool(was_active and not next_active)' in source


def test_batch_b1_web_wizard_requires_current_inactive_draft_evidence():
    source = (ROOT / "api" / "routers" / "access_template_web_wizard.py").read_text(encoding="utf-8")
    assert "require_inactive_draft: bool = False" in source
    assert '"WEB_WIZARD_DRAFT_REQUIRED"' in source
    assert source.count("require_inactive_draft=True") >= 3
    assert "AccessTemplateTestResult.tested_at >= template.updated_at" in source
    assert "successful_test = await _require_successful_test" in source
    assert "preview.activated_at < successful_test.tested_at" in source
