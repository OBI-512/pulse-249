from pathlib import Path
from uuid import uuid4

from app.schemas.batch_discovery import BatchDiscoveryRequest
from app.schemas.discovery import DiscoveryRunRequest


APP_ROOT = Path(__file__).resolve().parents[1]


def _source(relative: str) -> str:
    return (APP_ROOT / relative).read_text(encoding="utf-8-sig")


def test_single_and_batch_discovery_accept_access_template_reference():
    template_id = uuid4()
    single = DiscoveryRunRequest(ip_address="192.0.2.10", methods=["SNMP"], access_template_id=template_id)
    batch = BatchDiscoveryRequest(ip_addresses=["192.0.2.10"], methods=["SNMP"], access_template_id=template_id)
    assert single.access_template_id == template_id
    assert batch.access_template_id == template_id


def test_snmp_access_template_selection_is_validated_without_resolving_secrets():
    source = _source("services/discovery_access_templates.py")
    assert "access_template.read" in source
    assert 'AccessTemplate.protocol == "SNMP"' in source
    assert "AccessTemplate.is_active.is_(True)" in source
    assert "AccessTemplate.deleted_at.is_(None)" in source
    validation = source.split("async def require_discovery_snmp_template", 1)[1].split("async def resolve_discovery_snmp_template", 1)[0]
    assert "resolved_secrets" not in validation


def test_single_discovery_resolves_access_template_server_side_and_keeps_one_time_compatibility():
    source = _source("api/routers/discovery.py")
    assert "payload.access_template_id is not None" in source
    assert "require_discovery_snmp_template" in source
    assert "resolve_discovery_snmp_template" in source
    assert 'credential_source = "ACCESS_TEMPLATE"' in source
    assert 'credential_source = "ONE_TIME"' in source
    assert "_validated_snmp_options(payload)" in source


def test_batch_snmp_requires_template_id_and_worker_resolves_it_at_execution_time():
    router = _source("api/routers/batch_discovery.py")
    worker = _source("tasks/discovery.py")
    engine = _source("discovery/batch_engine.py")
    assert '"SNMP_BATCH_ACCESS_TEMPLATE_REQUIRED"' in router
    assert "require_discovery_snmp_template" in router
    assert "str(payload.access_template_id) if payload.access_template_id else None" in router
    assert "resolve_discovery_snmp_template" in worker
    assert "snmp_context_kwargs(runtime)" in worker
    assert "access_template_id: str | None = None" in worker
    assert "snmp_context=snmp_context" in worker
    assert "**(snmp_context or {})" in engine
    assert "SNMP batch discovery is disabled" not in router


def test_candidate_generation_is_idempotent_by_ip_for_registered_and_pending_inventory():
    source = _source("services/candidates.py")
    assert "select(DeviceIP).where(DeviceIP.ip_address == aggregate.ip_address)" in source
    assert "if existing_ip is not None:\n        return None" in source
    assert "select(DeviceCandidate).where(DeviceCandidate.ip_address == aggregate.ip_address)" in source
    assert "if existing.state != CANDIDATE_REGISTERED:" in source
    assert "_copy_aggregate(existing, aggregate)" in source
    assert "return existing" in source


def test_manual_web_fallback_is_server_verified_and_same_origin_bounded():
    service = _source("services/manual_web_template_discovery.py")
    wizard = _source("api/routers/access_template_web_wizard.py")
    assert "async def verify_manual_web_template" in service
    assert "authenticate_web_client(client, runtime)" in service
    assert "httpx_auth_for_web(runtime)" in service
    assert "parsed.scheme or parsed.netloc or not path.startswith" in service
    assert '"WEB_MANUAL_VERIFICATION_FAILED"' in service
    assert 'discovery_mode: Literal["AUTO", "MANUAL"]' in wizard
    assert "verify_manual_web_template(" in wizard
    assert '"discovery_mode": payload.discovery_mode' in wizard
    assert 'is_active=False' in wizard
