from types import SimpleNamespace
import pytest

from app.discovery.registry import build_default_registry


def test_default_registry_contains_expected_adapters():
    registry = build_default_registry()
    assert registry.methods() == ["HTTP", "HTTPS", "ICMP", "SNMP", "TCP"]


def test_unknown_adapter_is_not_registered():
    registry = build_default_registry()
    assert registry.get("SSH") is None


def test_discovery_read_schemas_accept_orm_objects():
    from datetime import datetime, timezone
    from uuid import uuid4
    from app.schemas.discovery import DiscoveryResultRead, DiscoveryJobRead

    job_id = uuid4()
    result = SimpleNamespace(
        id=uuid4(),
        discovery_job_id=job_id,
        ip_address="192.0.2.1",
        discovery_method="TCP",
        status="UNREACHABLE",
        vendor=None,
        model=None,
        hostname=None,
        serial_number=None,
        raw_data={"open_ports": []},
        created_at=datetime.now(timezone.utc),
    )
    job = SimpleNamespace(
        id=job_id,
        scope_type="IP",
        scope_value="192.0.2.1",
        status="COMPLETED",
        metadata_={},
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    assert DiscoveryResultRead.model_validate(result).ip_address == "192.0.2.1"
    assert DiscoveryJobRead.model_validate(job).scope_value == "192.0.2.1"
