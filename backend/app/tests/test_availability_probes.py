import asyncio
from unittest.mock import AsyncMock

from app.availability import probes
from app.availability.state import ProbeOutcome
from app.discovery.models import DiscoveryResult


def test_probe_retries_failure_and_stops_on_success(monkeypatch):
    adapter = AsyncMock()
    adapter.discover.side_effect = [
        DiscoveryResult(False, "ICMP", "192.0.2.1", raw_data={"probe_available": True}),
        DiscoveryResult(True, "ICMP", "192.0.2.1", response_time_ms=3.5, raw_data={"probe_available": True}),
    ]
    monkeypatch.setattr(probes, "_ICMP", adapter)
    result = asyncio.run(probes.probe_availability(
        profile="ICMP", ip_address="192.0.2.1", timeout_seconds=1,
        retries=1, tcp_ports=(22,), credential_reference=None,
    ))
    assert result.outcome is ProbeOutcome.SUCCESS
    assert adapter.discover.await_count == 2


def test_missing_management_ip_is_indeterminate():
    result = asyncio.run(probes.probe_availability(
        profile="ICMP", ip_address=None, timeout_seconds=1,
        retries=1, tcp_ports=(22,), credential_reference=None,
    ))
    assert result.outcome is ProbeOutcome.INDETERMINATE
    assert result.result_code == "NO_MANAGEMENT_IP"


def test_snmp_missing_credential_is_indeterminate_and_not_retried():
    result = asyncio.run(probes.probe_availability(
        profile="SNMP", ip_address="192.0.2.2", timeout_seconds=1,
        retries=2, tcp_ports=(22,), credential_reference="env://FTTW_TEST_MISSING_SNMP",
    ))
    assert result.outcome is ProbeOutcome.INDETERMINATE
    assert result.result_code == "SNMP_CREDENTIAL_NOT_AVAILABLE"
