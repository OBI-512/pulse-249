from types import SimpleNamespace

from app.discovery.aggregation import aggregate_discovery_records


def record(method, status="DISCOVERED", hostname=None, vendor=None, model=None, serial=None):
    return SimpleNamespace(
        id=f"{method}-id",
        ip_address="192.0.2.10",
        discovery_method=method,
        status=status,
        hostname=hostname,
        vendor=vendor,
        model=model,
        serial_number=serial,
        raw_data={"message": f"{method} observation", "response_time_ms": 1.0},
    )


def test_snmp_hostname_wins_over_http_reverse_dns():
    aggregate = aggregate_discovery_records([
        record("HTTP", hostname="runtime-name.example"),
        record("SNMP", hostname="edge-router-01"),
    ])
    assert aggregate is not None
    assert aggregate.hostname == "edge-router-01"
    assert aggregate.field_sources["hostname"] == "SNMP"
    assert aggregate.management_protocol == "SNMP"


def test_partial_protocol_failure_keeps_device_reachable():
    aggregate = aggregate_discovery_records([
        record("ICMP", status="UNREACHABLE"),
        record("HTTP", status="DISCOVERED", hostname="http-name"),
        record("SNMP", status="UNREACHABLE"),
    ])
    assert aggregate is not None
    assert aggregate.reachable is True
    assert aggregate.protocol_status == {
        "ICMP": "UNREACHABLE",
        "HTTP": "DISCOVERED",
        "SNMP": "UNREACHABLE",
    }


def test_all_protocol_failures_mark_endpoint_unreachable():
    aggregate = aggregate_discovery_records([
        record("ICMP", status="UNREACHABLE"),
        record("HTTP", status="UNREACHABLE"),
    ])
    assert aggregate is not None
    assert aggregate.reachable is False
    assert aggregate.hostname is None
    assert aggregate.confidence == 0.0


def test_identity_fields_can_be_combined_from_different_protocols():
    aggregate = aggregate_discovery_records([
        record("HTTP", vendor="ExampleVendor", model="HTTP-Model"),
        record("SNMP", hostname="device-01", serial="ABC123"),
    ])
    assert aggregate is not None
    assert aggregate.hostname == "device-01"
    assert aggregate.vendor == "ExampleVendor"
    assert aggregate.model == "HTTP-Model"
    assert aggregate.serial_number == "ABC123"
    assert aggregate.field_sources == {
        "hostname": "SNMP",
        "vendor": "HTTP",
        "model": "HTTP",
        "serial_number": "SNMP",
    }
