from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


METHOD_PRIORITY = {
    "SNMP": 100,
    "HTTPS": 90,
    "HTTP": 80,
    "TCP": 60,
    "ICMP": 40,
}

FIELD_PRIORITY = {
    "hostname": {
        "SNMP": 100,
        "HTTPS": 70,
        "HTTP": 60,
        "TCP": 20,
        "ICMP": 10,
    },
    "vendor": {"SNMP": 100, "HTTPS": 80, "HTTP": 70, "TCP": 10, "ICMP": 0},
    "model": {"SNMP": 100, "HTTPS": 80, "HTTP": 70, "TCP": 10, "ICMP": 0},
    "serial_number": {"SNMP": 100, "HTTPS": 80, "HTTP": 70, "TCP": 10, "ICMP": 0},
}


@dataclass(frozen=True)
class DiscoveryAggregate:
    ip_address: str
    reachable: bool
    hostname: str | None
    vendor: str | None
    model: str | None
    serial_number: str | None
    management_protocol: str | None
    primary_result_id: Any | None
    confidence: float
    protocol_status: dict[str, str]
    field_sources: dict[str, str]
    evidence: dict[str, dict[str, Any]]


def _method(record: Any) -> str:
    return str(getattr(record, "discovery_method", getattr(record, "method", "")) or "").upper()


def _status(record: Any) -> str:
    explicit = getattr(record, "status", None)
    if explicit:
        return str(explicit).upper()
    return "DISCOVERED" if bool(getattr(record, "success", False)) else "UNREACHABLE"


def _value(record: Any, field: str) -> str | None:
    value = getattr(record, field, None)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _pick_field(records: list[Any], field: str) -> tuple[str | None, str | None]:
    best: tuple[int, int, str, str] | None = None
    priorities = FIELD_PRIORITY[field]
    for index, record in enumerate(records):
        if _status(record) != "DISCOVERED":
            continue
        value = _value(record, field)
        if value is None:
            continue
        method = _method(record)
        rank = priorities.get(method, 0)
        candidate = (rank, -index, value, method)
        if best is None or candidate[:2] > best[:2]:
            best = candidate
    if best is None:
        return None, None
    return best[2], best[3]


def _confidence(records: list[Any], fields: dict[str, str | None]) -> float:
    successful = [_method(record) for record in records if _status(record) == "DISCOVERED"]
    if not successful:
        return 0.0
    strongest = max((METHOD_PRIORITY.get(method, 30) for method in successful), default=30) / 100
    corroboration = min(0.12, max(0, len(set(successful)) - 1) * 0.03)
    identity_bonus = 0.0
    if fields.get("hostname"):
        identity_bonus += 0.04
    if fields.get("vendor"):
        identity_bonus += 0.04
    if fields.get("model"):
        identity_bonus += 0.04
    if fields.get("serial_number"):
        identity_bonus += 0.05
    return min(1.0, round(strongest + corroboration + identity_bonus, 2))


def aggregate_discovery_records(records: Iterable[Any]) -> DiscoveryAggregate | None:
    rows = list(records)
    if not rows:
        return None

    ip_address = str(getattr(rows[0], "ip_address"))
    same_ip = [row for row in rows if str(getattr(row, "ip_address")) == ip_address]
    if not same_ip:
        return None

    protocol_status: dict[str, str] = {}
    evidence: dict[str, dict[str, Any]] = {}
    for record in same_ip:
        method = _method(record)
        status = _status(record)
        # If a duplicate method is present, a successful observation wins.
        previous = protocol_status.get(method)
        if previous != "DISCOVERED" or status == "DISCOVERED":
            protocol_status[method] = status

        raw_data = dict(getattr(record, "raw_data", None) or {})
        evidence[method] = {
            "status": status,
            "hostname": _value(record, "hostname"),
            "vendor": _value(record, "vendor"),
            "model": _value(record, "model"),
            "serial_number": _value(record, "serial_number"),
            "message": raw_data.get("message"),
            "response_time_ms": raw_data.get("response_time_ms"),
            "management_protocol": raw_data.get("management_protocol") or method,
            "port": raw_data.get("port"),
            "requested_url": raw_data.get("requested_url"),
        }

    hostname, hostname_source = _pick_field(same_ip, "hostname")
    vendor, vendor_source = _pick_field(same_ip, "vendor")
    model, model_source = _pick_field(same_ip, "model")
    serial_number, serial_source = _pick_field(same_ip, "serial_number")

    field_sources = {
        key: source
        for key, source in {
            "hostname": hostname_source,
            "vendor": vendor_source,
            "model": model_source,
            "serial_number": serial_source,
        }.items()
        if source
    }

    successful = [row for row in same_ip if _status(row) == "DISCOVERED"]
    primary = max(successful, key=lambda row: METHOD_PRIORITY.get(_method(row), 30), default=None)
    management_protocol = _method(primary) if primary is not None else None
    primary_result_id = getattr(primary, "id", None) if primary is not None else None

    fields = {
        "hostname": hostname,
        "vendor": vendor,
        "model": model,
        "serial_number": serial_number,
    }

    return DiscoveryAggregate(
        ip_address=ip_address,
        reachable=bool(successful),
        hostname=hostname,
        vendor=vendor,
        model=model,
        serial_number=serial_number,
        management_protocol=management_protocol,
        primary_result_id=primary_result_id,
        confidence=_confidence(same_ip, fields),
        protocol_status=protocol_status,
        field_sources=field_sources,
        evidence=evidence,
    )


def aggregate_by_ip(records: Iterable[Any]) -> list[DiscoveryAggregate]:
    groups: dict[str, list[Any]] = {}
    for record in records:
        groups.setdefault(str(getattr(record, "ip_address")), []).append(record)
    aggregates: list[DiscoveryAggregate] = []
    for ip_address in sorted(groups):
        aggregate = aggregate_discovery_records(groups[ip_address])
        if aggregate is not None:
            aggregates.append(aggregate)
    return aggregates
