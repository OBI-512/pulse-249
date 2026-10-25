from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..discovery.aggregation import DiscoveryAggregate, aggregate_discovery_records
from ..models import DeviceCandidate, DeviceIP, DeviceType, DiscoveryJob, DiscoveryResult

CANDIDATE_NEW = "NEW"
CANDIDATE_APPROVED = "APPROVED"
CANDIDATE_REJECTED = "REJECTED"
CANDIDATE_REGISTERED = "REGISTERED"

TERMINAL_STATES = {CANDIDATE_REGISTERED}

# Backward-compatible per-observation confidence contract. Aggregated candidates
# use DiscoveryAggregate.confidence; this helper remains for existing callers/tests.
METHOD_WEIGHT = {
    "HTTPS": 0.95,
    "HTTP": 0.90,
    "SNMP": 0.98,
    "TCP": 0.65,
    "ICMP": 0.55,
}


def can_transition(current: str, target: str) -> bool:
    transitions = {
        CANDIDATE_NEW: {CANDIDATE_APPROVED, CANDIDATE_REJECTED},
        CANDIDATE_APPROVED: {CANDIDATE_REJECTED},
        CANDIDATE_REJECTED: {CANDIDATE_NEW},
        CANDIDATE_REGISTERED: set(),
    }
    return target in transitions.get(current, set())


def _confidence(result) -> float:
    """Preserve the pre-aggregation confidence helper for compatibility."""
    method = str(
        getattr(result, "discovery_method", getattr(result, "method", "")) or ""
    ).upper()
    base = METHOD_WEIGHT.get(method, 0.5)
    bonus = 0.0
    if getattr(result, "vendor", None):
        bonus += 0.10
    if getattr(result, "model", None):
        bonus += 0.10
    if getattr(result, "hostname", None):
        bonus += 0.05
    if getattr(result, "serial_number", None):
        bonus += 0.10
    return min(1.0, round(base + bonus, 2))


async def generate_candidate(
    db: AsyncSession,
    result: DiscoveryResult,
) -> DeviceCandidate | None:
    """Compatibility wrapper for older call sites."""
    return await generate_candidate_from_results(db, [result])


async def _authorization_scope_from_results(db: AsyncSession, results: Sequence[DiscoveryResult]) -> dict | None:
    job_ids = {result.discovery_job_id for result in results if result.discovery_job_id is not None}
    if not job_ids:
        return None
    jobs = list((await db.scalars(select(DiscoveryJob).where(DiscoveryJob.id.in_(tuple(job_ids))))).all())
    payloads = [(job.metadata_ or {}).get("_authorization_scope") for job in jobs]
    payloads = [payload for payload in payloads if isinstance(payload, dict)]
    if not payloads:
        return None
    keys: dict[str, bool] = {}
    actor_ids: list[str] = []
    for payload in payloads:
        raw_keys = payload.get("keys") or {}
        if isinstance(raw_keys, dict):
            keys.update({str(key): True for key, value in raw_keys.items() if value})
        if payload.get("actor_user_id"):
            actor_ids.append(str(payload["actor_user_id"]))
    if not keys:
        return None
    return {"version": 1, "actor_user_id": actor_ids[0] if actor_ids else None, "keys": keys}


def _merge_authorization_scope(existing: dict | None, incoming: dict | None) -> dict | None:
    if incoming is None:
        return existing
    if existing is None:
        return incoming
    keys = dict(existing.get("keys") or {})
    keys.update(incoming.get("keys") or {})
    return {"version": 1, "actor_user_id": existing.get("actor_user_id") or incoming.get("actor_user_id"), "keys": keys}


async def generate_candidate_from_results(
    db: AsyncSession,
    results: Sequence[DiscoveryResult],
) -> DeviceCandidate | None:
    aggregate = aggregate_discovery_records(results)
    if aggregate is None or not aggregate.reachable:
        return None

    authorization_scope = await _authorization_scope_from_results(db, results)

    existing_ip = await db.scalar(
        select(DeviceIP).where(DeviceIP.ip_address == aggregate.ip_address)
    )
    if existing_ip is not None:
        return None

    existing = await db.scalar(
        select(DeviceCandidate).where(DeviceCandidate.ip_address == aggregate.ip_address)
    )
    if existing is not None:
        if existing.state != CANDIDATE_REGISTERED:
            _copy_aggregate(existing, aggregate)
            merged_scope = _merge_authorization_scope((existing.metadata_ or {}).get("_authorization_scope"), authorization_scope)
            if merged_scope is not None:
                existing.metadata_ = {**(existing.metadata_ or {}), "_authorization_scope": merged_scope}
            suggested_type = await suggest_device_type(
                db, aggregate.vendor, aggregate.model
            )
            if suggested_type is not None:
                existing.suggested_device_type_id = suggested_type
        return existing

    candidate = DeviceCandidate(
        discovery_result_id=aggregate.primary_result_id,
        ip_address=aggregate.ip_address,
        state=CANDIDATE_NEW,
        confidence=aggregate.confidence,
        display_name_suggestion=_suggest_name(aggregate),
        hostname=aggregate.hostname,
        vendor=aggregate.vendor,
        model=aggregate.model,
        serial_number=aggregate.serial_number,
        management_protocol=aggregate.management_protocol,
        metadata_={**_discovery_metadata(aggregate), **({"_authorization_scope": authorization_scope} if authorization_scope else {})},
    )
    candidate.suggested_device_type_id = await suggest_device_type(
        db, aggregate.vendor, aggregate.model
    )
    db.add(candidate)
    await db.flush()
    return candidate


async def suggest_device_type(
    db: AsyncSession,
    vendor: str | None,
    model: str | None,
):
    text = f"{vendor or ''} {model or ''}".lower()
    if not text.strip():
        return None

    keywords = [
        ("cpe", ("cpe", "customer premise", "subscriber")),
        ("access_point", ("access point", "wireless ap", "wifi ap", "wi-fi ap")),
        ("router", ("router", "gateway")),
        ("sector", ("sector", "base station", "basestation", "airmax")),
        ("switch", ("switch",)),
        ("firewall", ("firewall",)),
        ("server", ("server",)),
        ("wireless_bridge", ("wireless bridge", "bridge")),
    ]
    for code, words in keywords:
        if any(word in text for word in words):
            return await db.scalar(
                select(DeviceType.id).where(
                    DeviceType.code.ilike(code),
                    DeviceType.is_active.is_(True),
                )
            )
    return None


def _suggest_name(record) -> str:
    """Generate a deterministic candidate name from an aggregate or observation."""
    hostname = getattr(record, "hostname", None)
    if hostname:
        return hostname
    vendor = (getattr(record, "vendor", None) or "DEVICE").replace(" ", "_")
    model = (getattr(record, "model", None) or "").replace(" ", "_")
    suffix = f"-{model}" if model else ""
    ip_address = str(getattr(record, "ip_address"))
    return f"{vendor}{suffix}-{ip_address.replace('.', '-').replace(':', '-')}"


def _discovery_metadata(aggregate: DiscoveryAggregate) -> dict:
    return {
        "discovery": {
            "reachable": aggregate.reachable,
            "protocol_status": aggregate.protocol_status,
            "field_sources": aggregate.field_sources,
            "evidence": aggregate.evidence,
            "primary_protocol": aggregate.management_protocol,
        }
    }


def _copy_aggregate(candidate: DeviceCandidate, aggregate: DiscoveryAggregate) -> None:
    candidate.discovery_result_id = aggregate.primary_result_id
    candidate.confidence = aggregate.confidence
    candidate.hostname = aggregate.hostname
    candidate.vendor = aggregate.vendor
    candidate.model = aggregate.model
    candidate.serial_number = aggregate.serial_number
    candidate.management_protocol = aggregate.management_protocol
    candidate.display_name_suggestion = _suggest_name(aggregate)
    candidate.metadata_ = {
        **(candidate.metadata_ or {}),
        **_discovery_metadata(aggregate),
    }
