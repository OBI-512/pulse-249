from __future__ import annotations

import asyncio
from dataclasses import dataclass
import re
import shutil
import subprocess
import time
from typing import Any

from app.availability.credentials import AvailabilityCredentialError, resolve_snmp_credential
from app.discovery.adapters.snmp import SNMPConfigurationError, _build_command
from app.discovery.models import DiscoveryContext


_OID_RE = re.compile(r"^\.?\d+(?:\.\d+)+$")
_TIMETICKS_RE = re.compile(r"\bTimeticks:\s*(?:\((\d+)\)|(\d+))", re.IGNORECASE)
_TIMETICKS_DAYS_RE = re.compile(r"^(\d+)\s+days?,\s*(\d+):(\d{2}):(\d{2}(?:\.\d+)?)$", re.IGNORECASE)
_TIMETICKS_COLON_RE = re.compile(r"^(?:(\d+):)?(\d+):(\d{2}):(\d{2}(?:\.\d+)?)$")
_BARE_NUMBER_RE = re.compile(r"^[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?$")
_NUMBER_RE = re.compile(r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?")


class TelemetryCollectionError(RuntimeError):
    def __init__(self, code: str, message: str | None = None):
        self.code = code
        super().__init__(message or code)


@dataclass(frozen=True)
class CollectedMetric:
    key: str
    kind: str
    numeric_value: float | None
    text_value: str | None
    unit: str | None
    vendor_key: str | None
    oid: str


def normalize_metric_value(raw: str, transform: str) -> tuple[float | None, str | None]:
    """Normalize one SNMP scalar while preserving unparseable vendor text.

    The function is deliberately pure so emulator/fixture tests can establish
    correctness independently of network access and Celery.
    """

    text_value = raw.strip().strip('"')
    transform = (transform or "raw").strip().lower()
    if transform == "raw":
        return None, text_value
    if transform == "timeticks_seconds":
        match = _TIMETICKS_RE.search(text_value)
        if match:
            ticks = float(match.group(1) or match.group(2))
            return ticks / 100.0, None

        if _BARE_NUMBER_RE.fullmatch(text_value):
            return float(text_value) / 100.0, None

        days_match = _TIMETICKS_DAYS_RE.fullmatch(text_value)
        if days_match:
            days, hours, minutes, seconds = days_match.groups()
            total_seconds = (
                int(days) * 86400
                + int(hours) * 3600
                + int(minutes) * 60
                + float(seconds)
            )
            return total_seconds, None

        colon_match = _TIMETICKS_COLON_RE.fullmatch(text_value)
        if colon_match:
            days, hours, minutes, seconds = colon_match.groups()
            total_seconds = (
                int(days or 0) * 86400
                + int(hours) * 3600
                + int(minutes) * 60
                + float(seconds)
            )
            return total_seconds, None

        raise TelemetryCollectionError("TELEMETRY_VALUE_INVALID_TIMETICKS")
    match = _NUMBER_RE.search(text_value)
    if not match:
        raise TelemetryCollectionError("TELEMETRY_VALUE_NOT_NUMERIC")
    number = float(match.group(0))
    if transform == "int":
        number = float(int(number))
    elif transform != "float":
        raise TelemetryCollectionError("TELEMETRY_TRANSFORM_UNSUPPORTED")
    return number, None


def _context_from_credential(
    *,
    ip_address: str,
    credential_reference: str | None,
    timeout_seconds: int,
    retries: int,
    credential: dict[str, str] | None = None,
    port: int = 161,
) -> DiscoveryContext:
    if credential is None:
        try:
            resolved = resolve_snmp_credential(credential_reference)
        except AvailabilityCredentialError as exc:
            raise TelemetryCollectionError(str(exc)) from exc
    else:
        # Managed Access Template secrets are resolved inside the worker and
        # passed only in memory. They are never serialized to the task broker.
        resolved = dict(credential)
    return DiscoveryContext(
        ip_address=ip_address,
        timeout_seconds=float(timeout_seconds),
        snmp_retries=int(retries),
        snmp_port=int(port),
        snmp_version=resolved.get("version", "2c"),
        snmp_community=resolved.get("community"),
        snmp_v3_username=resolved.get("username"),
        snmp_v3_security_level=resolved.get("security_level", "noAuthNoPriv"),
        snmp_v3_auth_protocol=resolved.get("auth_protocol"),
        snmp_v3_auth_password=resolved.get("auth_password"),
        snmp_v3_priv_protocol=resolved.get("priv_protocol"),
        snmp_v3_priv_password=resolved.get("priv_password"),
        snmp_v3_context_name=resolved.get("context_name"),
    )


def _metric_definitions(definitions: list[dict[str, Any]], max_metrics: int) -> list[dict[str, Any]]:
    if not isinstance(definitions, list) or not definitions:
        raise TelemetryCollectionError("TELEMETRY_PROFILE_NO_METRICS")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in definitions[: max(1, min(64, int(max_metrics)))]:
        if not isinstance(item, dict):
            raise TelemetryCollectionError("TELEMETRY_PROFILE_INVALID_METRIC")
        key = str(item.get("key") or "").strip()
        oid = str(item.get("oid") or "").strip().lstrip(".")
        if not key or len(key) > 160 or key in seen or not _OID_RE.fullmatch(oid):
            raise TelemetryCollectionError("TELEMETRY_PROFILE_INVALID_METRIC")
        seen.add(key)
        result.append({
            "key": key,
            "oid": oid,
            "unit": (str(item.get("unit")).strip()[:60] if item.get("unit") is not None else None),
            "kind": str(item.get("kind") or "GAUGE").upper(),
            "transform": str(item.get("transform") or "float").lower(),
            "vendor_key": (str(item.get("vendor_key")).strip()[:180] if item.get("vendor_key") else None),
        })
    return result


def validate_metric_definitions(definitions: list[dict[str, Any]], *, max_metrics: int = 64) -> list[dict[str, Any]]:
    """Validate a profile without performing network I/O."""
    return _metric_definitions(definitions, max_metrics)


def _run_snmpget_many(context: DiscoveryContext, metric_definitions: list[dict[str, Any]]) -> tuple[list[str], float]:
    # Reuse the already validated discovery command builder so v1/v2c/v3
    # credential semantics remain identical. Replace its final sysName OID with
    # the profile OID vector; argv is never logged.
    if not shutil.which("snmpget"):
        raise TelemetryCollectionError("SNMP_CLIENT_NOT_INSTALLED")
    try:
        command, _version = _build_command(context)
    except SNMPConfigurationError as exc:
        raise TelemetryCollectionError("SNMP_CONFIGURATION_INVALID", str(exc)) from exc
    command = command[:-1] + [item["oid"] for item in metric_definitions]
    started = time.perf_counter()
    outer_timeout = max(3.0, float(context.timeout_seconds) * (int(context.snmp_retries) + 1) + 3.0)
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=outer_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TelemetryCollectionError("SNMP_EXECUTION_TIMEOUT") from exc
    duration_ms = (time.perf_counter() - started) * 1000.0
    if completed.returncode != 0:
        stderr = (completed.stderr or "").lower()
        if "timeout" in stderr or "no response" in stderr:
            raise TelemetryCollectionError("SNMP_NO_RESPONSE")
        if "authentication failure" in stderr or "unknown user" in stderr:
            raise TelemetryCollectionError("SNMP_AUTHENTICATION_FAILED")
        raise TelemetryCollectionError("SNMP_PROBE_FAILED")
    lines = [line.strip() for line in (completed.stdout or "").splitlines() if line.strip()]
    if len(lines) != len(metric_definitions):
        raise TelemetryCollectionError("SNMP_RESPONSE_CARDINALITY_MISMATCH")
    return lines, duration_ms


async def collect_snmp_metrics(
    *,
    ip_address: str,
    credential_reference: str | None,
    timeout_seconds: int,
    retries: int,
    metric_definitions: list[dict[str, Any]],
    max_metrics: int,
    credential: dict[str, str] | None = None,
    port: int = 161,
) -> tuple[list[CollectedMetric], float]:
    definitions = _metric_definitions(metric_definitions, max_metrics)
    context = _context_from_credential(
        ip_address=ip_address,
        credential_reference=credential_reference,
        timeout_seconds=timeout_seconds,
        retries=retries,
        credential=credential,
        port=port,
    )
    lines, duration_ms = await asyncio.to_thread(_run_snmpget_many, context, definitions)
    metrics: list[CollectedMetric] = []
    for definition, raw in zip(definitions, lines, strict=True):
        try:
            numeric, text = normalize_metric_value(raw, definition["transform"])
        except TelemetryCollectionError:
            numeric, text = None, raw.strip()[:4000]
        metrics.append(CollectedMetric(
            key=definition["key"],
            kind=definition["kind"] if definition["kind"] in {"GAUGE", "COUNTER", "STATE"} else "GAUGE",
            numeric_value=numeric,
            text_value=text,
            unit=definition["unit"],
            vendor_key=definition["vendor_key"],
            oid=definition["oid"],
        ))
    return metrics, duration_ms
