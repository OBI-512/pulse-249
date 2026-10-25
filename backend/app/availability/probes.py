from __future__ import annotations

import asyncio

from app.discovery.adapters.icmp import ICMPDiscoveryAdapter
from app.discovery.adapters.snmp import SNMPDiscoveryAdapter
from app.discovery.adapters.tcp import TCPDiscoveryAdapter
from app.discovery.models import DiscoveryContext

from .credentials import AvailabilityCredentialError, resolve_snmp_credential
from .state import ProbeObservation, ProbeOutcome


_ICMP = ICMPDiscoveryAdapter()
_TCP = TCPDiscoveryAdapter()
_SNMP = SNMPDiscoveryAdapter()


async def _single_probe(
    *,
    profile: str,
    ip_address: str,
    timeout_seconds: float,
    tcp_ports: tuple[int, ...],
    credential_reference: str | None,
    credential: dict[str, str] | None = None,
    snmp_port: int = 161,
) -> ProbeObservation:
    normalized = profile.upper()
    if normalized == "ICMP":
        result = await _ICMP.discover(DiscoveryContext(ip_address=ip_address, timeout_seconds=timeout_seconds))
        if result.raw_data.get("probe_available") is False:
            return ProbeObservation(ProbeOutcome.INDETERMINATE, "ICMP_PROBE_UNAVAILABLE", result.response_time_ms)
        return ProbeObservation(
            ProbeOutcome.SUCCESS if result.success else ProbeOutcome.FAILURE,
            "ICMP_REACHABLE" if result.success else "ICMP_NO_RESPONSE",
            result.response_time_ms,
        )

    if normalized == "TCP":
        result = await _TCP.discover(DiscoveryContext(
            ip_address=ip_address,
            timeout_seconds=timeout_seconds,
            metadata={"ports": list(tcp_ports)},
        ))
        return ProbeObservation(
            ProbeOutcome.SUCCESS if result.success else ProbeOutcome.FAILURE,
            "TCP_REACHABLE" if result.success else "TCP_NO_RESPONSE",
            result.response_time_ms,
        )

    if normalized == "SNMP":
        if credential is None:
            try:
                secret = resolve_snmp_credential(credential_reference)
            except AvailabilityCredentialError as exc:
                return ProbeObservation(ProbeOutcome.INDETERMINATE, str(exc))
        else:
            # Managed Access Template credentials are already resolved inside
            # the worker process. They never traverse Celery or get persisted.
            secret = credential
        context = DiscoveryContext(
            ip_address=ip_address,
            timeout_seconds=timeout_seconds,
            credential_reference=credential_reference,
            snmp_version=secret.get("version", "2c"),
            snmp_port=snmp_port,
            snmp_community=secret.get("community"),
            # C1 owns retries uniformly. Net-SNMP is therefore invoked once per
            # C1 attempt instead of multiplying retries at two different layers.
            snmp_retries=0,
            snmp_v3_username=secret.get("username"),
            snmp_v3_security_level=secret.get("security_level", "noAuthNoPriv"),
            snmp_v3_auth_protocol=secret.get("auth_protocol", "SHA"),
            snmp_v3_auth_password=secret.get("auth_password"),
            snmp_v3_priv_protocol=secret.get("priv_protocol", "AES"),
            snmp_v3_priv_password=secret.get("priv_password"),
            snmp_v3_context_name=secret.get("context_name"),
        )
        result = await _SNMP.discover(context)
        if result.success:
            return ProbeObservation(ProbeOutcome.SUCCESS, "SNMP_REACHABLE", result.response_time_ms)
        message = (result.message or "").lower()
        error_code = str(result.raw_data.get("error_code") or "")
        if "authentication failed" in message:
            return ProbeObservation(ProbeOutcome.INDETERMINATE, "SNMP_AUTHENTICATION_FAILED", result.response_time_ms)
        if error_code == "SNMP_CLIENT_NOT_INSTALLED":
            return ProbeObservation(ProbeOutcome.INDETERMINATE, "SNMP_CLIENT_NOT_INSTALLED", result.response_time_ms)
        if "required" in message or "unsupported" in message:
            return ProbeObservation(ProbeOutcome.INDETERMINATE, "SNMP_CONFIGURATION_INVALID", result.response_time_ms)
        if "timed out" in message or "no response" in message:
            return ProbeObservation(ProbeOutcome.FAILURE, "SNMP_NO_RESPONSE", result.response_time_ms)
        return ProbeObservation(ProbeOutcome.INDETERMINATE, "SNMP_PROBE_ERROR", result.response_time_ms)

    return ProbeObservation(ProbeOutcome.INDETERMINATE, "AVAILABILITY_PROFILE_UNSUPPORTED")


async def probe_availability(
    *,
    profile: str,
    ip_address: str | None,
    timeout_seconds: float,
    retries: int,
    tcp_ports: tuple[int, ...],
    credential_reference: str | None,
    credential: dict[str, str] | None = None,
    snmp_port: int = 161,
) -> ProbeObservation:
    if not ip_address:
        return ProbeObservation(ProbeOutcome.INDETERMINATE, "NO_MANAGEMENT_IP")

    last = ProbeObservation(ProbeOutcome.INDETERMINATE, "PROBE_NOT_EXECUTED")
    for attempt in range(max(0, int(retries)) + 1):
        try:
            last = await _single_probe(
                profile=profile,
                ip_address=ip_address,
                timeout_seconds=timeout_seconds,
                tcp_ports=tcp_ports,
                credential_reference=credential_reference,
                credential=credential,
                snmp_port=snmp_port,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            # Never propagate raw probe exceptions into audit/log/queue payloads.
            last = ProbeObservation(ProbeOutcome.INDETERMINATE, "PROBE_EXECUTION_ERROR")
        if last.outcome is ProbeOutcome.SUCCESS:
            return last
        if last.outcome is ProbeOutcome.INDETERMINATE:
            return last
        if attempt < retries:
            await asyncio.sleep(0)
    return last
