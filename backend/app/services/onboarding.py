import asyncio
import platform
import subprocess
import time
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address


@dataclass
class ProbeResult:
    ip_address: str
    reachable: bool
    response_time_ms: float | None
    protocol: str | None
    message: str | None


async def probe_icmp(address: str, timeout_seconds: float = 2.0) -> ProbeResult:
    """Perform a conservative OS-level ping.

    This is deliberately limited to a single supplied address. It does not
    perform subnet scanning or port scanning.
    """
    parsed = ip_address(address)
    if isinstance(parsed, IPv4Address):
        command = ["ping", "-c", "1", "-W", str(max(1, int(timeout_seconds))), address]
    else:
        command = ["ping6", "-c", "1", "-W", str(max(1, int(timeout_seconds))), address]

    if platform.system().lower().startswith("win"):
        command = ["ping", "-n", "1", "-w", str(int(timeout_seconds * 1000)), address]

    started = time.perf_counter()
    try:
        proc = await asyncio.to_thread(
            subprocess.run,
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds + 1,
        )
        elapsed = round((time.perf_counter() - started) * 1000, 2)
        if proc.returncode == 0:
            return ProbeResult(address, True, elapsed, "ICMP", "Device responded to ICMP.")
        return ProbeResult(address, False, elapsed, "ICMP", "No ICMP response.")
    except subprocess.TimeoutExpired:
        return ProbeResult(address, False, None, "ICMP", "Probe timed out.")
    except Exception as exc:
        return ProbeResult(address, False, None, "ICMP", f"Probe failed: {exc}")


def normalize_ip(value: str) -> str:
    return str(ip_address(value))


def build_display_name(
    device_type_code: str,
    ip: str,
    vendor: str | None = None,
    model: str | None = None,
) -> str:
    """Create a deterministic provisional name.

    Final naming conventions can later be replaced by an FTTW hierarchy-aware
    naming policy without changing the onboarding API.
    """
    parts = [device_type_code.upper(), ip.replace(":", "-").replace(".", "-")]
    if vendor:
        parts.append(vendor.strip().upper().replace(" ", "_"))
    if model:
        parts.append(model.strip().upper().replace(" ", "_"))
    return "-".join(parts)
