import asyncio
import platform
import shutil
import subprocess
import time

from ..base import DiscoveryAdapter
from ..models import DiscoveryContext, DiscoveryResult


class ICMPDiscoveryAdapter(DiscoveryAdapter):
    name = "ICMP"
    method = "ICMP"

    async def discover(self, context: DiscoveryContext) -> DiscoveryResult:
        ping_binary = shutil.which("ping")
        if not ping_binary:
            return DiscoveryResult(
                success=False,
                method=self.method,
                ip_address=context.ip_address,
                management_protocol="ICMP",
                message="ICMP probe unavailable: ping utility is not installed in the backend container.",
                raw_data={"probe_available": False},
            )

        if platform.system().lower().startswith("win"):
            command = [
                ping_binary, "-n", "1",
                "-w", str(int(context.timeout_seconds * 1000)),
                context.ip_address,
            ]
        else:
            command = [
                ping_binary, "-c", "1",
                "-W", str(max(1, int(context.timeout_seconds))),
                context.ip_address,
            ]

        started = time.perf_counter()
        try:
            proc = await asyncio.to_thread(
                subprocess.run,
                command,
                capture_output=True,
                text=True,
                timeout=context.timeout_seconds + 1,
            )
            elapsed = round((time.perf_counter() - started) * 1000, 2)
            if proc.returncode == 0:
                return DiscoveryResult(
                    success=True,
                    method=self.method,
                    ip_address=context.ip_address,
                    management_protocol="ICMP",
                    response_time_ms=elapsed,
                    message="ICMP response received.",
                    raw_data={"probe_available": True},
                )
            return DiscoveryResult(
                success=False,
                method=self.method,
                ip_address=context.ip_address,
                management_protocol="ICMP",
                response_time_ms=elapsed,
                message="No ICMP response.",
                raw_data={"probe_available": True},
            )
        except subprocess.TimeoutExpired:
            return DiscoveryResult(
                success=False,
                method=self.method,
                ip_address=context.ip_address,
                management_protocol="ICMP",
                message="ICMP probe timed out.",
                raw_data={"probe_available": True},
            )
        except Exception as exc:
            return DiscoveryResult(
                success=False,
                method=self.method,
                ip_address=context.ip_address,
                management_protocol="ICMP",
                message=f"ICMP probe failed: {exc}",
                raw_data={"probe_available": True},
            )
