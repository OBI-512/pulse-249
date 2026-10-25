import asyncio
import socket
import time

from ..base import DiscoveryAdapter
from ..models import DiscoveryContext, DiscoveryResult


class TCPDiscoveryAdapter(DiscoveryAdapter):
    name = "TCP"
    method = "TCP"

    async def discover(self, context: DiscoveryContext) -> DiscoveryResult:
        ports = context.metadata.get("ports", [80, 443, 22])
        results = []
        started = time.perf_counter()

        async def probe(port: int):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(context.ip_address, port),
                    timeout=context.timeout_seconds,
                )
                writer.close()
                if hasattr(writer, "wait_closed"):
                    await writer.wait_closed()
                return {"port": port, "open": True}
            except Exception:
                return {"port": port, "open": False}

        results = await asyncio.gather(*(probe(int(p)) for p in ports))
        open_ports = [item["port"] for item in results if item["open"]]
        elapsed = round((time.perf_counter() - started) * 1000, 2)

        return DiscoveryResult(
            success=bool(open_ports),
            method=self.method,
            ip_address=context.ip_address,
            management_protocol="TCP",
            response_time_ms=elapsed,
            message=(
                f"Open TCP ports detected: {', '.join(map(str, open_ports))}."
                if open_ports else
                "No configured TCP ports responded."
            ),
            raw_data={
                "ports_checked": [int(p) for p in ports],
                "open_ports": open_ports,
            },
        )
