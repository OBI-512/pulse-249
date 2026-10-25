from .adapters.http import HTTPDiscoveryAdapter, HTTPSDiscoveryAdapter
from .adapters.icmp import ICMPDiscoveryAdapter
from .adapters.snmp import SNMPDiscoveryAdapter
from .adapters.tcp import TCPDiscoveryAdapter
from .base import DiscoveryAdapter


class DiscoveryRegistry:
    def __init__(self):
        self._adapters: dict[str, DiscoveryAdapter] = {}

    def register(self, adapter: DiscoveryAdapter) -> None:
        self._adapters[adapter.method.upper()] = adapter

    def get(self, method: str) -> DiscoveryAdapter | None:
        return self._adapters.get(method.upper())

    def methods(self) -> list[str]:
        return sorted(self._adapters)


def build_default_registry() -> DiscoveryRegistry:
    registry = DiscoveryRegistry()
    registry.register(ICMPDiscoveryAdapter())
    registry.register(HTTPDiscoveryAdapter())
    registry.register(HTTPSDiscoveryAdapter())
    registry.register(SNMPDiscoveryAdapter())
    registry.register(TCPDiscoveryAdapter())
    return registry


registry = build_default_registry()
