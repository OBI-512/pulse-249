from abc import ABC, abstractmethod

from .models import DiscoveryContext, DiscoveryResult


class DiscoveryAdapter(ABC):
    name: str
    method: str

    @abstractmethod
    async def discover(self, context: DiscoveryContext) -> DiscoveryResult:
        raise NotImplementedError
