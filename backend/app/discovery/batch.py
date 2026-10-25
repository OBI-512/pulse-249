from dataclasses import dataclass
from ipaddress import ip_address, ip_network


@dataclass(frozen=True)
class DiscoveryTarget:
    ip_address: str


def expand_targets(
    ip_addresses: list[str] | None = None,
    cidrs: list[str] | None = None,
    max_targets: int = 10000,
) -> list[DiscoveryTarget]:
    """Expand explicit IPs and CIDRs into unique discovery targets.

    This is deliberately bounded. Large discovery operations should be
    chunked into multiple jobs rather than creating an unbounded task.
    """
    addresses: set[str] = set()

    for value in ip_addresses or []:
        addresses.add(str(ip_address(value)))

    for cidr in cidrs or []:
        network = ip_network(cidr, strict=False)
        for address in network.hosts():
            addresses.add(str(address))
            if len(addresses) > max_targets:
                raise ValueError(
                    f"Discovery target count exceeds configured limit of {max_targets}."
                )

    if len(addresses) > max_targets:
        raise ValueError(
            f"Discovery target count exceeds configured limit of {max_targets}."
        )

    return [DiscoveryTarget(x) for x in sorted(addresses, key=_ip_sort_key)]


def _ip_sort_key(value: str):
    parsed = ip_address(value)
    return parsed.version, int(parsed)
