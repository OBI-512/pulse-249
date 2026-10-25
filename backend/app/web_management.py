from __future__ import annotations

from ipaddress import ip_address


DEFAULT_WEB_PORTS = {"HTTP": 80, "HTTPS": 443}


def normalize_web_scheme(scheme: str) -> str:
    normalized = scheme.strip().upper()
    if normalized not in DEFAULT_WEB_PORTS:
        raise ValueError("Web management scheme must be HTTP or HTTPS.")
    return normalized


def effective_web_port(scheme: str, configured_port: int | None) -> int:
    normalized = normalize_web_scheme(scheme)
    if configured_port is None:
        return DEFAULT_WEB_PORTS[normalized]
    if not isinstance(configured_port, int) or isinstance(configured_port, bool) or not 1 <= configured_port <= 65535:
        raise ValueError("Web management port must be between 1 and 65535.")
    return configured_port


def web_management_url(scheme: str, host: str, configured_port: int | None = None) -> str:
    normalized = normalize_web_scheme(scheme)
    port = effective_web_port(normalized, configured_port)
    raw_host = host.strip()
    try:
        parsed = ip_address(raw_host.strip("[]"))
        authority_host = f"[{parsed}]" if parsed.version == 6 else str(parsed)
    except ValueError:
        authority_host = raw_host
    suffix = "" if port == DEFAULT_WEB_PORTS[normalized] else f":{port}"
    return f"{normalized.lower()}://{authority_host}{suffix}"
