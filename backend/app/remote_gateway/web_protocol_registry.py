from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable

import httpx

from .web_protocol_session import WebProtocolSession


class WebProtocolAdapterError(RuntimeError):
    """Normalized failure from a registered embedded-Web protocol adapter."""


@dataclass(frozen=True)
class WebProtocolAdapterResult:
    landing_path: str
    protocol_session: WebProtocolSession


@dataclass(frozen=True)
class WebProtocolAdapter:
    """Vendor-neutral registration contract for proprietary Web protocol families."""

    family: str
    credential_modes: frozenset[str]
    matches: Callable[[str], bool]
    authenticate: Callable[[httpx.AsyncClient, str], Awaitable[WebProtocolAdapterResult]]


_REGISTRY: list[WebProtocolAdapter] = []
_BUILTINS_LOADED = False


def register_web_protocol_adapter(adapter: WebProtocolAdapter) -> None:
    family = adapter.family.strip().upper()
    if not family:
        raise ValueError("WEB_PROTOCOL_ADAPTER_FAMILY_REQUIRED")
    if any(existing.family.upper() == family for existing in _REGISTRY):
        raise ValueError("WEB_PROTOCOL_ADAPTER_FAMILY_DUPLICATE")
    _REGISTRY.append(adapter)


def _ensure_builtin_adapters() -> None:
    """Load built-in adapters at the composition boundary, not in generic auth."""

    global _BUILTINS_LOADED
    if _BUILTINS_LOADED:
        return

    # Imports are intentionally local. The generic Web authentication/proxy
    # layers depend only on this registry contract and never on vendor modules.
    from .tp_link_mr_web_auth import (
        TP_LINK_MR_AUTH_FAMILY,
        TPLinkMRWebAuthenticationError,
        authenticate_tp_link_mr_rsa_aes_session,
        looks_like_tp_link_mr_rsa_aes,
    )

    async def authenticate_tp_link_mr(client: httpx.AsyncClient, password: str) -> WebProtocolAdapterResult:
        try:
            result = await authenticate_tp_link_mr_rsa_aes_session(client, password=password)
        except TPLinkMRWebAuthenticationError as exc:
            raise WebProtocolAdapterError(str(exc)) from exc
        return WebProtocolAdapterResult(
            landing_path=result.landing_path,
            protocol_session=result.protocol_session,
        )

    register_web_protocol_adapter(
        WebProtocolAdapter(
            family=TP_LINK_MR_AUTH_FAMILY,
            credential_modes=frozenset({"PASSWORD_ONLY"}),
            matches=looks_like_tp_link_mr_rsa_aes,
            authenticate=authenticate_tp_link_mr,
        )
    )
    _BUILTINS_LOADED = True


def registered_web_protocol_families() -> tuple[str, ...]:
    _ensure_builtin_adapters()
    return tuple(adapter.family for adapter in _REGISTRY)


async def authenticate_registered_web_protocol(
    client: httpx.AsyncClient,
    *,
    credential_mode: str,
    login_page_text: str,
    password: str,
) -> WebProtocolAdapterResult | None:
    """Dispatch to the first matching registered protocol family.

    Matching is based on the observed browser/wire protocol, not device model,
    vendor inventory metadata, management address, serial number, or UUID.
    Returning ``None`` preserves the generic HTML-form authentication fallback.
    """

    _ensure_builtin_adapters()
    normalized_mode = credential_mode.strip().upper()
    page = login_page_text[:2_000_000]
    for adapter in _REGISTRY:
        if normalized_mode not in adapter.credential_modes:
            continue
        try:
            matched = adapter.matches(page)
        except Exception:
            matched = False
        if not matched:
            continue
        return await adapter.authenticate(client, password)
    return None
