from __future__ import annotations

from typing import Protocol

import httpx


class WebProtocolSessionError(httpx.ProtocolError):
    """Fail-closed error raised by a post-auth Web protocol session adapter."""


class WebProtocolSession(Protocol):
    """Optional post-authentication protocol bridge for embedded Web GUIs.

    Some device families keep cryptographic/session state in the browser after
    login and use it for subsequent API calls. FTTW authenticates server-side,
    so an adapter may retain that ephemeral protocol state inside the gateway,
    transform exact-origin requests, and bootstrap only the minimum non-password
    session material required by the isolated proxied browser.
    """

    family: str

    def prepare_request(self, request: httpx.Request) -> httpx.Request:
        """Return the upstream request that should be sent to the device."""

    async def prepare_response(
        self,
        request: httpx.Request,
        response: httpx.Response,
    ) -> httpx.Response:
        """Return the device response that should continue through the proxy."""
