from __future__ import annotations

import asyncio
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from app.remote_gateway.web_template_bootstrap import IdempotentRemoteProtocolRetryClient


class _TestProtocolSession:
    family = "TEST_PROTOCOL"

    def prepare_request(self, request: httpx.Request) -> httpx.Request:
        headers = httpx.Headers(request.headers)
        headers["X-Test-Protocol"] = "prepared"
        return httpx.Request(
            request.method,
            request.url,
            headers=headers,
            content=request.content,
            extensions=dict(request.extensions),
        )

    async def prepare_response(self, request: httpx.Request, response: httpx.Response) -> httpx.Response:
        body = await response.aread()
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            content=body + b"-bridged",
            request=request,
        )


def test_secure_web_client_requests_connection_close():
    async def scenario():
        seen_connection = None

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal seen_connection
            seen_connection = request.headers.get("connection")
            return httpx.Response(200, text="ok", request=request)

        async with IdempotentRemoteProtocolRetryClient(
            base_url="http://192.0.2.30",
            transport=httpx.MockTransport(handler),
            fttw_session_id=uuid4(),
        ) as client:
            response = await client.get("/status")
            assert response.status_code == 200
            assert seen_connection == "close"

    asyncio.run(scenario())


def test_secure_web_client_invokes_generic_protocol_session_hooks():
    async def scenario():
        async def handler(request: httpx.Request) -> httpx.Response:
            assert request.headers.get("X-Test-Protocol") == "prepared"
            return httpx.Response(200, content=b"device", request=request)

        async with IdempotentRemoteProtocolRetryClient(
            base_url="http://192.0.2.30",
            transport=httpx.MockTransport(handler),
            fttw_session_id=uuid4(),
        ) as client:
            client.set_protocol_session(_TestProtocolSession())
            response = await client.post("/cgi", content=b"payload")
            assert response.content == b"device-bridged"

    asyncio.run(scenario())


def test_idempotent_get_retries_one_remote_protocol_disconnect():
    async def scenario():
        attempts = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            assert request.headers.get("connection") == "close"
            if attempts == 1:
                raise httpx.RemoteProtocolError("legacy server disconnected", request=request)
            return httpx.Response(200, text="ok", request=request)

        async with IdempotentRemoteProtocolRetryClient(
            base_url="http://192.0.2.30",
            transport=httpx.MockTransport(handler),
            fttw_session_id=uuid4(),
        ) as client:
            response = await client.get("/status")
            assert response.status_code == 200
            assert response.text == "ok"
            assert attempts == 2

    asyncio.run(scenario())


def test_mutating_post_is_never_retried_after_remote_protocol_error():
    async def scenario():
        attempts = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            assert request.headers.get("connection") == "close"
            raise httpx.RemoteProtocolError("legacy server disconnected", request=request)

        async with IdempotentRemoteProtocolRetryClient(
            base_url="http://192.0.2.30",
            transport=httpx.MockTransport(handler),
            fttw_session_id=uuid4(),
        ) as client:
            with pytest.raises(httpx.RemoteProtocolError):
                await client.post("/apply", content=b"change=1")
            assert attempts == 1

    asyncio.run(scenario())


def test_idempotent_retry_is_bounded_to_one_retry():
    async def scenario():
        attempts = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            raise httpx.RemoteProtocolError("legacy server disconnected", request=request)

        async with IdempotentRemoteProtocolRetryClient(
            base_url="http://192.0.2.30",
            transport=httpx.MockTransport(handler),
            fttw_session_id=uuid4(),
        ) as client:
            with pytest.raises(httpx.RemoteProtocolError):
                await client.get("/status")
            assert attempts == 2

    asyncio.run(scenario())


def test_authenticated_template_bootstrap_precedes_compatibility_proxy_router():
    source = (
        Path(__file__).resolve().parents[1] / "remote_gateway" / "main.py"
    ).read_text(encoding="utf-8")
    authenticated = "app.include_router(web_template_bootstrap_router)"
    compatibility = "app.include_router(web_proxy_router)"
    assert authenticated in source
    assert compatibility in source
    assert source.index(authenticated) < source.index(compatibility)