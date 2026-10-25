from __future__ import annotations

import asyncio
from pathlib import Path
from uuid import uuid4

import httpx

from app.remote_gateway.web_auth import (
    WebInitialResponse,
    authenticate_web_client_with_session,
)
from app.remote_gateway.web_proxy import _validated_opener_origin
from app.remote_gateway.web_template_bootstrap import (
    IdempotentRemoteProtocolRetryClient,
)
from app.services.access_template_runtime import WebRuntimeAccess


def test_cookie_less_form_login_preserves_successful_post_response():
    async def scenario():
        requests: list[tuple[str, str]] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            requests.append((request.method, request.url.path))

            if request.method == "GET" and request.url.path == "/":
                return httpx.Response(
                    200,
                    text=(
                        '<form method="post" action="">'
                        '<input type="hidden" name="hdnAction" value="">'
                        '<input type="text" name="inpLogUser">'
                        '<input type="password" name="inpLogPass">'
                        "</form>"
                    ),
                    request=request,
                )

            if request.method == "POST" and request.url.path == "/":
                body = request.content.decode("utf-8")

                assert "hdnAction=" in body
                assert "inpLogUser=TESTUSER" in body
                assert "inpLogPass=TESTPASS" in body

                return httpx.Response(
                    200,
                    headers={"Content-Type": "text/html"},
                    content=(
                        b'<html><input type="hidden" '
                        b'id="hdnSession" value="opaque"></html>'
                    ),
                    request=request,
                )

            return httpx.Response(404, request=request)

        runtime = WebRuntimeAccess(
            auth_mode="FORM_POST",
            credential_mode="USERNAME_PASSWORD",
            username="TESTUSER",
            password="TESTPASS",
            login_page_path="/",
            login_submit_path="/",
            username_field="inpLogUser",
            password_field="inpLogPass",
            capture_hidden_fields=True,
            success_text="hdnSession",
        )

        async with httpx.AsyncClient(
            base_url="http://192.0.2.35",
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
        ) as client:
            result = await authenticate_web_client_with_session(
                client,
                runtime,
            )

        assert result.landing_path == "/"
        assert result.initial_response is not None
        assert result.initial_response.status_code == 200
        assert b"hdnSession" in result.initial_response.content
        assert b"TESTPASS" not in result.initial_response.content
        assert "TESTPASS" not in repr(result)

        assert all(
            key.lower() not in {"set-cookie", "set-cookie2"}
            for key, _value in result.initial_response.headers
        )

        assert requests == [
            ("GET", "/"),
            ("POST", "/"),
        ]

    asyncio.run(scenario())


def test_cookie_backed_form_login_keeps_existing_get_behavior():
    async def scenario():
        async def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET" and request.url.path == "/login":
                return httpx.Response(
                    200,
                    text=(
                        '<form action="/session" method="post">'
                        '<input type="text" name="user">'
                        '<input type="password" name="pass">'
                        "</form>"
                    ),
                    request=request,
                )

            if request.method == "POST" and request.url.path == "/session":
                return httpx.Response(
                    302,
                    headers={
                        "Location": "/dashboard",
                        "Set-Cookie": "device_session=ok; Path=/",
                    },
                    request=request,
                )

            if request.method == "GET" and request.url.path == "/dashboard":
                return httpx.Response(
                    200,
                    text="Authenticated dashboard",
                    request=request,
                )

            return httpx.Response(404, request=request)

        runtime = WebRuntimeAccess(
            auth_mode="FORM_POST",
            credential_mode="USERNAME_PASSWORD",
            username="TESTUSER",
            password="TESTPASS",
            login_page_path="/login",
            login_submit_path="/session",
            username_field="user",
            password_field="pass",
            success_path_prefix="/dashboard",
            capture_hidden_fields=True,
        )

        async with httpx.AsyncClient(
            base_url="https://192.0.2.20",
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
        ) as client:
            result = await authenticate_web_client_with_session(
                client,
                runtime,
            )

            assert client.cookies.get("device_session") == "ok"

        assert result.landing_path == "/dashboard"
        assert result.initial_response is None

    asyncio.run(scenario())


def test_reflected_password_disables_response_local_handoff():
    async def scenario():
        async def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(
                    200,
                    text=(
                        '<form method="post">'
                        '<input type="text" name="user">'
                        '<input type="password" name="pass">'
                        "</form>"
                    ),
                    request=request,
                )

            return httpx.Response(
                200,
                text="authenticated TESTPASS",
                request=request,
            )

        runtime = WebRuntimeAccess(
            auth_mode="FORM_POST",
            credential_mode="USERNAME_PASSWORD",
            username="TESTUSER",
            password="TESTPASS",
            login_page_path="/",
            login_submit_path="/",
            username_field="user",
            password_field="pass",
            success_text="authenticated",
        )

        async with httpx.AsyncClient(
            base_url="http://192.0.2.40",
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
        ) as client:
            result = await authenticate_web_client_with_session(
                client,
                runtime,
            )

        assert result.landing_path == "/"
        assert result.initial_response is None

    asyncio.run(scenario())


def test_initial_response_is_consumed_once_before_fresh_get():
    async def scenario():
        upstream_gets = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal upstream_gets
            upstream_gets += 1

            return httpx.Response(
                200,
                text="LOGIN PAGE",
                request=request,
            )

        snapshot = WebInitialResponse(
            status_code=200,
            headers=(("content-type", "text/html"),),
            content=b"AUTHENTICATED POST RESPONSE",
        )

        async with IdempotentRemoteProtocolRetryClient(
            base_url="http://192.0.2.35",
            transport=httpx.MockTransport(handler),
            fttw_session_id=uuid4(),
        ) as client:
            client.set_initial_response("/", snapshot)

            first = await client.get("/")

            assert first.content == b"AUTHENTICATED POST RESPONSE"
            assert upstream_gets == 0

            second = await client.get("/")

            assert second.text == "LOGIN PAGE"
            assert upstream_gets == 1

    asyncio.run(scenario())


def test_opener_origin_is_exact_and_rejects_cross_allowed_mismatch():
    allowed = {
        "http://localhost:3000",
        "http://localhost:8080",
    }

    assert (
        _validated_opener_origin(
            "http://localhost:3000",
            "http://localhost:3000/access-templates",
            allowed,
        )
        == "http://localhost:3000"
    )

    assert (
        _validated_opener_origin(
            "http://localhost:8080",
            "http://localhost:3000/access-templates",
            allowed,
        )
        is None
    )

    assert (
        _validated_opener_origin(
            "",
            "http://localhost:3000/access-templates",
            allowed,
        )
        == "http://localhost:3000"
    )

    assert (
        _validated_opener_origin(
            "https://attacker.invalid",
            None,
            allowed,
        )
        is None
    )


def test_gateway_launch_no_longer_broadcasts_ready_to_all_origins():
    source = (
        Path(__file__).resolve().parents[1]
        / "remote_gateway"
        / "web_proxy.py"
    ).read_text(encoding="utf-8")

    assert "for(const origin of allowed)" not in source
    assert "openerOrigin" in source
    assert "event.origin!==openerOrigin" in source
