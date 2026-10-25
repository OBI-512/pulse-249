import asyncio
from types import SimpleNamespace

import httpx
import pytest

from app.core.exceptions import APIError
from app.remote_gateway.web_auth import (
    WebAuthenticationError,
    authenticate_web_client,
    httpx_auth_for_web,
)
from app.remote_gateway.web_proxy import _BROWSER_RESPONSE_DROP
from app.services.access_template_runtime import WebRuntimeAccess, build_web_runtime_access
from app.services.access_templates import validate_template_definition


def test_web_template_validation_keeps_transport_device_specific():
    protocol, variant, settings = validate_template_definition(
        protocol="WEB",
        protocol_variant="FORM_POST",
        template_settings={
            "port": 8443,
            "timeout_seconds": 7,
            "login_page_path": "/login",
            "login_submit_path": "/session",
            "username_field": "user",
            "password_field": "pass",
            "success_path_prefix": "/dashboard",
            "capture_hidden_fields": True,
        },
        secret_keys={"username", "password"},
        is_active=True,
    )
    assert protocol == "WEB"
    assert variant == "FORM_POST"
    assert "port" not in settings
    assert settings["login_page_path"] == "/login"
    assert settings["login_submit_path"] == "/session"
    assert settings["credential_mode"] == "USERNAME_PASSWORD"


def test_web_template_requires_credentials_when_authentication_is_enabled():
    with pytest.raises(APIError) as exc:
        validate_template_definition(
            protocol="WEB",
            protocol_variant="HTTP_BASIC",
            template_settings={},
            secret_keys=set(),
            is_active=True,
        )
    assert exc.value.detail["code"] == "ACCESS_TEMPLATE_INCOMPLETE"


def test_password_only_form_requires_only_password_and_drops_username_field_metadata():
    protocol, variant, settings = validate_template_definition(
        protocol="WEB",
        protocol_variant="FORM_POST",
        template_settings={
            "credential_mode": "PASSWORD_ONLY",
            "login_page_path": "/login",
            "login_submit_path": "/login",
            "username_field": "must_not_be_used",
            "password_field": "passcode",
        },
        secret_keys={"password"},
        is_active=True,
    )
    assert protocol == "WEB"
    assert variant == "FORM_POST"
    assert settings["credential_mode"] == "PASSWORD_ONLY"
    assert settings["password_field"] == "passcode"
    assert "username_field" not in settings


def test_password_only_form_still_requires_password():
    with pytest.raises(APIError) as exc:
        validate_template_definition(
            protocol="WEB",
            protocol_variant="FORM_POST",
            template_settings={"credential_mode": "PASSWORD_ONLY"},
            secret_keys=set(),
            is_active=True,
        )
    assert exc.value.detail["code"] == "ACCESS_TEMPLATE_INCOMPLETE"


def test_nested_secret_looking_web_settings_are_rejected():
    with pytest.raises(APIError) as exc:
        validate_template_definition(
            protocol="WEB",
            protocol_variant="FORM_POST",
            template_settings={"vendor": {"password_value": "must-not-live-here"}},
            secret_keys={"username", "password"},
            is_active=True,
        )
    assert exc.value.detail["code"] == "ACCESS_TEMPLATE_SECRET_IN_SETTINGS"


def test_web_runtime_repr_does_not_disclose_credentials():
    template = SimpleNamespace(
        protocol_variant="FORM_POST",
        settings_json={"login_page_path": "/login", "login_submit_path": "/session"},
    )
    runtime = build_web_runtime_access(
        template,
        {"username": "TEST-WEB-USER", "password": "TEST-WEB-PASSWORD"},
    )
    text = repr(runtime)
    assert "TEST-WEB-USER" not in text
    assert "TEST-WEB-PASSWORD" not in text


def test_password_only_runtime_does_not_require_or_disclose_username():
    template = SimpleNamespace(
        protocol_variant="FORM_POST",
        settings_json={
            "credential_mode": "PASSWORD_ONLY",
            "login_page_path": "/login",
            "login_submit_path": "/session",
            "password_field": "passcode",
        },
    )
    runtime = build_web_runtime_access(template, {"password": "ONLY-PASSWORD"})
    assert runtime.credential_mode == "PASSWORD_ONLY"
    assert runtime.username is None
    assert "ONLY-PASSWORD" not in repr(runtime)


def test_form_authentication_keeps_cookie_gateway_side_and_returns_authenticated_landing_path():
    async def scenario():
        async def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET" and request.url.path == "/login":
                return httpx.Response(
                    200,
                    text=(
                        '<form action="/session" method="post">'
                        '<input type="hidden" name="csrf" value="TOKEN123">'
                        '<input type="text" name="user">'
                        '<input type="password" name="pass">'
                        '</form>'
                    ),
                    request=request,
                )
            if request.method == "POST" and request.url.path == "/session":
                body = request.content.decode("utf-8")
                assert "csrf=TOKEN123" in body
                assert "user=TESTUSER" in body
                assert "pass=TESTPASS" in body
                return httpx.Response(
                    302,
                    headers={"Location": "/dashboard?from=login", "Set-Cookie": "device_session=abc; Path=/; HttpOnly"},
                    request=request,
                )
            if request.method == "GET" and request.url.path == "/dashboard":
                return httpx.Response(200, text="Authenticated dashboard", request=request)
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
            landing_path = await authenticate_web_client(client, runtime)
            assert landing_path == "/dashboard?from=login"
            assert client.cookies.get("device_session") == "abc"

    asyncio.run(scenario())


def test_password_only_form_submits_no_username_field():
    async def scenario():
        async def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET" and request.url.path == "/login":
                return httpx.Response(
                    200,
                    text=(
                        '<form action="/unlock" method="post">'
                        '<input type="hidden" name="csrf" value="TOKEN123">'
                        '<input type="password" name="passcode">'
                        '</form>'
                    ),
                    request=request,
                )
            if request.method == "POST" and request.url.path == "/unlock":
                body = request.content.decode("utf-8")
                assert "csrf=TOKEN123" in body
                assert "passcode=ONLYPASS" in body
                assert "username" not in body
                assert "user=" not in body
                return httpx.Response(
                    302,
                    headers={"Location": "/home", "Set-Cookie": "device_session=ok; Path=/"},
                    request=request,
                )
            if request.method == "GET" and request.url.path == "/home":
                return httpx.Response(200, text="authenticated", request=request)
            return httpx.Response(404, request=request)

        runtime = WebRuntimeAccess(
            auth_mode="FORM_POST",
            credential_mode="PASSWORD_ONLY",
            password="ONLYPASS",
            login_page_path="/login",
            login_submit_path="/unlock",
            password_field="passcode",
            success_path_prefix="/home",
        )
        async with httpx.AsyncClient(
            base_url="http://192.0.2.20",
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
        ) as client:
            assert await authenticate_web_client(client, runtime) == "/home"

    asyncio.run(scenario())


def test_form_authentication_honors_same_origin_form_action_and_multipart_enctype():
    async def scenario():
        async def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET" and request.url.path == "/login.cgi":
                return httpx.Response(
                    200,
                    text=(
                        '<form action="/login.cgi" method="post" enctype="multipart/form-data">'
                        '<input type="hidden" name="uri" value="/index.cgi">'
                        '<input type="text" name="username">'
                        '<input type="password" name="password">'
                        '</form>'
                    ),
                    headers={"Set-Cookie": "AIROS_SESSIONID=preauth; Path=/"},
                    request=request,
                )
            if request.method == "POST" and request.url.path == "/login.cgi":
                content_type = request.headers.get("content-type", "")
                body = request.content.decode("utf-8", errors="replace")
                assert content_type.startswith("multipart/form-data; boundary=")
                assert 'name="uri"' in body and "/index.cgi" in body
                assert 'name="username"' in body and "TESTUSER" in body
                assert 'name="password"' in body and "TESTPASS" in body
                return httpx.Response(
                    302,
                    headers={"Location": "/index.cgi", "Set-Cookie": "AIROS_SESSIONID=authenticated; Path=/"},
                    request=request,
                )
            if request.method == "GET" and request.url.path == "/index.cgi":
                return httpx.Response(200, text="airOS dashboard", request=request)
            return httpx.Response(404, request=request)

        runtime = WebRuntimeAccess(
            auth_mode="FORM_POST",
            username="TESTUSER",
            password="TESTPASS",
            login_page_path="/login.cgi?uri=/index.cgi",
            login_submit_path="/wrong-configured-path",
            username_field="username",
            password_field="password",
            success_path_prefix="/index.cgi",
            capture_hidden_fields=True,
        )
        async with httpx.AsyncClient(
            base_url="http://192.0.2.20",
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
        ) as client:
            landing_path = await authenticate_web_client(client, runtime)
            assert landing_path == "/index.cgi"
            assert client.cookies.get("AIROS_SESSIONID") == "authenticated"

    asyncio.run(scenario())


def test_web_login_external_redirect_is_blocked_before_following():
    async def scenario():
        async def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login":
                return httpx.Response(
                    200,
                    text=(
                        '<form action="/session" method="post">'
                        '<input type="text" name="username">'
                        '<input type="password" name="password">'
                        '</form>'
                    ),
                    request=request,
                )
            if request.url.path == "/session":
                return httpx.Response(302, headers={"Location": "https://example.invalid/steal"}, request=request)
            return httpx.Response(404, request=request)

        runtime = WebRuntimeAccess(
            auth_mode="FORM_POST",
            username="TESTUSER",
            password="TESTPASS",
            login_page_path="/login",
            login_submit_path="/session",
            capture_hidden_fields=False,
        )
        async with httpx.AsyncClient(
            base_url="https://192.0.2.20",
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
        ) as client:
            with pytest.raises(WebAuthenticationError) as exc:
                await authenticate_web_client(client, runtime)
            assert str(exc.value) == "WEB_AUTH_EXTERNAL_REDIRECT_BLOCKED"

    asyncio.run(scenario())


def test_external_form_action_is_blocked_before_credentials_are_sent():
    async def scenario():
        requests: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            requests.append(str(request.url))
            return httpx.Response(
                200,
                text=(
                    '<form action="https://example.invalid/steal" method="post">'
                    '<input type="text" name="username">'
                    '<input type="password" name="password">'
                    '</form>'
                ),
                request=request,
            )

        runtime = WebRuntimeAccess(
            auth_mode="FORM_POST",
            username="TESTUSER",
            password="TESTPASS",
            login_page_path="/login",
            login_submit_path="/session",
        )
        async with httpx.AsyncClient(
            base_url="https://192.0.2.20",
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
        ) as client:
            with pytest.raises(WebAuthenticationError) as exc:
                await authenticate_web_client(client, runtime)
            assert str(exc.value) == "WEB_AUTH_EXTERNAL_REDIRECT_BLOCKED"
            assert requests == ["https://192.0.2.20/login"]

    asyncio.run(scenario())


def test_basic_and_digest_auth_objects_are_gateway_side_httpx_auth():
    basic = httpx_auth_for_web(WebRuntimeAccess(auth_mode="HTTP_BASIC", username="u", password="p"))
    digest = httpx_auth_for_web(WebRuntimeAccess(auth_mode="HTTP_DIGEST", username="u", password="p"))
    assert isinstance(basic, httpx.BasicAuth)
    assert isinstance(digest, httpx.DigestAuth)


def test_device_set_cookie_is_never_forwarded_to_browser():
    assert "set-cookie" in _BROWSER_RESPONSE_DROP


def test_authenticated_bootstrap_route_precedes_compatibility_bootstrap():
    from app.remote_gateway.main import app

    matches = [route for route in app.routes if getattr(route, "path", None) == "/web/bootstrap"]
    assert len(matches) >= 2
    assert matches[0].endpoint.__module__.endswith("web_template_bootstrap")
