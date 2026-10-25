import asyncio
import base64
import json

import httpx
import pytest

from app.remote_gateway.tp_link_mr_web_auth import (
    _aes_cbc_base64,
    _parse_key_material,
    looks_like_tp_link_mr_rsa_aes,
)
from app.remote_gateway.web_auth import (
    WebAuthenticationError,
    authenticate_web_client,
    authenticate_web_client_with_session,
)
from app.remote_gateway.web_protocol_session import WebProtocolSessionError
from app.services.access_template_runtime import WebRuntimeAccess


NN = "DFBBDEAD2BC700A78318BDBB7CE5EE22E2199CFF32EFAF4A067B2474817B00AE5A589A8EB7D194EE7321B3147994E871804A1250C91463196F992446A66640AB"
EE = "010001"
SEQ = "643618060"
LOGIN_PAGE = "<html><script>var a='cgi/getParm';var b='cgi/login';var c='tpEncrypt AESEncrypt Iencryptor';</script><input id='pc-login-password'></html>"


def _runtime(password: str) -> WebRuntimeAccess:
    return WebRuntimeAccess(
        auth_mode="FORM_POST",
        credential_mode="PASSWORD_ONLY",
        password=password,
        login_page_path="/",
        login_submit_path="/cgi/login",
        password_field="password",
        capture_hidden_fields=False,
    )


def test_tp_link_mr_marker_detection_requires_endpoints_and_crypto_marker():
    assert looks_like_tp_link_mr_rsa_aes(LOGIN_PAGE)
    assert not looks_like_tp_link_mr_rsa_aes("cgi/getParm cgi/login")
    assert not looks_like_tp_link_mr_rsa_aes("tpEncrypt cgi/login")


def test_tp_link_mr_key_material_accepts_mr600_json_and_legacy_javascript():
    json_keys = _parse_key_material(
        json.dumps({"ee": EE, "nn": NN, "userSetting": 1, "seq": SEQ, "ret": 0})
    )
    legacy_keys = _parse_key_material(
        f'$.ret=0;var ee="{EE}";var nn="{NN}";var seq="{SEQ}";'
    )
    assert json_keys == legacy_keys
    assert json_keys.modulus_hex == NN
    assert json_keys.exponent_hex == EE
    assert json_keys.sequence == int(SEQ)


def test_tp_link_mr_password_only_authentication_is_gateway_side_and_confirmed():
    async def scenario():
        login_requests = 0
        getparm_requests = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal login_requests, getparm_requests
            if request.method == "GET" and request.url.path == "/":
                cookie = request.headers.get("cookie", "")
                if "JSESSIONID=SESSION123" in cookie:
                    return httpx.Response(
                        200,
                        text='<html><script>var token="TOKEN123";</script><div id="status">Router status</div></html>',
                        headers={"Content-Type": "text/html; charset=utf-8"},
                        request=request,
                    )
                return httpx.Response(200, text=LOGIN_PAGE, request=request)

            if request.method == "GET" and request.url.path == "/cgi/getParm":
                getparm_requests += 1
                assert request.headers.get("referer") == "http://192.0.2.44/"
                return httpx.Response(
                    200,
                    json={"ee": EE, "nn": NN, "userSetting": 1, "seq": SEQ, "ret": 0},
                    request=request,
                )

            if request.method == "POST" and request.url.path == "/cgi/login":
                login_requests += 1
                params = request.url.params
                assert params.get("Action") == "1"
                assert params.get("LoginStatus") == "0"
                assert params.get("isMobile") is None
                encrypted = params.get("data") or ""
                signature = params.get("sign") or ""
                assert "ONLYPASS" not in str(request.url)
                assert "ONLYPASS" not in request.content.decode("utf-8", errors="ignore")
                decoded = base64.b64decode(encrypted, validate=True)
                assert decoded and len(decoded) % 16 == 0
                assert len(signature) == 256
                assert all(ch in "0123456789abcdef" for ch in signature.lower())
                return httpx.Response(
                    200,
                    json={"ret": 0},
                    headers={"Set-Cookie": "JSESSIONID=SESSION123; Path=/; HttpOnly"},
                    request=request,
                )

            return httpx.Response(404, request=request)

        runtime = _runtime("ONLYPASS")
        async with httpx.AsyncClient(
            base_url="http://192.0.2.44",
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
        ) as client:
            assert await authenticate_web_client(client, runtime) == "/"
            assert client.cookies.get("JSESSIONID") == "SESSION123"
            assert getparm_requests == 1
            assert login_requests == 1

    asyncio.run(scenario())


def test_tp_link_mr_post_auth_bridge_preserves_crypto_without_exposing_password_hash():
    async def scenario():
        async def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET" and request.url.path == "/":
                cookie = request.headers.get("cookie", "")
                if "JSESSIONID=SESSION123" in cookie:
                    return httpx.Response(
                        200,
                        text='<html><body><script>var token="TOKEN123";</script><div>Router status</div></body></html>',
                        headers={"Content-Type": "text/html; charset=utf-8"},
                        request=request,
                    )
                return httpx.Response(200, text=LOGIN_PAGE, request=request)
            if request.method == "GET" and request.url.path == "/cgi/getParm":
                return httpx.Response(
                    200,
                    json={"ee": EE, "nn": NN, "userSetting": 1, "seq": SEQ, "ret": 0},
                    request=request,
                )
            if request.method == "POST" and request.url.path == "/cgi/login":
                return httpx.Response(
                    200,
                    json={"ret": 0},
                    headers={"Set-Cookie": "JSESSIONID=SESSION123; Path=/; HttpOnly"},
                    request=request,
                )
            return httpx.Response(404, request=request)

        runtime = _runtime("ONLYPASS")
        async with httpx.AsyncClient(
            base_url="http://192.0.2.44",
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
        ) as client:
            result = await authenticate_web_client_with_session(client, runtime)
            protocol = result.protocol_session
            assert protocol is not None
            assert protocol.family == "TP_LINK_MR_RSA_AES"
            assert result.landing_path == "/"

            plaintext = "1&1&1&8\r\n[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,1\r\nmodelName\r\n"
            encrypted_data = _aes_cbc_base64(
                plaintext,
                key=protocol.aes_key,
                iv=protocol.aes_iv,
            )
            browser_request = httpx.Request(
                "POST",
                "http://192.0.2.44/cgi_gdpr",
                headers={"Content-Type": "text/plain", "TokenID": "BROWSER_VALUE"},
                content=f"sign={'0' * 256}\r\ndata={encrypted_data}\r\n".encode("ascii"),
            )
            upstream_request = protocol.prepare_request(browser_request)
            upstream_body = upstream_request.content.decode("ascii")
            assert upstream_request.headers["TokenID"] == "TOKEN123"
            assert f"data={encrypted_data}" in upstream_body
            assert f"sign={'0' * 256}" not in upstream_body
            assert "ONLYPASS" not in upstream_body
            assert protocol.credential_hash not in upstream_body

            wrong_key = ("0" if protocol.aes_key[0] != "0" else "1") + protocol.aes_key[1:]
            mismatched_data = _aes_cbc_base64(
                plaintext,
                key=wrong_key,
                iv=protocol.aes_iv,
            )
            mismatched_request = httpx.Request(
                "POST",
                "http://192.0.2.44/cgi_gdpr",
                headers={"Content-Type": "text/plain"},
                content=f"sign={'0' * 256}\r\ndata={mismatched_data}\r\n".encode("ascii"),
            )
            with pytest.raises(WebProtocolSessionError) as exc:
                protocol.prepare_request(mismatched_request)
            assert str(exc.value) == "WEB_PROTOCOL_SESSION_BROWSER_CRYPTO_MISMATCH"

            page_request = httpx.Request("GET", "http://192.0.2.44/")
            vendor_startup = "window.__vendorStartup='after-crypto';"
            page_response = httpx.Response(
                200,
                text=(
                    '<html><head>'
                    '<script src="/js/encrypt.js"></script>'
                    '<script src="/js/tpEncrypt.js"></script>'
                    '<script src="/js/lib.js"></script>'
                    f'<script>{vendor_startup}</script>'
                    '</head><body><div>Router status</div></body></html>'
                ),
                headers={"Content-Type": "text/html; charset=utf-8"},
                request=page_request,
            )
            bridged = await protocol.prepare_response(page_request, page_response)
            html = bridged.text
            assert "fttw-web-protocol-session-bootstrap" in html
            assert html.index("fttw-web-protocol-session-bootstrap") < html.index(vendor_startup)
            assert "setAESStringKey" in html
            assert "AESEncrypt" in html
            assert "AESDecrypt" in html
            assert "genAESKey" in html
            assert "wrapManagerFactory" in html
            assert "getEncryptor" in html
            assert "setInterval" in html
            assert protocol.aes_key in html
            assert protocol.aes_iv in html
            assert protocol.credential_hash not in html
            assert "ONLYPASS" not in html
            assert "TOKEN123" not in html

    asyncio.run(scenario())


def test_tp_link_mr_wrong_password_response_fails_closed_and_keeps_legacy_getparm_compatibility():
    async def scenario():
        async def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET" and request.url.path == "/":
                return httpx.Response(200, text=LOGIN_PAGE, request=request)
            if request.method == "GET" and request.url.path == "/cgi/getParm":
                return httpx.Response(
                    200,
                    text=f'$.ret=0;var ee="{EE}";var nn="{NN}";var seq="{SEQ}";',
                    request=request,
                )
            if request.method == "POST" and request.url.path == "/cgi/login":
                return httpx.Response(200, text="$.ret=71233;", request=request)
            return httpx.Response(404, request=request)

        runtime = _runtime("WRONGPASS")
        async with httpx.AsyncClient(
            base_url="http://192.0.2.44",
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
        ) as client:
            with pytest.raises(WebAuthenticationError) as exc:
                await authenticate_web_client(client, runtime)
            assert str(exc.value) == "WEB_AUTHENTICATION_FAILED"

    asyncio.run(scenario())