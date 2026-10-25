from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.remote_gateway import web_proxy
from app.remote_gateway.web_proxy import _navigation_rescue_page, build_web_ssl_context, rewrite_reference, rewrite_text_payload, validate_management_target


def _state():
    session_id = uuid4()
    return SimpleNamespace(
        session_id=session_id,
        target_scheme="HTTPS",
        target_host="192.168.50.10",
        target_port=443,
        target_origin="https://192.168.50.10",
        proxy_base=f"/web/s/{session_id}",
    )


def test_management_target_rejects_loopback_link_local_and_non_ip():
    for value in ("127.0.0.1", "169.254.1.2", "not-an-ip", "0.0.0.0", "224.0.0.1"):
        with pytest.raises(ValueError):
            validate_management_target(value)
    assert validate_management_target("192.168.50.10") == "192.168.50.10"


def test_reference_rewriting_contains_registered_target_and_blocks_other_hosts():
    state = _state()
    origin = "https://gateway.example.test"
    assert rewrite_reference("/login", state, origin) == f"{state.proxy_base}/login"
    assert rewrite_reference("https://192.168.50.10/status", state, origin) == f"{origin}{state.proxy_base}/status"
    assert rewrite_reference("https://203.0.113.5/escape", state, origin) == "#fttw-blocked-external"


def test_relative_vendor_references_resolve_against_device_response_url():
    state = _state()
    origin = "https://gateway.example.test"
    page = "https://192.168.50.10/userRpm/LoginRpm.htm"

    assert rewrite_reference("../css/main.css", state, origin, page) == f"{state.proxy_base}/css/main.css"
    assert rewrite_reference("./login.css", state, origin, page) == f"{state.proxy_base}/userRpm/login.css"
    assert rewrite_reference("LoginRpm.htm?Save=Save", state, origin, page) == f"{state.proxy_base}/userRpm/LoginRpm.htm?Save=Save"
    assert rewrite_reference("//203.0.113.5/escape", state, origin, page) == "#fttw-blocked-external"


def test_relative_html_and_css_assets_stay_inside_exact_proxy_session():
    state = _state()
    origin = "https://gateway.example.test"
    page = "https://192.168.50.10/userRpm/LoginRpm.htm"
    source = """<html><head>
      <link rel="stylesheet" href="../css/main.css">
      <script src="../js/lib.js"></script>
      <style>.logo{background:url('../img/logo.png')}</style>
    </head><body>
      <form action="LoginRpm.htm" method="post"></form>
      <img src="./images/icon.png">
    </body></html>"""
    rewritten = rewrite_text_payload(source, "text/html", state, origin, page)

    assert f'href="{state.proxy_base}/css/main.css"' in rewritten
    assert f'src="{state.proxy_base}/js/lib.js"' in rewritten
    assert f"url('{state.proxy_base}/img/logo.png')" in rewritten
    assert f'action="{state.proxy_base}/userRpm/LoginRpm.htm"' in rewritten
    assert f'src="{state.proxy_base}/userRpm/images/icon.png"' in rewritten
    assert f"{state.proxy_base}/../" not in rewritten

    css = "@import '../theme/base.css'; .x{background:url('../img/bg.png')}"
    css_rewritten = rewrite_text_payload(
        css,
        "text/css",
        state,
        origin,
        "https://192.168.50.10/css/pages/login.css",
    )
    assert f"{state.proxy_base}/css/theme/base.css" in css_rewritten
    assert f"{state.proxy_base}/css/img/bg.png" in css_rewritten


def test_html_css_and_runtime_proxy_rewriting_cover_common_vendor_gui_paths():
    state = _state()
    origin = "https://gateway.example.test"
    source = '''<html><head></head><body>
      <a href="/status">Status</a>
      <img src="https://192.168.50.10/logo.png">
      <form action="/login" method="post"></form>
      <script>fetch("https://192.168.50.10/api/state"); const parsed = new URL("/status", window.location.href);</script>
      <style>.x{background:url('/bg.png')}</style>
    </body></html>'''
    rewritten = rewrite_text_payload(source, "text/html", state, origin)
    assert f'href="{state.proxy_base}/status"' in rewritten
    assert f'{origin}{state.proxy_base}/logo.png' in rewritten
    assert f'action="{state.proxy_base}/login"' in rewritten
    assert f'{origin}{state.proxy_base}/api/state' in rewritten
    assert f"url('{state.proxy_base}/bg.png')" in rewritten
    assert "MutationObserver" in rewritten
    assert "window.WebSocket" in rewritten
    assert "function currentTargetUrl()" in rewritten
    assert "function mapUrl(value)" in rewritten
    assert "new URL(value,currentTargetUrl())" in rewritten
    assert f'const TARGET="{state.target_origin}";' in rewritten
    assert f'const ABS="{origin}{state.proxy_base}";' in rewritten
    assert f'const TARGET="{origin}{state.proxy_base}";' not in rewritten
    assert 'new URL("/status", window.location.href)' in rewritten


def test_gateway_source_keeps_vendor_cookies_server_side():
    source = (Path(__file__).resolve().parents[1] / "remote_gateway" / "web_proxy.py").read_text(encoding="utf-8")
    assert '"set-cookie"' in source
    assert "httponly=True" in source
    assert 'samesite="strict"' in source
    assert 'COOKIE_NAME = "fttw_web_proxy_session"' in source




def test_upstream_referer_is_synthesized_and_browser_host_is_never_forwarded():
    state = _state()

    # Browser receives Referrer-Policy: no-referrer, so the common case has no
    # browser Referer. Legacy vendor assets still receive a same-device Referer.
    headers = web_proxy._upstream_headers({}, state)
    assert headers["Referer"] == "https://192.168.50.10/"

    # When a same-session browser Referer exists, preserve only its path/query.
    browser_ref = f"https://gateway.example.test{state.proxy_base}/admin/status?tab=radio"
    headers = web_proxy._upstream_headers({"referer": browser_ref}, state)
    assert headers["Referer"] == "https://192.168.50.10/admin/status?tab=radio"
    assert "gateway.example.test" not in headers["Referer"]

    # A Referer outside this exact proxy session is never mapped upstream.
    headers = web_proxy._upstream_headers({"referer": "https://attacker.invalid/escape"}, state)
    assert headers["Referer"] == "https://192.168.50.10/"


def test_pinned_tls_mode_is_exact_certificate_trust_not_global_verify_disable():
    source = (Path(__file__).resolve().parents[1] / "remote_gateway" / "web_proxy.py").read_text(encoding="utf-8")
    assert "ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)" in source
    assert "context.verify_mode = ssl.CERT_REQUIRED" in source
    assert "context.check_hostname = False" in source
    assert "VERIFY_X509_PARTIAL_CHAIN" in source
    assert "verify=False" not in source


def test_legacy_weak_certificate_compatibility_is_pinned_and_context_local(monkeypatch):
    class FakeContext:
        def __init__(self, protocol):
            self.protocol = protocol
            self.verify_mode = None
            self.check_hostname = None
            self.verify_flags = 0
            self.cipher_policy = None
            self.cadata = None

        def set_ciphers(self, value):
            self.cipher_policy = value

        def load_verify_locations(self, *, cadata):
            self.cadata = cadata

    monkeypatch.setattr(web_proxy.ssl, "SSLContext", FakeContext)
    monkeypatch.setattr(web_proxy, "resolve_secret_reference", lambda _: "-----BEGIN CERTIFICATE-----\nPIN\n-----END CERTIFICATE-----")
    profile = SimpleNamespace(
        web_scheme="HTTPS",
        web_tls_mode="PINNED_CERT",
        web_tls_compat_profile="LEGACY_WEAK_CERT_KEY",
        web_tls_pinned_certificate_reference="env://DEVICE_WEB_CERT_PEM",
    )
    context = build_web_ssl_context(profile)
    assert context.cipher_policy == "DEFAULT:@SECLEVEL=1"
    assert context.verify_mode == web_proxy.ssl.CERT_REQUIRED
    assert context.check_hostname is False
    assert "BEGIN CERTIFICATE" in context.cadata


def test_modern_pinned_certificate_does_not_lower_openssl_security_level(monkeypatch):
    class FakeContext:
        def __init__(self, protocol):
            self.verify_mode = None
            self.check_hostname = None
            self.verify_flags = 0
            self.cipher_policy = None

        def set_ciphers(self, value):
            self.cipher_policy = value

        def load_verify_locations(self, *, cadata):
            pass

    monkeypatch.setattr(web_proxy.ssl, "SSLContext", FakeContext)
    monkeypatch.setattr(web_proxy, "resolve_secret_reference", lambda _: "-----BEGIN CERTIFICATE-----\nPIN\n-----END CERTIFICATE-----")
    profile = SimpleNamespace(
        web_scheme="HTTPS",
        web_tls_mode="PINNED_CERT",
        web_tls_compat_profile="MODERN",
        web_tls_pinned_certificate_reference="env://DEVICE_WEB_CERT_PEM",
    )
    context = build_web_ssl_context(profile)
    assert context.cipher_policy is None


def test_inline_vendor_javascript_is_not_rewritten_as_html_tag_attributes():
    state = _state()
    origin = "https://gateway.example.test"
    source = '''<html><head></head><body><script>
var src = "../js/runtime.js";
var data = "../api/state?x=1&y=2";
var action = "../login";
var href = "../status";
if (a<b && c>d) { href = "../next"; }
</script></body></html>'''
    rewritten = rewrite_text_payload(
        source,
        "text/html",
        state,
        origin,
        "https://192.168.50.10/userRpm/LoginRpm.htm",
    )
    assert 'var src = "../js/runtime.js";' in rewritten
    assert 'var data = "../api/state?x=1&y=2";' in rewritten
    assert 'var action = "../login";' in rewritten
    assert 'var href = "../status";' in rewritten
    assert 'if (a<b && c>d) { href = "../next"; }' in rewritten
    assert "&amp;" not in rewritten.split("</script>")[-2].split("<script>")[-1]


def test_runtime_mapper_synchronously_contains_dynamic_vendor_asset_urls():
    state = _state()
    origin = "https://gateway.example.test"
    rewritten = rewrite_text_payload("<html><head></head><body></body></html>", "text/html", state, origin)

    # TP-Link-style jQuery script injection starts the network request as soon as
    # script.src/setAttribute is assigned. MutationObserver alone is too late.
    assert "const nativeSetAttribute=Element.prototype.setAttribute;" in rewritten
    assert "Element.prototype.setAttribute=function(name,value)" in rewritten
    assert "patchUrlProperty(proto,prop,mapper)" in rewritten
    assert "window.HTMLScriptElement?.prototype,'src'" in rewritten
    assert "window.HTMLImageElement?.prototype,'src'" in rewritten
    assert "window.HTMLLinkElement?.prototype,'href'" in rewritten

    # Repair browser-resolved legacy paths like /web/s/js/foo.js while refusing
    # to retarget a path that already names a valid remote-session UUID.
    assert "function repairOrphanProxyPath(parsed)" in rewritten
    assert "SESSION_UUID_RE.test(first)" in rewritten
    assert "return BASE+'/'+tail+parsed.search+parsed.hash;" in rewritten


def test_runtime_mapper_contains_vendor_location_origin_root_requests_for_rsa_bootstrap():
    state = _state()
    origin = "https://gateway.example.test"
    rewritten = rewrite_text_payload("<html><head></head><body></body></html>", "text/html", state, origin)

    # TP-Link-style code can build /cgi/getParm from location.origin, which is
    # the gateway origin in the isolated browser. It must be remapped into the
    # exact remote session instead of reaching gateway root.
    assert "if(browserParsed.origin===window.location.origin)" in rewritten
    assert "browserParsed.pathname.startsWith('/web/s/')" in rewritten
    assert "return '#fttw-blocked-external';" in rewritten
    assert "return BASE+browserParsed.pathname+browserParsed.search+browserParsed.hash;" in rewritten
    assert "repairOrphanProxyPath(browserParsed)" in rewritten


def test_vendor_alert_notifications_use_fttw_styled_proxy_modal_without_replacing_confirm_prompt():
    state = _state()
    origin = "https://gateway.example.test"
    rewritten = rewrite_text_payload("<html><head></head><body></body></html>", "text/html", state, origin)

    assert "fttw-proxy-alert-overlay" in rewritten
    assert "role=\"alertdialog\"" in rewritten
    assert "window.alert=function(message)" in rewritten
    assert "Device message" in rewritten
    # Synchronous vendor control-flow semantics remain untouched.
    assert "window.confirm=" not in rewritten
    assert "window.prompt=" not in rewritten


def test_vendor_hard_navigation_to_gateway_root_is_recovered_per_tab_without_broad_cookie():
    state = _state()
    origin = "https://gateway.example.test"
    rewritten = rewrite_text_payload("<html><head></head><body></body></html>", "text/html", state, origin)

    # Each browsing tab remembers only its opaque proxy-session path. This avoids
    # a path=/ session cookie, which would collide when operators open multiple
    # devices in separate tabs.
    assert "const SESSION_MARKER_KEY='fttw.remoteWeb.sessionBase';" in rewritten
    assert "sessionStorage.setItem(SESSION_MARKER_KEY,BASE)" in rewritten
    assert "window.name='fttw-remote-web:'+BASE" in rewritten

    rescue = _navigation_rescue_page()
    assert "fttw.remoteWeb.sessionBase" in rescue
    assert "fttw-remote-web:" in rescue
    assert "window.location.replace(base+'/')" in rescue
    # The rescue page validates a stored opaque session base using a regex.
    # Because the JavaScript regex escapes slashes, do not require an
    # impossible literal "/web/s/" substring in the generated source.
    assert "const VALID=/^\\/web\\/s\\/" in rescue
    assert "target_host" not in rescue


def test_navigation_rescue_does_not_create_a_gateway_root_proxy_target():
    source = (Path(__file__).resolve().parents[1] / "remote_gateway" / "web_proxy.py").read_text(encoding="utf-8")
    assert '@router.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)' in source
    assert "No destination host, IP, or port is accepted here." in source
    # The real Web-GUI authentication cookie remains restricted to the session path.
    assert "path=state.proxy_base" in source




def test_generic_upstream_headers_forward_vendor_application_headers_without_vendor_rules():
    state = _state()
    headers = web_proxy._upstream_headers(
        {
            "accept": "*/*",
            "content-type": "text/plain",
            "TokenID": "vendor-session-token",
            "X-CSRF-Token": "csrf-value",
            "X-Vendor-Bootstrap": "opaque-bootstrap",
            "Sec-Fetch-Site": "same-origin",
        },
        state,
    )

    assert headers["TokenID"] == "vendor-session-token"
    assert headers["X-CSRF-Token"] == "csrf-value"
    assert headers["X-Vendor-Bootstrap"] == "opaque-bootstrap"
    assert headers["Sec-Fetch-Site"] == "same-origin"
    assert headers["Accept-Encoding"] == "identity"
    assert headers["Referer"] == "https://192.168.50.10/"


def test_generic_upstream_headers_block_proxy_owned_sensitive_headers_and_connection_tokens():
    state = _state()
    headers = web_proxy._upstream_headers(
        {
            "Host": "gateway.example.test",
            "Cookie": "fttw_web_proxy_session=secret; device_cookie=browser-copy",
            "Content-Length": "999",
            "Accept-Encoding": "gzip, br",
            "Connection": "keep-alive, X-Hop-Private",
            "X-Hop-Private": "must-not-forward",
            "Proxy-Authorization": "must-not-forward",
            "Forwarded": "for=203.0.113.10",
            "Via": "browser-proxy",
            "X-Forwarded-For": "203.0.113.10",
            "X-Forwarded-Host": "gateway.example.test",
            "X-Forwarded-Proto": "https",
            "X-Real-IP": "203.0.113.10",
            "X-FTTW-Web-Bootstrap": "internal",
            "X-FTTW-Anything": "internal",
            "X-Remote-Access-Ticket": "internal-secret",
            "X-Remote-Access-Anything": "internal",
            "TokenID": "vendor-session-token",
        },
        state,
    )

    lowered = {key.lower() for key in headers}
    for blocked in (
        "host", "cookie", "content-length", "connection", "x-hop-private",
        "proxy-authorization", "forwarded", "via", "x-forwarded-for",
        "x-forwarded-host", "x-forwarded-proto", "x-real-ip",
        "x-fttw-web-bootstrap", "x-fttw-anything", "x-remote-access-ticket",
        "x-remote-access-anything",
    ):
        assert blocked not in lowered
    assert headers["TokenID"] == "vendor-session-token"
    assert headers["Accept-Encoding"] == "identity"


def test_generic_upstream_headers_rewrite_origin_and_referer_to_registered_device_only():
    state = _state()
    headers = web_proxy._upstream_headers(
        {
            "Origin": "https://gateway.example.test",
            "Referer": "https://gateway.example.test/web/s/00000000-0000-4000-8000-000000000000/admin?tab=1",
            "X-Vendor-Request": "ok",
        },
        state,
    )

    assert headers["Origin"] == "https://192.168.50.10"
    assert headers["Referer"].startswith("https://192.168.50.10/")
    assert "gateway.example.test" not in headers["Origin"]
    assert "gateway.example.test" not in headers["Referer"]
    assert headers["X-Vendor-Request"] == "ok"


def test_generic_response_headers_preserve_vendor_end_to_end_metadata_but_strip_proxy_unsafe_headers():
    import httpx

    response = httpx.Response(
        200,
        headers={
            "X-Vendor-State": "ready",
            "Set-Cookie": "device_session=secret; Path=/",
            "Connection": "keep-alive",
            "Content-Length": "123",
            "Location": "/admin",
        },
    )
    headers = web_proxy._safe_response_headers(response)
    lowered = {key.lower(): value for key, value in headers.items()}

    assert lowered["x-vendor-state"] == "ready"
    assert "set-cookie" not in lowered
    assert "connection" not in lowered
    assert "content-length" not in lowered
    assert "location" not in lowered


def test_active_gateway_source_has_no_vendor_specific_header_or_cookie_compatibility_rules():
    source = (Path(__file__).resolve().parents[1] / "remote_gateway" / "web_proxy.py").read_text(encoding="utf-8")
    assert "TokenID" not in source
    assert "TPLINK" not in source.upper()
    assert "_vendor_web_compat_profile" not in source
    assert "__fttw_vc_" not in source


def test_tls10_compatibility_is_not_exposed_by_active_gateway_source():
    source = (Path(__file__).resolve().parents[1] / "remote_gateway" / "web_proxy.py").read_text(encoding="utf-8")
    assert "LEGACY_TLS_1_0" not in source
    assert "TLSVersion.TLSv1" not in source
    assert "DHE-RSA-AES256-SHA" not in source


def test_web_gui_activity_refreshes_linked_auth_session_without_changing_remote_timeouts():
    source = (Path(__file__).resolve().parents[1] / "remote_gateway" / "web_proxy.py").read_text(encoding="utf-8")
    assert "auth.last_user_activity_at = now" in source
    assert "remote.last_activity_at = now" in source
    assert "settings.remote_access_idle_timeout_seconds" in source
    assert "settings.remote_access_session_max_seconds" in source
    assert "AUTH_SESSION_EXPIRED" in source
