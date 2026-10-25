from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx

from ..services.access_template_runtime import WebRuntimeAccess
from .web_protocol_registry import WebProtocolAdapterError, authenticate_registered_web_protocol
from .web_protocol_session import WebProtocolSession


class WebAuthenticationError(RuntimeError):
    pass


@dataclass(frozen=True)
class WebInitialResponse:
    """Gateway-only snapshot of a successful form-login response."""

    status_code: int
    headers: tuple[tuple[str, str], ...]
    content: bytes = field(repr=False)


@dataclass(frozen=True)
class WebAuthenticationResult:
    landing_path: str
    protocol_session: WebProtocolSession | None = None
    initial_response: WebInitialResponse | None = field(
        default=None,
        repr=False,
    )


class _LoginFormParser(HTMLParser):
    """Capture the login form that owns the configured password field.

    Only non-secret form metadata and hidden field values from the device login
    page are retained. A parsed action is used only after exact same-origin
    validation, so a malicious/compromised login page cannot redirect gateway
    credentials to another origin.
    """

    def __init__(self, *, password_field: str) -> None:
        super().__init__(convert_charrefs=True)
        self.password_field = password_field
        self.selected_hidden: dict[str, str] = {}
        self.selected_action: str | None = None
        self.selected_enctype: str | None = None
        self._current: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        lowered = tag.lower()
        values = {str(key).lower(): str(value or "") for key, value in attrs if key}
        if lowered == "form":
            self._current = {
                "action": values.get("action", ""),
                "enctype": values.get("enctype", ""),
                "hidden": {},
                "has_password": False,
            }
            return
        if lowered != "input" or self._current is None:
            return

        name = values.get("name", "").strip()
        if not name or len(name) > 80:
            return
        if name == self.password_field:
            self._current["has_password"] = True
        if values.get("type", "").lower() != "hidden":
            return
        hidden = self._current["hidden"]
        if not isinstance(hidden, dict) or len(hidden) >= 64:
            return
        value = values.get("value", "")
        if len(value) <= 2048:
            hidden[name] = value

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form" or self._current is None:
            return
        if self.selected_action is None and bool(self._current.get("has_password")):
            hidden = self._current.get("hidden")
            self.selected_hidden = dict(hidden) if isinstance(hidden, dict) else {}
            self.selected_action = str(self._current.get("action") or "")
            self.selected_enctype = str(self._current.get("enctype") or "")
        self._current = None


def httpx_auth_for_web(runtime: WebRuntimeAccess) -> httpx.Auth | None:
    if runtime.auth_mode == "HTTP_BASIC":
        return httpx.BasicAuth(runtime.username or "", runtime.password or "")
    if runtime.auth_mode == "HTTP_DIGEST":
        return httpx.DigestAuth(runtime.username or "", runtime.password or "")
    return None


def _origin_tuple(url: httpx.URL | str) -> tuple[str, str, int]:
    parts = urlsplit(str(url))
    scheme = parts.scheme.lower()
    default_port = 443 if scheme == "https" else 80
    return scheme, (parts.hostname or "").lower(), parts.port or default_port


def _landing_path(url: httpx.URL | str) -> str:
    parts = urlsplit(str(url))
    path = parts.path or "/"
    return path + (f"?{parts.query}" if parts.query else "")


async def _same_origin_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    data: dict[str, str] | None = None,
    files: list[tuple[str, tuple[None, str]]] | None = None,
    headers: dict[str, str] | None = None,
    max_redirects: int = 5,
) -> httpx.Response:
    current_method = method.upper()
    current_url = url
    current_data = data
    current_files = files
    expected_origin = _origin_tuple(client.base_url)

    initial_target = urljoin(str(client.base_url), current_url)
    if _origin_tuple(initial_target) != expected_origin:
        raise WebAuthenticationError("WEB_AUTH_EXTERNAL_REDIRECT_BLOCKED")

    for _hop in range(max_redirects + 1):
        response = await client.request(
            current_method,
            current_url,
            data=current_data,
            files=current_files,
            headers=headers,
            follow_redirects=False,
        )
        if response.status_code not in {301, 302, 303, 307, 308}:
            return response
        location = response.headers.get("location")
        if not location:
            return response
        target = urljoin(str(response.url), location)
        if _origin_tuple(target) != expected_origin:
            raise WebAuthenticationError("WEB_AUTH_EXTERNAL_REDIRECT_BLOCKED")
        if response.status_code in {301, 302, 303} and current_method not in {"GET", "HEAD"}:
            current_method = "GET"
            current_data = None
            current_files = None
        current_url = target
    raise WebAuthenticationError("WEB_AUTH_REDIRECT_LIMIT")


def _authentication_status(response: httpx.Response) -> None:
    if response.status_code in {401, 403}:
        raise WebAuthenticationError("WEB_AUTHENTICATION_FAILED")
    if response.status_code >= 500:
        raise WebAuthenticationError("WEB_AUTH_UPSTREAM_FAILURE")
    if response.status_code >= 400:
        raise WebAuthenticationError("WEB_AUTH_LOGIN_REQUEST_REJECTED")


def _initial_response_snapshot(
    response: httpx.Response,
    *,
    forbidden_values: tuple[str | None, ...] = (),
) -> WebInitialResponse | None:
    content = bytes(response.content)

    # Keep this compatibility handoff tightly bounded. Oversized responses fall
    # back to the ordinary post-authentication GET behavior.
    if len(content) > 2_000_000:
        return None

    text = response.text

    # Never make a successful login response browser-visible if it reflects the
    # submitted password. Failing closed is preferable to credential exposure.
    if any(value and value in text for value in forbidden_values):
        return None

    # Device cookies are already retained inside the gateway-owned httpx jar.
    # They must never be copied into the browser-facing response.
    headers = tuple(
        (key, value)
        for key, value in response.headers.multi_items()
        if key.lower() not in {"set-cookie", "set-cookie2"}
    )

    return WebInitialResponse(
        status_code=response.status_code,
        headers=headers,
        content=content,
    )


async def authenticate_web_client_with_session(
    client: httpx.AsyncClient,
    runtime: WebRuntimeAccess,
) -> WebAuthenticationResult:
    """Authenticate a gateway-owned client and preserve optional protocol state.

    Device credentials and cookies remain gateway-side. Device families whose
    Web UIs require post-login protocol state can return an ephemeral adapter for
    the isolated proxy session without changing the generic Web proxy contract.
    """

    if runtime.auth_mode == "NONE":
        return WebAuthenticationResult(landing_path="/")

    if runtime.auth_mode in {"HTTP_BASIC", "HTTP_DIGEST"}:
        try:
            response = await _same_origin_request(client, "GET", "/")
        except httpx.HTTPError as exc:
            raise WebAuthenticationError("WEB_AUTH_CONNECT_FAILED") from exc
        _authentication_status(response)
        return WebAuthenticationResult(landing_path=_landing_path(response.url))

    if runtime.auth_mode != "FORM_POST":
        raise WebAuthenticationError("WEB_AUTH_MODE_UNSUPPORTED")
    if not runtime.password:
        raise WebAuthenticationError("WEB_AUTHENTICATION_FAILED")
    if runtime.credential_mode == "USERNAME_PASSWORD" and not runtime.username:
        raise WebAuthenticationError("WEB_AUTHENTICATION_FAILED")
    if runtime.credential_mode not in {"USERNAME_PASSWORD", "PASSWORD_ONLY"}:
        raise WebAuthenticationError("WEB_CREDENTIAL_MODE_UNSUPPORTED")

    try:
        login_page = await _same_origin_request(client, "GET", runtime.login_page_path)
    except httpx.HTTPError as exc:
        raise WebAuthenticationError("WEB_AUTH_CONNECT_FAILED") from exc
    _authentication_status(login_page)

    # Proprietary browser protocols are selected by observed protocol markers
    # through the registry. Generic authentication never branches on a device
    # model, vendor, management address, serial number, or UUID.
    try:
        adapter_result = await authenticate_registered_web_protocol(
            client,
            credential_mode=runtime.credential_mode,
            login_page_text=login_page.text,
            password=runtime.password,
        )
    except WebProtocolAdapterError as exc:
        raise WebAuthenticationError(str(exc)) from exc
    if adapter_result is not None:
        return WebAuthenticationResult(
            landing_path=adapter_result.landing_path,
            protocol_session=adapter_result.protocol_session,
        )

    parser = _LoginFormParser(password_field=runtime.password_field)
    try:
        parser.feed(login_page.text[:2_000_000])
    except Exception:
        parser = _LoginFormParser(password_field=runtime.password_field)

    fields: dict[str, str] = {}
    if runtime.capture_hidden_fields:
        fields.update(parser.selected_hidden)
    if runtime.credential_mode == "USERNAME_PASSWORD":
        fields[runtime.username_field] = runtime.username or ""
    fields[runtime.password_field] = runtime.password

    referer = str(login_page.url)
    parsed = urlsplit(referer)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    submit_target = runtime.login_submit_path
    if parser.selected_action:
        parsed_action = urljoin(str(login_page.url), parser.selected_action)
        if _origin_tuple(parsed_action) != _origin_tuple(client.base_url):
            raise WebAuthenticationError("WEB_AUTH_EXTERNAL_REDIRECT_BLOCKED")
        submit_target = parsed_action

    enctype = (parser.selected_enctype or "").strip().lower()
    multipart = enctype.startswith("multipart/form-data")
    multipart_fields = [(key, (None, value)) for key, value in fields.items()] if multipart else None

    try:
        result = await _same_origin_request(
            client,
            "POST",
            submit_target,
            data=None if multipart else fields,
            files=multipart_fields,
            headers={"Referer": referer, "Origin": origin},
        )
    except httpx.HTTPError as exc:
        raise WebAuthenticationError("WEB_AUTH_CONNECT_FAILED") from exc
    _authentication_status(result)

    body = result.text[:2_000_000]
    if runtime.failure_text and runtime.failure_text in body:
        raise WebAuthenticationError("WEB_AUTHENTICATION_FAILED")

    positive = False
    if runtime.success_text:
        positive = runtime.success_text in body
    if runtime.success_path_prefix:
        positive = positive or urlsplit(str(result.url)).path.startswith(runtime.success_path_prefix)

    if not positive:
        redirected = str(result.url) != str(login_page.url) and urlsplit(str(result.url)).path != runtime.login_page_path
        positive = redirected and bool(client.cookies)
    if not positive:
        raise WebAuthenticationError("WEB_AUTHENTICATION_UNCONFIRMED")
    initial_response = None

    # Some embedded Web interfaces establish no persistent cookie-backed
    # session. A normal browser renders the successful POST response itself;
    # preserve that response once so the isolated gateway can do the same.
    if not client.cookies:
        initial_response = _initial_response_snapshot(
            result,
            forbidden_values=(runtime.password,),
        )

    return WebAuthenticationResult(
        landing_path=_landing_path(result.url),
        initial_response=initial_response,
    )


async def authenticate_web_client(
    client: httpx.AsyncClient,
    runtime: WebRuntimeAccess,
) -> str:
    """Backward-compatible authentication API returning only the landing path."""

    result = await authenticate_web_client_with_session(client, runtime)
    return result.landing_path
