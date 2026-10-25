from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import DeviceRemoteAccessProfile
from ..remote_gateway.tp_link_mr_web_auth import TP_LINK_MR_AUTH_FAMILY, looks_like_tp_link_mr_rsa_aes
from ..remote_gateway.web_auth import WebAuthenticationError, authenticate_web_client, httpx_auth_for_web
from ..remote_gateway.web_proxy import build_web_ssl_context, validate_management_target
from .access_template_runtime import WebRuntimeAccess
from .remote_access import profile_web_port, web_profile_is_ready


COMMON_WEB_ENDPOINTS: tuple[tuple[str, int], ...] = (
    ("HTTPS", 443),
    ("HTTP", 80),
    ("HTTPS", 8443),
    ("HTTP", 8080),
)
COMMON_LOGIN_PATHS: tuple[str, ...] = ("/", "/login", "/login.cgi", "/index.html", "/index.cgi")


class WebTemplateDiscoveryError(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(code)


@dataclass(frozen=True)
class DiscoveredWebTemplate:
    device_id: UUID
    management_ip: str
    scheme: str
    port: int
    auth_mode: str
    credential_mode: str
    settings: dict[str, object]
    landing_path: str
    form_encoding: str | None
    username_field: str | None
    password_field: str | None
    auth_family: str | None = None
    confidence: str = "HIGH"


class _FormInventoryParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, object]] = []
        self._current: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        lowered = tag.lower()
        values = {str(key).lower(): str(value or "") for key, value in attrs if key}
        if lowered == "form":
            self._current = {
                "action": values.get("action", ""),
                "method": values.get("method", "GET").upper(),
                "enctype": values.get("enctype", "application/x-www-form-urlencoded").lower(),
                "inputs": [],
            }
            self.forms.append(self._current)
            return
        if lowered != "input" or self._current is None:
            return
        name = values.get("name", "").strip()
        if not name or len(name) > 80:
            return
        input_type = values.get("type", "text").strip().lower() or "text"
        inputs = self._current.get("inputs")
        if isinstance(inputs, list) and len(inputs) < 128:
            inputs.append({"name": name, "type": input_type})

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current = None


def _origin(scheme: str, host: str, port: int) -> str:
    scheme_lower = scheme.lower()
    default = (scheme_lower == "http" and port == 80) or (scheme_lower == "https" and port == 443)
    host_text = f"[{host}]" if ":" in host else host
    return f"{scheme_lower}://{host_text}{'' if default else ':' + str(port)}"


def _same_origin(left: str | httpx.URL, right: str | httpx.URL) -> bool:
    def parts(value):
        parsed = urlsplit(str(value))
        scheme = parsed.scheme.lower()
        default = 443 if scheme == "https" else 80
        return scheme, (parsed.hostname or "").lower(), parsed.port or default

    return parts(left) == parts(right)


def _path_and_query(value: str | httpx.URL) -> str:
    parsed = urlsplit(str(value))
    path = parsed.path or "/"
    return path + (f"?{parsed.query}" if parsed.query else "")


async def _tcp_open(host: str, port: int, timeout_seconds: int) -> bool:
    writer = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=max(1, min(timeout_seconds, 5)),
        )
        return True
    except (OSError, asyncio.TimeoutError):
        return False
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def _safe_get(client: httpx.AsyncClient, path: str, *, max_redirects: int = 5) -> httpx.Response:
    target: str = path
    for _hop in range(max_redirects + 1):
        response = await client.get(target, follow_redirects=False)
        if response.status_code not in {301, 302, 303, 307, 308}:
            return response
        location = response.headers.get("location")
        if not location:
            return response
        next_url = urljoin(str(response.url), location)
        if not _same_origin(next_url, client.base_url):
            raise WebTemplateDiscoveryError(
                "WEB_DISCOVERY_EXTERNAL_REDIRECT",
                "The device redirected discovery outside its registered management origin.",
            )
        target = next_url
    raise WebTemplateDiscoveryError(
        "WEB_DISCOVERY_REDIRECT_LIMIT",
        "The device exceeded the bounded discovery redirect limit.",
    )


def _auth_challenge(response: httpx.Response) -> str | None:
    challenge = response.headers.get("www-authenticate", "").strip().lower()
    if challenge.startswith("basic"):
        return "HTTP_BASIC"
    if challenge.startswith("digest"):
        return "HTTP_DIGEST"
    return None


def _candidate_form(response: httpx.Response, credential_mode: str):
    parser = _FormInventoryParser()
    try:
        parser.feed(response.text[:2_000_000])
    except Exception:
        return None

    for form in parser.forms:
        if str(form.get("method") or "GET").upper() != "POST":
            continue
        inputs = form.get("inputs")
        if not isinstance(inputs, list):
            continue
        password_inputs = [item for item in inputs if isinstance(item, dict) and item.get("type") == "password"]
        if not password_inputs:
            continue
        password_field = str(password_inputs[0].get("name") or "").strip()
        if not password_field:
            continue

        username_field = None
        if credential_mode == "USERNAME_PASSWORD":
            possible = [
                item for item in inputs
                if isinstance(item, dict)
                and item.get("type") in {"text", "email", "username"}
                and item.get("name") != password_field
            ]
            if not possible:
                continue
            preferred = [
                item for item in possible
                if any(marker in str(item.get("name") or "").lower() for marker in ("user", "login", "email", "account"))
            ]
            username_field = str((preferred or possible)[0].get("name") or "").strip()
            if not username_field:
                continue

        return {
            "action": str(form.get("action") or ""),
            "enctype": str(form.get("enctype") or "application/x-www-form-urlencoded").lower(),
            "username_field": username_field,
            "password_field": password_field,
        }
    return None


async def _ssl_context_for_candidate(
    db: AsyncSession,
    *,
    device_id: UUID,
    scheme: str,
    port: int,
):
    profile = await db.scalar(
        select(DeviceRemoteAccessProfile).where(DeviceRemoteAccessProfile.device_id == device_id)
    )
    if (
        profile is not None
        and web_profile_is_ready(profile)
        and profile.web_scheme == scheme
        and profile_web_port(profile) == port
    ):
        return build_web_ssl_context(profile)
    if scheme == "HTTP":
        return False
    return ssl.create_default_context()


async def _discover_on_origin(
    db: AsyncSession,
    *,
    device_id: UUID,
    management_ip: str,
    scheme: str,
    port: int,
    credential_mode: str,
    username: str | None,
    password: str,
    timeout_seconds: int,
) -> DiscoveredWebTemplate | None:
    verify = await _ssl_context_for_candidate(
        db,
        device_id=device_id,
        scheme=scheme,
        port=port,
    )
    origin = _origin(scheme, management_ip, port)
    timeout = httpx.Timeout(max(1, timeout_seconds), connect=max(1, timeout_seconds))

    try:
        async with httpx.AsyncClient(
            base_url=origin,
            verify=verify,
            follow_redirects=False,
            timeout=timeout,
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
        ) as discovery_client:
            inspected: set[str] = set()
            for candidate_path in COMMON_LOGIN_PATHS:
                if candidate_path in inspected:
                    continue
                inspected.add(candidate_path)
                try:
                    response = await _safe_get(discovery_client, candidate_path)
                except WebTemplateDiscoveryError:
                    continue

                challenge = _auth_challenge(response)
                if challenge:
                    if credential_mode != "USERNAME_PASSWORD":
                        raise WebTemplateDiscoveryError(
                            "WEB_DISCOVERY_CREDENTIAL_MODE_MISMATCH",
                            "The device uses HTTP Basic/Digest authentication, which requires both username and password.",
                        )
                    runtime = WebRuntimeAccess(
                        auth_mode=challenge,
                        credential_mode="USERNAME_PASSWORD",
                        username=username,
                        password=password,
                        timeout_seconds=timeout_seconds,
                    )
                    async with httpx.AsyncClient(
                        base_url=origin,
                        verify=verify,
                        auth=httpx_auth_for_web(runtime),
                        follow_redirects=False,
                        timeout=timeout,
                    ) as auth_client:
                        landing = await authenticate_web_client(auth_client, runtime)
                    return DiscoveredWebTemplate(
                        device_id=device_id,
                        management_ip=management_ip,
                        scheme=scheme,
                        port=port,
                        auth_mode=challenge,
                        credential_mode="USERNAME_PASSWORD",
                        settings={"timeout_seconds": timeout_seconds, "credential_mode": "USERNAME_PASSWORD"},
                        landing_path=landing,
                        form_encoding=None,
                        username_field=None,
                        password_field=None,
                    )

                if looks_like_tp_link_mr_rsa_aes(response.text):
                    if credential_mode != "PASSWORD_ONLY":
                        raise WebTemplateDiscoveryError(
                            "WEB_DISCOVERY_CREDENTIAL_MODE_MISMATCH",
                            "This device presents a password-only encrypted management login. Choose Password only and run discovery again.",
                        )
                    login_page_path = _path_and_query(response.url)
                    settings = {
                        "timeout_seconds": timeout_seconds,
                        "credential_mode": "PASSWORD_ONLY",
                        "login_page_path": login_page_path,
                        "login_submit_path": "/cgi/login",
                        "password_field": "password",
                        "capture_hidden_fields": False,
                    }
                    runtime = WebRuntimeAccess(
                        auth_mode="FORM_POST",
                        credential_mode="PASSWORD_ONLY",
                        password=password,
                        timeout_seconds=timeout_seconds,
                        login_page_path=login_page_path,
                        login_submit_path="/cgi/login",
                        password_field="password",
                        capture_hidden_fields=False,
                    )
                    async with httpx.AsyncClient(
                        base_url=origin,
                        verify=verify,
                        follow_redirects=False,
                        timeout=timeout,
                        limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
                    ) as auth_client:
                        landing = await authenticate_web_client(auth_client, runtime)
                    return DiscoveredWebTemplate(
                        device_id=device_id,
                        management_ip=management_ip,
                        scheme=scheme,
                        port=port,
                        auth_mode="FORM_POST",
                        credential_mode="PASSWORD_ONLY",
                        settings=settings,
                        landing_path=landing,
                        form_encoding="TP-Link RSA/AES encrypted handshake",
                        username_field=None,
                        password_field=None,
                        auth_family=TP_LINK_MR_AUTH_FAMILY,
                    )

                form = _candidate_form(response, credential_mode)
                if not form:
                    continue
                login_page_path = _path_and_query(response.url)
                action = str(form["action"] or "")
                action_url = urljoin(str(response.url), action or login_page_path)
                if not _same_origin(action_url, discovery_client.base_url):
                    raise WebTemplateDiscoveryError(
                        "WEB_DISCOVERY_EXTERNAL_FORM_ACTION",
                        "The detected login form submits outside the registered management origin.",
                    )
                submit_path = _path_and_query(action_url)
                settings: dict[str, object] = {
                    "timeout_seconds": timeout_seconds,
                    "credential_mode": credential_mode,
                    "login_page_path": login_page_path,
                    "login_submit_path": submit_path,
                    "password_field": form["password_field"],
                    "capture_hidden_fields": True,
                }
                if credential_mode == "USERNAME_PASSWORD":
                    settings["username_field"] = form["username_field"]

                runtime = WebRuntimeAccess(
                    auth_mode="FORM_POST",
                    credential_mode=credential_mode,
                    username=username,
                    password=password,
                    timeout_seconds=timeout_seconds,
                    login_page_path=login_page_path,
                    login_submit_path=submit_path,
                    username_field=str(form["username_field"] or "username"),
                    password_field=str(form["password_field"]),
                    capture_hidden_fields=True,
                )
                async with httpx.AsyncClient(
                    base_url=origin,
                    verify=verify,
                    follow_redirects=False,
                    timeout=timeout,
                    limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
                ) as auth_client:
                    landing = await authenticate_web_client(auth_client, runtime)

                landing_path = urlsplit(landing).path or "/"
                login_path = urlsplit(login_page_path).path or "/"
                if landing_path != login_path:
                    settings["success_path_prefix"] = landing_path
                return DiscoveredWebTemplate(
                    device_id=device_id,
                    management_ip=management_ip,
                    scheme=scheme,
                    port=port,
                    auth_mode="FORM_POST",
                    credential_mode=credential_mode,
                    settings=settings,
                    landing_path=landing,
                    form_encoding=str(form["enctype"]),
                    username_field=str(form["username_field"]) if form["username_field"] else None,
                    password_field=str(form["password_field"]),
                )
    except httpx.ConnectError as exc:
        if scheme == "HTTPS" and isinstance(exc.__cause__, ssl.SSLError):
            raise WebTemplateDiscoveryError(
                "WEB_DISCOVERY_TLS_TRUST_REQUIRED",
                "HTTPS is reachable but its certificate is not trusted. Configure device-specific TLS trust, then run discovery again.",
            ) from exc
        return None
    except httpx.TransportError:
        return None
    except WebAuthenticationError as exc:
        code = str(exc)
        messages = {
            "WEB_AUTHENTICATION_FAILED": "The reference device rejected the supplied credentials.",
            "WEB_AUTHENTICATION_UNCONFIRMED": "FTTW submitted the detected login exchange but could not confirm an authenticated session.",
            "WEB_AUTH_EXTERNAL_REDIRECT_BLOCKED": "The device attempted to redirect authentication outside its registered management origin.",
            "WEB_AUTH_REDIRECT_LIMIT": "The authentication exchange exceeded the bounded redirect limit.",
            "WEB_AUTH_LOGIN_REQUEST_REJECTED": "The device rejected the detected login request.",
            "WEB_AUTH_UPSTREAM_FAILURE": "The device Web-GUI failed during authentication.",
            "WEB_AUTH_CONNECT_FAILED": "FTTW could not complete the detected authentication exchange.",
            "WEB_AUTH_VENDOR_CRYPTO_UNSUPPORTED": "FTTW recognized an encrypted device login family, but this firmware uses a crypto variant that is not yet supported.",
            "WEB_AUTH_MODE_UNSUPPORTED": "The detected Web-GUI authentication family is not supported by the current gateway.",
        }
        raise WebTemplateDiscoveryError(
            code if code in messages else "WEB_DISCOVERY_AUTHENTICATION_FAILED",
            messages.get(code, "The detected Web-GUI authentication exchange failed."),
        ) from exc
    return None


async def discover_web_template(
    db: AsyncSession,
    *,
    device_id: UUID,
    management_ip: str,
    credential_mode: str,
    username: str | None,
    password: str,
    timeout_seconds: int = 10,
) -> DiscoveredWebTemplate:
    target = validate_management_target(management_ip)
    mode = credential_mode.strip().upper()
    if mode not in {"USERNAME_PASSWORD", "PASSWORD_ONLY"}:
        raise WebTemplateDiscoveryError(
            "WEB_DISCOVERY_CREDENTIAL_MODE_INVALID",
            "Choose whether the reference device requires username + password or password only.",
        )
    if not password:
        raise WebTemplateDiscoveryError(
            "WEB_DISCOVERY_PASSWORD_REQUIRED",
            "The reference device password is required for discovery.",
        )
    if mode == "USERNAME_PASSWORD" and not username:
        raise WebTemplateDiscoveryError(
            "WEB_DISCOVERY_USERNAME_REQUIRED",
            "The reference device username is required for username + password discovery.",
        )
    timeout_seconds = max(1, min(int(timeout_seconds), 30))

    open_endpoints: list[tuple[str, int]] = []
    for scheme, port in COMMON_WEB_ENDPOINTS:
        if await _tcp_open(target, port, timeout_seconds):
            open_endpoints.append((scheme, port))
    if not open_endpoints:
        raise WebTemplateDiscoveryError(
            "WEB_DISCOVERY_PORT_UNREACHABLE",
            "No supported Web-GUI management port was reachable on the registered reference device.",
        )

    deferred_tls_error: WebTemplateDiscoveryError | None = None
    for scheme, port in open_endpoints:
        try:
            result = await _discover_on_origin(
                db,
                device_id=device_id,
                management_ip=target,
                scheme=scheme,
                port=port,
                credential_mode=mode,
                username=username,
                password=password,
                timeout_seconds=timeout_seconds,
            )
        except WebTemplateDiscoveryError as exc:
            if exc.code == "WEB_DISCOVERY_TLS_TRUST_REQUIRED":
                deferred_tls_error = exc
                continue
            raise
        if result is not None:
            return result

    if deferred_tls_error is not None:
        raise deferred_tls_error
    raise WebTemplateDiscoveryError(
        "WEB_DISCOVERY_LOGIN_CONTRACT_NOT_FOUND",
        "FTTW reached the reference device but could not identify a supported Basic, Digest, HTML form, or recognized encrypted login contract.",
    )
