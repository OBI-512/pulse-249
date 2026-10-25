from __future__ import annotations

from urllib.parse import urlsplit
from uuid import UUID

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from ..remote_gateway.web_auth import WebAuthenticationError, authenticate_web_client, httpx_auth_for_web
from ..remote_gateway.web_proxy import validate_management_target
from .access_template_runtime import WebRuntimeAccess
from .web_template_discovery import (
    DiscoveredWebTemplate,
    WebTemplateDiscoveryError,
    _origin,
    _ssl_context_for_candidate,
)


def _relative_path(value: str, *, field: str) -> str:
    path = value.strip() or "/"
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or not path.startswith("/"):
        raise WebTemplateDiscoveryError(
            "WEB_MANUAL_PATH_INVALID",
            f"{field} must be a target-relative path beginning with '/'.",
        )
    return path


async def verify_manual_web_template(
    db: AsyncSession,
    *,
    device_id: UUID,
    management_ip: str,
    scheme: str,
    port: int,
    auth_mode: str,
    credential_mode: str,
    username: str | None,
    password: str,
    timeout_seconds: int,
    login_page_path: str = "/",
    login_submit_path: str = "/",
    username_field: str = "username",
    password_field: str = "password",
    capture_hidden_fields: bool = True,
    success_path_prefix: str | None = None,
    success_text: str | None = None,
    failure_text: str | None = None,
) -> DiscoveredWebTemplate:
    """Verify an operator-supplied generic Web login contract before draft creation."""

    target = validate_management_target(management_ip)
    normalized_scheme = scheme.strip().upper()
    if normalized_scheme not in {"HTTP", "HTTPS"}:
        raise WebTemplateDiscoveryError("WEB_MANUAL_SCHEME_INVALID", "Manual Web transport must be HTTP or HTTPS.")
    if port < 1 or port > 65535:
        raise WebTemplateDiscoveryError("WEB_MANUAL_PORT_INVALID", "Manual Web port must be between 1 and 65535.")

    normalized_auth = auth_mode.strip().upper()
    if normalized_auth not in {"FORM_POST", "HTTP_BASIC", "HTTP_DIGEST"}:
        raise WebTemplateDiscoveryError(
            "WEB_MANUAL_AUTH_MODE_INVALID",
            "Manual fallback supports HTML form, HTTP Basic, or HTTP Digest authentication.",
        )
    normalized_credential_mode = credential_mode.strip().upper()
    if normalized_credential_mode not in {"USERNAME_PASSWORD", "PASSWORD_ONLY"}:
        raise WebTemplateDiscoveryError("WEB_MANUAL_CREDENTIAL_MODE_INVALID", "Invalid manual credential mode.")
    if normalized_auth in {"HTTP_BASIC", "HTTP_DIGEST"} and normalized_credential_mode != "USERNAME_PASSWORD":
        raise WebTemplateDiscoveryError(
            "WEB_MANUAL_CREDENTIAL_MODE_INVALID",
            "HTTP Basic and Digest require username + password credentials.",
        )
    if not password:
        raise WebTemplateDiscoveryError("WEB_DISCOVERY_PASSWORD_REQUIRED", "The reference device password is required.")
    if normalized_credential_mode == "USERNAME_PASSWORD" and not username:
        raise WebTemplateDiscoveryError("WEB_DISCOVERY_USERNAME_REQUIRED", "The reference device username is required.")

    timeout_seconds = max(1, min(int(timeout_seconds), 30))
    login_path = _relative_path(login_page_path, field="Login page path")
    submit_path = _relative_path(login_submit_path, field="Login submit path")
    success_prefix = _relative_path(success_path_prefix, field="Success path prefix") if success_path_prefix else None
    if not password_field.strip():
        raise WebTemplateDiscoveryError("WEB_MANUAL_PASSWORD_FIELD_REQUIRED", "Password field is required for form authentication.")
    if normalized_auth == "FORM_POST" and normalized_credential_mode == "USERNAME_PASSWORD" and not username_field.strip():
        raise WebTemplateDiscoveryError("WEB_MANUAL_USERNAME_FIELD_REQUIRED", "Username field is required for this form login.")

    settings: dict[str, object] = {
        "timeout_seconds": timeout_seconds,
        "credential_mode": normalized_credential_mode,
    }
    runtime_kwargs: dict[str, object] = {}
    if normalized_auth == "FORM_POST":
        settings.update({
            "login_page_path": login_path,
            "login_submit_path": submit_path,
            "password_field": password_field.strip(),
            "capture_hidden_fields": bool(capture_hidden_fields),
        })
        if normalized_credential_mode == "USERNAME_PASSWORD":
            settings["username_field"] = username_field.strip()
        if success_prefix:
            settings["success_path_prefix"] = success_prefix
        if success_text and success_text.strip():
            settings["success_text"] = success_text.strip()
        if failure_text and failure_text.strip():
            settings["failure_text"] = failure_text.strip()
        runtime_kwargs = {
            "login_page_path": login_path,
            "login_submit_path": submit_path,
            "username_field": username_field.strip() or "username",
            "password_field": password_field.strip(),
            "capture_hidden_fields": bool(capture_hidden_fields),
            "success_path_prefix": success_prefix,
            "success_text": success_text.strip() if success_text else None,
            "failure_text": failure_text.strip() if failure_text else None,
        }

    runtime = WebRuntimeAccess(
        auth_mode=normalized_auth,
        credential_mode=normalized_credential_mode,
        username=username,
        password=password,
        timeout_seconds=timeout_seconds,
        **runtime_kwargs,
    )
    verify = await _ssl_context_for_candidate(
        db,
        device_id=device_id,
        scheme=normalized_scheme,
        port=port,
    )
    origin = _origin(normalized_scheme, target, port)
    timeout = httpx.Timeout(timeout_seconds, connect=timeout_seconds)

    try:
        async with httpx.AsyncClient(
            base_url=origin,
            verify=verify,
            auth=httpx_auth_for_web(runtime),
            follow_redirects=False,
            timeout=timeout,
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
        ) as client:
            landing = await authenticate_web_client(client, runtime)
    except WebAuthenticationError as exc:
        raise WebTemplateDiscoveryError(
            "WEB_MANUAL_VERIFICATION_FAILED",
            "The supplied manual Web login contract did not authenticate successfully.",
        ) from exc
    except httpx.TransportError as exc:
        raise WebTemplateDiscoveryError(
            "WEB_MANUAL_CONNECT_FAILED",
            "FTTW could not reach the manual Web transport using the supplied scheme and port.",
        ) from exc

    return DiscoveredWebTemplate(
        device_id=device_id,
        management_ip=target,
        scheme=normalized_scheme,
        port=port,
        auth_mode=normalized_auth,
        credential_mode=normalized_credential_mode,
        settings=settings,
        landing_path=landing,
        form_encoding="operator-supplied / server-verified" if normalized_auth == "FORM_POST" else None,
        username_field=username_field.strip() if normalized_auth == "FORM_POST" and normalized_credential_mode == "USERNAME_PASSWORD" else None,
        password_field=password_field.strip() if normalized_auth == "FORM_POST" else None,
        confidence="MEDIUM",
    )
