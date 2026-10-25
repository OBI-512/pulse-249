from __future__ import annotations

import logging
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from ..db.session import AsyncSessionLocal
from ..models import AccessTemplate, AccessTemplateTestResult
from ..services.access_template_lifecycle import (
    list_revisions,
    resolved_revision_secrets,
    revision_definition_sha256,
    runtime_template_for_revision,
)
from ..services.access_template_runtime import build_web_runtime_access, resolve_web_runtime_access
from ..services.access_templates import AccessTemplateSecretError, resolve_effective_access, resolved_secrets
from ..settings import settings
from .web_auth import (
    WebAuthenticationError,
    WebInitialResponse,
    authenticate_web_client_with_session,
    httpx_auth_for_web,
)
from .web_protocol_session import WebProtocolSession, WebProtocolSessionError
from .web_proxy import (
    COOKIE_NAME,
    _audit_web,
    _browser_transport_is_secure,
    _consume_web_ticket,
    _create_state,
    _drop_state,
    _mark_web_failed,
    _security_headers,
)


logger = logging.getLogger("fttw.remote_gateway.web.bootstrap")
router = APIRouter()


class IdempotentRemoteProtocolRetryClient(httpx.AsyncClient):
    """Legacy-safe gateway client for authenticated embedded Web interfaces.

    Many embedded management servers advertise HTTP/1.1 persistence but close
    sockets without a standards-compliant response boundary. Reusing those
    sockets can surface as ``RemoteProtocolError`` on the next browser request,
    including POST-based read APIs used by vendor GUIs. The gateway therefore
    asks the device to close every upstream response and keeps no idle upstream
    connections. Cookies and application tokens remain session state and are
    preserved independently of the TCP connection.

    An optional protocol-session adapter can retain post-login cryptographic
    state required by a device family. The generic client invokes that adapter
    before/after exact-origin requests; the Web proxy itself remains vendor
    agnostic. A single retry remains available only for idempotent GET/HEAD.
    Mutating methods are never retried automatically.
    """

    def __init__(self, *args, fttw_session_id=None, **kwargs):
        headers = httpx.Headers(kwargs.pop("headers", None))
        headers["Connection"] = "close"
        kwargs["headers"] = headers
        kwargs.setdefault(
            "limits",
            httpx.Limits(
                max_connections=16,
                max_keepalive_connections=0,
                keepalive_expiry=0.0,
            ),
        )
        super().__init__(*args, **kwargs)
        self._fttw_session_id = fttw_session_id
        self._protocol_session: WebProtocolSession | None = None
        self._initial_response: tuple[str, WebInitialResponse] | None = None

    def set_protocol_session(self, protocol_session: WebProtocolSession | None) -> None:
        self._protocol_session = protocol_session

    def set_initial_response(
        self,
        landing_path: str,
        initial_response: WebInitialResponse | None,
    ) -> None:
        self._initial_response = (
            (landing_path, initial_response)
            if initial_response is not None
            else None
        )

    async def send(self, request: httpx.Request, *args, **kwargs) -> httpx.Response:
        active_request = request
        if self._protocol_session is not None:
            try:
                active_request = self._protocol_session.prepare_request(request)
            except WebProtocolSessionError:
                logger.warning(
                    "remote_access_web_protocol_request_failure session_id=%s family=%s method=%s path=%s",
                    self._fttw_session_id,
                    self._protocol_session.family,
                    request.method.upper(),
                    request.url.path,
                )
                raise

        # A browser normally renders the HTTP response that completed FORM_POST
        # authentication. Do the same once when the device created no persistent
        # cookie-backed session instead of immediately issuing a fresh GET.
        pending = self._initial_response

        if pending is not None and active_request.method.upper() == "GET":
            landing_path, snapshot = pending

            parsed = urlsplit(str(active_request.url))
            request_path = parsed.path or "/"

            if parsed.query:
                request_path += f"?{parsed.query}"

            if request_path == landing_path:
                self._initial_response = None

                return httpx.Response(
                    snapshot.status_code,
                    headers=snapshot.headers,
                    content=snapshot.content,
                    request=active_request,
                )

        try:
            response = await super().send(active_request, *args, **kwargs)
        except httpx.RemoteProtocolError:
            method = active_request.method.upper()
            if method not in {"GET", "HEAD"}:
                logger.warning(
                    "remote_access_web_remote_protocol_non_idempotent_failure session_id=%s method=%s path=%s",
                    self._fttw_session_id,
                    method,
                    active_request.url.path,
                )
                raise
            logger.info(
                "remote_access_web_remote_protocol_retry session_id=%s method=%s path=%s",
                self._fttw_session_id,
                method,
                active_request.url.path,
            )
            try:
                response = await super().send(active_request, *args, **kwargs)
            except httpx.RemoteProtocolError:
                logger.warning(
                    "remote_access_web_remote_protocol_retry_exhausted session_id=%s method=%s path=%s",
                    self._fttw_session_id,
                    method,
                    active_request.url.path,
                )
                raise

        if self._protocol_session is None:
            return response
        try:
            return await self._protocol_session.prepare_response(active_request, response)
        except WebProtocolSessionError:
            await response.aclose()
            logger.warning(
                "remote_access_web_protocol_response_failure session_id=%s family=%s method=%s path=%s",
                self._fttw_session_id,
                self._protocol_session.family,
                active_request.method.upper(),
                active_request.url.path,
            )
            raise


async def _inactive_web_revision_runtime(db, *, template: AccessTemplate, device_id):
    revisions = [
        row
        for row in await list_revisions(db, template_id=template.id)
        if row.lifecycle_status != "RETIRED"
    ]
    if not revisions:
        raise AccessTemplateSecretError("WEB_WIZARD_REVISION_REQUIRED")
    if len(revisions) != 1:
        raise AccessTemplateSecretError("WEB_WIZARD_REVISION_AMBIGUOUS")
    revision = revisions[0]
    if revision.lifecycle_status not in {"TESTED", "APPROVED"}:
        raise AccessTemplateSecretError("WEB_WIZARD_CONNECTION_TEST_REQUIRED")
    fingerprint = await revision_definition_sha256(
        db,
        template=template,
        revision=revision,
    )
    if not revision.definition_sha256 or revision.definition_sha256 != fingerprint:
        raise AccessTemplateSecretError("WEB_WIZARD_CONNECTION_TEST_STALE")
    latest = await db.scalar(
        select(AccessTemplateTestResult)
        .where(
            AccessTemplateTestResult.template_id == template.id,
            AccessTemplateTestResult.revision_id == revision.id,
            AccessTemplateTestResult.device_id == device_id,
        )
        .order_by(
            AccessTemplateTestResult.tested_at.desc(),
            AccessTemplateTestResult.id.desc(),
        )
        .limit(1)
    )
    if latest is None or latest.status != "SUCCESS":
        raise AccessTemplateSecretError("WEB_WIZARD_CONNECTION_TEST_REQUIRED")
    runtime_template = runtime_template_for_revision(template, revision)
    auth_mode = (revision.protocol_variant or "FORM_POST").strip().upper()
    secrets = {} if auth_mode == "NONE" else await resolved_revision_secrets(
        db,
        template_id=template.id,
        revision_id=revision.id,
    )
    return build_web_runtime_access(runtime_template, secrets)


async def _web_template_context(device_id, explicit_template_id=None):
    async with AsyncSessionLocal() as db:
        if explicit_template_id is not None:
            template = await db.get(AccessTemplate, explicit_template_id)
            if template is None or template.deleted_at is not None or template.protocol != "WEB":
                raise AccessTemplateSecretError("WEB_ACCESS_TEMPLATE_REQUIRED")
            if not template.is_active:
                runtime = await _inactive_web_revision_runtime(
                    db,
                    template=template,
                    device_id=device_id,
                )
                return runtime, template.id, template.name, False
            auth_mode = (template.protocol_variant or "FORM_POST").strip().upper()
            secrets = {} if auth_mode == "NONE" else await resolved_secrets(db, template.id)
            runtime = build_web_runtime_access(template, secrets)
            return runtime, template.id, template.name, template.is_active

        effective = await resolve_effective_access(db, device_id=device_id, protocol="WEB")
        if effective.status == "NONE" or effective.template is None:
            raise AccessTemplateSecretError("WEB_ACCESS_TEMPLATE_REQUIRED")
        if effective.status == "CONFLICT":
            raise AccessTemplateSecretError("CONFIGURATION_CONFLICT")
        runtime = await resolve_web_runtime_access(db, device_id=device_id)
        if runtime is None:
            raise AccessTemplateSecretError("WEB_ACCESS_TEMPLATE_REQUIRED")
        return runtime, effective.template.id, effective.template.name, effective.template.is_active


async def _configure_authenticated_client(state, runtime) -> str:
    auth = httpx_auth_for_web(runtime)
    old_client = state.client
    client = IdempotentRemoteProtocolRetryClient(
        base_url=state.target_origin,
        verify=state.ssl_context,
        auth=auth,
        follow_redirects=False,
        timeout=httpx.Timeout(
            max(1, runtime.timeout_seconds),
            connect=max(1, runtime.timeout_seconds),
        ),
        limits=httpx.Limits(
            max_connections=16,
            max_keepalive_connections=0,
            keepalive_expiry=0.0,
        ),
        fttw_session_id=state.session_id,
    )
    state.client = client
    await old_client.aclose()
    result = await authenticate_web_client_with_session(client, runtime)
    client.set_protocol_session(result.protocol_session)
    client.set_initial_response(
        result.landing_path,
        result.initial_response,
    )
    return result.landing_path


@router.post("/web/bootstrap")
async def web_template_bootstrap(
    request: Request,
    x_remote_access_ticket: str | None = Header(default=None, alias="X-Remote-Access-Ticket"),
    x_fttw_web_bootstrap: str | None = Header(default=None, alias="X-FTTW-Web-Bootstrap"),
):
    if not settings.remote_access_enabled:
        return JSONResponse({"message": "Remote access is disabled."}, status_code=503)
    if settings.fttw_env.lower() == "production" and not _browser_transport_is_secure(request):
        return JSONResponse({"message": "HTTPS is required for native Web-GUI sessions."}, status_code=503)
    if x_fttw_web_bootstrap != "1" or not x_remote_access_ticket:
        return JSONResponse({"message": "One-time launch ticket required."}, status_code=401)

    context, error = await _consume_web_ticket(x_remote_access_ticket.strip())
    if error:
        return JSONResponse({"message": "Remote Web-GUI launch was denied.", "code": error}, status_code=401)

    state = None
    landing_path = "/"
    try:
        runtime, template_id, template_name, template_active = await _web_template_context(
            context["device_id"],
            getattr(context["session"], "access_template_id", None),
        )
        state = await _create_state(context)
        landing_path = await _configure_authenticated_client(state, runtime)
        await _audit_web(
            context["session"],
            "REMOTE_ACCESS_WEB_AUTHENTICATED",
            "Device Web-GUI authentication completed inside the access gateway.",
            {
                "credential_source": "ACCESS_TEMPLATE",
                "template_id": str(template_id),
                "template_name": template_name[:160],
                "template_active": bool(template_active),
                "auth_mode": runtime.auth_mode,
                "credential_mode": runtime.credential_mode,
                "browser_received_device_credentials": False,
            },
        )
    except AccessTemplateSecretError as exc:
        code = str(exc)
        if state is not None:
            await _drop_state(state.handle)
        await _mark_web_failed(context["session"].id, code)
        return JSONResponse(
            {"message": "Secure Web-GUI Access Template is unavailable or conflicted.", "code": code},
            status_code=409,
        )
    except WebAuthenticationError as exc:
        code = str(exc)
        if state is not None:
            await _drop_state(state.handle)
        await _mark_web_failed(context["session"].id, code)
        return JSONResponse(
            {"message": "The device Web-GUI authentication could not be completed by FTTW.", "code": code},
            status_code=502,
        )
    except httpx.HTTPError:
        if state is not None:
            await _drop_state(state.handle)
        await _mark_web_failed(context["session"].id, "WEB_AUTH_CONNECT_FAILED")
        return JSONResponse(
            {"message": "The device Web-GUI could not be reached for server-side authentication.", "code": "WEB_AUTH_CONNECT_FAILED"},
            status_code=502,
        )

    response = JSONResponse({"session_id": str(state.session_id), "launch_path": f"{state.proxy_base}{landing_path}"})
    response.set_cookie(
        COOKIE_NAME,
        state.handle,
        max_age=max(60, settings.remote_access_session_max_seconds),
        httponly=True,
        secure=_browser_transport_is_secure(request),
        samesite="strict",
        path=state.proxy_base,
    )
    response.headers.update(_security_headers())
    return response
