from __future__ import annotations

import logging
import socket
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from ..core.exceptions import APIError
from ..db.session import AsyncSessionLocal
from ..models import AuthSession, Device, DeviceIP, DeviceRemoteAccessProfile, RemoteAccessSession, User
from ..security.sessions import SESSION_IDLE_TIMEOUT_MINUTES
from ..services.remote_access import hash_remote_ticket, profile_web_port, web_profile_is_ready_async
from ..services.web_tls_runtime import resolve_verified_web_ssl_context
from ..settings import settings
from .web_template_bootstrap import _configure_authenticated_client, _web_template_context
from .web_proxy import (
    COOKIE_NAME,
    _audit_web,
    _browser_transport_is_secure,
    _create_state,
    _drop_state,
    _mark_web_failed,
    _security_headers,
    validate_management_target,
)
from ..services.access_templates import AccessTemplateSecretError
from .web_auth import WebAuthenticationError


logger = logging.getLogger("fttw.remote_gateway.web.tls_bootstrap")
router = APIRouter()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _api_error_code(exc: APIError, fallback: str) -> str:
    detail = exc.detail if isinstance(exc.detail, dict) else {}
    return str(detail.get("code") or fallback)


async def _record_web_denied(db, session: RemoteAccessSession, code: str) -> tuple[None, str]:
    actor = await db.get(User, session.actor_user_id) if session.actor_user_id else None
    from ..services.audit import record_audit

    await record_audit(
        db,
        action="REMOTE_ACCESS_WEB_DENIED",
        entity_type="Device",
        entity_id=session.device_id,
        actor_user_id=session.actor_user_id,
        actor_username_snapshot=getattr(actor, "username", None),
        actor_display_name_snapshot=getattr(actor, "display_name", None),
        description="Brokered native Web-GUI launch was denied.",
        metadata={"remote_access_session_id": str(session.id), "denial_code": code[:120]},
    )
    await db.commit()
    return None, code


async def _consume_verified_web_ticket(ticket: str):
    """Consume one WEB ticket only after a credential-free TLS verification.

    For HTTPS this function validates the configured trust using a TLS handshake
    that sends no HTTP/application bytes. WEB Access Template credentials are
    deliberately resolved later by the bootstrap handler, after this function
    has returned a verified transport context.
    """

    now = _utcnow()
    async with AsyncSessionLocal() as db:
        session = await db.scalar(
            select(RemoteAccessSession)
            .where(RemoteAccessSession.ticket_hash == hash_remote_ticket(ticket))
            .with_for_update()
        )
        if session is None:
            return None, "REMOTE_ACCESS_TICKET_INVALID"
        if session.mode != "WEB":
            return await _record_web_denied(db, session, "REMOTE_ACCESS_TICKET_MODE_INVALID")
        if session.status != "ISSUED" or session.consumed_at is not None:
            return await _record_web_denied(db, session, "REMOTE_ACCESS_TICKET_ALREADY_USED")
        if session.revoked_at is not None or session.expires_at <= now:
            return await _record_web_denied(db, session, "REMOTE_ACCESS_TICKET_EXPIRED")

        auth = await db.get(AuthSession, session.auth_session_id) if session.auth_session_id else None
        if auth is None:
            return await _record_web_denied(db, session, "AUTH_SESSION_REQUIRED")
        auth_last = auth.last_user_activity_at or auth.created_at
        if (
            auth.revoked_at is not None
            or auth.expires_at <= now
            or auth_last <= now - timedelta(minutes=SESSION_IDLE_TIMEOUT_MINUTES)
        ):
            return await _record_web_denied(db, session, "AUTH_SESSION_EXPIRED")

        device = await db.get(Device, session.device_id)
        if device is None or device.deleted_at is not None or device.lifecycle_state == "DECOMMISSIONED":
            return await _record_web_denied(db, session, "DEVICE_NOT_AVAILABLE")

        profile = await db.scalar(
            select(DeviceRemoteAccessProfile).where(DeviceRemoteAccessProfile.device_id == device.id)
        )
        if not await web_profile_is_ready_async(db, profile):
            return await _record_web_denied(db, session, "REMOTE_ACCESS_WEB_NOT_CONFIGURED")
        assert profile is not None
        try:
            target_port = profile_web_port(profile)
        except ValueError:
            return await _record_web_denied(db, session, "REMOTE_ACCESS_WEB_PORT_INVALID")

        ip = await db.scalar(
            select(DeviceIP.ip_address)
            .where(
                DeviceIP.device_id == device.id,
                DeviceIP.deleted_at.is_(None),
                DeviceIP.is_management.is_(True),
            )
            .order_by(DeviceIP.is_primary.desc(), DeviceIP.created_at.asc())
            .limit(1)
        )
        if not ip:
            return await _record_web_denied(db, session, "DEVICE_MANAGEMENT_IP_REQUIRED")

        try:
            target_host = validate_management_target(ip)
            ssl_context = await resolve_verified_web_ssl_context(
                db,
                profile=profile,
                management_ip=target_host,
                port=target_port,
                actor_user_id=session.actor_user_id,
            )
        except APIError as exc:
            return await _record_web_denied(
                db,
                session,
                _api_error_code(exc, "REMOTE_ACCESS_WEB_TLS_OR_CONNECT_FAILURE"),
            )
        except ValueError:
            return await _record_web_denied(db, session, "REMOTE_ACCESS_WEB_TARGET_INVALID")

        auth.last_user_activity_at = now
        session.status = "ACTIVE"
        session.consumed_at = now
        session.activated_at = now
        session.last_activity_at = now
        session.gateway_instance = socket.gethostname()[:120]

        from ..services.audit import record_audit

        actor = await db.get(User, session.actor_user_id) if session.actor_user_id else None
        await record_audit(
            db,
            action="REMOTE_ACCESS_WEB_STARTED",
            entity_type="Device",
            entity_id=device.id,
            actor_user_id=session.actor_user_id,
            actor_username_snapshot=getattr(actor, "username", None),
            actor_display_name_snapshot=getattr(actor, "display_name", None),
            description="Brokered native Web-GUI session started after credential-free TLS verification.",
            metadata={
                "remote_access_session_id": str(session.id),
                "scheme": profile.web_scheme,
                "port": target_port,
                "tls_mode": profile.web_tls_mode,
                "tls_verified_before_credentials": True,
                "credentials_sent_during_tls_preflight": False,
                "application_data_sent_during_tls_preflight": False,
            },
        )
        await db.commit()
        return {
            "session": session,
            "device_id": device.id,
            "auth_session_id": auth.id,
            "target_host": target_host,
            "scheme": profile.web_scheme,
            "port": target_port,
            "tls_mode": profile.web_tls_mode,
            "ssl_context": ssl_context,
            "activated_at": now,
        }, None


@router.post("/web/bootstrap")
async def web_tls_template_bootstrap(
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

    context, error = await _consume_verified_web_ticket(x_remote_access_ticket.strip())
    if error:
        return JSONResponse(
            {"message": "Remote Web-GUI launch was denied.", "code": error},
            status_code=401,
        )

    state = None
    landing_path = "/"
    try:
        # This is intentionally the first point where Access Template secrets
        # may be resolved. The TLS identity has already been verified above.
        runtime, template_id, template_name, template_active = await _web_template_context(
            context["device_id"],
            getattr(context["session"], "access_template_id", None),
        )
        state = await _create_state(context)
        landing_path = await _configure_authenticated_client(state, runtime)
        await _audit_web(
            context["session"],
            "REMOTE_ACCESS_WEB_AUTHENTICATED",
            "Device Web-GUI authentication completed inside the access gateway after TLS verification.",
            {
                "credential_source": "ACCESS_TEMPLATE",
                "template_id": str(template_id),
                "template_name": template_name[:160],
                "template_active": bool(template_active),
                "auth_mode": runtime.auth_mode,
                "credential_mode": runtime.credential_mode,
                "browser_received_device_credentials": False,
                "tls_verified_before_credentials": True,
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
            {
                "message": "The device Web-GUI could not be reached for server-side authentication.",
                "code": "WEB_AUTH_CONNECT_FAILED",
            },
            status_code=502,
        )

    response = JSONResponse(
        {"session_id": str(state.session_id), "launch_path": f"{state.proxy_base}{landing_path}"}
    )
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
