from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import socket
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.session import AsyncSessionLocal
from ..models import (
    AuthSession,
    Device,
    DeviceIP,
    DeviceRemoteAccessProfile,
    RemoteAccessSession,
    User,
)
from ..security.sessions import SESSION_IDLE_TIMEOUT_MINUTES
from ..services.access_template_runtime import resolve_ssh_runtime_access
from ..services.access_templates import AccessTemplateSecretError
from ..services.audit import record_audit
from ..services.remote_access import hash_remote_ticket
from ..settings import settings
from .secrets import RemoteAccessSecretError, resolve_secret_reference
from .ssh_transport import (
    SSH_HOST_KEY_LINE_METADATA_KEY,
    SSHTransportError,
    read_pty,
    resize_pty,
    start_ssh,
    write_pty,
    write_pty_bytes,
)
from .telnet_gateway import router as telnet_router
from .web_tls_bootstrap import router as web_tls_bootstrap_router
from .web_template_bootstrap import router as web_template_bootstrap_router
from .web_proxy import router as web_proxy_router, start_web_proxy_cleanup, stop_web_proxy_cleanup


logger = logging.getLogger("fttw.remote_gateway")


@asynccontextmanager
async def lifespan(_: FastAPI):
    await start_web_proxy_cleanup()
    try:
        yield
    finally:
        await stop_web_proxy_cleanup()


app = FastAPI(
    title="FTTW Remote Access Gateway",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
# TP3's TLS-first authenticated bootstrap must be the first /web/bootstrap
# route. Starlette resolves the first matching route, so WEB credentials cannot
# be resolved until the registered HTTPS identity has passed its credential-free
# verification. Historical bootstrap/proxy routes remain as compatibility code
# behind this first-match security boundary.
app.include_router(web_tls_bootstrap_router)
app.include_router(web_template_bootstrap_router)
app.include_router(web_proxy_router)
app.include_router(telnet_router)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _allowed_origins() -> set[str]:
    return {
        value.strip()
        for value in settings.remote_access_allowed_origins.split(",")
        if value.strip()
    }


async def _mark_failed(session_id: UUID, code: str) -> None:
    async with AsyncSessionLocal() as db:
        session = await db.scalar(
            select(RemoteAccessSession)
            .where(RemoteAccessSession.id == session_id)
            .with_for_update()
        )
        if session is None:
            return
        now = _utcnow()
        if session.status not in {"REVOKED", "CLOSED"}:
            session.status = "FAILED"
            session.ended_at = now
            session.error_message = code[:500]
        actor = await db.get(User, session.actor_user_id) if session.actor_user_id else None
        await record_audit(
            db,
            action="REMOTE_ACCESS_SSH_FAILED",
            entity_type="Device",
            entity_id=session.device_id,
            actor_user_id=session.actor_user_id,
            actor_username_snapshot=getattr(actor, "username", None),
            actor_display_name_snapshot=getattr(actor, "display_name", None),
            description="Brokered Web SSH session failed.",
            metadata={
                "remote_access_session_id": str(session.id),
                "failure_code": code,
            },
        )
        await db.commit()


async def _mark_closed(session_id: UUID) -> None:
    async with AsyncSessionLocal() as db:
        session = await db.scalar(
            select(RemoteAccessSession)
            .where(RemoteAccessSession.id == session_id)
            .with_for_update()
        )
        if session is None:
            return
        now = _utcnow()
        if session.status == "ACTIVE":
            session.status = "CLOSED"
            session.ended_at = now
        actor = await db.get(User, session.actor_user_id) if session.actor_user_id else None
        await record_audit(
            db,
            action="REMOTE_ACCESS_SSH_ENDED",
            entity_type="Device",
            entity_id=session.device_id,
            actor_user_id=session.actor_user_id,
            actor_username_snapshot=getattr(actor, "username", None),
            actor_display_name_snapshot=getattr(actor, "display_name", None),
            description="Brokered Web SSH session ended.",
            metadata={"remote_access_session_id": str(session.id)},
        )
        await db.commit()


async def _touch_remote_activity(session_id: UUID) -> None:
    async with AsyncSessionLocal() as db:
        session = await db.get(RemoteAccessSession, session_id)
        if session is not None and session.status == "ACTIVE":
            now = _utcnow()
            session.last_activity_at = now
            # SSH keystrokes are authenticated operator activity too. Keep the
            # linked FTTW auth session alive while the child session is active;
            # logout/revocation and absolute auth expiry still terminate it.
            if session.auth_session_id is not None:
                auth = await db.get(AuthSession, session.auth_session_id)
                if auth is not None and auth.revoked_at is None and auth.expires_at > now:
                    auth.last_user_activity_at = now
            await db.commit()


async def _consume_ticket(ticket: str):
    now = _utcnow()
    ticket_hash = hash_remote_ticket(ticket)
    async with AsyncSessionLocal() as db:
        session = await db.scalar(
            select(RemoteAccessSession)
            .where(RemoteAccessSession.ticket_hash == ticket_hash)
            .with_for_update()
        )
        if session is None:
            return None, "REMOTE_ACCESS_TICKET_INVALID"
        if session.mode != "SSH":
            return None, "REMOTE_ACCESS_TICKET_MODE_INVALID"
        if session.status != "ISSUED" or session.consumed_at is not None:
            return None, "REMOTE_ACCESS_TICKET_ALREADY_USED"
        if session.revoked_at is not None or session.expires_at <= now:
            return None, "REMOTE_ACCESS_TICKET_EXPIRED"

        auth_session = await db.get(AuthSession, session.auth_session_id) if session.auth_session_id else None
        if auth_session is None:
            return None, "AUTH_SESSION_REQUIRED"
        last_activity = auth_session.last_user_activity_at or auth_session.created_at
        if (
            auth_session.revoked_at is not None
            or auth_session.expires_at <= now
            or last_activity <= now - timedelta(minutes=SESSION_IDLE_TIMEOUT_MINUTES)
        ):
            return None, "AUTH_SESSION_EXPIRED"

        device = await db.get(Device, session.device_id)
        if device is None or device.deleted_at is not None or device.lifecycle_state == "DECOMMISSIONED":
            return None, "DEVICE_NOT_AVAILABLE"
        profile = await db.scalar(
            select(DeviceRemoteAccessProfile).where(
                DeviceRemoteAccessProfile.device_id == device.id
            )
        )
        if (
            profile is None
            or not profile.ssh_enabled
            or not profile.ssh_host_key_fingerprint
        ):
            return None, "REMOTE_ACCESS_NOT_CONFIGURED"

        try:
            template_runtime = await resolve_ssh_runtime_access(db, device_id=device.id)
        except AccessTemplateSecretError as exc:
            return None, str(exc)

        if template_runtime is None:
            if not profile.ssh_username_reference or not (
                profile.ssh_password_reference or profile.ssh_private_key_reference
            ):
                return None, "REMOTE_ACCESS_NOT_CONFIGURED"
            credential_source = "REMOTE_ACCESS_PROFILE"
            port = profile.ssh_port
            compatibility_profile = profile.ssh_compatibility_profile
            username = None
            password = None
            private_key = None
            username_reference = profile.ssh_username_reference
            password_reference = profile.ssh_password_reference
            private_key_reference = profile.ssh_private_key_reference
        else:
            credential_source = "ACCESS_TEMPLATE"
            port = template_runtime.port
            compatibility_profile = template_runtime.compatibility_profile
            username = template_runtime.username
            password = template_runtime.password
            private_key = template_runtime.private_key
            username_reference = None
            password_reference = None
            private_key_reference = None

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
            return None, "DEVICE_MANAGEMENT_IP_REQUIRED"

        profile_metadata = dict(profile.metadata_ or {})
        trusted_host_key_line = profile_metadata.get(SSH_HOST_KEY_LINE_METADATA_KEY)
        if not isinstance(trusted_host_key_line, str):
            trusted_host_key_line = None

        # Launching Web SSH is authenticated operator activity. Refresh the
        # parent idle timestamp before the watchdog starts.
        auth_session.last_user_activity_at = now
        session.status = "ACTIVE"
        session.consumed_at = now
        session.activated_at = now
        session.last_activity_at = now
        session.gateway_instance = socket.gethostname()[:120]
        actor = await db.get(User, session.actor_user_id) if session.actor_user_id else None
        await record_audit(
            db,
            action="REMOTE_ACCESS_SSH_STARTED",
            entity_type="Device",
            entity_id=device.id,
            actor_user_id=session.actor_user_id,
            actor_username_snapshot=getattr(actor, "username", None),
            actor_display_name_snapshot=getattr(actor, "display_name", None),
            description="Brokered Web SSH session started.",
            metadata={
                "remote_access_session_id": str(session.id),
                "credential_source": credential_source,
                "trusted_host_key_cached": bool(trusted_host_key_line),
            },
        )
        await db.commit()
        return {
            "session_id": session.id,
            "device_id": device.id,
            "ip": ip,
            "port": port,
            "compatibility_profile": compatibility_profile,
            "credential_source": credential_source,
            "username": username,
            "password": password,
            "private_key": private_key,
            "username_reference": username_reference,
            "password_reference": password_reference,
            "private_key_reference": private_key_reference,
            "fingerprint": profile.ssh_host_key_fingerprint,
            "trusted_host_key_line": trusted_host_key_line,
            "auth_session_id": session.auth_session_id,
            "activated_at": now,
        }, None


async def _session_watchdog(websocket: WebSocket, process, session_id: UUID, auth_session_id: UUID, activated_at: datetime):
    while process.process.poll() is None:
        await asyncio.sleep(2)
        now = _utcnow()
        async with AsyncSessionLocal() as db:
            remote = await db.get(RemoteAccessSession, session_id)
            auth = await db.get(AuthSession, auth_session_id)
            if remote is None or remote.status != "ACTIVE" or remote.revoked_at is not None:
                process.process.terminate()
                await websocket.close(code=4003, reason="Remote-access session revoked.")
                return
            if now >= activated_at + timedelta(seconds=max(60, settings.remote_access_session_max_seconds)):
                remote.status = "REVOKED"
                remote.revoked_at = now
                remote.ended_at = now
                remote.revoked_reason = "MAX_SESSION_DURATION"
                await db.commit()
                process.process.terminate()
                await websocket.close(code=4003, reason="Remote-access session expired.")
                return
            last_remote_activity = remote.last_activity_at or remote.activated_at or remote.issued_at
            if last_remote_activity <= now - timedelta(seconds=max(60, settings.remote_access_idle_timeout_seconds)):
                remote.status = "REVOKED"
                remote.revoked_at = now
                remote.ended_at = now
                remote.revoked_reason = "REMOTE_IDLE_TIMEOUT"
                await db.commit()
                process.process.terminate()
                await websocket.close(code=4003, reason="Remote-access session idle timeout.")
                return
            if auth is None:
                process.process.terminate()
                await websocket.close(code=4003, reason="Authentication session unavailable.")
                return
            auth_last = auth.last_user_activity_at or auth.created_at
            if auth.revoked_at is not None or auth.expires_at <= now or auth_last <= now - timedelta(minutes=SESSION_IDLE_TIMEOUT_MINUTES):
                remote.status = "REVOKED"
                remote.revoked_at = now
                remote.ended_at = now
                remote.revoked_reason = "AUTH_SESSION_EXPIRED"
                await db.commit()
                process.process.terminate()
                await websocket.close(code=4003, reason="Authentication session expired.")
                return


@app.get("/health")
async def health():
    return {
        "service": "fttw-access-gateway",
        "status": "online",
        "remote_access_enabled": settings.remote_access_enabled,
        "telnet_access_enabled": settings.telnet_access_enabled,
        "core_dependency": False,
    }


@app.websocket("/ws/ssh")
async def websocket_ssh(websocket: WebSocket):
    origin = websocket.headers.get("origin")
    if origin not in _allowed_origins():
        await websocket.close(code=4403, reason="Origin not allowed.")
        return
    if not settings.remote_access_enabled:
        await websocket.close(code=1013, reason="Remote access is disabled.")
        return
    await websocket.accept()
    try:
        raw_launch = await asyncio.wait_for(websocket.receive_text(), timeout=5)
        launch = json.loads(raw_launch)
    except (asyncio.TimeoutError, json.JSONDecodeError, WebSocketDisconnect):
        await websocket.close(code=4401, reason="Launch ticket required.")
        return
    if launch.get("type") != "launch":
        await websocket.close(code=4401, reason="Launch ticket required.")
        return
    ticket = str(launch.get("ticket") or "").strip()
    if not ticket:
        await websocket.close(code=4401, reason="Launch ticket required.")
        return

    context, error = await _consume_ticket(ticket)
    if error:
        try:
            await websocket.send_text(json.dumps({"type": "error", "code": error}))
        finally:
            await websocket.close(code=4401, reason=error)
        return

    session_id = context["session_id"]
    process = None
    try:
        if context["credential_source"] == "ACCESS_TEMPLATE":
            username = context["username"]
            password = context["password"]
            private_key = context["private_key"]
        else:
            username = resolve_secret_reference(context["username_reference"])
            password = (
                resolve_secret_reference(context["password_reference"])
                if context["password_reference"]
                else None
            )
            private_key = (
                resolve_secret_reference(context["private_key_reference"])
                if context["private_key_reference"]
                else None
            )
        process = await start_ssh(
            host=context["ip"],
            port=context["port"],
            username=username,
            password=password,
            private_key=private_key,
            expected_fingerprint=context["fingerprint"],
            compatibility_profile=context["compatibility_profile"],
            trusted_host_key_line=context["trusted_host_key_line"],
        )
        await websocket.send_text(json.dumps({"type": "ready", "session_id": str(session_id), "compatibility_profile": context["compatibility_profile"]}))

        async def output_loop():
            while process.process.poll() is None:
                data = await read_pty(process.master_fd)
                if not data:
                    break
                await websocket.send_text(
                    json.dumps({"type": "output_binary", "data": base64.b64encode(data).decode("ascii")})
                )

        async def input_loop():
            while process.process.poll() is None:
                message = await websocket.receive_text()
                try:
                    payload = json.loads(message)
                except json.JSONDecodeError:
                    payload = {"type": "input", "data": message}
                kind = payload.get("type")
                if kind == "input":
                    data = str(payload.get("data") or "")
                    if len(data) > 8192:
                        data = data[:8192]
                    await write_pty(process.master_fd, data)
                    await _touch_remote_activity(session_id)
                elif kind == "binary":
                    encoded = str(payload.get("data") or "")
                    try:
                        raw = base64.b64decode(encoded, validate=True)[:8192]
                    except (ValueError, TypeError):
                        raw = b""
                    if raw:
                        await write_pty_bytes(process.master_fd, raw)
                        await _touch_remote_activity(session_id)
                elif kind == "resize":
                    await resize_pty(
                        process.master_fd,
                        int(payload.get("rows") or 30),
                        int(payload.get("cols") or 120),
                    )
                elif kind == "close":
                    process.process.terminate()
                    return

        watchdog = asyncio.create_task(
            _session_watchdog(
                websocket,
                process,
                session_id,
                context["auth_session_id"],
                context["activated_at"],
            )
        )
        output = asyncio.create_task(output_loop())
        input_task = asyncio.create_task(input_loop())
        done, pending = await asyncio.wait(
            {output, input_task, watchdog},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        if process.process.poll() is None:
            process.process.terminate()
        try:
            await asyncio.to_thread(process.process.wait, 3)
        except Exception:
            process.process.kill()
        await _mark_closed(session_id)
    except WebSocketDisconnect:
        if process and process.process.poll() is None:
            process.process.terminate()
        await _mark_closed(session_id)
    except (AccessTemplateSecretError, RemoteAccessSecretError, SSHTransportError) as exc:
        logger.warning("remote_access_ssh_failed session_id=%s code=%s", session_id, str(exc))
        await _mark_failed(session_id, str(exc))
        try:
            await websocket.send_text(json.dumps({"type": "error", "code": str(exc)}))
            await websocket.close(code=1011, reason="SSH session could not be established.")
        except Exception:
            pass
    except Exception:
        logger.exception("remote_access_gateway_failure session_id=%s", session_id)
        await _mark_failed(session_id, "REMOTE_ACCESS_GATEWAY_FAILURE")
        try:
            await websocket.close(code=1011, reason="Remote access gateway failure.")
        except Exception:
            pass
    finally:
        if process is not None:
            process.close()
