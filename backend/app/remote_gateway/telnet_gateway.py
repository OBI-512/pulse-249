from __future__ import annotations

import asyncio
import base64
import json
import logging
import socket
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from ..db.session import AsyncSessionLocal
from ..models import AuthSession, Device, DeviceIP, RemoteAccessSession, User
from ..security.sessions import SESSION_IDLE_TIMEOUT_MINUTES
from ..services.access_template_runtime import resolve_telnet_runtime_access
from ..services.access_templates import AccessTemplateSecretError
from ..services.audit import record_audit
from ..services.remote_access import hash_remote_ticket
from ..settings import settings
from .telnet_transport import TelnetConnection, TelnetTransportError, start_telnet


logger = logging.getLogger("fttw.remote_gateway.telnet")
router = APIRouter()


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
            action="REMOTE_ACCESS_TELNET_FAILED",
            entity_type="Device",
            entity_id=session.device_id,
            actor_user_id=session.actor_user_id,
            actor_username_snapshot=getattr(actor, "username", None),
            actor_display_name_snapshot=getattr(actor, "display_name", None),
            description="Brokered legacy Telnet session failed.",
            metadata={
                "remote_access_session_id": str(session.id),
                "failure_code": code,
                "insecure_transport": True,
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
            action="REMOTE_ACCESS_TELNET_ENDED",
            entity_type="Device",
            entity_id=session.device_id,
            actor_user_id=session.actor_user_id,
            actor_username_snapshot=getattr(actor, "username", None),
            actor_display_name_snapshot=getattr(actor, "display_name", None),
            description="Brokered legacy Telnet session ended.",
            metadata={
                "remote_access_session_id": str(session.id),
                "insecure_transport": True,
            },
        )
        await db.commit()


async def _touch_remote_activity(session_id: UUID) -> None:
    async with AsyncSessionLocal() as db:
        session = await db.get(RemoteAccessSession, session_id)
        if session is None or session.status != "ACTIVE":
            return
        now = _utcnow()
        session.last_activity_at = now
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
        if session.mode != "TELNET":
            return None, "REMOTE_ACCESS_TICKET_MODE_INVALID"
        if session.status != "ISSUED" or session.consumed_at is not None:
            return None, "REMOTE_ACCESS_TICKET_ALREADY_USED"
        if session.revoked_at is not None or session.expires_at <= now:
            return None, "REMOTE_ACCESS_TICKET_EXPIRED"
        if not settings.remote_access_enabled or not settings.telnet_access_enabled:
            return None, "TELNET_ACCESS_DISABLED"

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

        try:
            runtime = await resolve_telnet_runtime_access(db, device_id=device.id)
        except AccessTemplateSecretError as exc:
            return None, str(exc)
        if runtime is None:
            return None, "TELNET_ACCESS_NOT_CONFIGURED"

        auth_session.last_user_activity_at = now
        session.status = "ACTIVE"
        session.consumed_at = now
        session.activated_at = now
        session.last_activity_at = now
        session.gateway_instance = socket.gethostname()[:120]
        actor = await db.get(User, session.actor_user_id) if session.actor_user_id else None
        await record_audit(
            db,
            action="REMOTE_ACCESS_TELNET_STARTED",
            entity_type="Device",
            entity_id=device.id,
            actor_user_id=session.actor_user_id,
            actor_username_snapshot=getattr(actor, "username", None),
            actor_display_name_snapshot=getattr(actor, "display_name", None),
            description="Brokered legacy Telnet session started.",
            metadata={
                "remote_access_session_id": str(session.id),
                "credential_source": "ACCESS_TEMPLATE",
                "insecure_transport": True,
            },
        )
        await db.commit()
        return {
            "session_id": session.id,
            "device_id": device.id,
            "ip": ip,
            "port": runtime.port,
            "timeout_seconds": runtime.timeout_seconds,
            "username": runtime.username,
            "password": runtime.password,
            "auth_session_id": session.auth_session_id,
            "activated_at": now,
        }, None


async def _watchdog(
    websocket: WebSocket,
    connection: TelnetConnection,
    session_id: UUID,
    auth_session_id: UUID,
    activated_at: datetime,
) -> None:
    while not connection.closed:
        await asyncio.sleep(2)
        now = _utcnow()
        reason: str | None = None
        async with AsyncSessionLocal() as db:
            remote = await db.get(RemoteAccessSession, session_id)
            auth = await db.get(AuthSession, auth_session_id)
            if remote is None or remote.status != "ACTIVE" or remote.revoked_at is not None:
                reason = "REMOTE_ACCESS_REVOKED"
            elif now >= activated_at + timedelta(seconds=max(60, settings.remote_access_session_max_seconds)):
                remote.status = "REVOKED"
                remote.revoked_at = now
                remote.ended_at = now
                remote.revoked_reason = "MAX_SESSION_DURATION"
                reason = "MAX_SESSION_DURATION"
                await db.commit()
            else:
                last_remote_activity = remote.last_activity_at or remote.activated_at or remote.issued_at
                if last_remote_activity <= now - timedelta(seconds=max(60, settings.remote_access_idle_timeout_seconds)):
                    remote.status = "REVOKED"
                    remote.revoked_at = now
                    remote.ended_at = now
                    remote.revoked_reason = "REMOTE_IDLE_TIMEOUT"
                    reason = "REMOTE_IDLE_TIMEOUT"
                    await db.commit()
                elif auth is None:
                    reason = "AUTH_SESSION_REQUIRED"
                else:
                    auth_last = auth.last_user_activity_at or auth.created_at
                    if (
                        auth.revoked_at is not None
                        or auth.expires_at <= now
                        or auth_last <= now - timedelta(minutes=SESSION_IDLE_TIMEOUT_MINUTES)
                    ):
                        remote.status = "REVOKED"
                        remote.revoked_at = now
                        remote.ended_at = now
                        remote.revoked_reason = "AUTH_SESSION_EXPIRED"
                        reason = "AUTH_SESSION_EXPIRED"
                        await db.commit()
        if reason:
            await connection.close()
            try:
                await websocket.close(code=4003, reason=reason)
            except Exception:
                pass
            return


@router.websocket("/ws/telnet")
async def websocket_telnet(websocket: WebSocket):
    origin = websocket.headers.get("origin")
    if origin not in _allowed_origins():
        await websocket.close(code=4403, reason="Origin not allowed.")
        return
    if not settings.remote_access_enabled or not settings.telnet_access_enabled:
        await websocket.close(code=1013, reason="Legacy Telnet access is disabled.")
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
    connection: TelnetConnection | None = None
    try:
        connection = await start_telnet(
            host=context["ip"],
            port=context["port"],
            username=context["username"],
            password=context["password"],
            timeout_seconds=context["timeout_seconds"],
        )
        await websocket.send_text(
            json.dumps(
                {
                    "type": "ready",
                    "session_id": str(session_id),
                    "protocol": "TELNET",
                    "insecure_transport": True,
                }
            )
        )
        if connection.initial_output:
            await websocket.send_text(
                json.dumps(
                    {
                        "type": "output_binary",
                        "data": base64.b64encode(connection.initial_output).decode("ascii"),
                    }
                )
            )

        async def output_loop():
            while not connection.closed:
                data = await connection.read(4096)
                if not data:
                    break
                await websocket.send_text(
                    json.dumps(
                        {
                            "type": "output_binary",
                            "data": base64.b64encode(data).decode("ascii"),
                        }
                    )
                )

        async def input_loop():
            while not connection.closed:
                message = await websocket.receive_text()
                try:
                    payload = json.loads(message)
                except json.JSONDecodeError:
                    payload = {"type": "input", "data": message}
                kind = payload.get("type")
                if kind == "input":
                    data = str(payload.get("data") or "").encode("utf-8", "replace")[:8192]
                    if data:
                        await connection.write(data)
                        await _touch_remote_activity(session_id)
                elif kind == "binary":
                    encoded = str(payload.get("data") or "")
                    try:
                        raw = base64.b64decode(encoded, validate=True)[:8192]
                    except (ValueError, TypeError):
                        raw = b""
                    if raw:
                        await connection.write(raw)
                        await _touch_remote_activity(session_id)
                elif kind == "resize":
                    await connection.resize(
                        int(payload.get("rows") or 30),
                        int(payload.get("cols") or 120),
                    )
                elif kind == "close":
                    await connection.close()
                    return

        watchdog = asyncio.create_task(
            _watchdog(
                websocket,
                connection,
                session_id,
                context["auth_session_id"],
                context["activated_at"],
            )
        )
        output = asyncio.create_task(output_loop())
        input_task = asyncio.create_task(input_loop())
        _done, pending = await asyncio.wait(
            {output, input_task, watchdog},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        await connection.close()
        await _mark_closed(session_id)
    except WebSocketDisconnect:
        if connection is not None:
            await connection.close()
        await _mark_closed(session_id)
    except (AccessTemplateSecretError, TelnetTransportError) as exc:
        logger.warning("remote_access_telnet_failed session_id=%s code=%s", session_id, str(exc))
        await _mark_failed(session_id, str(exc))
        try:
            await websocket.send_text(json.dumps({"type": "error", "code": str(exc)}))
            await websocket.close(code=1011, reason="Telnet session could not be established.")
        except Exception:
            pass
    except Exception:
        logger.exception("remote_access_telnet_gateway_failure session_id=%s", session_id)
        await _mark_failed(session_id, "REMOTE_ACCESS_GATEWAY_FAILURE")
        try:
            await websocket.close(code=1011, reason="Remote access gateway failure.")
        except Exception:
            pass
    finally:
        if connection is not None:
            await connection.close()
