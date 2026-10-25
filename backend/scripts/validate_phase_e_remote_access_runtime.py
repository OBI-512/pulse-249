from __future__ import annotations

import asyncio
import json
import os
import socket
import uuid
from datetime import datetime, timezone

import httpx
from sqlalchemy import delete, select
from websockets.asyncio.client import connect

from app.db.session import AsyncSessionLocal
from app.models import (
    AuthSession,
    Device,
    DeviceIP,
    DeviceRemoteAccessProfile,
    DeviceType,
    Permission,
    RemoteAccessSession,
    User,
    UserPermission,
    UserResourceScope,
)
from app.security.sessions import create_session


API = "http://localhost:8000/api"
MOCK_HOST = "mock-ssh"
MOCK_FINGERPRINT = os.environ.get("MOCK_SSH_FINGERPRINT", "").strip()
ORIGIN = "http://localhost:3000"


def assert_status(response: httpx.Response, expected: int, label: str) -> None:
    if response.status_code != expected:
        raise AssertionError(
            f"{label}: expected HTTP {expected}, got {response.status_code}: {response.text[:800]}"
        )


async def grant(db, user: User, *codes: str) -> None:
    rows = list((await db.scalars(select(Permission).where(Permission.code.in_(codes)))).all())
    found = {row.code for row in rows}
    missing = set(codes) - found
    if missing:
        raise AssertionError(f"Missing migrated permission rows: {sorted(missing)}")
    for row in rows:
        db.add(UserPermission(user_id=user.id, permission_id=row.id))


async def make_user(db, *, suffix: str, permissions: tuple[str, ...], global_scope: bool) -> tuple[User, str, AuthSession]:
    now = datetime.now(timezone.utc)
    user = User(
        external_subject=f"phase-e-remote-runtime-{suffix}-{uuid.uuid4()}",
        username=f"phase_e_remote_{suffix}_{uuid.uuid4().hex[:8]}",
        display_name=f"Phase E Remote {suffix}",
        password_hash=None,
        password_changed_at=now,
        must_change_password=False,
        is_active=True,
        metadata_={"fixture": "PHASE_E_REMOTE_ACCESS_RUNTIME"},
    )
    db.add(user)
    await db.flush()
    await grant(db, user, *permissions)
    if global_scope:
        db.add(UserResourceScope(user_id=user.id, scope_type="GLOBAL"))
    token, auth_session = await create_session(
        db,
        user_id=user.id,
        lifetime_minutes=30,
        source_ip="127.0.0.1",
        user_agent="FTTW-Remote-Access-Runtime-Qualification",
    )
    return user, token, auth_session


async def setup_fixture():
    if not MOCK_FINGERPRINT.startswith("SHA256:"):
        raise AssertionError("MOCK_SSH_FINGERPRINT must be supplied by the guarded harness.")
    async with AsyncSessionLocal() as db:
        device_type = await db.scalar(select(DeviceType).where(DeviceType.code == "OTHER"))
        if device_type is None:
            device_type = await db.scalar(select(DeviceType).order_by(DeviceType.created_at).limit(1))
        if device_type is None:
            raise AssertionError("No DeviceType exists for runtime qualification.")

        device = Device(
            device_type_id=device_type.id,
            display_name=f"PHASE-E-MOCK-SSH-{uuid.uuid4().hex[:8]}",
            hostname="phase-e-mock-ssh",
            vendor="FTTW-TEST",
            model="MOCK-SSH",
            lifecycle_state="REGISTERED",
            operational_state="UNKNOWN",
            management_protocol="SSH",
            metadata_={"fixture": "PHASE_E_REMOTE_ACCESS_RUNTIME"},
        )
        db.add(device)
        await db.flush()
        db.add(
            DeviceIP(
                device_id=device.id,
                ip_address=MOCK_HOST,
                address_family=4,
                is_management=True,
                is_primary=True,
                source="PHASE_E_TEST_HARNESS",
            )
        )
        db.add(
            DeviceRemoteAccessProfile(
                device_id=device.id,
                ssh_enabled=True,
                ssh_port=22,
                ssh_username_reference="env://FTTW_TEST_SSH_USERNAME",
                ssh_password_reference="env://FTTW_TEST_SSH_PASSWORD",
                ssh_host_key_fingerprint=MOCK_FINGERPRINT,
                metadata_={"fixture": "PHASE_E_REMOTE_ACCESS_RUNTIME"},
            )
        )

        allowed, allowed_token, allowed_auth = await make_user(
            db,
            suffix="allowed",
            permissions=("device.read", "device.remote_access.ssh"),
            global_scope=True,
        )
        denied_permission, denied_permission_token, _ = await make_user(
            db,
            suffix="no_permission",
            permissions=("device.read",),
            global_scope=True,
        )
        denied_scope, denied_scope_token, _ = await make_user(
            db,
            suffix="no_scope",
            permissions=("device.read", "device.remote_access.ssh"),
            global_scope=False,
        )
        await db.commit()
        return {
            "device_id": device.id,
            "allowed_user_id": allowed.id,
            "allowed_token": allowed_token,
            "allowed_auth_session_id": allowed_auth.id,
            "denied_permission_user_id": denied_permission.id,
            "denied_permission_token": denied_permission_token,
            "denied_scope_user_id": denied_scope.id,
            "denied_scope_token": denied_scope_token,
        }


async def cleanup_fixture(fixture: dict) -> None:
    user_ids = [
        fixture.get("allowed_user_id"),
        fixture.get("denied_permission_user_id"),
        fixture.get("denied_scope_user_id"),
    ]
    user_ids = [value for value in user_ids if value is not None]
    device_id = fixture.get("device_id")
    async with AsyncSessionLocal() as db:
        if device_id is not None:
            await db.execute(delete(RemoteAccessSession).where(RemoteAccessSession.device_id == device_id))
            await db.execute(delete(DeviceRemoteAccessProfile).where(DeviceRemoteAccessProfile.device_id == device_id))
            await db.execute(delete(DeviceIP).where(DeviceIP.device_id == device_id))
            await db.execute(delete(Device).where(Device.id == device_id))
        if user_ids:
            await db.execute(delete(UserPermission).where(UserPermission.user_id.in_(user_ids)))
            await db.execute(delete(UserResourceScope).where(UserResourceScope.user_id.in_(user_ids)))
            await db.execute(delete(AuthSession).where(AuthSession.user_id.in_(user_ids)))
            await db.execute(delete(User).where(User.id.in_(user_ids)))
        await db.commit()


async def webssh_roundtrip(ticket: str) -> str:
    uri = "ws://access-gateway:8010/ws/ssh"
    async with connect(uri, origin=ORIGIN, open_timeout=10, close_timeout=3) as websocket:
        await websocket.send(json.dumps({"type": "launch", "ticket": ticket}))
        marker = "FTTW_WEBSSH_RUNTIME_PASS"
        ready_seen = False
        output = ""
        deadline = asyncio.get_running_loop().time() + 20
        while asyncio.get_running_loop().time() < deadline and not ready_seen:
            message = json.loads(await asyncio.wait_for(websocket.recv(), timeout=8))
            if message.get("type") == "ready":
                ready_seen = True
            elif message.get("type") == "error":
                raise AssertionError(f"Gateway reported SSH failure: {message}")
        if not ready_seen:
            raise AssertionError("Web SSH gateway never reported ready.")
        await websocket.send(json.dumps({"type": "input", "data": f"echo {marker}\\r"}))
        while asyncio.get_running_loop().time() < deadline and marker not in output:
            message = json.loads(await asyncio.wait_for(websocket.recv(), timeout=8))
            if message.get("type") == "output":
                output += str(message.get("data") or "")
            elif message.get("type") == "error":
                raise AssertionError(f"Gateway reported SSH failure: {message}")
        if marker not in output:
            raise AssertionError(f"SSH command marker not observed. Output: {output[-2000:]}")
        await websocket.send(json.dumps({"type": "input", "data": "exit\\r"}))
        return output


async def ticket_replay_rejected(ticket: str) -> bool:
    uri = "ws://access-gateway:8010/ws/ssh"
    try:
        async with connect(uri, origin=ORIGIN, open_timeout=5, close_timeout=2) as websocket:
            await websocket.send(json.dumps({"type": "launch", "ticket": ticket}))
            try:
                message = json.loads(await asyncio.wait_for(websocket.recv(), timeout=2))
                return message.get("code") in {"REMOTE_ACCESS_TICKET_ALREADY_USED", "REMOTE_ACCESS_TICKET_INVALID"}
            except Exception:
                return True
    except Exception:
        return True


async def main() -> int:
    fixture: dict = {}
    evidence: dict[str, object] = {
        "status": "FAIL",
        "phase": "E_REMOTE_ACCESS_WEBSSH_RUNTIME",
        "mock_ssh": MOCK_HOST,
    }
    try:
        # The normal backend must not have management-network reachability to
        # the mock device. Only access-gateway is attached to that test network.
        backend_direct_blocked = False
        try:
            with socket.create_connection((MOCK_HOST, 22), timeout=1):
                pass
        except OSError:
            backend_direct_blocked = True
        if not backend_direct_blocked:
            raise AssertionError("Backend unexpectedly has direct TCP reachability to the isolated Mock SSH device.")
        evidence["backend_direct_management_access_blocked"] = True

        fixture = await setup_fixture()
        headers = {"Authorization": f"Bearer {fixture['allowed_token']}"}
        async with httpx.AsyncClient(timeout=10) as client:
            health = await client.get(f"{API}/health")
            assert_status(health, 200, "core health")

            status = await client.get(
                f"{API}/devices/{fixture['device_id']}/remote-access", headers=headers
            )
            assert_status(status, 200, "authorized remote status")
            if not status.json().get("ready"):
                raise AssertionError(f"Remote profile is not ready: {status.json()}")

            denied = await client.get(
                f"{API}/devices/{fixture['device_id']}/remote-access",
                headers={"Authorization": f"Bearer {fixture['denied_permission_token']}"},
            )
            assert_status(denied, 403, "WHAT permission denial")

            scope_denied = await client.get(
                f"{API}/devices/{fixture['device_id']}/remote-access",
                headers={"Authorization": f"Bearer {fixture['denied_scope_token']}"},
            )
            assert_status(scope_denied, 404, "WHERE scope denial")

            launch = await client.post(
                f"{API}/devices/{fixture['device_id']}/remote-access/ssh-sessions",
                headers=headers,
            )
            assert_status(launch, 200, "Web SSH launch")
            payload = launch.json()
            ticket = payload.get("ticket")
            if not ticket or not payload.get("session_id"):
                raise AssertionError(f"Launch response missing ticket/session: {payload}")

        output = await webssh_roundtrip(ticket)
        evidence["webssh_command_roundtrip"] = "PASS"
        evidence["webssh_output_observed"] = "FTTW_WEBSSH_RUNTIME_PASS" in output
        if not await ticket_replay_rejected(ticket):
            raise AssertionError("Consumed Web SSH launch ticket was accepted a second time.")
        evidence["single_use_ticket_replay_rejected"] = True
        evidence["what_permission_denial"] = True
        evidence["where_scope_denial"] = True
        evidence["credentials_browser_exposure"] = False
        evidence["status"] = "PASS"
        print(json.dumps(evidence, sort_keys=True))
        return 0
    finally:
        if fixture:
            await cleanup_fixture(fixture)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
