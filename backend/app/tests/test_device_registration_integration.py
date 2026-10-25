from __future__ import annotations

import asyncio
from uuid import uuid4

import httpx
from sqlalchemy import delete, select

from app.db.session import AsyncSessionLocal
from app.main import app
from app.security.sessions import create_session
from app.services.audit import enable_audit_maintenance

from app.models import (
    AuditLog,
    City,
    Device,
    DeviceCandidate,
    DeviceIP,
    DevicePlacement,
    DeviceType,
    Location,
    Network,
    Sector,
    AuthSession,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
)


# ---------------------------------------------------------------------------
# Test event-loop bridge
# ---------------------------------------------------------------------------
#
# pytest-asyncio is intentionally not required by this project.
# All async database/API operations in this module therefore run on the same
# event loop so that the application's SQLAlchemy/asyncpg pool remains bound
# to one loop.
#

_TEST_EVENT_LOOP = asyncio.new_event_loop()
asyncio.set_event_loop(_TEST_EVENT_LOOP)


def run(coro):
    return _TEST_EVENT_LOOP.run_until_complete(coro)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def create_device_type(db, code: str = "CPE"):
    return await db.scalar(
        select(DeviceType).where(
            DeviceType.code == code
        )
    )


async def create_candidate(
    db,
    *,
    state: str = "APPROVED",
    device_type_id=None,
    ip_address: str | None = None,
    network_id=None,
    city_id=None,
    location_id=None,
    sector_id=None,
    customer_id=None,
    relationship_target_device_id=None,
    relationship_type=None,
    relationship_direction=None,
):
    if device_type_id is None:
        device_type = await create_device_type(db)
        device_type_id = device_type.id

    candidate = DeviceCandidate(
        ip_address=ip_address or f"192.0.{uuid4().int % 254 + 1}.{(uuid4().int % 254) + 1}",
        state=state,
        confidence=0.95,
        suggested_device_type_id=device_type_id,
        display_name_suggestion=f"REG-DEVICE-{uuid4().hex[:8]}",
        hostname=f"reg-{uuid4().hex[:8]}",
        vendor="Test Vendor",
        model="Test Model",
        serial_number=f"TEST-{uuid4().hex[:12]}",
        management_protocol="SNMP",
        network_id=network_id,
        city_id=city_id,
        location_id=location_id,
        sector_id=sector_id,
        customer_id=customer_id,
        relationship_target_device_id=relationship_target_device_id,
        relationship_type=relationship_type,
        relationship_direction=relationship_direction,
        metadata_={},
    )

    db.add(candidate)
    await db.flush()

    return candidate


async def create_independent_location_context(db):
    network = Network(
        name=f"Registration Network {uuid4().hex[:8]}",
        code=f"REG-NET-{uuid4().hex[:8]}",
        status="ACTIVE",
    )
    db.add(network)
    await db.flush()
    city = City(
        network_id=network.id,
        name=f"Registration City {uuid4().hex[:8]}",
        code=f"REG-CITY-{uuid4().hex[:8]}",
        status="ACTIVE",
    )
    db.add(city)
    await db.flush()
    location = Location(
        city_id=city.id,
        name=f"Registration Location {uuid4().hex[:8]}",
        code=f"REG-LOC-{uuid4().hex[:8]}",
        status="ACTIVE",
        metadata_={},
    )
    db.add(location)
    await db.flush()
    return network, city, location


async def cleanup_independent_location_context(network_id, city_id, location_id):
    async with AsyncSessionLocal() as db:
        async with db.begin():
            await db.execute(delete(Location).where(Location.id == location_id))
            await db.execute(delete(City).where(City.id == city_id))
            await db.execute(delete(Network).where(Network.id == network_id))



async def cleanup_candidate(candidate_id):
    """
    Remove data created by a device-registration integration test.

    Registration commits independently, so cleanup is performed explicitly
    after the HTTP operation.
    """
    async with AsyncSessionLocal() as db:
        transaction = await db.begin()

        try:
            candidate = await db.get(
                DeviceCandidate,
                candidate_id,
            )

            device_id = None

            if candidate is not None:
                registration = (
                    candidate.metadata_ or {}
                ).get(
                    "registration",
                    {},
                )

                raw_device_id = registration.get("device_id")

                if raw_device_id:
                    try:
                        from uuid import UUID

                        device_id = UUID(raw_device_id)
                    except (TypeError, ValueError):
                        device_id = None

            if device_id is not None:
                await db.execute(
                    delete(DevicePlacement).where(
                        DevicePlacement.device_id == device_id
                    )
                )

                await db.execute(
                    delete(DeviceIP).where(
                        DeviceIP.device_id == device_id
                    )
                )

                await enable_audit_maintenance(db)
                await db.execute(
                    delete(AuditLog).where(
                        AuditLog.entity_type == "DeviceCandidate",
                        AuditLog.entity_id == candidate_id,
                    )
                )

                await db.execute(
                    delete(Device).where(
                        Device.id == device_id
                    )
                )

            await db.execute(
                delete(DeviceCandidate).where(
                    DeviceCandidate.id == candidate_id
                )
            )

            await transaction.commit()

        except Exception:
            await transaction.rollback()
            raise

async def create_registration_auth_context(db):
    """
    Create an authenticated test user with candidate.register permission.

    The candidate.register permission is shared RBAC data. Reuse the
    existing permission when it is already present.
    """

    user = User(
        external_subject=f"registration-test-{uuid4()}",
        username=f"registration-user-{uuid4().hex[:10]}",
        display_name="Registration Integration Test User",
        is_active=True,
        metadata_={},
    )

    role = Role(
        name=f"Registration Test Role {uuid4()}",
        code=f"REG-AUTH-{uuid4().hex[:10]}",
        description="Registration integration test role",
    )

    permission = await db.scalar(
        select(Permission).where(
            Permission.code == "candidate.register"
        )
    )

    permission_created = False

    if permission is None:
        permission = Permission(
            name="Candidate Registration",
            code="candidate.register",
            description="Register approved device candidates",
        )

        db.add(permission)
        await db.flush()

        permission_created = True

    db.add(user)
    db.add(role)

    await db.flush()

    db.add(
        UserRole(
            user_id=user.id,
            role_id=role.id,
        )
    )

    db.add(
        RolePermission(
            role_id=role.id,
            permission_id=permission.id,
        )
    )

    await db.flush()

    token, session = await create_session(
        db,
        user_id=user.id,
    )

    await db.commit()

    return {
        "user_id": user.id,
        "role_id": role.id,
        "permission_id": permission.id,
        "permission_created": permission_created,
        "session_id": session.id,
        "token": token,
    }

async def cleanup_registration_auth_context(context):
    async with AsyncSessionLocal() as db:
        transaction = await db.begin()

        try:
            await db.execute(
                delete(AuthSession).where(
                    AuthSession.id == context["session_id"]
                )
            )

            await db.execute(
                delete(UserRole).where(
                    UserRole.user_id == context["user_id"]
                )
            )

            await db.execute(
                delete(RolePermission).where(
                    RolePermission.role_id == context["role_id"]
                )
            )

            await db.execute(
                delete(User).where(
                    User.id == context["user_id"]
                )
            )

            await db.execute(
                delete(Role).where(
                    Role.id == context["role_id"]
                )
            )

            if context.get("permission_created"):
                await db.execute(
                    delete(Permission).where(
                        Permission.id == context["permission_id"]
                    )
                )

            await transaction.commit()

        except Exception:
            await transaction.rollback()
            raise

async def request_register(
    candidate_id,
    bearer_token: str | None = None,
):
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as client:

        headers = {}

        if bearer_token is not None:
            headers["Authorization"] = (
                f"Bearer {bearer_token}"
            )

        return await client.post(
            f"/api/device-candidates/{candidate_id}/register",
            headers=headers,
        )

def test_approved_candidate_registers_successfully():
    async def scenario():
        context = None
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()

            try:
                network, city, location = await create_independent_location_context(db)
                context = (network.id, city.id, location.id)
                device_type = await create_device_type(db, "SWITCH")
                assert device_type is not None
                candidate = await create_candidate(
                    db,
                    device_type_id=device_type.id,
                    network_id=network.id,
                    city_id=city.id,
                    location_id=location.id,
                )

                candidate_id = candidate.id
                ip_address = candidate.ip_address

                await transaction.commit()

            except Exception:
                await transaction.rollback()
                raise

        auth_context = None

        try:
            async with AsyncSessionLocal() as db:
                auth_context = await create_registration_auth_context(db)

            response = await request_register(
                candidate_id,
                auth_context["token"],
            )

            assert response.status_code == 200

            body = response.json()

            assert body["candidate_id"] == str(candidate_id)
            assert body["state"] == "REGISTERED"
            assert body["idempotent"] is False

            device_id = body["device_id"]
            ip_id = body["ip_id"]

            async with AsyncSessionLocal() as db:
                registered_candidate = await db.get(
                    DeviceCandidate,
                    candidate_id,
                )

                assert registered_candidate is not None
                assert registered_candidate.state == "REGISTERED"

                registration = (
                    registered_candidate.metadata_ or {}
                ).get("registration", {})

                assert registration["device_id"] == device_id
                assert registration["ip_id"] == ip_id

                device = await db.get(
                    Device,
                    device_id,
                )

                assert device is not None
                assert device.lifecycle_state == "REGISTERED"

                ip_obj = await db.get(
                    DeviceIP,
                    ip_id,
                )

                assert ip_obj is not None
                assert ip_obj.device_id == device.id
                assert ip_obj.ip_address == ip_address
                assert ip_obj.is_management is True
                assert ip_obj.is_primary is True

        finally:
            await cleanup_candidate(candidate_id)
            if context is not None:
                await cleanup_independent_location_context(*context)

            if auth_context is not None:
                await cleanup_registration_auth_context(auth_context)

    run(scenario())


def test_registered_candidate_registration_is_idempotent():
    async def scenario():
        context = None
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()

            try:
                network, city, location = await create_independent_location_context(db)
                context = (network.id, city.id, location.id)
                device_type = await create_device_type(db, "SWITCH")
                assert device_type is not None
                candidate = await create_candidate(
                    db,
                    device_type_id=device_type.id,
                    network_id=network.id,
                    city_id=city.id,
                    location_id=location.id,
                )
                candidate_id = candidate.id

                await transaction.commit()

            except Exception:
                await transaction.rollback()
                raise

        auth_context = None

        try:
            async with AsyncSessionLocal() as db:
                auth_context = await create_registration_auth_context(db)

            first = await request_register(
                candidate_id,
                auth_context["token"],
            )

            assert first.status_code == 200

            first_body = first.json()

            first_device_id = first_body["device_id"]
            first_ip_id = first_body["ip_id"]

            second = await request_register(
                candidate_id,
                auth_context["token"],
            )

            assert second.status_code == 200

            second_body = second.json()

            assert second_body["candidate_id"] == str(candidate_id)
            assert second_body["device_id"] == first_device_id
            assert second_body["ip_id"] == first_ip_id
            assert second_body["state"] == "REGISTERED"
            assert second_body["idempotent"] is True

            async with AsyncSessionLocal() as db:
                devices = (
                    await db.execute(
                        select(Device)
                        .join(
                            DeviceIP,
                            DeviceIP.device_id == Device.id,
                        )
                        .where(
                            DeviceIP.ip_address
                            == (
                                await db.get(
                                    DeviceCandidate,
                                    candidate_id,
                                )
                            ).ip_address
                        )
                    )
                ).scalars().all()

                assert len(devices) == 1

        finally:
            await cleanup_candidate(candidate_id)
            if context is not None:
                await cleanup_independent_location_context(*context)

            if auth_context is not None:
                await cleanup_registration_auth_context(auth_context)

    run(scenario())


def test_new_candidate_cannot_register():
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()

            try:
                candidate = await create_candidate(
                    db,
                    state="NEW",
                )

                candidate_id = candidate.id

                await transaction.commit()

            except Exception:
                await transaction.rollback()
                raise

        auth_context = None

        try:
            async with AsyncSessionLocal() as db:
                auth_context = await create_registration_auth_context(db)

            response = await request_register(
                candidate_id,
                auth_context["token"],
            )

            assert response.status_code == 409

            body = response.json()

            assert body["detail"]["code"] == "CANDIDATE_NOT_APPROVED"

            async with AsyncSessionLocal() as db:
                refreshed = await db.get(
                    DeviceCandidate,
                    candidate_id,
                )

                assert refreshed.state == "NEW"

                devices = (
                    await db.execute(
                        select(Device).where(
                            Device.metadata_[
                                "registered_from_candidate"
                            ].as_string()
                            == str(candidate_id)
                        )
                    )
                ).scalars().all()

                assert devices == []

        finally:
            await cleanup_candidate(candidate_id)

            if auth_context is not None:
                await cleanup_registration_auth_context(auth_context)

    run(scenario())


def test_rejected_candidate_cannot_register():
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()

            try:
                candidate = await create_candidate(
                    db,
                    state="REJECTED",
                )

                candidate_id = candidate.id

                await transaction.commit()

            except Exception:
                await transaction.rollback()
                raise

        auth_context = None

        try:
            async with AsyncSessionLocal() as db:
                auth_context = await create_registration_auth_context(db)

            response = await request_register(
                candidate_id,
                auth_context["token"],
            )

            assert response.status_code == 409

            body = response.json()

            assert body["detail"]["code"] == "CANDIDATE_NOT_APPROVED"

            async with AsyncSessionLocal() as db:
                refreshed = await db.get(
                    DeviceCandidate,
                    candidate_id,
                )

                assert refreshed.state == "REJECTED"

        finally:
            await cleanup_candidate(candidate_id)

            if auth_context is not None:
                await cleanup_registration_auth_context(auth_context)

    run(scenario())


def test_approved_candidate_without_device_type_cannot_register():
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()

            try:
                candidate = await create_candidate(
                    db,
                    device_type_id=None,
                )

                candidate.suggested_device_type_id = None
                await db.flush()

                candidate_id = candidate.id

                await transaction.commit()

            except Exception:
                await transaction.rollback()
                raise

        auth_context = None

        try:
            async with AsyncSessionLocal() as db:
                auth_context = await create_registration_auth_context(db)

            response = await request_register(
                candidate_id,
                auth_context["token"],
            )

            assert response.status_code == 422

            body = response.json()

            assert body["detail"]["code"] == "DEVICE_TYPE_REQUIRED"

            async with AsyncSessionLocal() as db:
                refreshed = await db.get(
                    DeviceCandidate,
                    candidate_id,
                )

                assert refreshed.state == "APPROVED"

        finally:
            await cleanup_candidate(candidate_id)

            if auth_context is not None:
                await cleanup_registration_auth_context(auth_context)

    run(scenario())


def test_duplicate_ip_is_rejected():
    async def scenario():
        context = None
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()

            try:
                network, city, location = await create_independent_location_context(db)
                context = (network.id, city.id, location.id)
                device_type = await create_device_type(db, "SWITCH")
                assert device_type is not None

                existing_device = Device(
                    device_type_id=device_type.id,
                    display_name=f"EXISTING-{uuid4().hex[:8]}",
                    lifecycle_state="REGISTERED",
                    operational_state="UNKNOWN",
                )

                db.add(existing_device)
                await db.flush()

                ip_address = f"198.51.100.{uuid4().int % 200 + 1}"

                existing_ip = DeviceIP(
                    device_id=existing_device.id,
                    ip_address=ip_address,
                    address_family=4,
                    is_management=True,
                    is_primary=True,
                    source="TEST",
                )

                db.add(existing_ip)
                await db.flush()

                candidate = await create_candidate(
                    db,
                    device_type_id=device_type.id,
                    ip_address=ip_address,
                    network_id=network.id,
                    city_id=city.id,
                    location_id=location.id,
                )

                candidate_id = candidate.id
                existing_device_id = existing_device.id

                await transaction.commit()

            except Exception:
                await transaction.rollback()
                raise

        auth_context = None

        try:
            async with AsyncSessionLocal() as db:
                auth_context = await create_registration_auth_context(db)

            response = await request_register(
                candidate_id,
                auth_context["token"],
            )

            assert response.status_code == 409

            body = response.json()

            assert body["detail"]["code"] == "IP_ALREADY_REGISTERED"
            assert body["detail"]["device_id"] == str(
                existing_device_id
            )

            async with AsyncSessionLocal() as db:
                refreshed = await db.get(
                    DeviceCandidate,
                    candidate_id,
                )

                assert refreshed.state == "APPROVED"
                assert refreshed.duplicate_device_id == existing_device_id

        finally:
            async with AsyncSessionLocal() as db:
                transaction = await db.begin()

                try:
                    await db.execute(
                        delete(DeviceCandidate).where(
                            DeviceCandidate.id == candidate_id
                        )
                    )

                    await db.execute(
                        delete(DeviceIP).where(
                            DeviceIP.device_id == existing_device_id
                        )
                    )

                    await db.execute(
                        delete(Device).where(
                            Device.id == existing_device_id
                        )
                    )

                    await transaction.commit()

                except Exception:
                    await transaction.rollback()
                    raise

                if auth_context is not None:
                    await cleanup_registration_auth_context(auth_context)
                if context is not None:
                    await cleanup_independent_location_context(*context)

    run(scenario())


def test_registration_with_network_context_creates_placement():
    async def scenario():
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()

            try:
                network = Network(
                    name=f"Registration Network {uuid4().hex[:8]}",
                    code=f"REG-NET-{uuid4().hex[:8]}",
                    status="ACTIVE",
                )
                db.add(network)
                await db.flush()

                city = City(
                    network_id=network.id,
                    name=f"Registration City {uuid4().hex[:8]}",
                    code=f"REG-CITY-{uuid4().hex[:8]}",
                    status="ACTIVE",
                )
                db.add(city)
                await db.flush()

                location = Location(
                    city_id=city.id,
                    name=f"Registration Location {uuid4().hex[:8]}",
                    code=f"REG-LOC-{uuid4().hex[:8]}",
                    status="ACTIVE",
                    metadata_={},
                )
                db.add(location)
                await db.flush()

                switch_type = await create_device_type(db, "SWITCH")
                assert switch_type is not None
                candidate = await create_candidate(
                    db,
                    device_type_id=switch_type.id,
                    network_id=network.id,
                    city_id=city.id,
                    location_id=location.id,
                )

                candidate_id = candidate.id

                await transaction.commit()

            except Exception:
                await transaction.rollback()
                raise

        auth_context = None

        try:
            async with AsyncSessionLocal() as db:
                auth_context = await create_registration_auth_context(db)

            response = await request_register(
                candidate_id,
                auth_context["token"],
            )

            assert response.status_code == 200

            body = response.json()

            device_id = body["device_id"]

            async with AsyncSessionLocal() as db:
                placement = await db.scalar(
                    select(DevicePlacement).where(
                        DevicePlacement.device_id == device_id
                    )
                )

                assert placement is not None
                assert placement.network_id == network.id
                assert placement.city_id == city.id
                assert placement.location_id == location.id

        finally:
            await cleanup_candidate(candidate_id)

            async with AsyncSessionLocal() as db:
                transaction = await db.begin()

                try:
                    await db.execute(
                        delete(Sector).where(
                            Sector.location_id == location.id
                        )
                    )

                    await db.execute(
                        delete(Location).where(
                            Location.id == location.id
                        )
                    )

                    await db.execute(
                        delete(City).where(
                            City.id == city.id
                        )
                    )

                    await db.execute(
                        delete(Network).where(
                            Network.id == network.id
                        )
                    )

                    await transaction.commit()

                except Exception:
                    await transaction.rollback()
                    raise

            if auth_context is not None:
                await cleanup_registration_auth_context(auth_context)

    run(scenario())






