"""Focused Stage B coverage for business-domain audit instrumentation."""

from __future__ import annotations

import asyncio
import inspect
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.routers import customers, devices, geo, groups, networks
from app.core.audit_context import (
    bind_audit_actor,
    bind_request_context,
    reset_audit_context,
)
from app.models import (
    AuditLog,
    City,
    Customer,
    CustomerService,
    Device,
    DeviceGroup,
    DeviceGroupMembership,
    DeviceHierarchyLink,
    DeviceIP,
    DevicePlacement,
    DeviceType,
    Location,
    Network,
    Sector,
)
from app.schemas.customer import CustomerCreate, CustomerUpdate
from app.schemas.device import DeviceUpdate
from app.schemas.group import (
    DeviceGroupCreate,
    DeviceGroupScope,
    DeviceGroupUpdate,
    DeviceScope,
)
from app.services import (
    customer_services,
    device_registration,
    groups as group_services,
    movement,
    placements,
    relationships,
    sector_roles,
)
from app.services.audit import enable_audit_maintenance
from app.services.device_domain import create_domain_placement
from app.settings import settings


def _run(coroutine):
    asyncio.run(coroutine)


def test_required_domain_actions_are_instrumented_at_mutation_boundaries():
    action_sources = {
        "NETWORK_CREATED": networks.create_network,
        "NETWORK_UPDATED": networks.update_network,
        "CITY_CREATED": geo.create_city,
        "CITY_UPDATED": geo.update_city,
        "LOCATION_CREATED": geo.create_location,
        "LOCATION_UPDATED": geo.update_location,
        "SECTOR_CREATED": geo.create_sector,
        "SECTOR_UPDATED": geo.update_sector,
        "SECTOR_ROLE_CHANGED": sector_roles.transition_sector_role,
        "DEVICE_CREATED": device_registration.register_domain_device,
        "DEVICE_UPDATED": devices.update_device,
        "DEVICE_DECOMMISSIONED": devices.decommission_device,
        "DEVICE_IP_ADDED": devices.add_device_ip,
        "DEVICE_IP_UPDATED": devices.update_device_ip,
        "DEVICE_INTERFACE_CHANGED": devices.update_device_interface,
        "DEVICE_ACCESS_ATTEMPT": devices.test_device_accessibility,
        "DEVICE_ACCESS_SUCCESS": devices.test_device_accessibility,
        "DEVICE_ACCESS_FAILURE": devices.test_device_accessibility,
        "CUSTOMER_CREATED": customers.create_customer,
        "CUSTOMER_UPDATED": customers.update_customer,
        "CUSTOMER_SERVICE_CREATED": customer_services.create_customer_service,
        "CUSTOMER_SERVICE_UPDATED": customer_services.update_customer_service,
        "GROUP_CREATED": groups.create_group,
        "GROUP_UPDATED": groups.update_group,
        "GROUP_MEMBERSHIP_ADDED": group_services.add_membership,
        "GROUP_MEMBERSHIP_REMOVED": group_services.remove_membership,
        "GROUP_MEMBERSHIP_RECONCILED": group_services.reconcile_physical_move_memberships,
        "SECTOR_MOVED": movement.move_sector_to_location,
        "CPE_MOVED": movement.move_cpe_to_sector,
        "AP_REASSIGNED": movement.reassign_access_point,
        "DEVICE_PLACEMENT_UPDATED": placements.update_device_placement,
        "DEVICE_RELATIONSHIP_CREATED": relationships.create_device_relationship,
    }
    for action, mutation in action_sources.items():
        assert f'action="{action}"' in inspect.getsource(mutation), (
            action,
            mutation.__name__,
        )


def test_shared_registration_and_device_update_capture_context_without_credentials():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        suffix = uuid4().hex[:10]
        actor_id = uuid4()
        request_id = f"domain-audit-{suffix}"
        credential_one = f"vault://never-audit-{suffix}"
        credential_two = f"vault://never-audit-updated-{suffix}"
        ids = {}
        request_token = bind_request_context(
            request_id=request_id,
            source_ip="192.0.2.44",
        )
        actor_token = bind_audit_actor(actor_id, f"domain-auditor-{suffix}")
        try:
            async with factory() as db:
                network = Network(
                    name=f"Audit Network {suffix}",
                    code=f"AUD-N-{suffix}",
                )
                db.add(network)
                await db.flush()
                city = City(
                    network_id=network.id,
                    name=f"Audit City {suffix}",
                    code=f"AUD-C-{suffix}",
                )
                db.add(city)
                await db.flush()
                location = Location(
                    city_id=city.id,
                    name=f"Audit Location {suffix}",
                    code=f"AUD-L-{suffix}",
                    metadata_={},
                )
                db.add(location)
                device_type = await db.scalar(
                    select(DeviceType).where(DeviceType.code == "SWITCH")
                )
                assert device_type is not None
                await db.flush()

                registration = await device_registration.register_domain_device(
                    db,
                    device_type_id=device_type.id,
                    display_name=f"Audit Switch {suffix}",
                    management_ip=f"fd00:{suffix[:4]}:{suffix[4:8]}::{suffix[8:10]}",
                    location_id=location.id,
                    sector_id=None,
                    parent_device_id=None,
                    credential_reference=credential_one,
                    metadata={"password": "also-never-audit"},
                    ip_source="AUDIT_TEST",
                )
                await db.commit()

                await devices.update_device(
                    registration.device.id,
                    DeviceUpdate(
                        display_name=f"Updated Audit Switch {suffix}",
                        credential_reference=credential_two,
                    ),
                    db,
                )
                ids.update(
                    network_id=network.id,
                    city_id=city.id,
                    location_id=location.id,
                    device_id=registration.device.id,
                    ip_id=registration.management_ip.id,
                )

            async with factory() as verify:
                rows = (
                    await verify.scalars(
                        select(AuditLog)
                        .where(
                            AuditLog.entity_id.in_([ids["device_id"], ids["ip_id"]]),
                            AuditLog.action.in_(
                                ["DEVICE_CREATED", "DEVICE_IP_ADDED", "DEVICE_UPDATED"]
                            ),
                        )
                        .order_by(AuditLog.occurred_at, AuditLog.id)
                    )
                ).all()
                assert {row.action for row in rows} == {
                    "DEVICE_CREATED",
                    "DEVICE_IP_ADDED",
                    "DEVICE_UPDATED",
                }
                for row in rows:
                    assert row.actor_user_id == actor_id
                    assert row.actor_username_snapshot == f"domain-auditor-{suffix}"
                    assert row.request_id == request_id
                    assert row.source_ip == "192.0.2.44"
                    assert row.result == "SUCCESS"

                evidence = json.dumps(
                    [
                        {
                            "display": row.entity_display_snapshot,
                            "before": row.before_summary,
                            "after": row.after_summary,
                            "metadata": row.metadata_,
                            "description": row.description,
                        }
                        for row in rows
                    ],
                    default=str,
                )
                assert credential_one not in evidence
                assert credential_two not in evidence
                assert "also-never-audit" not in evidence
                assert "credential_reference" not in evidence
        finally:
            reset_audit_context(actor_token)
            reset_audit_context(request_token)
            if ids:
                async with factory() as cleanup:
                    await enable_audit_maintenance(cleanup)
                    await cleanup.execute(
                        delete(AuditLog).where(
                            AuditLog.entity_id.in_([ids["device_id"], ids["ip_id"]])
                        )
                    )
                    await cleanup.execute(
                        delete(DevicePlacement).where(
                            DevicePlacement.device_id == ids["device_id"]
                        )
                    )
                    await cleanup.execute(delete(DeviceIP).where(DeviceIP.id == ids["ip_id"]))
                    await cleanup.execute(delete(Device).where(Device.id == ids["device_id"]))
                    await cleanup.execute(delete(Location).where(Location.id == ids["location_id"]))
                    await cleanup.execute(delete(City).where(City.id == ids["city_id"]))
                    await cleanup.execute(delete(Network).where(Network.id == ids["network_id"]))
                    await cleanup.commit()
            await engine.dispose()

    _run(scenario())


def test_device_access_records_attempt_failure_and_success(monkeypatch):
    unexpected_secret = f"unexpected-never-audit-{uuid4().hex}"

    class FakeClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def get(self, _url):
            return SimpleNamespace(status_code=204)

    monkeypatch.setattr(devices.httpx, "AsyncClient", FakeClient)

    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        suffix = uuid4().hex[:10]
        ids = {}
        request_token = bind_request_context(
            request_id=f"access-audit-{suffix}",
            source_ip="198.51.100.9",
        )
        actor_token = bind_audit_actor(uuid4(), f"access-auditor-{suffix}")
        try:
            async with factory() as db:
                device_type = await db.scalar(
                    select(DeviceType).where(DeviceType.code == "SWITCH")
                )
                assert device_type is not None
                device = Device(
                    device_type_id=device_type.id,
                    display_name=f"Access Audit Device {suffix}",
                    lifecycle_state="REGISTERED",
                    operational_state="UNKNOWN",
                    management_protocol="HTTP",
                    metadata_={},
                )
                db.add(device)
                await db.commit()
                ids["device_id"] = device.id

                failed = await devices.test_device_accessibility(device.id, db)
                assert failed.reachable is False

                ip_row = DeviceIP(
                    device_id=device.id,
                    ip_address=f"fd01:{suffix[:4]}:{suffix[4:8]}::{suffix[8:10]}",
                    address_family=6,
                    is_management=True,
                    is_primary=True,
                    source="AUDIT_TEST",
                )
                db.add(ip_row)
                await db.commit()
                ids["ip_id"] = ip_row.id

                succeeded = await devices.test_device_accessibility(device.id, db)
                assert succeeded.reachable is True
                assert succeeded.status_code == 204

                class UnexpectedClient(FakeClient):
                    async def get(self, _url):
                        raise RuntimeError(unexpected_secret)

                monkeypatch.setattr(devices.httpx, "AsyncClient", UnexpectedClient)
                with pytest.raises(RuntimeError, match="unexpected-never-audit"):
                    await devices.test_device_accessibility(device.id, db)

            async with factory() as verify:
                events = (
                    await verify.scalars(
                        select(AuditLog)
                        .where(
                            AuditLog.entity_id == ids["device_id"],
                            AuditLog.action.in_(
                                [
                                    "DEVICE_ACCESS_ATTEMPT",
                                    "DEVICE_ACCESS_FAILURE",
                                    "DEVICE_ACCESS_SUCCESS",
                                ]
                            ),
                        )
                        .order_by(AuditLog.occurred_at, AuditLog.id)
                    )
                ).all()
                assert [event.action for event in events].count("DEVICE_ACCESS_ATTEMPT") == 3
                assert [event.action for event in events].count("DEVICE_ACCESS_FAILURE") == 2
                assert [event.action for event in events].count("DEVICE_ACCESS_SUCCESS") == 1
                assert {
                    event.result for event in events if event.action == "DEVICE_ACCESS_ATTEMPT"
                } == {"ATTEMPT"}
                assert {
                    event.result for event in events if event.action == "DEVICE_ACCESS_FAILURE"
                } == {"FAILURE"}
                assert next(
                    event for event in events if event.action == "DEVICE_ACCESS_SUCCESS"
                ).result == "SUCCESS"
                unexpected_failures = [
                    event
                    for event in events
                    if event.action == "DEVICE_ACCESS_FAILURE"
                    and event.metadata_.get("error_type") == "RuntimeError"
                ]
                assert len(unexpected_failures) == 1
                evidence = json.dumps(
                    [
                        {
                            "description": event.description,
                            "display": event.entity_display_snapshot,
                            "before": event.before_summary,
                            "after": event.after_summary,
                            "metadata": event.metadata_,
                        }
                        for event in events
                    ],
                    default=str,
                )
                assert unexpected_secret not in evidence
        finally:
            reset_audit_context(actor_token)
            reset_audit_context(request_token)
            if ids:
                async with factory() as cleanup:
                    await enable_audit_maintenance(cleanup)
                    await cleanup.execute(
                        delete(AuditLog).where(AuditLog.entity_id == ids["device_id"])
                    )
                    if ids.get("ip_id"):
                        await cleanup.execute(delete(DeviceIP).where(DeviceIP.id == ids["ip_id"]))
                    await cleanup.execute(delete(Device).where(Device.id == ids["device_id"]))
                    await cleanup.commit()
            await engine.dispose()

    _run(scenario())


def test_customer_group_and_physical_movement_audits_are_committed_with_context():
    async def scenario():
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        suffix = uuid4().hex[:10]
        actor_id = uuid4()
        request_id = f"domain-runtime-audit-{suffix}"
        secret = f"runtime-secret-never-audit-{suffix}"
        ids: dict[str, object] = {"device_ids": [], "group_ids": []}
        request_token = bind_request_context(
            request_id=request_id,
            source_ip="203.0.113.27",
        )
        actor_token = bind_audit_actor(actor_id, f"runtime-auditor-{suffix}")
        try:
            async with factory() as db:
                network = Network(
                    name=f"Runtime Audit Network {suffix}",
                    code=f"RTA-N-{suffix}",
                )
                db.add(network)
                await db.flush()
                city = City(
                    network_id=network.id,
                    name=f"Runtime Audit City {suffix}",
                    code=f"RTA-C-{suffix}",
                )
                db.add(city)
                await db.flush()
                source_location = Location(
                    city_id=city.id,
                    name=f"Runtime Audit Source {suffix}",
                    code=f"RTA-LS-{suffix}",
                    metadata_={},
                )
                destination_location = Location(
                    city_id=city.id,
                    name=f"Runtime Audit Destination {suffix}",
                    code=f"RTA-LD-{suffix}",
                    metadata_={},
                )
                db.add_all([source_location, destination_location])
                await db.flush()
                source_sector = Sector(
                    location_id=source_location.id,
                    name=f"Runtime Audit Source Sector {suffix}",
                    code=f"RTA-SS-{suffix}",
                    sequence_number=1,
                    role="CUSTOMER_ACCESS",
                    metadata_={},
                )
                destination_sector = Sector(
                    location_id=destination_location.id,
                    name=f"Runtime Audit Destination Sector {suffix}",
                    code=f"RTA-SD-{suffix}",
                    sequence_number=1,
                    role="CUSTOMER_ACCESS",
                    metadata_={},
                )
                db.add_all([source_sector, destination_sector])
                await db.flush()

                type_rows = (
                    await db.scalars(
                        select(DeviceType).where(
                            DeviceType.code.in_(["SECTOR", "CPE", "ACCESS_POINT"])
                        )
                    )
                ).all()
                device_types = {row.code: row for row in type_rows}
                assert set(device_types) == {"SECTOR", "CPE", "ACCESS_POINT"}

                async def add_device(type_code: str, label: str) -> Device:
                    device = Device(
                        device_type_id=device_types[type_code].id,
                        display_name=f"{label} {suffix}",
                        hostname=f"{label.lower()}-{suffix}",
                        lifecycle_state="ACTIVE",
                        operational_state="UP",
                        metadata_={},
                    )
                    db.add(device)
                    await db.flush()
                    ids["device_ids"].append(device.id)
                    return device

                source_sector_device = await add_device("SECTOR", "RTA-SOURCE-SECTOR")
                destination_sector_device = await add_device(
                    "SECTOR", "RTA-DESTINATION-SECTOR"
                )
                source_cpe = await add_device("CPE", "RTA-SOURCE-CPE")
                access_point = await add_device("ACCESS_POINT", "RTA-AP")
                destination_cpe = await add_device("CPE", "RTA-DESTINATION-CPE")

                await create_domain_placement(
                    db,
                    source_sector_device,
                    "SECTOR",
                    location_id=None,
                    sector_id=source_sector.id,
                    parent_device_id=None,
                )
                await db.flush()
                await create_domain_placement(
                    db,
                    destination_sector_device,
                    "SECTOR",
                    location_id=None,
                    sector_id=destination_sector.id,
                    parent_device_id=None,
                )
                await db.flush()
                await create_domain_placement(
                    db,
                    source_cpe,
                    "CPE",
                    location_id=None,
                    sector_id=None,
                    parent_device_id=source_sector_device.id,
                )
                await db.flush()
                await create_domain_placement(
                    db,
                    access_point,
                    "ACCESS_POINT",
                    location_id=None,
                    sector_id=None,
                    parent_device_id=source_cpe.id,
                )
                await db.flush()
                await create_domain_placement(
                    db,
                    destination_cpe,
                    "CPE",
                    location_id=None,
                    sector_id=None,
                    parent_device_id=destination_sector_device.id,
                )
                await db.commit()

                ids.update(
                    network_id=network.id,
                    city_id=city.id,
                    location_ids=[source_location.id, destination_location.id],
                    sector_ids=[source_sector.id, destination_sector.id],
                )

                customer = await customers.create_customer(
                    CustomerCreate(
                        customer_code=f"RTA-CUSTOMER-{suffix}",
                        name=f"Runtime Audit Customer {suffix}",
                        metadata={"password": secret},
                    ),
                    db,
                )
                ids["customer_id"] = customer.id
                await customers.update_customer(
                    customer.id,
                    CustomerUpdate(name=f"Updated Runtime Audit Customer {suffix}"),
                    db,
                )

                service = await customer_services.create_customer_service(
                    db,
                    customer_id=customer.id,
                    sector_id=source_sector.id,
                    service_code=f"RTA-SERVICE-{suffix}",
                    status="ACTIVE",
                    cpe_device_id=source_cpe.id,
                    access_point_device_id=access_point.id,
                    router_device_id=None,
                    metadata={"token": secret},
                )
                await db.commit()
                ids["service_id"] = service.id
                await customer_services.update_customer_service(
                    db,
                    service,
                    sector_id=source_sector.id,
                    status="SUSPENDED",
                    cpe_device_id=source_cpe.id,
                    access_point_device_id=access_point.id,
                    router_device_id=None,
                    metadata={"token": f"updated-{secret}"},
                )
                await db.commit()

                global_group = await groups.create_group(
                    DeviceGroupCreate(
                        name=f"Runtime Audit Global Group {suffix}",
                        code=f"RTA-GG-{suffix}",
                        scope_type=DeviceGroupScope.GLOBAL,
                        device_scope=DeviceScope.ANY,
                        metadata={"credential_reference": secret},
                    ),
                    db,
                )
                ids["group_ids"].append(global_group.id)
                await groups.update_group(
                    global_group.id,
                    DeviceGroupUpdate(name=f"Updated Runtime Audit Global Group {suffix}"),
                    db,
                )
                global_membership = await group_services.add_membership(
                    db,
                    source_cpe.id,
                    global_group.id,
                )
                await db.commit()
                ids["global_membership_id"] = global_membership.id
                await group_services.remove_membership(
                    db,
                    source_cpe.id,
                    global_group.id,
                )
                await db.commit()

                scoped_group = await groups.create_group(
                    DeviceGroupCreate(
                        name=f"Runtime Audit Source Sector Group {suffix}",
                        code=f"RTA-SG-{suffix}",
                        scope_type=DeviceGroupScope.SECTOR,
                        sector_id=source_sector.id,
                        device_scope=DeviceScope.CPE,
                    ),
                    db,
                )
                ids["group_ids"].append(scoped_group.id)
                scoped_membership = await group_services.add_membership(
                    db,
                    source_cpe.id,
                    scoped_group.id,
                )
                await db.commit()
                ids["scoped_membership_id"] = scoped_membership.id

                await movement.move_cpe_to_sector(
                    db,
                    cpe_device_id=source_cpe.id,
                    destination_sector_device_id=destination_sector_device.id,
                )
                await db.commit()
                await movement.reassign_access_point(
                    db,
                    access_point_device_id=access_point.id,
                    destination_cpe_device_id=destination_cpe.id,
                )
                await db.commit()

            async with factory() as verify:
                events = (
                    await verify.scalars(
                        select(AuditLog)
                        .where(AuditLog.request_id == request_id)
                        .order_by(AuditLog.occurred_at, AuditLog.id)
                    )
                ).all()
                events_by_action: dict[str, list[AuditLog]] = {}
                for event in events:
                    events_by_action.setdefault(event.action, []).append(event)

                required_actions = {
                    "CUSTOMER_CREATED",
                    "CUSTOMER_UPDATED",
                    "CUSTOMER_SERVICE_CREATED",
                    "CUSTOMER_SERVICE_UPDATED",
                    "GROUP_CREATED",
                    "GROUP_UPDATED",
                    "GROUP_MEMBERSHIP_ADDED",
                    "GROUP_MEMBERSHIP_REMOVED",
                    "GROUP_MEMBERSHIP_RECONCILED",
                    "CPE_MOVED",
                    "AP_REASSIGNED",
                }
                assert required_actions <= set(events_by_action)
                for action in required_actions:
                    for event in events_by_action[action]:
                        assert event.actor_user_id == actor_id
                        assert event.actor_username_snapshot == f"runtime-auditor-{suffix}"
                        assert event.request_id == request_id
                        assert event.source_ip == "203.0.113.27"
                        assert event.result == "SUCCESS"
                        assert event.entity_display_snapshot

                for action in {
                    "CUSTOMER_CREATED",
                    "CUSTOMER_SERVICE_CREATED",
                    "GROUP_CREATED",
                    "GROUP_MEMBERSHIP_ADDED",
                }:
                    assert any(event.after_summary for event in events_by_action[action])
                for action in {"CUSTOMER_UPDATED", "CUSTOMER_SERVICE_UPDATED", "GROUP_UPDATED"}:
                    event = events_by_action[action][0]
                    assert event.before_summary
                    assert event.after_summary
                for action in {
                    "GROUP_MEMBERSHIP_REMOVED",
                    "GROUP_MEMBERSHIP_RECONCILED",
                }:
                    assert any(event.before_summary for event in events_by_action[action])
                for action in {"CPE_MOVED", "AP_REASSIGNED"}:
                    event = events_by_action[action][0]
                    assert event.before_summary
                    assert event.after_summary

                evidence = json.dumps(
                    [
                        {
                            "description": event.description,
                            "display": event.entity_display_snapshot,
                            "before": event.before_summary,
                            "after": event.after_summary,
                            "metadata": event.metadata_,
                        }
                        for event in events
                    ],
                    default=str,
                )
                assert secret not in evidence
                assert f"updated-{secret}" not in evidence
        finally:
            reset_audit_context(actor_token)
            reset_audit_context(request_token)
            if ids.get("network_id"):
                async with factory() as cleanup:
                    await enable_audit_maintenance(cleanup)
                    await cleanup.execute(
                        delete(AuditLog).where(AuditLog.request_id == request_id)
                    )
                    if ids.get("customer_id"):
                        await cleanup.execute(
                            delete(CustomerService).where(
                                CustomerService.customer_id == ids["customer_id"]
                            )
                        )
                    device_ids = ids["device_ids"]
                    if device_ids:
                        await cleanup.execute(
                            delete(DeviceGroupMembership).where(
                                DeviceGroupMembership.device_id.in_(device_ids)
                            )
                        )
                    group_ids = ids["group_ids"]
                    if group_ids:
                        await cleanup.execute(
                            delete(DeviceGroup).where(DeviceGroup.id.in_(group_ids))
                        )
                    if device_ids:
                        await cleanup.execute(
                            delete(DeviceHierarchyLink).where(
                                (DeviceHierarchyLink.child_device_id.in_(device_ids))
                                | (DeviceHierarchyLink.parent_device_id.in_(device_ids))
                            )
                        )
                        await cleanup.execute(
                            delete(DevicePlacement).where(
                                DevicePlacement.device_id.in_(device_ids)
                            )
                        )
                        await cleanup.execute(delete(Device).where(Device.id.in_(device_ids)))
                    if ids.get("customer_id"):
                        await cleanup.execute(
                            delete(Customer).where(Customer.id == ids["customer_id"])
                        )
                    sector_ids = ids.get("sector_ids", [])
                    if sector_ids:
                        await cleanup.execute(delete(Sector).where(Sector.id.in_(sector_ids)))
                    location_ids = ids.get("location_ids", [])
                    if location_ids:
                        await cleanup.execute(
                            delete(Location).where(Location.id.in_(location_ids))
                        )
                    await cleanup.execute(delete(City).where(City.id == ids["city_id"]))
                    await cleanup.execute(delete(Network).where(Network.id == ids["network_id"]))
                    await cleanup.commit()
            await engine.dispose()

    _run(scenario())
