import asyncio
from uuid import uuid4

from sqlalchemy import select

from app.db.session import AsyncSessionLocal, engine
from app.models import (
    City,
    Device,
    DeviceGroup,
    DeviceGroupMembership,
    DeviceGroupScope,
    DevicePlacement,
    DeviceType,
    Location,
    Network,
)
from app.services.groups import move_membership


def test_move_membership_real_postgresql_transaction():
    """
    Real PostgreSQL integration test for organizational movement.

    The test executes the real async SQLAlchemy service through asyncio.run()
    because the project does not currently install an async pytest plugin.

    All test data is created inside a transaction and rolled back at the end.
    """

    async def run_test():
        await engine.dispose()
        
        async with AsyncSessionLocal() as db:
            transaction = await db.begin()

            try:
                # ---------------------------------------------------------
                # 1. Create physical hierarchy
                # ---------------------------------------------------------

                network = Network(
                    name=f"Integration Network {uuid4()}",
                    code=f"INT-NET-{uuid4().hex[:12]}",
                )

                db.add(network)
                await db.flush()

                city = City(
                    network_id=network.id,
                    name=f"Integration City {uuid4()}",
                    code=f"INT-CITY-{uuid4().hex[:12]}",
                )

                db.add(city)
                await db.flush()

                location = Location(
                    city_id=city.id,
                    name=f"Integration Location {uuid4()}",
                    code=f"INT-LOC-{uuid4().hex[:12]}",
                )

                db.add(location)
                await db.flush()

                # ---------------------------------------------------------
                # 2. Create device type and device
                # ---------------------------------------------------------

                device_type = await db.scalar(
                    select(DeviceType).where(DeviceType.code == "SWITCH")
                )
                assert device_type is not None

                device = Device(
                    device_type_id=device_type.id,
                    display_name=f"Integration Device {uuid4()}",
                    hostname=f"int-device-{uuid4().hex[:12]}",
                    vendor="Integration-Test",
                    model="TEST",
                )

                db.add(device)
                await db.flush()

                # ---------------------------------------------------------
                # 3. Create physical placement
                # ---------------------------------------------------------

                placement = DevicePlacement(
                    device_id=device.id,
                    network_id=network.id,
                    city_id=city.id,
                    location_id=location.id,
                    sector_id=None,
                )

                db.add(placement)
                await db.flush()

                placement_before = {
                    "network_id": placement.network_id,
                    "city_id": placement.city_id,
                    "location_id": placement.location_id,
                    "sector_id": placement.sector_id,
                    "metadata": dict(placement.metadata_),
                }

                # ---------------------------------------------------------
                # 4. Create two CITY groups in the same context
                # ---------------------------------------------------------

                source_group = DeviceGroup(
                    name=f"Integration Source Group {uuid4()}",
                    code=f"INT-SRC-{uuid4().hex[:12]}",
                    scope_type=DeviceGroupScope.CITY.value,
                    network_id=None,
                    city_id=city.id,
                    location_id=None,
                    sector_id=None,
                )

                destination_group = DeviceGroup(
                    name=f"Integration Destination Group {uuid4()}",
                    code=f"INT-DST-{uuid4().hex[:12]}",
                    scope_type=DeviceGroupScope.CITY.value,
                    network_id=None,
                    city_id=city.id,
                    location_id=None,
                    sector_id=None,
                )

                db.add_all(
                    [
                        source_group,
                        destination_group,
                    ]
                )

                await db.flush()

                # ---------------------------------------------------------
                # 5. Create unrelated GLOBAL membership
                # ---------------------------------------------------------

                global_group = DeviceGroup(
                    name=f"Integration Global Group {uuid4()}",
                    code=f"INT-GLOBAL-{uuid4().hex[:12]}",
                    scope_type=DeviceGroupScope.GLOBAL.value,
                    network_id=None,
                    city_id=None,
                    location_id=None,
                    sector_id=None,
                )

                db.add(global_group)
                await db.flush()

                source_membership = DeviceGroupMembership(
                    device_id=device.id,
                    group_id=source_group.id,
                )

                unrelated_membership = DeviceGroupMembership(
                    device_id=device.id,
                    group_id=global_group.id,
                )

                db.add_all(
                    [
                        source_membership,
                        unrelated_membership,
                    ]
                )

                await db.flush()

                # ---------------------------------------------------------
                # 6. Snapshot device state
                # ---------------------------------------------------------

                device_before = {
                    "display_name": device.display_name,
                    "hostname": device.hostname,
                    "vendor": device.vendor,
                    "model": device.model,
                    "lifecycle_state": device.lifecycle_state,
                    "operational_state": device.operational_state,
                    "management_protocol": device.management_protocol,
                    "credential_reference": device.credential_reference,
                    "metadata": dict(device.metadata_),
                }

                # ---------------------------------------------------------
                # 7. Execute actual organizational movement
                # ---------------------------------------------------------

                new_membership = await move_membership(
                    db,
                    device.id,
                    destination_group.id,
                )

                await db.flush()

                # ---------------------------------------------------------
                # 8. Destination membership exists
                # ---------------------------------------------------------

                destination_result = await db.execute(
                    select(DeviceGroupMembership).where(
                        DeviceGroupMembership.device_id == device.id,
                        DeviceGroupMembership.group_id == destination_group.id,
                    )
                )

                destination_membership = destination_result.scalar_one_or_none()

                assert destination_membership is not None
                assert destination_membership.id == new_membership.id

                # ---------------------------------------------------------
                # 9. Source membership removed
                # ---------------------------------------------------------

                source_result = await db.execute(
                    select(DeviceGroupMembership).where(
                        DeviceGroupMembership.device_id == device.id,
                        DeviceGroupMembership.group_id == source_group.id,
                    )
                )

                assert source_result.scalar_one_or_none() is None

                # ---------------------------------------------------------
                # 10. Unrelated GLOBAL membership remains
                # ---------------------------------------------------------

                unrelated_result = await db.execute(
                    select(DeviceGroupMembership).where(
                        DeviceGroupMembership.device_id == device.id,
                        DeviceGroupMembership.group_id == global_group.id,
                    )
                )

                assert unrelated_result.scalar_one_or_none() is not None

                # ---------------------------------------------------------
                # 11. Physical placement unchanged
                # ---------------------------------------------------------

                placement_result = await db.execute(
                    select(DevicePlacement).where(
                        DevicePlacement.device_id == device.id,
                    )
                )

                placement_after = placement_result.scalar_one()

                placement_after_snapshot = {
                    "network_id": placement_after.network_id,
                    "city_id": placement_after.city_id,
                    "location_id": placement_after.location_id,
                    "sector_id": placement_after.sector_id,
                    "metadata": dict(placement_after.metadata_),
                }

                assert placement_after_snapshot == placement_before

                # ---------------------------------------------------------
                # 12. Device itself unchanged
                # ---------------------------------------------------------

                device_result = await db.execute(
                    select(Device).where(
                        Device.id == device.id,
                    )
                )

                device_after = device_result.scalar_one()

                device_after_snapshot = {
                    "display_name": device_after.display_name,
                    "hostname": device_after.hostname,
                    "vendor": device_after.vendor,
                    "model": device_after.model,
                    "lifecycle_state": device_after.lifecycle_state,
                    "operational_state": device_after.operational_state,
                    "management_protocol": device_after.management_protocol,
                    "credential_reference": device_after.credential_reference,
                    "metadata": dict(device_after.metadata_),
                }

                assert device_after_snapshot == device_before

            finally:
                # ---------------------------------------------------------
                # 13. Remove all integration-test data
                # ---------------------------------------------------------

                await transaction.rollback()
                await engine.dispose()

    asyncio.run(run_test())
