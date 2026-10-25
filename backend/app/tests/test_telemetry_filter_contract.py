from __future__ import annotations

import asyncio
from uuid import uuid4

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.routers.telemetry import list_profiles, list_states
from app.models import Device, DeviceIP, DeviceType, TelemetryDeviceState, TelemetryProfile
from app.settings import settings as app_settings


def test_telemetry_profile_and_state_filters_are_server_side():
    async def scenario():
        engine = create_async_engine(app_settings.database_url, poolclass=NullPool)
        SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        device_id = None
        marker = uuid4().hex[:10]
        display_name = f"Telemetry Filter UAT {marker}"
        hostname = f"uat-{marker}.example"
        management_ip = None
        try:
            async with SessionLocal() as db:
                dtype = await db.scalar(select(DeviceType).where(DeviceType.code == "CPE"))
                assert dtype is not None
                for host in range(20, 255):
                    candidate_ip = f"192.0.2.{host}"
                    exists = await db.scalar(select(DeviceIP.id).where(DeviceIP.ip_address == candidate_ip))
                    if exists is None:
                        management_ip = candidate_ip
                        break
                assert management_ip is not None
                profile = await db.scalar(select(TelemetryProfile).where(TelemetryProfile.device_type_id == dtype.id))
                assert profile is not None

                device = Device(
                    device_type_id=dtype.id,
                    display_name=display_name,
                    hostname=hostname,
                    lifecycle_state="REGISTERED",
                    operational_state="UNKNOWN",
                    management_protocol="SNMP",
                    metadata_={},
                )
                db.add(device)
                await db.flush()
                device_id = device.id
                db.add(DeviceIP(
                    device_id=device.id,
                    ip_address=management_ip,
                    address_family=4,
                    is_management=True,
                    is_primary=True,
                    source="TEST",
                ))
                db.add(TelemetryDeviceState(
                    device_id=device.id,
                    profile_id=profile.id,
                    enabled=True,
                    status="OK",
                    consecutive_failures=0,
                ))
                await db.commit()

                by_name = await list_states(
                    page=1, page_size=50, search=marker, status="OK", enabled=True,
                    device_type="CPE", sort_by="device_name", sort_direction="asc", db=db, actor=None,
                )
                assert by_name.total == 1
                assert by_name.items[0]["device_id"] == device.id

                by_ip = await list_states(
                    page=1, page_size=50, search=management_ip, status=None, enabled=None,
                    device_type=None, sort_by="device_name", sort_direction="asc", db=db, actor=None,
                )
                assert by_ip.total == 1
                assert by_ip.items[0]["device_id"] == device.id

                filtered_profiles = await list_profiles(
                    search=profile.name, enabled=profile.enabled, db=db, actor=None,
                )
                assert any(row["id"] == profile.id for row in filtered_profiles)
        finally:
            if device_id is not None:
                async with SessionLocal() as db:
                    await db.execute(delete(Device).where(Device.id == device_id))
                    await db.commit()
            await engine.dispose()

    asyncio.run(scenario())

