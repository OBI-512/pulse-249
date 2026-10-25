from __future__ import annotations

import asyncio
from sqlalchemy import and_, case, func, or_, select

from app.db.session import AsyncSessionLocal
from app.models import Device, DeviceAvailability


async def main() -> int:
    async with AsyncSessionLocal() as db:
        expected = case(
            (DeviceAvailability.status == "ONLINE", case((Device.manual_degraded_override.is_(True), "DEGRADED"), else_="UP")),
            (DeviceAvailability.status == "OFFLINE", "DOWN"),
            (DeviceAvailability.status.in_(["SUSPECT", "UNKNOWN"]), "UNKNOWN"),
            else_=Device.operational_state,
        )
        mismatches = int((await db.scalar(
            select(func.count(Device.id))
            .join(DeviceAvailability, DeviceAvailability.device_id == Device.id)
            .where(
                Device.deleted_at.is_(None),
                Device.lifecycle_state != "DECOMMISSIONED",
                DeviceAvailability.status != "MAINTENANCE",
                Device.operational_state != expected,
            )
        )) or 0)
        decommissioned_bad = int((await db.scalar(
            select(func.count(Device.id)).where(
                Device.deleted_at.is_(None),
                Device.lifecycle_state == "DECOMMISSIONED",
                Device.operational_state != "UNKNOWN",
            )
        )) or 0)
        print({"availability_operational_mismatches": mismatches, "decommissioned_non_unknown": decommissioned_bad})
        if mismatches or decommissioned_bad:
            raise SystemExit(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
