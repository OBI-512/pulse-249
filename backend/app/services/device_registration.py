from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Device, DeviceIP
from ..availability.service import ensure_device_availability
from .audit import record_audit
from .audit_summaries import business_summary, display_snapshot
from .device_domain import create_domain_placement, get_type_code


@dataclass(frozen=True)
class DeviceRegistrationResult:
    device: Device
    management_ip: DeviceIP
    type_code: str


def _domain_error(code: str, message: str, status_code: int = 422) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"code": code, "message": message},
    )


async def register_domain_device(
    db: AsyncSession,
    *,
    device_type_id: UUID,
    display_name: str,
    management_ip: str,
    location_id: UUID | None,
    sector_id: UUID | None,
    parent_device_id: UUID | None,
    hostname: str | None = None,
    vendor: str | None = None,
    model: str | None = None,
    serial_number: str | None = None,
    description: str | None = None,
    lifecycle_state: str = "REGISTERED",
    operational_state: str = "UNKNOWN",
    management_protocol: str | None = None,
    credential_reference: str | None = None,
    metadata: dict[str, Any] | None = None,
    ip_source: str,
) -> DeviceRegistrationResult:
    """Create a device, its mandatory management IP, and domain placement.

    This is the single write primitive used by manual, discovery-candidate,
    and onboarding registration.  It deliberately never commits; the caller
    owns the surrounding transaction and any audit/state changes.
    """

    type_code = await get_type_code(db, device_type_id)

    if management_ip is None or not str(management_ip).strip():
        raise _domain_error(
            "MANAGEMENT_IP_REQUIRED",
            "A management IP address is required for device registration.",
        )

    try:
        parsed_ip = ip_address(str(management_ip).strip())
    except ValueError as exc:
        raise _domain_error(
            "INVALID_MANAGEMENT_IP",
            "The management IP address is invalid.",
        ) from exc

    normalized_ip = str(parsed_ip)
    existing_ip = await db.scalar(
        select(DeviceIP).where(DeviceIP.ip_address == normalized_ip)
    )
    if existing_ip is not None:
        raise _domain_error(
            "IP_ALREADY_REGISTERED",
            "This management IP address is already registered.",
            409,
        )

    device = Device(
        device_type_id=device_type_id,
        display_name=display_name,
        hostname=hostname,
        vendor=vendor,
        model=model,
        serial_number=serial_number,
        description=description,
        lifecycle_state=lifecycle_state,
        operational_state=operational_state,
        management_protocol=management_protocol,
        credential_reference=credential_reference,
        metadata_=metadata or {},
    )
    db.add(device)
    await db.flush()
    await ensure_device_availability(db, device)

    await create_domain_placement(
        db,
        device,
        type_code,
        location_id=location_id,
        sector_id=sector_id,
        parent_device_id=parent_device_id,
    )

    management_ip_row = DeviceIP(
        id=uuid4(),
        device_id=device.id,
        ip_address=normalized_ip,
        address_family=parsed_ip.version,
        is_management=True,
        is_primary=True,
        source=ip_source,
    )
    db.add(management_ip_row)

    # Audit at the shared registration boundary so manual, candidate, and
    # onboarding registration have identical evidence. Credential references
    # and free-form metadata are deliberately excluded from the summaries.
    await record_audit(
        db,
        action="DEVICE_CREATED",
        entity_type="Device",
        entity_id=device.id,
        description="Device created through authoritative domain registration.",
        entity_display_snapshot=display_snapshot(device),
        metadata={"device_type": type_code, "registration_source": ip_source},
        after_summary=business_summary(device),
    )
    await record_audit(
        db,
        action="DEVICE_IP_ADDED",
        entity_type="DeviceIP",
        entity_id=management_ip_row.id,
        description="Mandatory management IP created during device registration.",
        entity_display_snapshot=display_snapshot(management_ip_row),
        metadata={"registration_source": ip_source},
        after_summary=business_summary(management_ip_row),
    )

    return DeviceRegistrationResult(
        device=device,
        management_ip=management_ip_row,
        type_code=type_code,
    )
