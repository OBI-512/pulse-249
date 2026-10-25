from __future__ import annotations

from ipaddress import ip_address as parse_ip_address
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from ...security.authorization import require_permission
from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...security.authorization import authorize_request
from ...models import (
    AuditLog,
    City,
    Device,
    DeviceCandidate,
    DeviceIP,
    DeviceHierarchyLink,
    DevicePlacement,
    DeviceType,
    Location,
    Network,
    Sector,
)
from ...schemas.candidates import (
    CandidateApprove,
    CandidatePage,
    CandidateRead,
    CandidateReject,
    CandidateRegistration,
    CandidateUpdate,
)
from ...services.audit import record_audit
from ...services.candidates import (
    CANDIDATE_APPROVED,
    CANDIDATE_NEW,
    CANDIDATE_REGISTERED,
    CANDIDATE_REJECTED,
    can_transition,
)
from ...services.crud import get_or_404
from ...services.device_domain import get_type_code
from ...services.device_registration import register_domain_device
from ...services.relationships import RelationshipValidationError, create_device_relationship

async def _validate_review_assignment(
    db: AsyncSession,
    data: dict,
) -> None:
    network_id = data.get("network_id")
    city_id = data.get("city_id")
    location_id = data.get("location_id")
    sector_id = data.get("sector_id")

    hierarchy = (
        network_id,
        city_id,
        location_id,
    )

    if any(x is not None for x in hierarchy) and not all(
        x is not None for x in hierarchy
    ):
        raise HTTPException(
            status_code=422,
            detail={
                "code": "INCOMPLETE_PLACEMENT",
                "message": (
                    "Network, city, and location are required together "
                    "for device placement."
                ),
            },
        )

    if sector_id is not None and location_id is None:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "LOCATION_REQUIRED",
                "message": (
                    "Location is required when assigning a sector."
                ),
            },
        )

    if network_id is not None:
        await get_or_404(db, Network, network_id)

    if city_id is not None:
        city = await get_or_404(db, City, city_id)

        if network_id is not None and city.network_id != network_id:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "CITY_NETWORK_MISMATCH",
                    "message": (
                        "City does not belong to the selected network."
                    ),
                },
            )

    if location_id is not None:
        location = await get_or_404(
            db,
            Location,
            location_id,
        )

        if city_id is not None and location.city_id != city_id:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "LOCATION_CITY_MISMATCH",
                    "message": (
                        "Location does not belong to the selected city."
                    ),
                },
            )

    if sector_id is not None:
        sector = await get_or_404(
            db,
            Sector,
            sector_id,
        )

        if (
            location_id is not None
            and sector.location_id != location_id
        ):
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "SECTOR_LOCATION_MISMATCH",
                    "message": (
                        "Sector does not belong to the selected location."
                    ),
                },
            )

    if data.get("relationship_target_device_id") is not None:
        await get_or_404(
            db,
            Device,
            data["relationship_target_device_id"],
        )

        if not data.get("relationship_type"):
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "RELATIONSHIP_TYPE_REQUIRED",
                    "message": (
                        "Relationship type is required when a target "
                        "device is selected."
                    ),
                },
            )


async def _validate_type_specific_assignment(
    db: AsyncSession, *, type_code: str | None, data: dict, require_complete: bool
) -> None:
    if not type_code:
        return
    parent_id = data.get("relationship_target_device_id")
    sector_id = data.get("sector_id")
    location_id = data.get("location_id")
    if type_code == "CPE":
        if parent_id is None:
            if require_complete:
                raise HTTPException(422, detail={"code": "PARENT_DEVICE_REQUIRED", "message": "CPE candidates require a physical customer-access SECTOR parent."})
            return
        parent = (await db.execute(
            select(Device, Sector).join(DeviceType, DeviceType.id == Device.device_type_id).join(Sector, Sector.sector_device_id == Device.id).where(
                Device.id == parent_id, Device.deleted_at.is_(None), DeviceType.code == "SECTOR",
                Device.lifecycle_state != "DECOMMISSIONED", Sector.deleted_at.is_(None), Sector.status == "ACTIVE", Sector.role == "CUSTOMER_ACCESS",
            )
        )).first()
        if parent is None:
            raise HTTPException(422, detail={"code": "INVALID_CPE_PARENT", "message": "Select an active physical SECTOR device bound to a CUSTOMER_ACCESS logical sector."})
        return
    if type_code == "ACCESS_POINT":
        if parent_id is None:
            if require_complete:
                raise HTTPException(422, detail={"code": "PARENT_DEVICE_REQUIRED", "message": "ACCESS_POINT candidates require a CPE parent."})
            return
        parent_type = await db.scalar(
            select(DeviceType.code).join(Device, Device.device_type_id == DeviceType.id).where(
                Device.id == parent_id, Device.deleted_at.is_(None), Device.lifecycle_state != "DECOMMISSIONED"
            )
        )
        if parent_type != "CPE":
            raise HTTPException(422, detail={"code": "INVALID_AP_PARENT", "message": "Select an active CPE as the ACCESS_POINT parent."})
        existing_ap = await db.scalar(select(DeviceHierarchyLink.id).where(
            DeviceHierarchyLink.parent_device_id == parent_id, DeviceHierarchyLink.relationship_type == "CPE_ACCESS_POINT", DeviceHierarchyLink.deleted_at.is_(None),
        ))
        if existing_ap is not None:
            raise HTTPException(409, detail={"code": "CPE_ALREADY_HAS_ACCESS_POINT", "message": "The selected CPE already has an access point."})
        return
    if type_code == "SECTOR":
        if sector_id is None:
            if require_complete:
                raise HTTPException(422, detail={"code": "SECTOR_ID_REQUIRED", "message": "A SECTOR candidate must bind to an available logical sector."})
            return
        sector = await db.scalar(select(Sector).where(Sector.id == sector_id, Sector.deleted_at.is_(None), Sector.status == "ACTIVE"))
        if sector is None:
            raise HTTPException(422, detail={"code": "SECTOR_NOT_AVAILABLE", "message": "The selected logical sector is not active or no longer exists."})
        if sector.sector_device_id is not None:
            raise HTTPException(409, detail={"code": "SECTOR_ALREADY_HAS_DEVICE", "message": "The selected logical sector already has a physical SECTOR device."})
        return
    if location_id is None:
        if require_complete:
            raise HTTPException(422, detail={"code": "LOCATION_REQUIRED", "message": f"{type_code} candidates require an active location."})
        return
    location = await db.scalar(select(Location).where(Location.id == location_id, Location.deleted_at.is_(None), Location.status == "ACTIVE"))
    if location is None:
        raise HTTPException(422, detail={"code": "LOCATION_NOT_AVAILABLE", "message": "The selected location is not active or no longer exists."})


def _validated_ipv4(value: str) -> str:
    try:
        parsed = parse_ip_address(value.strip())
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_IPV4", "message": "Management IP must be a valid IPv4 address."},
        ) from exc
    if parsed.version != 4:
        raise HTTPException(
            status_code=422,
            detail={"code": "IPV4_REQUIRED", "message": "Management IP must use IPv4 format."},
        )
    return str(parsed)


def _candidate_ip_is_editable(candidate: DeviceCandidate) -> bool:
    metadata = candidate.metadata_ or {}
    return candidate.discovery_result_id is None and metadata.get("source") != "DISCOVERY" and "discovery" not in metadata


async def _ensure_candidate_ip_available(
    db: AsyncSession, *, candidate: DeviceCandidate, value: str
) -> str:
    normalized = _validated_ipv4(value)
    duplicate_candidate = await db.scalar(
        select(DeviceCandidate.id).where(
            DeviceCandidate.ip_address == normalized, DeviceCandidate.id != candidate.id
        )
    )
    if duplicate_candidate is not None:
        raise HTTPException(
            status_code=409,
            detail={"code": "CANDIDATE_IP_ALREADY_EXISTS", "message": "Another candidate already uses this IPv4 address."},
        )
    duplicate_device = await db.scalar(select(DeviceIP.id).where(DeviceIP.ip_address == normalized))
    if duplicate_device is not None:
        raise HTTPException(
            status_code=409,
            detail={"code": "IP_ALREADY_REGISTERED", "message": "This IPv4 address is already registered to a device."},
        )
    return normalized


def _placement_option(
    *, option_id, name: str, code: str, network: Network, city: City, location: Location, sector: Sector | None = None
) -> dict:
    context = f"{location.name} / {city.name} / {network.name}"
    label = f"{name} — {context}"
    return {
        "id": option_id, "name": name, "code": code,
        "network_id": network.id, "network_name": network.name,
        "city_id": city.id, "city_name": city.name,
        "location_id": location.id, "location_name": location.name,
        "sector_id": sector.id if sector else None,
        "sector_name": sector.name if sector else None,
        "sector_role": sector.role if sector else None,
        "label": label,
    }


def _parse_registration_uuid(
    value: object,
) -> UUID | None:
    """
    Parse a persisted registration identifier safely.

    Registration metadata is persisted as JSON, so values may be strings,
    nulls, or malformed legacy values. Invalid values must never propagate
    into UUID construction and cause an unhandled 500 response.
    """
    if value is None:
        return None

    try:
        return UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        return None
