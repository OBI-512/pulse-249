from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_db
from ...models import City, DeviceCandidate, DeviceIP, Location, Network, Sector
from ...schemas.candidates import CandidateApprove
from ...schemas.onboarding import (
    OnboardingCandidateCreate,
    OnboardingCandidateRead,
    OnboardingProbeRequest,
    OnboardingProbeResult,
    OnboardingRegisterRequest,
    OnboardingRegisterResponse,
)
from ...security.authorization import authorize_request
from ...security.resource_scope import authorization_scope_metadata, expanded_authorization_scope_keys, scope_for_actor
from ...security.scope_queries import candidate_scope_clause, require_candidate, require_device, require_location, require_sector
from ...services.candidates import CANDIDATE_NEW
from ...services.device_domain import get_type_code
from ...services.onboarding import normalize_ip, probe_icmp
from .candidates import approve_candidate, register_candidate as register_reviewed_candidate


router = APIRouter(
    prefix="/onboarding",
    tags=["Device Onboarding"],
    dependencies=[Depends(authorize_request)],
)


def _error(code: str, message: str, status_code: int) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"code": code, "message": message},
    )


def _message_for_state(state: str) -> str:
    if state == "REGISTERED":
        return "Device registered successfully."
    if state == "APPROVED":
        return "Candidate persisted and approved for registration."
    return f"Candidate is in {state} state."


def _to_onboarding_read(candidate: DeviceCandidate) -> OnboardingCandidateRead:
    onboarding_metadata = (candidate.metadata_ or {}).get("onboarding", {})
    return OnboardingCandidateRead(
        id=candidate.id,
        ip_address=candidate.ip_address,
        device_type_id=candidate.suggested_device_type_id,
        display_name=candidate.display_name_suggestion or f"DEVICE-{candidate.ip_address}",
        location_id=candidate.location_id,
        sector_id=candidate.sector_id,
        parent_device_id=candidate.relationship_target_device_id,
        hostname=candidate.hostname,
        vendor=candidate.vendor,
        model=candidate.model,
        serial_number=candidate.serial_number,
        management_protocol=candidate.management_protocol,
        credential_reference=onboarding_metadata.get("credential_reference"),
        state=candidate.state,
        message=_message_for_state(candidate.state),
    )


async def _location_context(
    db: AsyncSession,
    location_id: UUID,
) -> tuple[Network, City, Location]:
    location = await db.get(Location, location_id)
    if location is None:
        raise _error("LOCATION_NOT_FOUND", "Location does not exist.", 404)
    city = await db.get(City, location.city_id)
    if city is None:
        raise _error("LOCATION_CITY_NOT_FOUND", "Location has no valid city.", 422)
    network = await db.get(Network, city.network_id)
    if network is None:
        raise _error("CITY_NETWORK_NOT_FOUND", "City has no valid network.", 422)
    return network, city, location


async def _onboarding_candidate(
    db: AsyncSession,
    candidate_id: UUID,
) -> DeviceCandidate:
    candidate = await db.scalar(
        select(DeviceCandidate).where(
            DeviceCandidate.id == candidate_id,
            DeviceCandidate.metadata_.contains({"source": "ONBOARDING"}),
        )
    )
    if candidate is None:
        raise _error(
            "ONBOARDING_CANDIDATE_NOT_FOUND",
            "Onboarding candidate not found.",
            404,
        )
    return candidate


@router.post("/probe", response_model=OnboardingProbeResult)
async def probe_device(payload: OnboardingProbeRequest):
    address = normalize_ip(str(payload.ip_address))
    result = await probe_icmp(address, payload.timeout_seconds)
    return OnboardingProbeResult(
        ip_address=result.ip_address,
        reachable=result.reachable,
        response_time_ms=result.response_time_ms,
        protocol=result.protocol,
        message=result.message,
    )


@router.post(
    "/candidates",
    response_model=OnboardingCandidateRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_candidate(
    payload: OnboardingCandidateCreate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    authorization_keys = await expanded_authorization_scope_keys(db, scope)
    address = normalize_ip(str(payload.ip_address))
    type_code = await get_type_code(db, payload.device_type_id)

    existing_ip = await db.scalar(
        select(DeviceIP).where(DeviceIP.ip_address == address)
    )
    if existing_ip is not None:
        raise _error(
            "IP_ALREADY_REGISTERED",
            "This management IP address is already registered.",
            409,
        )

    existing_candidate = await db.scalar(
        select(DeviceCandidate).where(DeviceCandidate.ip_address == address)
    )
    if existing_candidate is not None:
        raise _error(
            "CANDIDATE_IP_ALREADY_EXISTS",
            "A persistent device candidate already uses this management IP address.",
            409,
        )

    network_id: UUID | None = None
    city_id: UUID | None = None
    location_id: UUID | None = None
    candidate_sector_id: UUID | None = None
    parent_device_id = payload.parent_device_id
    relationship_type: str | None = None

    if type_code == "SECTOR":
        if payload.sector_id is None:
            raise _error(
                "SECTOR_ID_REQUIRED",
                "A SECTOR device must bind to an existing sector.",
                422,
            )
        if parent_device_id is not None:
            raise _error(
                "PARENT_NOT_SUPPORTED",
                "A SECTOR device cannot have a device parent.",
                422,
            )
        if scope.global_access:
            sector = await db.scalar(select(Sector).where(Sector.id == payload.sector_id))
            if sector is None:
                raise _error("SECTOR_NOT_FOUND", "The selected sector does not exist.", 404)
        else:
            sector = await require_sector(db, scope, payload.sector_id)
        network, city, location = await _location_context(db, sector.location_id)
        if payload.location_id is not None and payload.location_id != location.id:
            raise _error(
                "SECTOR_LOCATION_MISMATCH",
                "The supplied location does not match the selected sector.",
                422,
            )
        network_id, city_id, location_id = network.id, city.id, location.id
        candidate_sector_id = sector.id
    elif type_code == "CPE":
        if payload.location_id is not None:
            raise _error(
                "HIERARCHY_INPUT_FORBIDDEN",
                "CPE geography is derived from its SECTOR device parent.",
                422,
            )
        if payload.sector_id is not None:
            if scope.global_access:
                sector = await db.scalar(select(Sector).where(Sector.id == payload.sector_id))
                if sector is None:
                    raise _error("SECTOR_NOT_FOUND", "The selected sector does not exist.", 404)
            else:
                sector = await require_sector(db, scope, payload.sector_id)
            if sector.sector_device_id is None:
                raise _error(
                    "SECTOR_DEVICE_PARENT_REQUIRED",
                    "The selected sector has no bound SECTOR device parent.",
                    422,
                )
            if parent_device_id is not None and parent_device_id != sector.sector_device_id:
                raise _error(
                    "CPE_SECTOR_PARENT_MISMATCH",
                    "The supplied parent is not the SECTOR device bound to the selected sector.",
                    422,
                )
            parent_device_id = sector.sector_device_id
        if parent_device_id is None:
            raise _error(
                "PARENT_DEVICE_REQUIRED",
                "CPE requires a valid SECTOR device parent.",
                422,
            )
        if not scope.global_access:
            parent = await require_device(db, scope, parent_device_id)
            from ...services.hierarchy import resolve_effective_hierarchy
            hierarchy = await resolve_effective_hierarchy(db, parent)
            if hierarchy.sector_id is not None:
                await require_sector(db, scope, hierarchy.sector_id)
        relationship_type = "SECTOR_CPE"
    elif type_code == "ACCESS_POINT":
        if payload.location_id is not None or payload.sector_id is not None:
            raise _error(
                "HIERARCHY_INPUT_FORBIDDEN",
                "Access-point geography is derived from its CPE parent.",
                422,
            )
        if parent_device_id is None:
            raise _error(
                "PARENT_DEVICE_REQUIRED",
                "ACCESS_POINT requires a valid CPE parent.",
                422,
            )
        if not scope.global_access:
            parent = await require_device(db, scope, parent_device_id)
            from ...services.hierarchy import resolve_effective_hierarchy
            hierarchy = await resolve_effective_hierarchy(db, parent)
            if hierarchy.sector_id is not None:
                await require_sector(db, scope, hierarchy.sector_id)
        relationship_type = "CPE_ACCESS_POINT"
    else:
        if parent_device_id is not None:
            raise _error(
                "PARENT_NOT_SUPPORTED",
                f"{type_code} is independently placed and cannot have a hierarchy parent.",
                422,
            )
        if payload.sector_id is not None:
            raise _error(
                "SECTOR_ASSIGNMENT_NOT_SUPPORTED",
                f"{type_code} is location-placed and cannot use customer-sector placement.",
                422,
            )
        if payload.location_id is None:
            raise _error(
                "LOCATION_REQUIRED",
                f"{type_code} requires a location.",
                422,
            )
        if not scope.global_access:
            await require_location(db, scope, payload.location_id)
        network, city, location = await _location_context(db, payload.location_id)
        network_id, city_id, location_id = network.id, city.id, location.id

    candidate = DeviceCandidate(
        ip_address=address,
        state=CANDIDATE_NEW,
        confidence=1.0,
        display_name_suggestion=payload.display_name,
        hostname=payload.hostname,
        vendor=payload.vendor,
        model=payload.model,
        serial_number=payload.serial_number,
        management_protocol=payload.management_protocol,
        metadata_={
            "source": "ONBOARDING",
            "_authorization_scope": authorization_scope_metadata(authorization_keys, actor_user_id=scope.user_id),
            "onboarding": {
                "credential_reference": payload.credential_reference,
                "device_metadata": payload.metadata,
            },
        },
    )
    db.add(candidate)
    await db.flush()

    approval = CandidateApprove(
        suggested_device_type_id=payload.device_type_id,
        display_name=payload.display_name,
        network_id=network_id,
        city_id=city_id,
        location_id=location_id,
        sector_id=candidate_sector_id,
        relationship_target_device_id=parent_device_id,
        relationship_type=relationship_type,
        relationship_direction="DIRECTED" if relationship_type else None,
        review_note="Created and approved through authoritative onboarding.",
    )

    try:
        approved = await approve_candidate(candidate.id, approval, actor=actor, db=db)
    except IntegrityError as exc:
        await db.rollback()
        raise _error(
            "CANDIDATE_IP_ALREADY_EXISTS",
            "A device candidate concurrently claimed this management IP address.",
            409,
        ) from exc

    return _to_onboarding_read(approved)


@router.get("/candidates", response_model=list[OnboardingCandidateRead])
async def list_candidates(
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    candidates = (
        await db.scalars(
            select(DeviceCandidate)
            .where(DeviceCandidate.metadata_.contains({"source": "ONBOARDING"}), await candidate_scope_clause(db, scope, candidate=DeviceCandidate))
            .order_by(DeviceCandidate.created_at.desc())
        )
    ).all()
    return [_to_onboarding_read(candidate) for candidate in candidates]


@router.get("/candidates/{candidate_id}", response_model=OnboardingCandidateRead)
async def get_candidate(
    candidate_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    candidate = await require_candidate(db, scope, candidate_id)
    if (candidate.metadata_ or {}).get("source") != "ONBOARDING":
        raise _error("ONBOARDING_CANDIDATE_NOT_FOUND", "Onboarding candidate not found.", 404)
    return _to_onboarding_read(candidate)


@router.post("/register", response_model=OnboardingRegisterResponse)
async def register_candidate(
    payload: OnboardingRegisterRequest,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    candidate = await require_candidate(db, scope, payload.candidate_id)
    if (candidate.metadata_ or {}).get("source") != "ONBOARDING":
        raise _error("ONBOARDING_CANDIDATE_NOT_FOUND", "Onboarding candidate not found.", 404)
    registration = await register_reviewed_candidate(payload.candidate_id, actor=actor, db=db)
    return OnboardingRegisterResponse(
        device_id=registration.device_id,
        ip_id=registration.ip_id,
        state=registration.state,
        message="Device registered successfully.",
    )
