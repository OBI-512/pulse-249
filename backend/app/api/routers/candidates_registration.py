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
from ...security.resource_scope import scope_for_actor
from ...security.scope_queries import require_candidate, require_device, require_location, require_sector
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
from ...services.hierarchy import resolve_effective_hierarchy

router = APIRouter()

from .candidates_validation import _parse_registration_uuid

@router.post(
    "/{candidate_id}/register",
    response_model=CandidateRegistration,
    dependencies=[
        Depends(require_permission("candidate.register")),
    ],
)
async def register_candidate(
    candidate_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    # Lock the candidate row so concurrent registration requests for the
    # same candidate cannot both create devices.
    candidate = await require_candidate(db, scope, candidate_id, for_update=True)

    # ------------------------------------------------------------------
    # Idempotent repeat
    # ------------------------------------------------------------------
    #
    # Persisted registration metadata is treated as untrusted state.
    # Invalid/missing identifiers must result in the explicit
    # REGISTERED_WITHOUT_RESULT response rather than an unhandled UUID
    # exception.
    #
    if candidate.state == CANDIDATE_REGISTERED:
        registration = (
            candidate.metadata_ or {}
        ).get(
            "registration",
            {},
        )

        device_id = _parse_registration_uuid(
            registration.get("device_id")
        )

        ip_id = _parse_registration_uuid(
            registration.get("ip_id")
        )

        if device_id is not None and ip_id is not None:
            return CandidateRegistration(
                candidate_id=candidate.id,
                device_id=device_id,
                ip_id=ip_id,
                state=CANDIDATE_REGISTERED,
                idempotent=True,
            )

        raise HTTPException(
            status_code=409,
            detail={
                "code": "REGISTERED_WITHOUT_RESULT",
                "message": (
                    "Candidate is registered but its "
                    "registration metadata is incomplete."
                ),
            },
        )

    # ------------------------------------------------------------------
    # State protection
    # ------------------------------------------------------------------

    if candidate.state != CANDIDATE_APPROVED:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "CANDIDATE_NOT_APPROVED",
                "message": (
                    "Only APPROVED candidates can be registered."
                ),
            },
        )

    if candidate.suggested_device_type_id is None:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "DEVICE_TYPE_REQUIRED",
                "message": (
                    "A device type is required before registration."
                ),
            },
        )

    type_code = await get_type_code(db, candidate.suggested_device_type_id)
    hierarchy_child = type_code in {"CPE", "ACCESS_POINT"}
    if hierarchy_child:
        if any(
            value is not None
            for value in (
                candidate.network_id,
                candidate.city_id,
                candidate.location_id,
                candidate.sector_id,
            )
        ):
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "HIERARCHY_INPUT_FORBIDDEN",
                    "message": "CPE and access-point candidates derive geographic hierarchy from their parent device.",
                },
            )
        expected_relationship_type = "SECTOR_CPE" if type_code == "CPE" else "CPE_ACCESS_POINT"
        if candidate.relationship_target_device_id is None:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "PARENT_DEVICE_REQUIRED",
                    "message": f"{type_code} candidates require a parent device.",
                },
            )
        if candidate.relationship_type != expected_relationship_type:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "HIERARCHY_RELATIONSHIP_TYPE_REQUIRED",
                    "message": f"{type_code} candidates must use {expected_relationship_type} as their parent relationship type.",
                },
            )
    elif type_code == "SECTOR":
        if candidate.sector_id is None:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "SECTOR_ID_REQUIRED",
                    "message": "A SECTOR candidate must bind to an existing sector.",
                },
            )
    elif candidate.location_id is None:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "LOCATION_REQUIRED",
                "message": f"{type_code} candidates require a location.",
            },
        )

    # Authorization of the registration destination is separate from candidate visibility.
    if hierarchy_child:
        parent = await require_device(db, scope, candidate.relationship_target_device_id)
        hierarchy = await resolve_effective_hierarchy(db, parent)
        if hierarchy.sector_id is not None:
            await require_sector(db, scope, hierarchy.sector_id)
        else:
            await require_location(db, scope, hierarchy.location_id)
    elif type_code == "SECTOR":
        await require_sector(db, scope, candidate.sector_id)
    else:
        await require_location(db, scope, candidate.location_id)
    if candidate.relationship_target_device_id is not None and not hierarchy_child:
        await require_device(db, scope, candidate.relationship_target_device_id)

    # ------------------------------------------------------------------
    # Duplicate IP protection
    # ------------------------------------------------------------------

    existing_ip = await db.scalar(
        select(DeviceIP).where(
            DeviceIP.ip_address == candidate.ip_address
        )
    )

    if existing_ip is not None:
        candidate.duplicate_device_id = (
            existing_ip.device_id
        )

        await db.commit()

        raise HTTPException(
            status_code=409,
            detail={
                "code": "IP_ALREADY_REGISTERED",
                "message": (
                    "The candidate IP is already registered."
                ),
                "device_id": str(
                    existing_ip.device_id
                ),
            },
        )

    # ------------------------------------------------------------------
    # Authoritative device, management IP, placement, and hierarchy
    # ------------------------------------------------------------------

    onboarding_metadata = (candidate.metadata_ or {}).get("onboarding", {})
    registration_result = await register_domain_device(
        db,
        device_type_id=candidate.suggested_device_type_id,
        display_name=(
            candidate.display_name_suggestion
            or f"DEVICE-{candidate.ip_address}"
        ),
        management_ip=candidate.ip_address,
        location_id=None if hierarchy_child else candidate.location_id,
        sector_id=candidate.sector_id if type_code == "SECTOR" else None,
        parent_device_id=candidate.relationship_target_device_id if hierarchy_child else None,
        hostname=candidate.hostname,
        vendor=candidate.vendor,
        model=candidate.model,
        serial_number=candidate.serial_number,
        lifecycle_state="REGISTERED",
        operational_state="UNKNOWN",
        management_protocol=candidate.management_protocol,
        credential_reference=onboarding_metadata.get("credential_reference"),
        metadata={
            **onboarding_metadata.get("device_metadata", {}),
            "registered_from_candidate": str(candidate.id),
            "discovery_confidence": candidate.confidence,
            "registration_source": (
                "ONBOARDING" if onboarding_metadata else "DISCOVERY_CANDIDATE"
            ),
        },
        ip_source="ONBOARDING" if onboarding_metadata else "DISCOVERY_CANDIDATE",
    )
    device = registration_result.device
    ip_obj = registration_result.management_ip

    # ------------------------------------------------------------------
    # Physical/device relationship
    # ------------------------------------------------------------------

    if candidate.relationship_target_device_id is not None and not hierarchy_child:
        try:
            await create_device_relationship(
                db,
                source_device_id=device.id,
                target_device_id=candidate.relationship_target_device_id,
                relationship_type=candidate.relationship_type or "CONNECTED_TO",
                direction=candidate.relationship_direction or "DIRECTED",
                metadata={"source": "CANDIDATE_REVIEW", "candidate_id": str(candidate.id)},
            )
        except RelationshipValidationError as exc:
            raise HTTPException(
                status_code=409 if exc.code == "RELATIONSHIP_CONFLICT" else 422,
                detail={"code": exc.code, "message": exc.message},
            ) from exc

    # ------------------------------------------------------------------
    # Candidate state + registration result
    # ------------------------------------------------------------------

    candidate.state = CANDIDATE_REGISTERED

    candidate.metadata_ = {
        **(candidate.metadata_ or {}),
        "registration": {
            "device_id": str(device.id),
            "ip_id": str(ip_obj.id),
        },
    }

    await record_audit(
        db,
        action="CANDIDATE_REGISTERED",
        entity_type="DeviceCandidate",
        entity_id=candidate.id,
        description=(
            "Approved discovery candidate registered "
            "as an FTTW device."
        ),
        metadata={
            "device_id": str(device.id),
            "ip_id": str(ip_obj.id),
            "ip_address": candidate.ip_address,
        },
        entity_display_snapshot={"ip_address": candidate.ip_address},
        before_summary={"state": CANDIDATE_APPROVED},
        after_summary={
            "state": CANDIDATE_REGISTERED,
            "device_id": str(device.id),
            "ip_id": str(ip_obj.id),
            "registration_source": (
                "ONBOARDING" if onboarding_metadata else "DISCOVERY_CANDIDATE"
            ),
        },
    )

    # ------------------------------------------------------------------
    # Transactional commit
    # ------------------------------------------------------------------

    try:
        await db.commit()

    except IntegrityError:
        await db.rollback()

        existing_ip = await db.scalar(
            select(DeviceIP).where(
                DeviceIP.ip_address
                == candidate.ip_address
            )
        )

        if existing_ip is not None:
            candidate = await db.scalar(
                select(DeviceCandidate).where(
                    DeviceCandidate.id == candidate_id
                )
            )

            if candidate is not None:
                candidate.duplicate_device_id = (
                    existing_ip.device_id
                )

                await db.commit()

            raise HTTPException(
                status_code=409,
                detail={
                    "code": "IP_ALREADY_REGISTERED",
                    "message": (
                        "The candidate IP was registered "
                        "concurrently by another operation."
                    ),
                    "device_id": str(
                        existing_ip.device_id
                    ),
                },
            )

        raise

    return CandidateRegistration(
        candidate_id=candidate.id,
        device_id=device.id,
        ip_id=ip_obj.id,
        state=CANDIDATE_REGISTERED,
        idempotent=False,
    )


@router.get(
    "/{candidate_id}/audit",
    response_model=list[dict],
)
async def candidate_audit(
    candidate_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    await require_candidate(db, scope, candidate_id)

    result = await db.execute(
        select(AuditLog)
        .where(
            AuditLog.entity_type == "DeviceCandidate",
            AuditLog.entity_id == candidate_id,
        )
        .order_by(
            AuditLog.occurred_at.desc()
        )
    )

    rows = result.scalars().all()

    return [
        {
            "id": row.id,
            "occurred_at": row.occurred_at,
            "action": row.action,
            "description": row.description,
            "metadata": row.metadata_,
        }
        for row in rows
    ]
