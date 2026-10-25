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
from ...security.resource_scope import preserve_authorization_metadata, scope_for_actor
from ...security.scope_queries import (require_candidate, require_city, require_device, require_location, require_network, require_sector)
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

router = APIRouter()

from .candidates_validation import (
    _validate_review_assignment, _validate_type_specific_assignment, _candidate_ip_is_editable,
    _ensure_candidate_ip_available,
)

async def _guard_destination_scope(db: AsyncSession, scope, data: dict) -> None:
    checks = (("network_id", require_network), ("city_id", require_city), ("location_id", require_location), ("sector_id", require_sector), ("relationship_target_device_id", require_device))
    for field, guard in checks:
        value = data.get(field)
        if value is not None:
            await guard(db, scope, value)


@router.patch(
    "/{candidate_id}",
    response_model=CandidateRead,
)
async def update_candidate(
    candidate_id: UUID,
    payload: CandidateUpdate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    candidate = await require_candidate(db, scope, candidate_id, for_update=True)

    if candidate.state == CANDIDATE_REGISTERED:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "CANDIDATE_REGISTERED",
                "message": (
                    "Registered candidates are immutable."
                ),
            },
        )

    data = payload.model_dump(
        exclude_unset=True,
    )

    if "ip_address" in data:
        requested_ip = data.pop("ip_address")
        if requested_ip is not None and requested_ip != candidate.ip_address:
            if not _candidate_ip_is_editable(candidate):
                raise HTTPException(
                    status_code=409,
                    detail={"code": "DISCOVERED_IP_IMMUTABLE", "message": "The management IP of a discovered candidate cannot be changed."},
                )
            candidate.ip_address = await _ensure_candidate_ip_available(db, candidate=candidate, value=requested_ip)

    if (
        "suggested_device_type_id" in data
        and data["suggested_device_type_id"]
    ):
        await get_or_404(
            db,
            DeviceType,
            data["suggested_device_type_id"],
        )

    await _guard_destination_scope(db, scope, data)
    await _validate_review_assignment(
        db,
        data,
    )

    effective_type_id = data.get("suggested_device_type_id", candidate.suggested_device_type_id)
    effective_type_code = await get_type_code(db, effective_type_id) if effective_type_id else None
    await _validate_type_specific_assignment(db, type_code=effective_type_code, data=data, require_complete=False)

    if "metadata" in data:
        candidate.metadata_ = preserve_authorization_metadata(candidate.metadata_, data.pop("metadata"))

    for key, value in data.items():
        setattr(
            candidate,
            key,
            value,
        )

    await record_audit(
        db,
        action="CANDIDATE_UPDATED",
        entity_type="DeviceCandidate",
        entity_id=candidate.id,
        description="Device candidate review data updated.",
    )

    await db.commit()
    await db.refresh(candidate)

    return candidate


@router.post(
    "/{candidate_id}/approve",
    response_model=CandidateRead,
)
async def approve_candidate(
    candidate_id: UUID,
    payload: CandidateApprove,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    candidate = await require_candidate(db, scope, candidate_id, for_update=True)
    before_state = candidate.state

    if not can_transition(
        candidate.state,
        CANDIDATE_APPROVED,
    ):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "INVALID_CANDIDATE_TRANSITION",
                "message": (
                    f"Candidate cannot transition from "
                    f"{candidate.state} to APPROVED."
                ),
            },
        )

    type_code = await get_type_code(db, payload.suggested_device_type_id)

    if payload.ip_address is not None and payload.ip_address != candidate.ip_address:
        if not _candidate_ip_is_editable(candidate):
            raise HTTPException(
                status_code=409,
                detail={"code": "DISCOVERED_IP_IMMUTABLE", "message": "The management IP of a discovered candidate cannot be changed."},
            )
        candidate.ip_address = await _ensure_candidate_ip_available(db, candidate=candidate, value=payload.ip_address)

    if type_code in {"CPE", "ACCESS_POINT"}:
        if any(
            value is not None
            for value in (payload.network_id, payload.city_id, payload.location_id, payload.sector_id)
        ):
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "HIERARCHY_INPUT_FORBIDDEN",
                    "message": "CPE and access-point candidates derive geographic hierarchy from their parent device.",
                },
            )
        expected_relationship_type = "SECTOR_CPE" if type_code == "CPE" else "CPE_ACCESS_POINT"
        if payload.relationship_target_device_id is None:
            raise HTTPException(
                status_code=422,
                detail={"code": "PARENT_DEVICE_REQUIRED", "message": f"{type_code} candidates require a parent device."},
            )
    elif type_code == "SECTOR" and payload.sector_id is None:
        raise HTTPException(
            status_code=422,
            detail={"code": "SECTOR_ID_REQUIRED", "message": "A SECTOR candidate must bind to an existing sector."},
        )

    review_data = payload.model_dump(
        exclude_unset=True,
    )
    # Parent relationships for hierarchy-managed devices are authoritative
    # domain behavior, not a generic operator-authored relationship field.
    # Supply the derived relationship to shared validation even when the UI
    # intentionally omits relationship type/direction controls.
    if type_code in {"CPE", "ACCESS_POINT"}:
        review_data["relationship_type"] = expected_relationship_type

    await _guard_destination_scope(db, scope, review_data)
    await _validate_review_assignment(
        db,
        review_data,
    )

    await _validate_type_specific_assignment(db, type_code=type_code, data=review_data, require_complete=True)

    candidate.suggested_device_type_id = (
        payload.suggested_device_type_id
    )
    candidate.display_name_suggestion = (
        payload.display_name
    )
    candidate.hostname = payload.hostname
    candidate.vendor = payload.vendor
    candidate.model = payload.model
    candidate.serial_number = payload.serial_number
    candidate.management_protocol = payload.management_protocol
    candidate.review_note = payload.review_note
    candidate.network_id = payload.network_id
    candidate.city_id = payload.city_id
    candidate.location_id = payload.location_id
    candidate.sector_id = payload.sector_id
    candidate.relationship_target_device_id = (
        payload.relationship_target_device_id
    )
    candidate.relationship_type = (
        "SECTOR_CPE" if type_code == "CPE" else
        "CPE_ACCESS_POINT" if type_code == "ACCESS_POINT" else
        None
    )
    candidate.relationship_direction = "DIRECTED"
    candidate.state = CANDIDATE_APPROVED

    await record_audit(
        db,
        action="CANDIDATE_APPROVED",
        entity_type="DeviceCandidate",
        entity_id=candidate.id,
        description=(
            "Device candidate approved for registration."
        ),
        metadata={
            "device_type_id": str(
                payload.suggested_device_type_id
            ),
        },
        entity_display_snapshot={"ip_address": candidate.ip_address},
        before_summary={"state": before_state},
        after_summary={
            "state": CANDIDATE_APPROVED,
            "device_type_id": str(payload.suggested_device_type_id),
            "network_id": str(payload.network_id) if payload.network_id else None,
            "city_id": str(payload.city_id) if payload.city_id else None,
            "location_id": str(payload.location_id) if payload.location_id else None,
            "sector_id": str(payload.sector_id) if payload.sector_id else None,
            "parent_device_id": (
                str(payload.relationship_target_device_id)
                if payload.relationship_target_device_id
                else None
            ),
        },
    )

    await db.commit()
    await db.refresh(candidate)

    return candidate


@router.post(
    "/{candidate_id}/reject",
    response_model=CandidateRead,
)
async def reject_candidate(
    candidate_id: UUID,
    payload: CandidateReject,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    candidate = await require_candidate(db, scope, candidate_id, for_update=True)
    before_state = candidate.state

    if not can_transition(
        candidate.state,
        CANDIDATE_REJECTED,
    ):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "INVALID_CANDIDATE_TRANSITION",
                "message": (
                    f"Candidate cannot transition from "
                    f"{candidate.state} to REJECTED."
                ),
            },
        )

    candidate.state = CANDIDATE_REJECTED
    candidate.review_note = payload.review_note

    await record_audit(
        db,
        action="CANDIDATE_REJECTED",
        entity_type="DeviceCandidate",
        entity_id=candidate.id,
        description=(
            "Device candidate rejected during review."
        ),
        entity_display_snapshot={"ip_address": candidate.ip_address},
        before_summary={"state": before_state},
        after_summary={"state": CANDIDATE_REJECTED},
    )

    await db.commit()
    await db.refresh(candidate)

    return candidate


@router.post(
    "/{candidate_id}/reopen",
    response_model=CandidateRead,
)
async def reopen_candidate(
    candidate_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    candidate = await require_candidate(db, scope, candidate_id, for_update=True)

    if not can_transition(
        candidate.state,
        CANDIDATE_NEW,
    ):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "INVALID_CANDIDATE_TRANSITION",
                "message": (
                    f"Candidate cannot transition from "
                    f"{candidate.state} to NEW."
                ),
            },
        )

    candidate.state = CANDIDATE_NEW

    await record_audit(
        db,
        action="CANDIDATE_REOPENED",
        entity_type="DeviceCandidate",
        entity_id=candidate.id,
        description=(
            "Rejected candidate reopened for review."
        ),
    )

    await db.commit()
    await db.refresh(candidate)

    return candidate
