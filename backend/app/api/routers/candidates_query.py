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
from ...security.scope_queries import candidate_scope_clause, location_scope_clause, require_candidate, sector_scope_clause
from ...models import (
    AuditLog,
    City,
    Customer,
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

from .candidates_validation import _placement_option

@router.get("/summary")
async def candidate_summary(
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    scoped = await candidate_scope_clause(db, scope, candidate=DeviceCandidate)
    rows = (
        await db.execute(
            select(DeviceCandidate.state, func.count(DeviceCandidate.id))
            .where(scoped)
            .group_by(DeviceCandidate.state)
        )
    ).all()
    counts = {"NEW": 0, "APPROVED": 0, "REJECTED": 0, "REGISTERED": 0}
    total = 0
    for raw_state, raw_count in rows:
        count = int(raw_count or 0)
        state = (raw_state or "").upper()
        if state in counts:
            counts[state] += count
        total += count
    return {"total": total, "counts": counts}


@router.get(
    "",
    response_model=CandidatePage,
)
async def list_candidates(
    state: str | None = Query(
        default=None,
        max_length=40,
    ),
    vendor: str | None = Query(
        default=None,
        max_length=100,
    ),
    device_type_id: UUID | None = Query(default=None),
    search: str | None = Query(
        default=None,
        max_length=200,
    ),
    sort_by: str = Query(default="created_at", max_length=40),
    sort_direction: str = Query(default="desc", pattern="^(?i:asc|desc)$"),
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    filters = [await candidate_scope_clause(db, scope, candidate=DeviceCandidate)]

    if state:
        filters.append(
            DeviceCandidate.state == state
        )

    if vendor:
        filters.append(
            DeviceCandidate.vendor.ilike(
                f"%{vendor}%"
            )
        )

    if device_type_id:
        filters.append(DeviceCandidate.suggested_device_type_id == device_type_id)

    if search:
        term = f"%{search}%"

        filters.append(
            or_(
                DeviceCandidate.ip_address.ilike(term),
                DeviceCandidate.hostname.ilike(term),
                DeviceCandidate.vendor.ilike(term),
                DeviceCandidate.model.ilike(term),
                DeviceCandidate.display_name_suggestion.ilike(term),
                DeviceType.name.ilike(term),
                DeviceType.code.ilike(term),
            )
        )

    count_stmt = (
        select(func.count(DeviceCandidate.id))
        .select_from(DeviceCandidate)
        .outerjoin(DeviceType, DeviceType.id == DeviceCandidate.suggested_device_type_id)
    )

    if filters:
        count_stmt = count_stmt.where(*filters)

    count = int(
        (await db.scalar(count_stmt)) or 0
    )

    sort_map = {
        "ip_address": DeviceCandidate.ip_address,
        "state": DeviceCandidate.state,
        "display_name": DeviceCandidate.display_name_suggestion,
        "device_type": DeviceType.name,
        "vendor": DeviceCandidate.vendor,
        "confidence": DeviceCandidate.confidence,
        "created_at": DeviceCandidate.created_at,
    }
    sort_expr = sort_map.get(sort_by)
    if sort_expr is None:
        raise HTTPException(422, detail={"code":"INVALID_CANDIDATE_SORT","message":"Unsupported candidate sort column."})
    order = sort_expr.desc() if sort_direction.lower() == "desc" else sort_expr.asc()
    stmt = (
        select(DeviceCandidate)
        .outerjoin(DeviceType, DeviceType.id == DeviceCandidate.suggested_device_type_id)
        .where(*filters)
        .order_by(order.nullslast(), DeviceCandidate.id.asc())
        .offset(offset)
        .limit(limit)
    )

    items = (
        await db.execute(stmt)
    ).scalars().all()

    return CandidatePage(
        items=items,
        limit=limit,
        offset=offset,
        count=count,
    )


@router.get("/placement-options/locations")
async def candidate_location_options(
    search: str | None = Query(None, max_length=200),
    selected_id: UUID | None = None,
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    stmt = (
        select(Location, City, Network)
        .join(City, City.id == Location.city_id)
        .join(Network, Network.id == City.network_id)
        .where(
            Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None),
            Location.status == "ACTIVE", City.status == "ACTIVE", Network.status == "ACTIVE",
            location_scope_clause(scope),
        )
    )
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(or_(Location.name.ilike(pattern), Location.code.ilike(pattern), City.name.ilike(pattern), Network.name.ilike(pattern)))
    stmt = stmt.order_by(Network.name, City.name, Location.name).limit(limit)
    rows = list((await db.execute(stmt)).all())
    if selected_id and not any(location.id == selected_id for location, _, _ in rows):
        selected = (await db.execute(
            select(Location, City, Network).join(City, City.id == Location.city_id).join(Network, Network.id == City.network_id)
            .where(Location.id == selected_id, Location.deleted_at.is_(None), location_scope_clause(scope))
        )).first()
        if selected:
            rows.insert(0, selected)
    return [_placement_option(option_id=location.id, name=location.name, code=location.code, network=network, city=city, location=location) for location, city, network in rows]


@router.get("/placement-options/logical-sectors")
async def candidate_logical_sector_options(
    search: str | None = Query(None, max_length=200),
    selected_id: UUID | None = None,
    current_sector_device_id: UUID | None = None,
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    stmt = (
        select(Sector, Location, City, Network)
        .join(Location, Location.id == Sector.location_id)
        .join(City, City.id == Location.city_id)
        .join(Network, Network.id == City.network_id)
        .where(
            Sector.deleted_at.is_(None), Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None),
            Sector.status == "ACTIVE", Location.status == "ACTIVE", City.status == "ACTIVE", Network.status == "ACTIVE",
            sector_scope_clause(scope),
            or_(
                Sector.sector_device_id.is_(None),
                Sector.sector_device_id == current_sector_device_id,
            ) if current_sector_device_id is not None else Sector.sector_device_id.is_(None),
        )
    )
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(or_(Sector.name.ilike(pattern), Sector.code.ilike(pattern), Location.name.ilike(pattern), City.name.ilike(pattern), Network.name.ilike(pattern)))
    stmt = stmt.order_by(Network.name, City.name, Location.name, Sector.sequence_number, Sector.name).limit(limit)
    rows = list((await db.execute(stmt)).all())
    if selected_id and not any(sector.id == selected_id for sector, *_ in rows):
        selected_stmt = (
            select(Sector, Location, City, Network)
            .join(Location, Location.id == Sector.location_id)
            .join(City, City.id == Location.city_id)
            .join(Network, Network.id == City.network_id)
            .where(
                Sector.id == selected_id,
                Sector.deleted_at.is_(None), Location.deleted_at.is_(None), City.deleted_at.is_(None), Network.deleted_at.is_(None),
                Sector.status == "ACTIVE", Location.status == "ACTIVE", City.status == "ACTIVE", Network.status == "ACTIVE",
                sector_scope_clause(scope),
            )
        )
        if current_sector_device_id is not None:
            selected_stmt = selected_stmt.where(or_(Sector.sector_device_id.is_(None), Sector.sector_device_id == current_sector_device_id))
        else:
            selected_stmt = selected_stmt.where(Sector.sector_device_id.is_(None))
        selected = (await db.execute(selected_stmt)).first()
        if selected:
            rows.insert(0, selected)
    return [_placement_option(option_id=sector.id, name=sector.name, code=sector.code, network=network, city=city, location=location, sector=sector) for sector, location, city, network in rows]


@router.get(
    "/{candidate_id}",
    response_model=CandidateRead,
)
async def get_candidate(
    candidate_id: UUID,
    db: AsyncSession = Depends(get_db),
    actor=Depends(authorize_request),
):
    scope = await scope_for_actor(db, actor)
    return await require_candidate(db, scope, candidate_id)
