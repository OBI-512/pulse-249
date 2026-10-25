"""Transactional role transitions for logical sectors.

Sector roles are domain state, not a freely editable attribute.  In
particular, a customer-serving sector cannot become BACKHAUL while its
authoritative hierarchy or an active customer service still depends on it.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import CustomerService, DeviceHierarchyLink, Sector
from ..schemas.domain import SectorRole
from .audit import record_audit
from .audit_summaries import business_summary, display_snapshot


class SectorRoleTransitionError(ValueError):
    """A requested sector-role transition violates the domain model."""

    def __init__(self, code: str, message: str, status_code: int = 422):
        self.code = code
        self.message = message
        self.status_code = status_code
        super().__init__(message)


async def transition_sector_role(
    db: AsyncSession,
    *,
    sector_id: UUID,
    target_role: SectorRole | str | None,
) -> Sector:
    """Lock and transition one sector without committing the transaction.

    CPE registration/movement and customer-service validation acquire the
    same sector-row lock.  That shared serialization point prevents a new
    customer dependency from racing a CUSTOMER_ACCESS -> BACKHAUL change.
    """

    sector = await db.scalar(
        select(Sector).where(Sector.id == sector_id).with_for_update()
    )
    if sector is None:
        raise SectorRoleTransitionError(
            "SECTOR_NOT_FOUND",
            "The sector does not exist.",
            404,
        )

    try:
        normalized_role = SectorRole(target_role).value
    except (TypeError, ValueError) as exc:
        raise SectorRoleTransitionError(
            "INVALID_SECTOR_ROLE",
            "Sector role must be CUSTOMER_ACCESS or BACKHAUL.",
        ) from exc

    if sector.role == normalized_role:
        return sector

    if (
        sector.role == SectorRole.CUSTOMER_ACCESS.value
        and normalized_role == SectorRole.BACKHAUL.value
    ):
        active_service_id = await db.scalar(
            select(CustomerService.id)
            .where(
                CustomerService.sector_id == sector.id,
                CustomerService.status == "ACTIVE",
            )
            .limit(1)
        )

        attached_cpe_id = None
        if sector.sector_device_id is not None:
            attached_cpe_id = await db.scalar(
                select(DeviceHierarchyLink.child_device_id)
                .where(
                    DeviceHierarchyLink.parent_device_id == sector.sector_device_id,
                    DeviceHierarchyLink.relationship_type == "SECTOR_CPE",
                )
                .limit(1)
            )

        if active_service_id is not None or attached_cpe_id is not None:
            raise SectorRoleTransitionError(
                "SECTOR_HAS_CUSTOMER_DEPENDENCIES",
                "Move or remove all attached CPEs and active customer services before changing this sector to BACKHAUL.",
                409,
            )

    previous_role = sector.role
    sector.role = normalized_role
    await record_audit(
        db,
        action="SECTOR_ROLE_CHANGED",
        entity_type="Sector",
        entity_id=sector.id,
        description="Sector role changed through the validated transition service.",
        entity_display_snapshot=display_snapshot(sector),
        before_summary={"role": previous_role},
        after_summary={"role": sector.role},
        metadata={"sector": business_summary(sector)},
    )
    await db.flush()
    return sector
