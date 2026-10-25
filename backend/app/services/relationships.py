from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Device, DeviceRelationship
from .crud import lock_active_rows
from .audit import record_audit
from .audit_summaries import business_summary, display_snapshot


class RelationshipValidationError(ValueError):
    """Raised when a device relationship violates business rules."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


async def create_device_relationship(
    db: AsyncSession,
    *,
    source_device_id: UUID,
    target_device_id: UUID,
    relationship_type: str,
    direction: str,
    metadata: dict,
) -> DeviceRelationship:
    """
    Create a protected physical device relationship.

    Rules:

    1. Source and target must be different devices.
    2. Both devices must exist.
    3. Direction must be DIRECTED or UNDIRECTED.
    4. Exact duplicate relationships are rejected.
    5. Reverse relationships of the same type are rejected.
    6. For UNDIRECTED relationships, reverse orientation represents
       the same physical relationship.
    7. This operation changes only DeviceRelationship.
       It does not modify placement, grouping, or customer service.
    """

    direction = direction.upper()

    if direction not in {"DIRECTED", "UNDIRECTED"}:
        raise RelationshipValidationError(
            "INVALID_DIRECTION",
            "Relationship direction must be DIRECTED or UNDIRECTED.",
        )

    if source_device_id == target_device_id:
        raise RelationshipValidationError(
            "SELF_RELATIONSHIP",
            "A device cannot be related to itself.",
        )

    locked_devices = await lock_active_rows(
        db,
        Device,
        (source_device_id, target_device_id),
    )

    if source_device_id not in locked_devices:
        raise RelationshipValidationError(
            "SOURCE_DEVICE_NOT_FOUND",
            "The source device does not exist.",
        )

    if target_device_id not in locked_devices:
        raise RelationshipValidationError(
            "TARGET_DEVICE_NOT_FOUND",
            "The target device does not exist.",
        )

    # ---------------------------------------------------------------
    # Exact duplicate
    # ---------------------------------------------------------------

    exact_result = await db.execute(
        select(DeviceRelationship).where(
            DeviceRelationship.source_device_id == source_device_id,
            DeviceRelationship.target_device_id == target_device_id,
            DeviceRelationship.relationship_type == relationship_type,
        )
    )

    if exact_result.scalar_one_or_none() is not None:
        raise RelationshipValidationError(
            "RELATIONSHIP_CONFLICT",
            "The device relationship already exists.",
        )

    # ---------------------------------------------------------------
    # Reverse relationship
    #
    # The project policy protects the physical edge from duplicate
    # reverse representation.
    # ---------------------------------------------------------------

    reverse_result = await db.execute(
        select(DeviceRelationship).where(
            DeviceRelationship.source_device_id == target_device_id,
            DeviceRelationship.target_device_id == source_device_id,
            DeviceRelationship.relationship_type == relationship_type,
        )
    )

    reverse = reverse_result.scalar_one_or_none()

    if reverse is not None:
        raise RelationshipValidationError(
            "RELATIONSHIP_CONFLICT",
            "The reverse relationship already exists.",
        )

    # ---------------------------------------------------------------
    # Create the relationship
    # ---------------------------------------------------------------

    obj = DeviceRelationship(
        source_device_id=source_device_id,
        target_device_id=target_device_id,
        relationship_type=relationship_type,
        direction=direction,
        metadata_=metadata,
    )

    db.add(obj)

    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()

        raise RelationshipValidationError(
            "RELATIONSHIP_CONFLICT",
            "The device relationship already exists.",
        ) from exc

    await db.refresh(obj)
    await record_audit(
        db,
        action="DEVICE_RELATIONSHIP_CREATED",
        entity_type="DeviceRelationship",
        entity_id=obj.id,
        description="Generic device relationship created through the shared validated service.",
        entity_display_snapshot=display_snapshot(obj),
        after_summary=business_summary(obj),
    )

    return obj
