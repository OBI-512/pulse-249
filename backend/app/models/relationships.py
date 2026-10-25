from __future__ import annotations

import uuid
from enum import Enum
from typing import Any

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Index, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .core import Common
from .recoverable import RecoverableMixin


class DeviceRelationship(RecoverableMixin, Common):
    __tablename__ = "device_relationships"

    __table_args__ = (
        Index(
            "uq_active_device_relationship",
            "source_device_id",
            "target_device_id",
            "relationship_type",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )

    source_device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
    )
    relationship_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    direction: Mapped[str] = mapped_column(
        String(30),
        default="DIRECTED",
        nullable=False,
    )
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        default=dict,
        nullable=False,
    )


class DeviceGroupScope(str, Enum):
    """
    Organizational context in which a device group exists.

    GLOBAL is retained for backward compatibility with groups created
    before organizational scoping was introduced.
    """

    GLOBAL = "GLOBAL"
    NETWORK = "NETWORK"
    CITY = "CITY"
    LOCATION = "LOCATION"
    SECTOR = "SECTOR"


class DeviceGroup(RecoverableMixin, Common):
    __tablename__ = "device_groups"

    __table_args__ = (
        CheckConstraint(
            "group_kind IN ('SYSTEM','CUSTOM')",
            name="ck_device_groups_group_kind",
        ),
        CheckConstraint(
            "membership_mode IN ('MANUAL','DYNAMIC')",
            name="ck_device_groups_membership_mode",
        ),
        CheckConstraint(
            "(group_kind = 'SYSTEM' AND membership_mode = 'DYNAMIC' AND system_key IS NOT NULL) OR (group_kind = 'CUSTOM' AND system_key IS NULL)",
            name="ck_device_groups_system_dynamic",
        ),
        CheckConstraint(
            "device_scope IN ('ANY','ACCESS_POINT','CPE','SECTOR','SWITCH','ROUTER','FIREWALL','SERVER','WIRELESS_BRIDGE','NETWORK_DEVICE','OTHER')",
            name="ck_device_groups_device_scope",
        ),
        CheckConstraint(
            "sector_role IS NULL OR sector_role IN ('CUSTOMER_ACCESS','BACKHAUL')",
            name="ck_device_groups_sector_role",
        ),
        CheckConstraint(
            "sector_role IS NULL OR device_scope = 'SECTOR'",
            name="ck_device_groups_sector_role_requires_sector_scope",
        ),
        CheckConstraint(
            """
            (
                scope_type = 'GLOBAL'
                AND network_id IS NULL
                AND city_id IS NULL
                AND location_id IS NULL
                AND sector_id IS NULL
            )
            OR
            (
                scope_type = 'NETWORK'
                AND network_id IS NOT NULL
                AND city_id IS NULL
                AND location_id IS NULL
                AND sector_id IS NULL
            )
            OR
            (
                scope_type = 'CITY'
                AND network_id IS NULL
                AND city_id IS NOT NULL
                AND location_id IS NULL
                AND sector_id IS NULL
            )
            OR
            (
                scope_type = 'LOCATION'
                AND network_id IS NULL
                AND city_id IS NULL
                AND location_id IS NOT NULL
                AND sector_id IS NULL
            )
            OR
            (
                scope_type = 'SECTOR'
                AND network_id IS NULL
                AND city_id IS NULL
                AND location_id IS NULL
                AND sector_id IS NOT NULL
            )
            """,
            name="ck_device_groups_scope_context",
        ),
        Index(
            "uq_device_groups_system_key",
            "system_key",
            unique=True,
            postgresql_where=text("system_key IS NOT NULL"),
        ),
        Index("ix_device_groups_kind_mode", "group_kind", "membership_mode"),
        Index(
            "ix_device_groups_network_id",
            "network_id",
        ),
        Index(
            "ix_device_groups_city_id",
            "city_id",
        ),
        Index(
            "ix_device_groups_location_id",
            "location_id",
        ),
        Index(
            "ix_device_groups_sector_id",
            "sector_id",
        ),
        Index(
            "uq_active_device_groups_name",
            "name",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index(
            "uq_active_device_groups_code",
            "code",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )

    name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    code: Mapped[str] = mapped_column(
        String(80),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
    )

    group_kind: Mapped[str] = mapped_column(
        String(20), default="CUSTOM", server_default="CUSTOM", nullable=False
    )
    membership_mode: Mapped[str] = mapped_column(
        String(20), default="MANUAL", server_default="MANUAL", nullable=False
    )
    system_key: Mapped[str | None] = mapped_column(String(80), nullable=True)

    scope_type: Mapped[str] = mapped_column(
        String(20),
        default=DeviceGroupScope.GLOBAL.value,
        server_default=DeviceGroupScope.GLOBAL.value,
        nullable=False,
    )

    network_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("networks.id", ondelete="RESTRICT"),
        nullable=True,
    )

    city_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cities.id", ondelete="RESTRICT"),
        nullable=True,
    )

    location_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("locations.id", ondelete="RESTRICT"),
        nullable=True,
    )

    sector_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sectors.id", ondelete="RESTRICT"),
        nullable=True,
    )

    device_scope: Mapped[str] = mapped_column(String(40), default="ANY", server_default="ANY", nullable=False)
    sector_role: Mapped[str | None] = mapped_column(String(30), nullable=True)

    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        default=dict,
        nullable=False,
    )


class DeviceGroupMembership(RecoverableMixin, Common):
    __tablename__ = "device_group_memberships"

    __table_args__ = (
        UniqueConstraint(
            "device_id",
            "group_id",
            name="uq_device_group_membership",
        ),
        Index(
            "ix_device_group_memberships_group",
            "group_id",
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index(
            "ix_device_group_memberships_group_active",
            "group_id",
            "device_id",
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
    )

    group_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("device_groups.id", ondelete="CASCADE"),
        nullable=False,
    )


class DeviceGroupNesting(RecoverableMixin, Common):
    """Organizational parent-child relationship between device groups.

    Nesting never changes physical placement and never implies ownership of
    the child group's devices.  One active parent per child keeps the
    organizational hierarchy a tree rather than an arbitrary graph.
    """
    __tablename__ = "device_group_nestings"
    __table_args__ = (
        CheckConstraint("parent_group_id <> child_group_id", name="ck_device_group_nestings_not_self"),
        Index(
            "uq_active_device_group_nestings_child",
            "child_group_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index(
            "uq_active_device_group_nestings_pair",
            "parent_group_id",
            "child_group_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_device_group_nestings_parent", "parent_group_id"),
    )
    parent_group_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("device_groups.id", ondelete="CASCADE"), nullable=False
    )
    child_group_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("device_groups.id", ondelete="CASCADE"), nullable=False
    )


class ExternalSystem(Common):
    __tablename__ = "external_systems"

    name: Mapped[str] = mapped_column(
        String(150),
        unique=True,
        nullable=False,
    )

    code: Mapped[str] = mapped_column(
        String(80),
        unique=True,
        nullable=False,
    )

    system_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    base_url: Mapped[str | None] = mapped_column(
        String(500),
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        default=dict,
        nullable=False,
    )


class ExternalObjectMapping(Common):
    __tablename__ = "external_object_mappings"

    __table_args__ = (
        UniqueConstraint(
            "external_system_id",
            "external_object_type",
            "external_object_id",
            name="uq_external_object_mapping",
        ),
    )

    external_system_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("external_systems.id", ondelete="RESTRICT"),
        nullable=False,
    )

    entity_type: Mapped[str] = mapped_column(
        String(80),
        nullable=False,
    )

    fttw_entity_id: Mapped[uuid.UUID] = mapped_column(
        nullable=False,
    )

    external_object_type: Mapped[str] = mapped_column(
        String(80),
        nullable=False,
    )

    external_object_id: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )

    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        default=dict,
        nullable=False,
    )
