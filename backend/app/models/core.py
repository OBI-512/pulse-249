from __future__ import annotations
import uuid
from typing import Any
from datetime import datetime
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint, CheckConstraint, func, Index, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column
from ..db.base import Base
from .recoverable import RecoverableMixin

class Common(Base):
    __abstract__ = True
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    # Application-managed onupdate gives every ordinary SQLAlchemy mutation a
    # consistent timestamp without database triggers.  The server default
    # remains the authoritative insert-time value.
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

class Network(RecoverableMixin, Common):
    __tablename__ = "networks"
    __table_args__ = (
        Index("uq_active_networks_code", "code", unique=True, postgresql_where=text("deleted_at IS NULL")),
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    code: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="ACTIVE", nullable=False)

class City(RecoverableMixin, Common):
    __tablename__ = "cities"
    __table_args__ = (
        Index("uq_active_cities_network_code", "network_id", "code", unique=True, postgresql_where=text("deleted_at IS NULL")),
        Index("uq_cities_service_vlan_id", "service_vlan_id", unique=True, postgresql_where=text("service_vlan_id IS NOT NULL")),
        CheckConstraint("service_vlan_id IS NULL OR service_vlan_id BETWEEN 2 AND 4094", name="ck_cities_service_vlan_id"),
    )
    network_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("networks.id", ondelete="RESTRICT"), nullable=False)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    code: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="ACTIVE", nullable=False)
    service_vlan_id: Mapped[int | None] = mapped_column(Integer)

class Location(RecoverableMixin, Common):
    __tablename__ = "locations"
    __table_args__ = (
        Index("uq_active_locations_city_code", "city_id", "code", unique=True, postgresql_where=text("deleted_at IS NULL")),
    )
    city_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cities.id", ondelete="RESTRICT"), nullable=False)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    code: Mapped[str] = mapped_column(String(50), nullable=False)
    address: Mapped[str | None] = mapped_column(Text)
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="ACTIVE", nullable=False)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)

class DeviceType(Common):
    __tablename__ = "device_types"
    __table_args__ = (
        CheckConstraint(
            "code IN ('ACCESS_POINT','CPE','SECTOR','SWITCH','ROUTER','FIREWALL','SERVER','WIRELESS_BRIDGE','NETWORK_DEVICE','OTHER')",
            name="ck_device_types_controlled",
        ),
    )
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    code: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

class Device(RecoverableMixin, Common):
    __tablename__ = "devices"
    __table_args__ = (
        Index("ix_devices_type_display_active", "device_type_id", "display_name", postgresql_where=text("deleted_at IS NULL")),
        Index("ix_devices_display_active", "display_name", postgresql_where=text("deleted_at IS NULL")),
    )
    device_type_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("device_types.id", ondelete="RESTRICT"), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255))
    vendor: Mapped[str | None] = mapped_column(String(100))
    model: Mapped[str | None] = mapped_column(String(150))
    serial_number: Mapped[str | None] = mapped_column(String(150))
    description: Mapped[str | None] = mapped_column(Text)
    lifecycle_state: Mapped[str] = mapped_column(String(40), default="REGISTERED", nullable=False)
    operational_state: Mapped[str] = mapped_column(String(40), default="UNKNOWN", nullable=False)
    manual_degraded_override: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false"), nullable=False
    )
    management_protocol: Mapped[str | None] = mapped_column(String(30))
    credential_reference: Mapped[str | None] = mapped_column(String(255))
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)

class Sector(RecoverableMixin, Common):
    __tablename__ = "sectors"
    __table_args__ = (
        Index("uq_active_sectors_location_code", "location_id", "code", unique=True, postgresql_where=text("deleted_at IS NULL")),
        CheckConstraint("role IN ('CUSTOMER_ACCESS','BACKHAUL')", name="ck_sectors_role"),
        CheckConstraint(
            "(customer_vlan_start IS NULL AND customer_vlan_end IS NULL) OR "
            "(customer_vlan_start BETWEEN 2 AND 4094 AND customer_vlan_end BETWEEN 2 AND 4094 AND customer_vlan_start <= customer_vlan_end)",
            name="ck_sectors_customer_vlan_range",
        ),
    )
    location_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("locations.id", ondelete="RESTRICT"), nullable=False)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    code: Mapped[str] = mapped_column(String(50), nullable=False)
    sequence_number: Mapped[int | None] = mapped_column(Integer)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="ACTIVE", nullable=False)
    role: Mapped[str] = mapped_column(String(30), default="CUSTOMER_ACCESS", server_default="CUSTOMER_ACCESS", nullable=False)
    customer_vlan_start: Mapped[int | None] = mapped_column(Integer)
    customer_vlan_end: Mapped[int | None] = mapped_column(Integer)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)
    sector_device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, unique=True
    )

class Customer(RecoverableMixin, Common):
    __tablename__ = "customers"
    __table_args__ = (
        Index("uq_active_customers_code", "customer_code", unique=True, postgresql_where=text("deleted_at IS NULL")),
        Index("ix_customers_status_name_active", "status", "name", postgresql_where=text("deleted_at IS NULL")),
    )
    customer_code: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="ACTIVE", nullable=False)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)

class CustomerService(RecoverableMixin, Common):
    __tablename__ = "customer_services"
    __table_args__ = (
        Index("uq_active_customer_services_customer", "customer_id", unique=True, postgresql_where=text("deleted_at IS NULL")),
        Index("uq_active_customer_services_code", "service_code", unique=True, postgresql_where=text("deleted_at IS NULL")),
        Index("uq_active_customer_services_cpe", "cpe_device_id", unique=True, postgresql_where=text("deleted_at IS NULL")),
        Index("uq_active_customer_services_ap", "access_point_device_id", unique=True, postgresql_where=text("deleted_at IS NULL")),
        Index("ix_customer_services_sector_status", "sector_id", "status", postgresql_where=text("deleted_at IS NULL")),
        Index("ix_customer_services_sector_active", "sector_id", postgresql_where=text("deleted_at IS NULL")),
        Index("ix_customer_services_customer_vlan", "customer_vlan_id"),
        CheckConstraint("customer_vlan_id IS NULL OR customer_vlan_id BETWEEN 2 AND 4094", name="ck_customer_services_customer_vlan_id"),
    )
    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id", ondelete="RESTRICT"), nullable=False)
    sector_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sectors.id", ondelete="RESTRICT"), nullable=False)
    service_code: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="ACTIVE", nullable=False)
    cpe_device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False)
    access_point_device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False)
    router_device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    customer_vlan_id: Mapped[int | None] = mapped_column(Integer)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)

class DeviceIP(RecoverableMixin, Common):
    __tablename__ = "device_ips"
    __table_args__ = (
        Index("uq_active_device_ips_address", "ip_address", unique=True, postgresql_where=text("deleted_at IS NULL")),
        CheckConstraint("NOT is_primary OR is_management", name="ck_device_ips_primary_requires_management"),
        Index("uq_active_device_ips_primary", "device_id", unique=True, postgresql_where=text("deleted_at IS NULL AND is_primary")),
        Index("ix_device_ips_device_priority_active", "device_id", "is_management", "is_primary", postgresql_where=text("deleted_at IS NULL")),
    )
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False)
    address_family: Mapped[int] = mapped_column(Integer, default=4, nullable=False)
    is_management: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    source: Mapped[str | None] = mapped_column(String(40))

class DevicePlacement(RecoverableMixin, Common):
    """Human-approved placement of a registered device in the FTTW hierarchy."""
    __tablename__ = "device_placements"
    __table_args__ = (
        Index("ix_device_placements_geography_active", "network_id", "city_id", "location_id", postgresql_where=text("deleted_at IS NULL")),
        Index("ix_device_placements_sector_active", "sector_id", postgresql_where=text("deleted_at IS NULL")),
    )
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, unique=True)
    network_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("networks.id", ondelete="RESTRICT"), nullable=False)
    city_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cities.id", ondelete="RESTRICT"), nullable=False)
    location_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("locations.id", ondelete="RESTRICT"), nullable=False)
    sector_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("sectors.id", ondelete="RESTRICT"))
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)

class DeviceHierarchyLink(RecoverableMixin, Common):
    """Authoritative parent-child relationship for the customer physical hierarchy."""
    __tablename__ = "device_hierarchy_links"
    __table_args__ = (
        Index("uq_active_device_hierarchy_child", "child_device_id", unique=True, postgresql_where=text("deleted_at IS NULL")),
        CheckConstraint("child_device_id <> parent_device_id", name="ck_device_hierarchy_no_self"),
        CheckConstraint("relationship_type IN ('SECTOR_CPE','CPE_ACCESS_POINT')", name="ck_device_hierarchy_type"),
        Index(
            "uq_device_hierarchy_cpe_access_point_parent",
            "parent_device_id",
            unique=True,
            postgresql_where=text("relationship_type = 'CPE_ACCESS_POINT' AND deleted_at IS NULL"),
        ),
        Index("ix_device_hierarchy_links_parent", "parent_device_id", postgresql_where=text("deleted_at IS NULL")),
        Index("ix_device_hierarchy_parent_type_active", "parent_device_id", "relationship_type", postgresql_where=text("deleted_at IS NULL")),
    )
    child_device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    parent_device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(40), nullable=False)


class DeviceInterface(RecoverableMixin, Common):
    __tablename__ = "device_interfaces"
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    interface_name: Mapped[str] = mapped_column(String(150), nullable=False)
    interface_index: Mapped[int | None] = mapped_column(Integer)
    mac_address: Mapped[str | None] = mapped_column(String(32))
    description: Mapped[str | None] = mapped_column(Text)
    operational_status: Mapped[str | None] = mapped_column(String(30))
    administrative_status: Mapped[str | None] = mapped_column(String(30))
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)

class DeviceCandidate(Common):
    __tablename__ = "device_candidates"
    __table_args__ = (
        UniqueConstraint("ip_address", name="uq_device_candidates_ip"),
        Index("ix_device_candidates_state_created", "state", "created_at"),
    )
    discovery_result_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("discovery_results.id", ondelete="SET NULL")
    )
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(40), default="NEW", nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    suggested_device_type_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("device_types.id", ondelete="SET NULL")
    )
    display_name_suggestion: Mapped[str | None] = mapped_column(String(200))
    hostname: Mapped[str | None] = mapped_column(String(255))
    vendor: Mapped[str | None] = mapped_column(String(100))
    model: Mapped[str | None] = mapped_column(String(150))
    serial_number: Mapped[str | None] = mapped_column(String(150))
    management_protocol: Mapped[str | None] = mapped_column(String(30))
    duplicate_device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL")
    )
    network_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("networks.id", ondelete="SET NULL"))
    city_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("cities.id", ondelete="SET NULL"))
    location_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("locations.id", ondelete="SET NULL"))
    sector_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("sectors.id", ondelete="SET NULL"))
    customer_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("customers.id", ondelete="SET NULL"))
    relationship_target_device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    relationship_type: Mapped[str | None] = mapped_column(String(50))
    relationship_direction: Mapped[str | None] = mapped_column(String(30))
    review_note: Mapped[str | None] = mapped_column(Text)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)

class SystemSetting(Common):
    __tablename__ = "system_settings"
    key: Mapped[str] = mapped_column(String(150), unique=True, nullable=False)
    value: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    is_secret: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
