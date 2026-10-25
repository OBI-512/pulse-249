from enum import Enum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class DeviceGroupScope(str, Enum):
    GLOBAL = "GLOBAL"
    NETWORK = "NETWORK"
    CITY = "CITY"
    LOCATION = "LOCATION"
    SECTOR = "SECTOR"


class DeviceScope(str, Enum):
    ANY = "ANY"
    ACCESS_POINT = "ACCESS_POINT"
    CPE = "CPE"
    SECTOR = "SECTOR"
    SWITCH = "SWITCH"
    ROUTER = "ROUTER"
    FIREWALL = "FIREWALL"
    SERVER = "SERVER"
    WIRELESS_BRIDGE = "WIRELESS_BRIDGE"
    NETWORK_DEVICE = "NETWORK_DEVICE"
    OTHER = "OTHER"


class SectorRole(str, Enum):
    CUSTOMER_ACCESS = "CUSTOMER_ACCESS"
    BACKHAUL = "BACKHAUL"


class GroupKind(str, Enum):
    SYSTEM = "SYSTEM"
    CUSTOM = "CUSTOM"


class GroupMembershipMode(str, Enum):
    MANUAL = "MANUAL"
    DYNAMIC = "DYNAMIC"


class DeviceGroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    code: str = Field(min_length=1, max_length=80)
    description: str | None = None
    scope_type: DeviceGroupScope = DeviceGroupScope.GLOBAL
    network_id: UUID | None = None
    city_id: UUID | None = None
    location_id: UUID | None = None
    sector_id: UUID | None = None
    device_scope: DeviceScope = DeviceScope.ANY
    sector_role: SectorRole | None = None
    membership_mode: GroupMembershipMode = GroupMembershipMode.MANUAL
    metadata: dict = Field(default_factory=dict)
    child_group_ids: list[UUID] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_scope_context(self):
        contexts = {
            DeviceGroupScope.NETWORK: self.network_id,
            DeviceGroupScope.CITY: self.city_id,
            DeviceGroupScope.LOCATION: self.location_id,
            DeviceGroupScope.SECTOR: self.sector_id,
        }
        if self.sector_role is not None and self.device_scope != DeviceScope.SECTOR:
            raise ValueError("Sector role can only be used when device_scope is SECTOR.")
        if self.scope_type == DeviceGroupScope.GLOBAL:
            if any(value is not None for value in contexts.values()):
                raise ValueError("GLOBAL groups cannot specify an organizational context.")
            return self
        selected = contexts[self.scope_type]
        if selected is None:
            raise ValueError(f"{self.scope_type.value} groups require the corresponding context ID.")
        if any(value is not None for scope, value in contexts.items() if scope != self.scope_type):
            raise ValueError(f"{self.scope_type.value} groups may only specify the corresponding organizational context.")
        return self


class DeviceGroupUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=150)
    description: str | None = None
    device_scope: DeviceScope | None = None
    sector_role: SectorRole | None = None
    membership_mode: GroupMembershipMode | None = None
    metadata: dict | None = None
    child_group_ids: list[UUID] | None = None
    reconcile_memberships: bool = False


class DeviceGroupRead(BaseModel):
    id: UUID
    name: str
    code: str
    description: str | None
    scope_type: DeviceGroupScope
    network_id: UUID | None
    city_id: UUID | None
    location_id: UUID | None
    sector_id: UUID | None
    device_scope: DeviceScope
    sector_role: SectorRole | None
    group_kind: GroupKind = GroupKind.CUSTOM
    membership_mode: GroupMembershipMode = GroupMembershipMode.MANUAL
    system_key: str | None = None
    metadata: dict = Field(default_factory=dict, validation_alias="metadata_")
    model_config = ConfigDict(from_attributes=True)


class DeviceGroupListRow(DeviceGroupRead):
    context_name: str | None = None
    parent_group_id: UUID | None = None
    parent_group_name: str | None = None
    child_count: int = 0
    device_count: int = 0


class DeviceGroupChildrenUpdate(BaseModel):
    child_group_ids: list[UUID] = Field(default_factory=list)


class DeviceGroupNestingRead(BaseModel):
    id: UUID
    parent_group_id: UUID
    child_group_id: UUID
    model_config = ConfigDict(from_attributes=True)


class GroupDeviceItem(BaseModel):
    item_type: Literal["GROUP", "DEVICE"] = "DEVICE"
    id: UUID
    display_name: str
    code: str | None = None
    hostname: str | None = None
    device_type_code: str
    management_ip: str | None = None
    lifecycle_state: str | None = None
    operational_state: str | None = None
    item_count: int | None = None
    source_groups: list[str] = Field(default_factory=list)


class GroupItemsPage(BaseModel):
    child_groups: list[DeviceGroupRead] = Field(default_factory=list)
    items: list[GroupDeviceItem] = Field(default_factory=list)
    total: int
    page: int
    page_size: int


class DeviceGroupDetail(BaseModel):
    direct_devices: list[UUID] = Field(default_factory=list)
    effective_devices: list[UUID] = Field(default_factory=list)
    child_groups: list[DeviceGroupRead] = Field(default_factory=list)
    parent_group: DeviceGroupRead | None = None
