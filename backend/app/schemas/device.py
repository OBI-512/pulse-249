from ipaddress import ip_address
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .remote_access import DeviceRemoteAccessUpdate


LIFECYCLE_STATES = {"REGISTERED", "ACTIVE", "MAINTENANCE", "DECOMMISSIONED"}
OPERATIONAL_STATES = {"UNKNOWN", "UP", "DOWN", "DEGRADED"}


def _validate_choice(value: str | None, allowed: set[str], field_name: str) -> str | None:
    if value is not None and value.upper() not in allowed:
        raise ValueError(f"Unsupported {field_name}: {value}")
    return value.upper() if value is not None else value


class DeviceTypeRead(BaseModel):
    id: UUID
    name: str
    code: str
    description: str | None = None
    is_active: bool
    model_config = ConfigDict(from_attributes=True)


class DeviceCreate(BaseModel):
    device_type_id: UUID
    display_name: str = Field(min_length=1, max_length=200)
    management_ip: str = Field(min_length=1, max_length=64)
    location_id: UUID | None = None
    sector_id: UUID | None = None
    parent_device_id: UUID | None = None
    sector_role: str | None = None
    hostname: str | None = Field(default=None, max_length=255)
    vendor: str | None = Field(default=None, max_length=100)
    model: str | None = Field(default=None, max_length=150)
    serial_number: str | None = Field(default=None, max_length=150)
    description: str | None = None
    lifecycle_state: str = Field(default="REGISTERED", max_length=40)
    operational_state: str = Field(default="UNKNOWN", max_length=40)
    management_protocol: str | None = Field(default=None, max_length=30)
    credential_reference: str | None = Field(default=None, max_length=255)
    metadata: dict = Field(default_factory=dict)

    @field_validator("management_ip")
    @classmethod
    def validate_management_ip(cls, value: str) -> str:
        try:
            parsed = ip_address(value.strip())
        except ValueError as exc:
            raise ValueError("Management IP must be a valid IPv4 address") from exc
        if parsed.version != 4:
            raise ValueError("Management IP must use IPv4 format")
        return str(parsed)

    @field_validator("sector_role")
    @classmethod
    def validate_sector_role(cls, value: str | None) -> str | None:
        if value is not None and value.upper() not in {"CUSTOMER_ACCESS", "BACKHAUL"}:
            raise ValueError("sector_role must be CUSTOMER_ACCESS or BACKHAUL")
        return value.upper() if value else value

    @model_validator(mode="after")
    def validate_parent_requirements(self):
        return self

    @field_validator("lifecycle_state")
    @classmethod
    def validate_lifecycle_state(cls, value: str) -> str:
        return _validate_choice(value, LIFECYCLE_STATES, "lifecycle_state") or "REGISTERED"

    @field_validator("operational_state")
    @classmethod
    def validate_operational_state(cls, value: str) -> str:
        return _validate_choice(value, OPERATIONAL_STATES, "operational_state") or "UNKNOWN"


class DeviceUpdate(BaseModel):
    device_type_id: UUID | None = None
    location_id: UUID | None = None
    sector_id: UUID | None = None
    parent_device_id: UUID | None = None
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    hostname: str | None = Field(default=None, max_length=255)
    vendor: str | None = Field(default=None, max_length=100)
    model: str | None = Field(default=None, max_length=150)
    serial_number: str | None = Field(default=None, max_length=150)
    description: str | None = None
    lifecycle_state: str | None = Field(default=None, max_length=40)
    operational_state: str | None = Field(default=None, max_length=40)
    manual_degraded_override: bool | None = None
    management_protocol: str | None = Field(default=None, max_length=30)
    credential_reference: str | None = Field(default=None, max_length=255)
    metadata: dict | None = None
    remote_access: DeviceRemoteAccessUpdate | None = None

    @field_validator("lifecycle_state")
    @classmethod
    def validate_lifecycle_state(cls, value: str | None) -> str | None:
        return _validate_choice(value, LIFECYCLE_STATES, "lifecycle_state")

    @field_validator("operational_state")
    @classmethod
    def validate_operational_state(cls, value: str | None) -> str | None:
        return _validate_choice(value, OPERATIONAL_STATES, "operational_state")


class DeviceRead(BaseModel):
    id: UUID
    device_type_id: UUID
    display_name: str
    hostname: str | None = None
    vendor: str | None = None
    model: str | None = None
    serial_number: str | None = None
    description: str | None = None
    lifecycle_state: str
    operational_state: str
    manual_degraded_override: bool = False
    management_protocol: str | None = None
    credential_reference: str | None = None
    metadata: dict = Field(default_factory=dict, validation_alias="metadata_")
    management_ip: str | None = None
    model_config = ConfigDict(from_attributes=True)

class LegacyDeviceRead(DeviceCreate):
    id: UUID
    metadata: dict = Field(
        default_factory=dict,
        validation_alias="metadata_",
    )
    model_config = ConfigDict(from_attributes=True)

class DeviceInventoryRead(DeviceRead):
    management_ip: str | None = None
    service_vlan_id: int | None = None
    customer_vlan_id: int | None = None
    customer_vlan_start: int | None = None
    customer_vlan_end: int | None = None
    customer_vlan_display: str | None = None

class DeviceAccessibilityResponse(BaseModel):
    device_id: UUID
    reachable: bool
    url: str
    status_code: int | None = None
    response_time_ms: int | None = None
    message: str


class DeviceIPCreate(BaseModel):
    ip_address: str = Field(min_length=1, max_length=64)
    address_family: int | None = None
    is_management: bool = False
    is_primary: bool = False
    source: str | None = Field(default=None, max_length=40)

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        try:
            return str(ip_address(value))
        except ValueError as exc:
            raise ValueError("Invalid IP address") from exc

    @field_validator("address_family")
    @classmethod
    def validate_family(cls, value: int | None) -> int | None:
        if value is not None and value not in (4, 6):
            raise ValueError("address_family must be 4 or 6")
        return value


class DeviceIPUpdate(BaseModel):
    is_management: bool | None = None
    is_primary: bool | None = None
    source: str | None = Field(default=None, max_length=40)


class DeviceIPRead(DeviceIPCreate):
    id: UUID
    device_id: UUID
    model_config = ConfigDict(from_attributes=True)


class DeviceInterfaceCreate(BaseModel):
    interface_name: str = Field(min_length=1, max_length=150)
    interface_index: int | None = Field(default=None, ge=0)
    mac_address: str | None = Field(default=None, max_length=32)
    description: str | None = None
    operational_status: str | None = Field(default=None, max_length=30)
    administrative_status: str | None = Field(default=None, max_length=30)
    metadata: dict = Field(default_factory=dict)


class DeviceInterfaceUpdate(BaseModel):
    interface_name: str | None = Field(default=None, min_length=1, max_length=150)
    interface_index: int | None = Field(default=None, ge=0)
    mac_address: str | None = Field(default=None, max_length=32)
    description: str | None = None
    operational_status: str | None = Field(default=None, max_length=30)
    administrative_status: str | None = Field(default=None, max_length=30)
    metadata: dict | None = None


class DeviceInterfaceRead(DeviceInterfaceCreate):
    id: UUID
    device_id: UUID
    metadata: dict = Field(
        default_factory=dict,
        validation_alias="metadata_",
    )
    model_config = ConfigDict(from_attributes=True)


class DeviceStatusUpdate(BaseModel):
    operational_state: str | None = Field(default=None, min_length=1, max_length=40)
    manual_degraded_override: bool | None = None
    lifecycle_state: str | None = Field(default=None, max_length=40)

    @field_validator("operational_state")
    @classmethod
    def validate_operational_state(cls, value: str | None) -> str | None:
        return _validate_choice(value, OPERATIONAL_STATES, "operational_state")

    @field_validator("lifecycle_state")
    @classmethod
    def validate_lifecycle_state(cls, value: str | None) -> str | None:
        return _validate_choice(value, LIFECYCLE_STATES, "lifecycle_state")

    @model_validator(mode="after")
    def require_change(self):
        if self.operational_state is None and self.manual_degraded_override is None and self.lifecycle_state is None:
            raise ValueError("At least one status field must be provided.")
        return self

class DeviceManagementRead(BaseModel):
    id: UUID
    device_type_id: UUID
    device_type_code: str
    display_name: str
    management_ip: str | None = None
    lifecycle_state: str
    operational_state: str
    manual_degraded_override: bool = False
    network_id: UUID | None = None
    network_name: str | None = None
    city_id: UUID | None = None
    city_name: str | None = None
    location_id: UUID | None = None
    location_name: str | None = None
    sector_id: UUID | None = None
    sector_name: str | None = None
    sector_role: str | None = None
    physical_sector_device_id: UUID | None = None
    physical_sector_device_name: str | None = None
    parent_device_id: UUID | None = None
    parent_device_name: str | None = None
    customer_id: UUID | None = None
    customer_name: str | None = None
    service_vlan_id: int | None = None
    customer_vlan_id: int | None = None
    customer_vlan_start: int | None = None
    customer_vlan_end: int | None = None


class DeviceVlanFilterOption(BaseModel):
    id: str
    label: str
    description: str | None = None
