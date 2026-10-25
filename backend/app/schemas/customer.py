from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class CustomerCreate(BaseModel):
    customer_code: str
    name: str
    status: str = "ACTIVE"
    metadata: dict = Field(default_factory=dict)


class CustomerUpdate(BaseModel):
    name: str | None = None
    status: str | None = None
    metadata: dict | None = None


class CustomerRead(CustomerCreate):
    id: UUID
    metadata: dict = Field(
        default_factory=dict,
        alias="metadata_",
    )
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
    )


class CustomerListRead(CustomerRead):
    service_code: str | None = None
    sector_id: UUID | None = None
    sector_name: str | None = None
    service_vlan_id: int | None = None
    customer_vlan_id: int | None = None


class CustomerFilterOption(BaseModel):
    id: str
    label: str
    description: str | None = None


class ServiceEndpointOption(BaseModel):
    access_point_device_id: UUID
    access_point_name: str
    cpe_device_id: UUID
    cpe_name: str
    sector_id: UUID
    sector_name: str
    city_id: UUID
    city_name: str
    service_vlan_id: int | None = None
    customer_vlan_start: int | None = None
    customer_vlan_end: int | None = None


class ServiceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    customer_id: UUID
    service_code: str
    status: str = "ACTIVE"
    access_point_device_id: UUID
    router_device_id: UUID | None = None
    customer_vlan_id: int | None = Field(default=None, ge=2, le=4094)
    metadata: dict = Field(default_factory=dict)


class ServiceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str | None = None
    access_point_device_id: UUID | None = None
    router_device_id: UUID | None = None
    customer_vlan_id: int | None = Field(default=None, ge=2, le=4094)
    metadata: dict | None = None


class ServiceRead(BaseModel):
    id: UUID
    customer_id: UUID
    sector_id: UUID
    service_code: str
    status: str
    cpe_device_id: UUID
    access_point_device_id: UUID
    router_device_id: UUID | None = None
    service_vlan_id: int | None = None
    customer_vlan_id: int | None = None
    sector_name: str | None = None
    cpe_name: str | None = None
    access_point_name: str | None = None
    metadata: dict = Field(default_factory=dict, alias="metadata_")
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)
