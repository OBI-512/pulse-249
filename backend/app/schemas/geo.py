from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .domain import SectorRole
from .network import NetworkRead

class CityCreate(BaseModel):
    name: str
    code: str
    description: str | None = None
    status: str = "ACTIVE"
    service_vlan_id: int = Field(ge=2, le=4094)

class CityUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    status: str | None = None
    service_vlan_id: int | None = Field(default=None, ge=2, le=4094)

class CityRead(BaseModel):
    id: UUID
    network_id: UUID
    name: str
    code: str
    description: str | None = None
    status: str
    service_vlan_id: int | None = None
    model_config = ConfigDict(from_attributes=True)

class LocationCreate(BaseModel):
    name: str
    code: str
    address: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    description: str | None = None
    status: str = "ACTIVE"
    metadata: dict = Field(default_factory=dict)

class LocationUpdate(BaseModel):
    name: str | None = None
    address: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    description: str | None = None
    status: str | None = None
    metadata: dict | None = None

class LocationRead(LocationCreate):
    id: UUID
    city_id: UUID
    metadata: dict = Field(
        default_factory=dict,
        alias="metadata_",
    )
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
    )

class SectorCreate(BaseModel):
    name: str
    code: str
    sequence_number: int | None = None
    description: str | None = None
    status: str = "ACTIVE"
    role: SectorRole = SectorRole.CUSTOMER_ACCESS
    customer_vlan_start: int | None = Field(default=None, ge=2, le=4094)
    customer_vlan_end: int | None = Field(default=None, ge=2, le=4094)
    metadata: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_vlan_range(self):
        if (self.customer_vlan_start is None) != (self.customer_vlan_end is None):
            raise ValueError("customer_vlan_start and customer_vlan_end must be set together")
        if self.customer_vlan_start is not None and self.customer_vlan_start > self.customer_vlan_end:
            raise ValueError("customer_vlan_start must be less than or equal to customer_vlan_end")
        return self

class SectorUpdate(BaseModel):
    name: str | None = None
    sequence_number: int | None = None
    description: str | None = None
    status: str | None = None
    role: SectorRole | None = None
    customer_vlan_start: int | None = Field(default=None, ge=2, le=4094)
    customer_vlan_end: int | None = Field(default=None, ge=2, le=4094)
    metadata: dict | None = None


class SectorRoleTransition(BaseModel):
    role: SectorRole

class SectorRead(SectorCreate):
    id: UUID
    location_id: UUID
    sector_device_id: UUID | None = None
    metadata: dict = Field(
        default_factory=dict,
        alias="metadata_",
    )
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
    )

class GeographyScopeOptionsRead(BaseModel):
    networks: list[NetworkRead]
    cities: list[CityRead]
    locations: list[LocationRead]
    sectors: list[SectorRead]



class CityListRow(CityRead):
    network_name: str
    location_count: int = 0


class LocationListRow(LocationRead):
    network_id: UUID
    network_name: str
    city_name: str
    service_vlan_id: int | None = None
    sector_count: int = 0


class SectorListRow(SectorRead):
    network_id: UUID
    network_name: str
    city_id: UUID
    city_name: str
    service_vlan_id: int | None = None
    location_name: str
    physical_sector_device_name: str | None = None
