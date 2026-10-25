from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, Field

from .geo import CityRead, LocationRead, SectorRead
from .network import NetworkRead



class TopologyScopeOptionsRead(BaseModel):
    source_networks: list[NetworkRead] = Field(default_factory=list)
    networks: list[NetworkRead] = Field(default_factory=list)
    cities: list[CityRead] = Field(default_factory=list)
    locations: list[LocationRead] = Field(default_factory=list)
    sectors: list[SectorRead] = Field(default_factory=list)

class TopologyDevice(BaseModel):
    id: UUID
    display_name: str
    device_type_id: UUID
    device_type_code: str
    hostname: str | None = None
    vendor: str | None = None
    model: str | None = None
    operational_state: str
    lifecycle_state: str
    management_ip: str | None = None
    management_protocol: str | None = None
    remote_ssh_ready: bool = False
    parent_device_id: UUID | None = None
    live_state: str | None = None
    live_state_source: str | None = None
    live_checked_at: datetime | None = None
    live_response_time_ms: float | None = None
    children: list["TopologyDevice"] = Field(default_factory=list)

class TopologyService(BaseModel):
    id: UUID
    service_code: str
    customer_id: UUID
    cpe_device_id: UUID
    access_point_device_id: UUID
    router_device_id: UUID | None = None
    status: str

class TopologySector(BaseModel):
    id: UUID
    name: str
    code: str
    sequence_number: int | None = None
    role: str
    devices: list[TopologyDevice] = Field(default_factory=list)
    services: list[TopologyService] = Field(default_factory=list)

class TopologyLocation(BaseModel):
    id: UUID
    name: str
    code: str
    devices: list[TopologyDevice] = Field(default_factory=list)
    sectors: list[TopologySector] = Field(default_factory=list)

class TopologyCity(BaseModel):
    id: UUID
    name: str
    code: str
    locations: list[TopologyLocation] = Field(default_factory=list)

class TopologyNetwork(BaseModel):
    id: UUID
    name: str
    code: str
    cities: list[TopologyCity] = Field(default_factory=list)


class TopologyGeographyNode(BaseModel):
    id: UUID
    name: str
    code: str

class SectorLiveTopology(BaseModel):
    network: TopologyGeographyNode
    city: TopologyGeographyNode
    location: TopologyGeographyNode
    sector: TopologySector



class TopologyHierarchyNode(BaseModel):
    id: UUID
    kind: str
    name: str
    code: str | None = None
    detail: str | None = None
    has_children: bool = False
    context_only: bool = False
    device_type_code: str | None = None
    hostname: str | None = None
    management_ip: str | None = None
    management_protocol: str | None = None
    remote_ssh_ready: bool = False
    lifecycle_state: str | None = None
    operational_state: str | None = None


class TopologyHierarchyChildren(BaseModel):
    items: list[TopologyHierarchyNode] = Field(default_factory=list)


class TopologyFilterOption(BaseModel):
    id: UUID | str
    label: str
    description: str | None = None


class TopologyFilterOptionPage(BaseModel):
    items: list[TopologyFilterOption] = Field(default_factory=list)
    total: int
    page: int
    page_size: int

class NetworkTopology(BaseModel):
    id: UUID
    name: str
    code: str
    cities: list[TopologyCity] = Field(default_factory=list)
    networks: list[TopologyNetwork] = Field(default_factory=list)

TopologyDevice.model_rebuild()
