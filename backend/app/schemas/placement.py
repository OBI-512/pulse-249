from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field

class DevicePlacementCreate(BaseModel):
    network_id: UUID
    city_id: UUID
    location_id: UUID
    sector_id: UUID | None = None
    metadata: dict = Field(default_factory=dict)

class DevicePlacementRead(DevicePlacementCreate):
    id: UUID
    device_id: UUID
    metadata: dict = Field(validation_alias="metadata_")
    model_config = ConfigDict(from_attributes=True)

class DevicePlacementUpdate(BaseModel):
    network_id: UUID | None = None
    city_id: UUID | None = None
    location_id: UUID | None = None
    sector_id: UUID | None = None
    metadata: dict | None = None
