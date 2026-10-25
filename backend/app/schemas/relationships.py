from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field

class DeviceRelationshipCreate(BaseModel):
    source_device_id: UUID
    target_device_id: UUID
    relationship_type: str = Field(min_length=1, max_length=50)
    direction: str = Field(default="DIRECTED", max_length=30)
    metadata: dict = Field(default_factory=dict)

class DeviceRelationshipRead(DeviceRelationshipCreate):
    id: UUID
    metadata: dict = Field(default_factory=dict, validation_alias="metadata_")
    model_config = ConfigDict(from_attributes=True)
