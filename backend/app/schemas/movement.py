from uuid import UUID

from pydantic import BaseModel, Field


class SectorMove(BaseModel):
    destination_location_id: UUID
    sequence_number: int | None = Field(default=None, ge=1)


class CpeMove(BaseModel):
    destination_sector_device_id: UUID


class AccessPointReassignment(BaseModel):
    destination_cpe_device_id: UUID
