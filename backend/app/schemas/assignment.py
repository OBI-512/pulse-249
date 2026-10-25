from uuid import UUID

from pydantic import BaseModel


class AssignmentOptionRead(BaseModel):
    id: UUID
    label: str
    description: str | None = None
    network_id: UUID | None = None
    network_name: str | None = None
    city_id: UUID | None = None
    city_name: str | None = None
    location_id: UUID | None = None
    location_name: str | None = None
    logical_sector_id: UUID | None = None
    logical_sector_name: str | None = None
    sector_role: str | None = None
    physical_sector_device_id: UUID | None = None
    physical_sector_device_name: str | None = None
    management_ip: str | None = None
    device_type_code: str | None = None
