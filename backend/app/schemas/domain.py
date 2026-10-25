from uuid import UUID
from enum import Enum
from pydantic import BaseModel, Field, model_validator

CONTROLLED_DEVICE_TYPES = {
    "ACCESS_POINT", "CPE", "SECTOR", "SWITCH", "ROUTER", "FIREWALL",
    "SERVER", "WIRELESS_BRIDGE", "NETWORK_DEVICE", "OTHER",
}

class SectorRole(str, Enum):
    CUSTOMER_ACCESS = "CUSTOMER_ACCESS"
    BACKHAUL = "BACKHAUL"

class DeviceHierarchyLinkCreate(BaseModel):
    parent_device_id: UUID
    relationship_type: str = Field(min_length=1, max_length=40)

class CustomerAssignment(BaseModel):
    sector_id: UUID
    cpe_device_id: UUID
    access_point_device_id: UUID
