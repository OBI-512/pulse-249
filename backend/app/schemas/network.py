from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field

class NetworkCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    code: str = Field(min_length=1, max_length=50)
    description: str | None = None
    status: str = "ACTIVE"

class NetworkUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    status: str | None = None

class NetworkRead(NetworkCreate):
    id: UUID
    model_config = ConfigDict(from_attributes=True)


class NetworkListRow(NetworkRead):
    city_count: int = 0
