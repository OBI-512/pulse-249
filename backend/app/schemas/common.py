from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class APIModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Timestamped(APIModel):
    id: UUID
    created_at: datetime
    updated_at: datetime
