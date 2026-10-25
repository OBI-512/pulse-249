from pydantic import BaseModel, Field


class PaginationParams(BaseModel):
    limit: int = Field(default=100, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class PageMeta(BaseModel):
    limit: int
    offset: int
    count: int
