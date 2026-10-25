from pydantic import BaseModel


class LogFilterOption(BaseModel):
    id: str
    label: str
    description: str | None = None
