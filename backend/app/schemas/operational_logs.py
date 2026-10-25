from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class OperationalLogRead(BaseModel):
    timestamp: str
    level: str
    service: str
    logger: str
    message: str
    request_id: str | None = None
    user_id: str | None = None
    exception_class: str | None = None
    context: dict[str, Any] = {}


class OperationalLogPage(BaseModel):
    items: list[OperationalLogRead]
    total: int
    page: int
    page_size: int
