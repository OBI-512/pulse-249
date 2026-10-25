from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ExternalCustomerRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    external_customer_id: str = Field(min_length=1, max_length=200)
    customer_code: str | None = Field(default=None, max_length=100)
    name: str | None = Field(default=None, max_length=200)
    status: str | None = Field(default=None, max_length=40)
    source_updated_at: datetime | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class ExternalServiceRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    external_service_id: str = Field(min_length=1, max_length=200)
    external_customer_id: str = Field(min_length=1, max_length=200)
    service_code: str | None = Field(default=None, max_length=100)
    status: str | None = Field(default=None, max_length=40)
    customer_vlan_id: int | None = Field(default=None, ge=2, le=4094)
    source_updated_at: datetime | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class CustomerSyncBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    customers: list[ExternalCustomerRecord] = Field(default_factory=list, max_length=5000)
    services: list[ExternalServiceRecord] = Field(default_factory=list, max_length=5000)
    cursor: str | None = Field(default=None, max_length=512)
    next_cursor: str | None = Field(default=None, max_length=512)
    has_more: bool = False


class CustomerSyncEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(min_length=1, max_length=200)
    event_type: Literal[
        "CUSTOMER_UPSERT",
        "SERVICE_UPSERT",
        "CUSTOMER_DEACTIVATED",
        "SERVICE_DEACTIVATED",
    ]
    occurred_at: datetime | None = None
    customer: ExternalCustomerRecord | None = None
    service: ExternalServiceRecord | None = None


class EventReceiptRead(BaseModel):
    event_id: str
    status: Literal["PROCESSED", "DUPLICATE"]
    changed: bool = False


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    scope: str
