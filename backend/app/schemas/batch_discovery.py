from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, IPvAnyAddress


class BatchDiscoveryRequest(BaseModel):
    ip_addresses: list[IPvAnyAddress] = Field(default_factory=list, max_length=10000)
    cidrs: list[str] = Field(default_factory=list, max_length=100)
    methods: list[str] = Field(default=["ICMP"], min_length=1, max_length=5)
    timeout_seconds: float = Field(default=2.0, gt=0, le=10)
    http_port: int | None = Field(default=None, ge=1, le=65535)
    https_port: int | None = Field(default=None, ge=1, le=65535)
    access_template_id: UUID | None = None
    concurrency: int = Field(default=25, ge=1, le=100)
    max_targets: int = Field(default=1000, ge=1, le=10000)


class BatchDiscoveryCreateResponse(BaseModel):
    job_id: UUID
    status: str
    target_count: int
    message: str


class BatchDiscoveryResultRead(BaseModel):
    id: UUID
    discovery_job_id: UUID
    ip_address: str
    discovery_method: str
    status: str
    vendor: str | None = None
    model: str | None = None
    hostname: str | None = None
    serial_number: str | None = None
    raw_data: dict
    created_at: datetime
