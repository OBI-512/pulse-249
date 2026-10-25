from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress


class DiscoveryRunRequest(BaseModel):
    ip_address: IPvAnyAddress
    methods: list[str] = Field(default=["ICMP"], min_length=1, max_length=5)
    timeout_seconds: float = Field(default=2.0, gt=0, le=10)
    http_port: int | None = Field(default=None, ge=1, le=65535)
    https_port: int | None = Field(default=None, ge=1, le=65535)
    credential_reference: str | None = Field(default=None, max_length=255)
    access_template_id: UUID | None = None
    snmp_version: str = Field(default="2c", max_length=8)
    snmp_community: str | None = None
    snmp_retries: int = Field(default=0, ge=0, le=5)
    snmp_v3_username: str | None = Field(default=None, max_length=255)
    snmp_v3_security_level: str = Field(default="noAuthNoPriv", max_length=32)
    snmp_v3_auth_protocol: str | None = Field(default="SHA", max_length=32)
    snmp_v3_auth_password: str | None = None
    snmp_v3_priv_protocol: str | None = Field(default="AES", max_length=32)
    snmp_v3_priv_password: str | None = None


class DiscoveryAggregateRead(BaseModel):
    ip_address: str
    reachable: bool
    hostname: str | None = None
    vendor: str | None = None
    model: str | None = None
    serial_number: str | None = None
    management_protocol: str | None = None
    confidence: float
    protocol_status: dict[str, str]
    field_sources: dict[str, str]


class DiscoveryRunResponse(BaseModel):
    job_id: UUID
    status: str
    results: list["DiscoveryResultRead"]
    consolidated: DiscoveryAggregateRead | None = None


class DiscoveryResultRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
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


class DiscoveryJobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    scope_type: str
    scope_value: str
    status: str
    metadata: dict = Field(validation_alias="metadata_")
    created_at: datetime
    updated_at: datetime
