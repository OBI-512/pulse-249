from datetime import datetime
from ipaddress import ip_address as parse_ip_address
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _normalize_ipv4(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        parsed = parse_ip_address(value.strip())
    except ValueError as exc:
        raise ValueError("Management IP must be a valid IPv4 address") from exc
    if parsed.version != 4:
        raise ValueError("Management IP must use IPv4 format")
    return str(parsed)



class CandidateRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    discovery_result_id: UUID | None = None
    ip_address: str
    state: str
    confidence: float
    suggested_device_type_id: UUID | None = None
    display_name_suggestion: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    model: str | None = None
    serial_number: str | None = None
    management_protocol: str | None = None
    duplicate_device_id: UUID | None = None
    review_note: str | None = None
    network_id: UUID | None = None
    city_id: UUID | None = None
    location_id: UUID | None = None
    sector_id: UUID | None = None
    relationship_target_device_id: UUID | None = None
    relationship_type: str | None = None
    relationship_direction: str | None = None
    metadata: dict = Field(validation_alias="metadata_")
    created_at: datetime
    updated_at: datetime


class CandidatePage(BaseModel):
    items: list[CandidateRead]
    limit: int
    offset: int
    count: int


class CandidateUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip_address: str | None = Field(default=None, max_length=64)
    suggested_device_type_id: UUID | None = None
    display_name_suggestion: str | None = Field(default=None, max_length=200)
    hostname: str | None = Field(default=None, max_length=255)
    vendor: str | None = Field(default=None, max_length=100)
    model: str | None = Field(default=None, max_length=150)
    serial_number: str | None = Field(default=None, max_length=150)
    management_protocol: str | None = Field(default=None, max_length=30)
    review_note: str | None = None
    network_id: UUID | None = None
    city_id: UUID | None = None
    location_id: UUID | None = None
    sector_id: UUID | None = None
    relationship_target_device_id: UUID | None = None
    relationship_type: str | None = Field(default=None, max_length=50)
    relationship_direction: str | None = Field(default=None, max_length=30)
    metadata: dict | None = None

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, value: str | None) -> str | None:
        return _normalize_ipv4(value)


class CandidateApprove(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip_address: str | None = Field(default=None, max_length=64)
    suggested_device_type_id: UUID
    display_name: str = Field(min_length=1, max_length=200)
    hostname: str | None = Field(default=None, max_length=255)
    vendor: str | None = Field(default=None, max_length=100)
    model: str | None = Field(default=None, max_length=150)
    serial_number: str | None = Field(default=None, max_length=150)
    management_protocol: str | None = Field(default=None, max_length=30)
    review_note: str | None = None
    network_id: UUID | None = None
    city_id: UUID | None = None
    location_id: UUID | None = None
    sector_id: UUID | None = None
    relationship_target_device_id: UUID | None = None
    relationship_type: str | None = Field(default=None, max_length=50)
    relationship_direction: str | None = Field(default=None, max_length=30)

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, value: str | None) -> str | None:
        return _normalize_ipv4(value)


class CandidateReject(BaseModel):
    review_note: str | None = None


class CandidateRegistration(BaseModel):
    candidate_id: UUID
    device_id: UUID
    ip_id: UUID
    state: str
    idempotent: bool = False
