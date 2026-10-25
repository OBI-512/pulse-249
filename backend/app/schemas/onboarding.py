from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress


class OnboardingProbeRequest(BaseModel):
    ip_address: IPvAnyAddress
    timeout_seconds: float = Field(default=2.0, gt=0, le=10)


class OnboardingProbeResult(BaseModel):
    ip_address: str
    reachable: bool
    response_time_ms: float | None = None
    protocol: str | None = None
    message: str | None = None


class OnboardingCandidateCreate(BaseModel):
    ip_address: IPvAnyAddress
    device_type_id: UUID
    display_name: str = Field(min_length=1, max_length=200)
    location_id: UUID | None = None
    sector_id: UUID | None = None
    parent_device_id: UUID | None = None
    hostname: str | None = None
    vendor: str | None = None
    model: str | None = None
    serial_number: str | None = None
    management_protocol: str | None = None
    credential_reference: str | None = None
    metadata: dict = Field(default_factory=dict)


class OnboardingCandidateRead(BaseModel):
    id: UUID
    ip_address: str
    device_type_id: UUID
    display_name: str
    location_id: UUID | None = None
    sector_id: UUID | None = None
    parent_device_id: UUID | None = None
    hostname: str | None = None
    vendor: str | None = None
    model: str | None = None
    serial_number: str | None = None
    management_protocol: str | None = None
    credential_reference: str | None = None
    state: str
    message: str | None = None
    model_config = ConfigDict(from_attributes=True)


class OnboardingRegisterRequest(BaseModel):
    candidate_id: UUID


class OnboardingRegisterResponse(BaseModel):
    device_id: UUID
    ip_id: UUID
    state: str
    message: str
