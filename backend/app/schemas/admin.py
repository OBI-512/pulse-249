from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, Field


class UserRead(BaseModel):
    id: UUID
    username: str
    display_name: str | None
    is_active: bool
    must_change_password: bool = False
    password_change_reason: str | None = None
    password_changed_at: datetime | None = None
    roles: list[str] = []
    permissions: list[str] = []
    direct_permissions: list[str] = []


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=150)
    display_name: str | None = None
    password: str = Field(min_length=1, max_length=200)
    role_codes: list[str] = Field(default_factory=list, max_length=1)
    permission_codes: list[str] = Field(default_factory=list)


class UserUpdate(BaseModel):
    display_name: str | None = None
    is_active: bool | None = None
    role_codes: list[str] | None = Field(default=None, max_length=1)
    permission_codes: list[str] | None = None
    password: str | None = Field(default=None, min_length=1, max_length=200)


class SecurityOptionRead(BaseModel):
    code: str
    name: str
    description: str | None = None
    requires: list[str] = Field(default_factory=list)


class SecurityOptionsRead(BaseModel):
    roles: list[SecurityOptionRead] = Field(default_factory=list)
    permissions: list[SecurityOptionRead] = Field(default_factory=list)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=1, max_length=200)


class PasswordReset(BaseModel):
    new_password: str = Field(min_length=1, max_length=200)


class SettingRead(BaseModel):
    key: str
    value: dict
    description: str | None = None
    is_secret: bool
    category: str | None = None
    is_configured: bool = True


class SettingWrite(BaseModel):
    value: dict
    description: str | None = None
    is_secret: bool | None = None


class AdminSessionRead(BaseModel):
    id: UUID
    user_id: UUID
    created_at: datetime
    last_seen_at: datetime | None = None
    last_user_activity_at: datetime | None = None
    expires_at: datetime
    revoked_at: datetime | None = None
    revoked_reason: str | None = None
    status: str
    login_ip: str | None = None
    last_ip: str | None = None
    browser_name: str | None = None
    browser_version: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    device_type: str | None = None
    user_agent: str | None = None


class OnlineSessionRead(AdminSessionRead):
    username: str
    display_name: str | None = None
    roles: list[str] = Field(default_factory=list)
    duration_seconds: int
    idle_seconds: int
    time_remaining_seconds: int


class SessionRevokeResponse(BaseModel):
    revoked_count: int


class ResourceScopeAssignmentWrite(BaseModel):
    scope_type: str = Field(pattern="^(GLOBAL|NETWORK|CITY|LOCATION|SECTOR|GROUP)$")
    resource_id: UUID | None = None


class ResourceScopeRead(BaseModel):
    id: UUID
    scope_type: str
    resource_id: UUID | None = None
    label: str
    context: str | None = None
    assigned_by_user_id: UUID | None = None
    created_at: datetime


class UserResourceScopesRead(BaseModel):
    user_id: UUID
    username: str
    direct_scopes: list[ResourceScopeRead] = Field(default_factory=list)
    effective_summary: dict = Field(default_factory=dict)


class UserResourceScopesWrite(BaseModel):
    scopes: list[ResourceScopeAssignmentWrite] = Field(default_factory=list, max_length=500)


class ResourceScopeOptionRead(BaseModel):
    scope_type: str
    resource_id: UUID | None = None
    label: str
    context: str | None = None
