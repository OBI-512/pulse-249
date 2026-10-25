from datetime import datetime
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=150)
    password: str = Field(min_length=1)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LogoutResponse(BaseModel):
    message: str


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=1, max_length=200)


class RequiredPasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=1, max_length=200)




class PasswordPolicyResponse(BaseModel):
    minimum_length: int
    require_complexity: bool
    history_count: int
    minimum_edit_distance: int
    maximum_age_days: int
    expiry_warning_days: int


class SessionStatusResponse(BaseModel):
    session_id: str
    expires_at: datetime
    seconds_remaining: int
    idle_seconds: int
    idle_timeout_seconds: int
    extension_window_seconds: int
    extension_eligible: bool
    renewal_minutes: int
    must_change_password: bool = False
    password_change_reason: str | None = None


class SessionExtendResponse(BaseModel):
    session_id: str
    expires_at: datetime
    seconds_remaining: int
    renewal_minutes: int


class ClientSessionMetadataRequest(BaseModel):
    user_agent: str | None = Field(default=None, max_length=1024)
    browser_name: str | None = Field(default=None, max_length=100)
    browser_version: str | None = Field(default=None, max_length=80)
    os_name: str | None = Field(default=None, max_length=100)
    os_version: str | None = Field(default=None, max_length=80)
    device_type: str | None = Field(default=None, max_length=30)


class CurrentUserResponse(BaseModel):
    id: str
    username: str
    display_name: str | None = None
    roles: list[str] = []
    permissions: list[str] = []
    must_change_password: bool = False
    password_change_reason: str | None = None
    password_changed_at: datetime | None = None
    password_expires_at: datetime | None = None
    password_expires_in_days: int | None = None
    password_expiry_warning: bool = False


class AuthSessionRead(BaseModel):
    id: str
    user_id: str
    created_at: datetime
    last_seen_at: datetime | None = None
    last_user_activity_at: datetime | None = None
    expires_at: datetime
    revoked_at: datetime | None = None
    revoked_reason: str | None = None
    is_current: bool = False
    status: str
    login_ip: str | None = None
    last_ip: str | None = None
    browser_name: str | None = None
    browser_version: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    device_type: str | None = None
    user_agent: str | None = None


class RevokeSessionsResponse(BaseModel):
    revoked_count: int
