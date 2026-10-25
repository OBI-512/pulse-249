from __future__ import annotations
from datetime import datetime
import uuid
from typing import Any
from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, String, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from .core import Common


class User(Common):
    __tablename__ = "users"
    external_subject: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    username: Mapped[str] = mapped_column(String(150), unique=True, nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(200))
    password_hash: Mapped[str | None] = mapped_column(String(512), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    password_change_reason: Mapped[str | None] = mapped_column(String(40), nullable=True)
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict, nullable=False)


class Role(Common):
    __tablename__ = "roles"
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    code: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(500))


class Permission(Common):
    __tablename__ = "permissions"
    name: Mapped[str] = mapped_column(String(150), unique=True, nullable=False)
    code: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(500))


class UserRole(Common):
    __tablename__ = "user_roles"
    __table_args__ = (UniqueConstraint("user_id", "role_id", name="uq_user_role"),)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)


class RolePermission(Common):
    __tablename__ = "role_permissions"
    __table_args__ = (UniqueConstraint("role_id", "permission_id", name="uq_role_permission"),)
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    permission_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False)


class UserPermission(Common):
    """Direct user permission overrides in addition to role-derived permissions."""
    __tablename__ = "user_permissions"
    __table_args__ = (
        UniqueConstraint("user_id", "permission_id", name="uq_user_permission"),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    permission_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False)


class UserResourceScope(Common):
    """Authoritative WHERE-dimension assignment for resource authorization.

    This model deliberately replaces neither roles nor direct permissions. It is
    the independent resource-scope dimension consumed by scoped authorization
    beginning in SA2. The legacy ``UserScope`` table remains non-authoritative.
    """
    __tablename__ = "user_resource_scopes"
    __table_args__ = (
        CheckConstraint(
            """
            (scope_type = 'GLOBAL' AND network_id IS NULL AND city_id IS NULL AND location_id IS NULL AND sector_id IS NULL AND group_id IS NULL)
            OR (scope_type = 'NETWORK' AND network_id IS NOT NULL AND city_id IS NULL AND location_id IS NULL AND sector_id IS NULL AND group_id IS NULL)
            OR (scope_type = 'CITY' AND network_id IS NULL AND city_id IS NOT NULL AND location_id IS NULL AND sector_id IS NULL AND group_id IS NULL)
            OR (scope_type = 'LOCATION' AND network_id IS NULL AND city_id IS NULL AND location_id IS NOT NULL AND sector_id IS NULL AND group_id IS NULL)
            OR (scope_type = 'SECTOR' AND network_id IS NULL AND city_id IS NULL AND location_id IS NULL AND sector_id IS NOT NULL AND group_id IS NULL)
            OR (scope_type = 'GROUP' AND network_id IS NULL AND city_id IS NULL AND location_id IS NULL AND sector_id IS NULL AND group_id IS NOT NULL)
            """,
            name="ck_user_resource_scopes_target",
        ),
        Index("ix_user_resource_scopes_user_type", "user_id", "scope_type"),
        Index("ix_user_resource_scopes_network", "network_id"),
        Index("ix_user_resource_scopes_city", "city_id"),
        Index("ix_user_resource_scopes_location", "location_id"),
        Index("ix_user_resource_scopes_sector", "sector_id"),
        Index("ix_user_resource_scopes_group", "group_id"),
        Index(
            "uq_user_resource_scopes_global_user",
            "user_id",
            unique=True,
            postgresql_where=text("scope_type = 'GLOBAL'"),
        ),
        Index(
            "uq_user_resource_scopes_network_user",
            "user_id", "network_id",
            unique=True,
            postgresql_where=text("scope_type = 'NETWORK'"),
        ),
        Index(
            "uq_user_resource_scopes_city_user",
            "user_id", "city_id",
            unique=True,
            postgresql_where=text("scope_type = 'CITY'"),
        ),
        Index(
            "uq_user_resource_scopes_location_user",
            "user_id", "location_id",
            unique=True,
            postgresql_where=text("scope_type = 'LOCATION'"),
        ),
        Index(
            "uq_user_resource_scopes_sector_user",
            "user_id", "sector_id",
            unique=True,
            postgresql_where=text("scope_type = 'SECTOR'"),
        ),
        Index(
            "uq_user_resource_scopes_group_user",
            "user_id", "group_id",
            unique=True,
            postgresql_where=text("scope_type = 'GROUP'"),
        ),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    scope_type: Mapped[str] = mapped_column(String(20), nullable=False)
    network_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("networks.id", ondelete="CASCADE"), nullable=True
    )
    city_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cities.id", ondelete="CASCADE"), nullable=True
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("locations.id", ondelete="CASCADE"), nullable=True
    )
    sector_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sectors.id", ondelete="CASCADE"), nullable=True
    )
    group_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("device_groups.id", ondelete="CASCADE"), nullable=True
    )
    assigned_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class UserScope(Common):
    """Deprecated, non-authoritative legacy data.

    FTTW authorization is deliberately role/direct-permission based.  No API,
    service, or permission decision reads ``UserScope``; keeping the historic
    rows avoids an unsafe data migration while preventing callers from
    mistaking them for geographical authorization.
    """
    __tablename__ = "user_scopes"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    scope_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    access_level: Mapped[str] = mapped_column(String(50), default="READ", nullable=False)


class AuthSession(Common):
    __tablename__ = "auth_sessions"

    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_auth_sessions_token_hash"),
        Index("ix_auth_sessions_active_lookup", "user_id", "revoked_at", "expires_at"),
        Index("ix_auth_sessions_last_seen", "last_seen_at"),
        Index("ix_auth_sessions_user_activity", "last_user_activity_at"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(80), nullable=True)

    login_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    browser_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    browser_version: Mapped[str | None] = mapped_column(String(80), nullable=True)
    os_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(80), nullable=True)
    device_type: Mapped[str | None] = mapped_column(String(30), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_user_activity_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PasswordHistory(Common):
    __tablename__ = "password_history"
    __table_args__ = (
        Index("ix_password_history_user_created", "user_id", "created_at"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
