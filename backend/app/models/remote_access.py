from __future__ import annotations

from datetime import datetime
from typing import Any
import uuid

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, LargeBinary, String, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .core import Common


class DeviceWebTLSTrust(Common):
    """Explicit per-device public X.509 identity trust for HTTPS management."""

    __tablename__ = "device_web_tls_trusts"
    __table_args__ = (
        CheckConstraint("port BETWEEN 1 AND 65535", name="ck_device_web_tls_trusts_port"),
        CheckConstraint(
            "compatibility_profile IN ('MODERN','LEGACY_WEAK_CERT_KEY')",
            name="ck_device_web_tls_trusts_compatibility",
        ),
        CheckConstraint(
            "status IN ('ACTIVE','SUPERSEDED','REVOKED')",
            name="ck_device_web_tls_trusts_status",
        ),
        Index("ix_device_web_tls_trusts_device_status", "device_id", "status"),
        Index(
            "uq_device_web_tls_trusts_active_device",
            "device_id",
            unique=True,
            postgresql_where=text("status = 'ACTIVE'"),
        ),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    management_ip_snapshot: Mapped[str] = mapped_column(String(64), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    compatibility_profile: Mapped[str] = mapped_column(String(32), nullable=False, default="MODERN", server_default="MODERN")
    certificate_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    certificate_der: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    subject: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    issuer: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    serial_number: Mapped[str] = mapped_column(String(160), nullable=False)
    not_valid_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_valid_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    san_dns: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list, server_default="[]")
    san_ip: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list, server_default="[]")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="ACTIVE", server_default="ACTIVE")
    trusted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    trusted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    supersedes_trust_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("device_web_tls_trusts.id", ondelete="SET NULL")
    )
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retired_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    retired_reason: Mapped[str | None] = mapped_column(String(500))


class DeviceRemoteAccessProfile(Common):
    """Non-secret per-device settings for brokered management access.

    Secret values never live in PostgreSQL. Credential fields store env://
    references resolved only inside the dedicated access-gateway service.
    Reusable SSH/WEB Access Templates may supply credentials instead, while
    this per-device profile remains the authoritative transport/trust control.
    Public WEB certificate trust may be linked through web_tls_trust_id.
    """

    __tablename__ = "device_remote_access_profiles"
    __table_args__ = (
        UniqueConstraint("device_id", name="uq_device_remote_access_profiles_device"),
        CheckConstraint("ssh_port BETWEEN 1 AND 65535", name="ck_device_remote_access_profiles_ssh_port"),
        CheckConstraint(
            "(ssh_enabled = false) OR ssh_host_key_fingerprint IS NOT NULL",
            name="ck_device_remote_access_profiles_ssh_ready",
        ),
        CheckConstraint(
            "ssh_compatibility_profile IN ('MODERN','LEGACY_SSH_RSA_DH1_CBC')",
            name="ck_device_remote_access_profiles_ssh_compatibility",
        ),
        CheckConstraint("web_port BETWEEN 1 AND 65535", name="ck_device_remote_access_profiles_web_port"),
        CheckConstraint("web_scheme IN ('HTTP','HTTPS')", name="ck_device_remote_access_profiles_web_scheme"),
        CheckConstraint(
            "web_tls_mode IN ('SYSTEM','PRIVATE_CA','PINNED_CERT')",
            name="ck_device_remote_access_profiles_web_tls_mode",
        ),
        CheckConstraint(
            "web_tls_compat_profile IN ('MODERN','LEGACY_WEAK_CERT_KEY')",
            name="ck_device_remote_access_profiles_web_tls_compat_profile",
        ),
        CheckConstraint(
            "web_tls_compat_profile = 'MODERN' OR "
            "(web_scheme = 'HTTPS' AND web_tls_mode = 'PINNED_CERT')",
            name="ck_device_remote_access_profiles_web_tls_legacy_pin",
        ),
        CheckConstraint(
            "(web_enabled = false) OR "
            "(web_scheme = 'HTTP') OR "
            "(web_scheme = 'HTTPS' AND ("
            "web_tls_mode = 'SYSTEM' OR "
            "(web_tls_mode = 'PRIVATE_CA' AND web_tls_ca_reference IS NOT NULL) OR "
            "(web_tls_mode = 'PINNED_CERT' AND (web_tls_trust_id IS NOT NULL OR web_tls_pinned_certificate_reference IS NOT NULL))"
            "))",
            name="ck_device_remote_access_profiles_web_ready",
        ),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    ssh_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    ssh_port: Mapped[int] = mapped_column(Integer, nullable=False, default=22, server_default="22")
    ssh_compatibility_profile: Mapped[str] = mapped_column(
        String(40), nullable=False, default="MODERN", server_default="MODERN"
    )
    ssh_username_reference: Mapped[str | None] = mapped_column(String(255))
    ssh_password_reference: Mapped[str | None] = mapped_column(String(255))
    ssh_private_key_reference: Mapped[str | None] = mapped_column(String(255))
    ssh_host_key_fingerprint: Mapped[str | None] = mapped_column(String(160))
    web_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    web_scheme: Mapped[str] = mapped_column(String(8), nullable=False, default="HTTPS", server_default="HTTPS")
    web_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    web_tls_mode: Mapped[str] = mapped_column(String(20), nullable=False, default="SYSTEM", server_default="SYSTEM")
    web_tls_compat_profile: Mapped[str] = mapped_column(String(32), nullable=False, default="MODERN", server_default="MODERN")
    web_tls_ca_reference: Mapped[str | None] = mapped_column(String(255))
    web_tls_pinned_certificate_reference: Mapped[str | None] = mapped_column(String(255))
    web_tls_trust_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("device_web_tls_trusts.id", ondelete="SET NULL"), nullable=True
    )
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict, server_default="{}"
    )


class RemoteAccessSession(Common):
    """Short-lived authorization/session record for brokered device access."""

    __tablename__ = "remote_access_sessions"
    __table_args__ = (
        UniqueConstraint("ticket_hash", name="uq_remote_access_sessions_ticket_hash"),
        CheckConstraint("mode IN ('SSH','TELNET','WEB')", name="ck_remote_access_sessions_mode"),
        CheckConstraint(
            "status IN ('ISSUED','ACTIVE','CLOSED','REVOKED','FAILED')",
            name="ck_remote_access_sessions_status",
        ),
        Index("ix_remote_access_sessions_actor_status", "actor_user_id", "status"),
        Index("ix_remote_access_sessions_device_status", "device_id", "status"),
        Index("ix_remote_access_sessions_expiry", "expires_at"),
        Index("ix_remote_access_sessions_access_template", "access_template_id"),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    auth_session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("auth_sessions.id", ondelete="SET NULL")
    )
    access_template_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("access_templates.id", ondelete="SET NULL"), nullable=True
    )
    mode: Mapped[str] = mapped_column(String(10), nullable=False, default="SSH", server_default="SSH")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="ISSUED", server_default="ISSUED")
    ticket_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_activity_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[str | None] = mapped_column(String(80))
    source_ip: Mapped[str | None] = mapped_column(String(64))
    gateway_instance: Mapped[str | None] = mapped_column(String(120))
    error_message: Mapped[str | None] = mapped_column(Text)
