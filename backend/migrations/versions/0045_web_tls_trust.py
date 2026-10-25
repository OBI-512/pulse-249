"""TP3 per-device Web TLS trust enrollment.

Revision ID: 0045_web_tls_trust
Revises: 0044_access_template_metadata

This migration introduces durable public X.509 trust state for HTTPS device
management while preserving legacy env:// pinned-certificate references as a
compatibility fallback.
"""
from __future__ import annotations

import uuid

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0045_web_tls_trust"
down_revision = "0044_access_template_metadata"
branch_labels = None
depends_on = None

_NAMESPACE = uuid.UUID("0cbafac1-8f41-44e2-9bf8-3fe69940aa45")
_PERMISSION_CODE = "device.remote_access.web.trust"
_PERMISSION_NAME = "Device Remote Access - Web TLS Trust"
_PROFILE_TABLE = "device_remote_access_profiles"
_TRUST_TABLE = "device_web_tls_trusts"
_READY_CONSTRAINT = "ck_device_remote_access_profiles_web_ready"
_INTERNAL_TRUST_FK = "fk_device_remote_access_profiles_web_tls_trust"


def _id(key: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, key)


def _has_column(inspector, table_name: str, column_name: str) -> bool:
    return inspector.has_table(table_name) and any(
        column["name"] == column_name for column in inspector.get_columns(table_name)
    )


def _has_check(inspector, table_name: str, name: str) -> bool:
    return inspector.has_table(table_name) and any(
        item.get("name") == name for item in inspector.get_check_constraints(table_name)
    )


def _has_fk_for_column(inspector, table_name: str, column_name: str) -> bool:
    return inspector.has_table(table_name) and any(
        column_name in (item.get("constrained_columns") or [])
        for item in inspector.get_foreign_keys(table_name)
    )


def _ensure_permission_catalog() -> None:
    bind = op.get_bind()
    bind.execute(
        sa.text(
            """
            INSERT INTO permissions (id, code, name, description)
            VALUES (:id, :code, :name, :description)
            ON CONFLICT (code) DO UPDATE
            SET name = EXCLUDED.name, description = EXCLUDED.description
            """
        ),
        {
            "id": _id(f"perm:{_PERMISSION_CODE}"),
            "code": _PERMISSION_CODE,
            "name": _PERMISSION_NAME,
            "description": "Explicitly trust or replace a device-specific HTTPS server certificate.",
        },
    )
    bind.execute(
        sa.text(
            """
            INSERT INTO role_permissions (id, role_id, permission_id)
            SELECT :id, roles.id, permissions.id
            FROM roles CROSS JOIN permissions
            WHERE roles.code = 'administrator' AND permissions.code = :code
            ON CONFLICT (role_id, permission_id) DO NOTHING
            """
        ),
        {
            "id": _id(f"roleperm:administrator:{_PERMISSION_CODE}"),
            "code": _PERMISSION_CODE,
        },
    )


def _create_trust_table() -> None:
    op.create_table(
        _TRUST_TABLE,
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("management_ip_snapshot", sa.String(64), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("compatibility_profile", sa.String(32), nullable=False, server_default="MODERN"),
        sa.Column("certificate_sha256", sa.String(64), nullable=False),
        sa.Column("certificate_der", sa.LargeBinary(), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False, server_default=""),
        sa.Column("issuer", sa.Text(), nullable=False, server_default=""),
        sa.Column("serial_number", sa.String(160), nullable=False),
        sa.Column("not_valid_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_valid_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("san_dns", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("san_ip", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("status", sa.String(20), nullable=False, server_default="ACTIVE"),
        sa.Column("trusted_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("trusted_by_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("supersedes_trust_id", postgresql.UUID(as_uuid=True), sa.ForeignKey(f"{_TRUST_TABLE}.id", ondelete="SET NULL")),
        sa.Column("retired_at", sa.DateTime(timezone=True)),
        sa.Column("retired_by_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("retired_reason", sa.String(500)),
        sa.CheckConstraint("port BETWEEN 1 AND 65535", name="ck_device_web_tls_trusts_port"),
        sa.CheckConstraint(
            "compatibility_profile IN ('MODERN','LEGACY_WEAK_CERT_KEY')",
            name="ck_device_web_tls_trusts_compatibility",
        ),
        sa.CheckConstraint(
            "status IN ('ACTIVE','SUPERSEDED','REVOKED')",
            name="ck_device_web_tls_trusts_status",
        ),
    )
    op.create_index(
        "ix_device_web_tls_trusts_device_status",
        _TRUST_TABLE,
        ["device_id", "status"],
    )
    op.create_index(
        "uq_device_web_tls_trusts_active_device",
        _TRUST_TABLE,
        ["device_id"],
        unique=True,
        postgresql_where=sa.text("status = 'ACTIVE'"),
    )


def _create_new_ready_constraint() -> None:
    op.create_check_constraint(
        _READY_CONSTRAINT,
        _PROFILE_TABLE,
        "(web_enabled = false) OR "
        "(web_scheme = 'HTTP') OR "
        "(web_scheme = 'HTTPS' AND ("
        "web_tls_mode = 'SYSTEM' OR "
        "(web_tls_mode = 'PRIVATE_CA' AND web_tls_ca_reference IS NOT NULL) OR "
        "(web_tls_mode = 'PINNED_CERT' AND (web_tls_trust_id IS NOT NULL OR web_tls_pinned_certificate_reference IS NOT NULL))"
        "))",
    )


def _create_old_ready_constraint() -> None:
    op.create_check_constraint(
        _READY_CONSTRAINT,
        _PROFILE_TABLE,
        "(web_enabled = false) OR "
        "(web_scheme = 'HTTP') OR "
        "(web_scheme = 'HTTPS' AND ("
        "web_tls_mode = 'SYSTEM' OR "
        "(web_tls_mode = 'PRIVATE_CA' AND web_tls_ca_reference IS NOT NULL) OR "
        "(web_tls_mode = 'PINNED_CERT' AND web_tls_pinned_certificate_reference IS NOT NULL)"
        "))",
    )


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table(_TRUST_TABLE):
        _create_trust_table()

    inspector = sa.inspect(bind)
    added_profile_column = False
    if not _has_column(inspector, _PROFILE_TABLE, "web_tls_trust_id"):
        op.add_column(
            _PROFILE_TABLE,
            sa.Column("web_tls_trust_id", postgresql.UUID(as_uuid=True), nullable=True),
        )
        added_profile_column = True

    inspector = sa.inspect(bind)
    if not _has_fk_for_column(inspector, _PROFILE_TABLE, "web_tls_trust_id"):
        op.create_foreign_key(
            _INTERNAL_TRUST_FK,
            _PROFILE_TABLE,
            _TRUST_TABLE,
            ["web_tls_trust_id"],
            ["id"],
            ondelete="SET NULL",
        )

    # On an incremental 0044 -> 0045 upgrade the existing readiness constraint
    # still requires the legacy env:// reference. Fresh installs already create
    # the current ORM constraint in migration 0001 and must not be rewritten.
    if added_profile_column:
        inspector = sa.inspect(bind)
        if _has_check(inspector, _PROFILE_TABLE, _READY_CONSTRAINT):
            op.drop_constraint(_READY_CONSTRAINT, _PROFILE_TABLE, type_="check")
        _create_new_ready_constraint()

    _ensure_permission_catalog()


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if _has_column(inspector, _PROFILE_TABLE, "web_tls_trust_id"):
        if _has_check(inspector, _PROFILE_TABLE, _READY_CONSTRAINT):
            op.drop_constraint(_READY_CONSTRAINT, _PROFILE_TABLE, type_="check")

        # A downgraded 0044 schema must not retain an internal-trust reference.
        inspector = sa.inspect(bind)
        for fk in inspector.get_foreign_keys(_PROFILE_TABLE):
            if "web_tls_trust_id" in (fk.get("constrained_columns") or []):
                if fk.get("name"):
                    op.drop_constraint(fk["name"], _PROFILE_TABLE, type_="foreignkey")
                break
        op.drop_column(_PROFILE_TABLE, "web_tls_trust_id")
        _create_old_ready_constraint()

    inspector = sa.inspect(bind)
    if inspector.has_table(_TRUST_TABLE):
        op.drop_table(_TRUST_TABLE)

    bind.execute(
        sa.text("DELETE FROM permissions WHERE code = :code"),
        {"code": _PERMISSION_CODE},
    )
