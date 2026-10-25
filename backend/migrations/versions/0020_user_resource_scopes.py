"""Add authoritative user resource scopes for scoped authorization.

Revision ID: 0020_user_resource_scopes
Revises: 0019_restricted_role

SA1 establishes only the data model and permission vocabulary. Runtime WHERE
scope enforcement begins in SA2. Existing users are backfilled GLOBAL so this
migration preserves current access semantics while the enforcement engine is
not yet active.

The replacement baseline creates current SQLAlchemy metadata in migration 0001,
so this migration deliberately supports both an existing 0019 database and a
fresh database where ``user_resource_scopes`` already exists.
"""
from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op

revision = "0020_user_resource_scopes"
down_revision = "0019_restricted_role"
branch_labels = None
depends_on = None

_NAMESPACE = uuid.UUID("8d3a2d89-4e70-4e36-9b1a-4d0f6e1c1f55")
_SCOPE_PERMISSIONS = (
    ("user.scopes.read", "User Scopes Read"),
    ("user.scopes.manage", "User Scopes Manage"),
)


def _id(key: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, key)


def _inspector(bind):
    return sa.inspect(bind)


def _has_table(bind, table_name: str) -> bool:
    return _inspector(bind).has_table(table_name)


def _index_names(bind, table_name: str) -> set[str]:
    return {row["name"] for row in _inspector(bind).get_indexes(table_name) if row.get("name")}


def _check_names(bind, table_name: str) -> set[str]:
    return {row["name"] for row in _inspector(bind).get_check_constraints(table_name) if row.get("name")}


def _create_table_if_missing(bind) -> None:
    if _has_table(bind, "user_resource_scopes"):
        return
    op.create_table(
        "user_resource_scopes",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("scope_type", sa.String(length=20), nullable=False),
        sa.Column("network_id", sa.UUID(), nullable=True),
        sa.Column("city_id", sa.UUID(), nullable=True),
        sa.Column("location_id", sa.UUID(), nullable=True),
        sa.Column("sector_id", sa.UUID(), nullable=True),
        sa.Column("group_id", sa.UUID(), nullable=True),
        sa.Column("assigned_by_user_id", sa.UUID(), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "(scope_type = 'GLOBAL' AND network_id IS NULL AND city_id IS NULL AND location_id IS NULL AND sector_id IS NULL AND group_id IS NULL) OR "
            "(scope_type = 'NETWORK' AND network_id IS NOT NULL AND city_id IS NULL AND location_id IS NULL AND sector_id IS NULL AND group_id IS NULL) OR "
            "(scope_type = 'CITY' AND network_id IS NULL AND city_id IS NOT NULL AND location_id IS NULL AND sector_id IS NULL AND group_id IS NULL) OR "
            "(scope_type = 'LOCATION' AND network_id IS NULL AND city_id IS NULL AND location_id IS NOT NULL AND sector_id IS NULL AND group_id IS NULL) OR "
            "(scope_type = 'SECTOR' AND network_id IS NULL AND city_id IS NULL AND location_id IS NULL AND sector_id IS NOT NULL AND group_id IS NULL) OR "
            "(scope_type = 'GROUP' AND network_id IS NULL AND city_id IS NULL AND location_id IS NULL AND sector_id IS NULL AND group_id IS NOT NULL)",
            name="ck_user_resource_scopes_target",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["network_id"], ["networks.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["city_id"], ["cities.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["location_id"], ["locations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["sector_id"], ["sectors.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["group_id"], ["device_groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["assigned_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )


def _ensure_indexes(bind) -> None:
    existing = _index_names(bind, "user_resource_scopes")
    definitions = (
        ("ix_user_resource_scopes_user_type", ["user_id", "scope_type"], False, None),
        ("ix_user_resource_scopes_network", ["network_id"], False, None),
        ("ix_user_resource_scopes_city", ["city_id"], False, None),
        ("ix_user_resource_scopes_location", ["location_id"], False, None),
        ("ix_user_resource_scopes_sector", ["sector_id"], False, None),
        ("ix_user_resource_scopes_group", ["group_id"], False, None),
        ("uq_user_resource_scopes_global_user", ["user_id"], True, sa.text("scope_type = 'GLOBAL'")),
        ("uq_user_resource_scopes_network_user", ["user_id", "network_id"], True, sa.text("scope_type = 'NETWORK'")),
        ("uq_user_resource_scopes_city_user", ["user_id", "city_id"], True, sa.text("scope_type = 'CITY'")),
        ("uq_user_resource_scopes_location_user", ["user_id", "location_id"], True, sa.text("scope_type = 'LOCATION'")),
        ("uq_user_resource_scopes_sector_user", ["user_id", "sector_id"], True, sa.text("scope_type = 'SECTOR'")),
        ("uq_user_resource_scopes_group_user", ["user_id", "group_id"], True, sa.text("scope_type = 'GROUP'")),
    )
    for name, columns, unique, where in definitions:
        if name in existing:
            continue
        kwargs = {"unique": unique}
        if where is not None:
            kwargs["postgresql_where"] = where
        op.create_index(name, "user_resource_scopes", columns, **kwargs)


def _ensure_target_check(bind) -> None:
    checks = _check_names(bind, "user_resource_scopes")
    if "ck_user_resource_scopes_target" in checks:
        return
    op.create_check_constraint(
        "ck_user_resource_scopes_target",
        "user_resource_scopes",
        "(scope_type = 'GLOBAL' AND network_id IS NULL AND city_id IS NULL AND location_id IS NULL AND sector_id IS NULL AND group_id IS NULL) OR "
        "(scope_type = 'NETWORK' AND network_id IS NOT NULL AND city_id IS NULL AND location_id IS NULL AND sector_id IS NULL AND group_id IS NULL) OR "
        "(scope_type = 'CITY' AND network_id IS NULL AND city_id IS NOT NULL AND location_id IS NULL AND sector_id IS NULL AND group_id IS NULL) OR "
        "(scope_type = 'LOCATION' AND network_id IS NULL AND city_id IS NULL AND location_id IS NOT NULL AND sector_id IS NULL AND group_id IS NULL) OR "
        "(scope_type = 'SECTOR' AND network_id IS NULL AND city_id IS NULL AND location_id IS NULL AND sector_id IS NOT NULL AND group_id IS NULL) OR "
        "(scope_type = 'GROUP' AND network_id IS NULL AND city_id IS NULL AND location_id IS NULL AND sector_id IS NULL AND group_id IS NOT NULL)",
    )


def _seed_permissions(bind) -> None:
    for code, name in _SCOPE_PERMISSIONS:
        bind.execute(
            sa.text(
                """
                INSERT INTO permissions (id, code, name, description)
                VALUES (:id, :code, :name, :description)
                ON CONFLICT (code) DO UPDATE
                SET name = EXCLUDED.name, description = EXCLUDED.description
                """
            ),
            {"id": _id(f"perm:{code}"), "code": code, "name": name, "description": f"{name} permission"},
        )
        bind.execute(
            sa.text(
                """
                INSERT INTO role_permissions (id, role_id, permission_id)
                SELECT :id, r.id, p.id
                FROM roles r CROSS JOIN permissions p
                WHERE r.code = 'administrator' AND p.code = :code
                ON CONFLICT (role_id, permission_id) DO NOTHING
                """
            ),
            {"id": _id(f"roleperm:administrator:{code}"), "code": code},
        )


def _backfill_existing_users_global(bind) -> None:
    user_ids = list(bind.execute(sa.text("SELECT id FROM users")).scalars())
    for user_id in user_ids:
        bind.execute(
            sa.text(
                """
                INSERT INTO user_resource_scopes
                    (id, user_id, scope_type, assigned_by_user_id)
                VALUES (:id, :user_id, 'GLOBAL', NULL)
                ON CONFLICT DO NOTHING
                """
            ),
            {"id": _id(f"user-resource-scope:global:{user_id}"), "user_id": user_id},
        )


def upgrade() -> None:
    bind = op.get_bind()
    _create_table_if_missing(bind)
    _ensure_target_check(bind)
    _ensure_indexes(bind)
    _seed_permissions(bind)
    _backfill_existing_users_global(bind)


def downgrade() -> None:
    bind = op.get_bind()

    # Downgrading removes WHERE authorization state. Refuse if any user is not
    # represented by exactly one GLOBAL row or if any non-GLOBAL assignment
    # exists, because old code would otherwise silently broaden access and/or
    # destroy meaningful scope assignments.
    unsafe_users = int(bind.scalar(sa.text(
        """
        SELECT COUNT(*)
        FROM users u
        WHERE (SELECT COUNT(*) FROM user_resource_scopes s
               WHERE s.user_id = u.id AND s.scope_type = 'GLOBAL') <> 1
           OR EXISTS (SELECT 1 FROM user_resource_scopes s
                      WHERE s.user_id = u.id AND s.scope_type <> 'GLOBAL')
        """
    )) or 0)
    if unsafe_users:
        raise RuntimeError(
            "Refusing downgrade: one or more users are restricted/scoped; "
            "downgrade would silently broaden access or discard scope state."
        )

    # Preserve any scope permission grants that were added after SA1. The only
    # expected grants at this revision are the migration-created Administrator
    # role grants.
    custom_grants = int(bind.scalar(sa.text(
        """
        SELECT COUNT(*)
        FROM permissions p
        WHERE p.code IN ('user.scopes.read','user.scopes.manage')
          AND (
            EXISTS (SELECT 1 FROM user_permissions up WHERE up.permission_id = p.id)
            OR EXISTS (
                SELECT 1 FROM role_permissions rp
                JOIN roles r ON r.id = rp.role_id
                WHERE rp.permission_id = p.id AND r.code <> 'administrator'
            )
          )
        """
    )) or 0)
    if custom_grants:
        raise RuntimeError(
            "Refusing downgrade: scoped-access permissions have custom grants."
        )

    bind.execute(sa.text(
        """
        DELETE FROM role_permissions rp
        USING roles r, permissions p
        WHERE rp.role_id = r.id AND rp.permission_id = p.id
          AND r.code = 'administrator'
          AND p.code IN ('user.scopes.read','user.scopes.manage')
        """
    ))
    bind.execute(sa.text(
        "DELETE FROM permissions WHERE code IN ('user.scopes.read','user.scopes.manage')"
    ))
    if _has_table(bind, "user_resource_scopes"):
        op.drop_table("user_resource_scopes")
