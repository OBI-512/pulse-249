"""Lifecycle, nested-group and discovery-flush hardening.

Revision ID: 0013_lifecycle_group_hardening
Revises: 0012_backend_closure

The replacement baseline intentionally uses ``Base.metadata.create_all()`` in
0001.  That means a *fresh* database already contains model-level objects added
by later revisions.  This migration therefore has to support both paths:

* upgrade of an existing 0012 database, where the Phase 13 DDL is absent;
* clean install from 0001, where current metadata already created the DDL.

Permission seeding remains safe and idempotent in both cases.
"""
from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op


revision = "0013_lifecycle_group_hardening"
down_revision = "0012_backend_closure"
branch_labels = None
depends_on = None

_NAMESPACE = uuid.UUID("9b3854b1-f08f-4e6d-b8a9-7200a277c0e5")
_NESTING_ENTITY = "DEVICE_GROUP_NESTING"


def _id(value: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, value)


def _inspector(bind):
    # Recreate the inspector after DDL so PostgreSQL catalog state is not read
    # from an inspector instance created before the change.
    return sa.inspect(bind)


def _has_table(bind, table_name: str) -> bool:
    return _inspector(bind).has_table(table_name)


def _index_names(bind, table_name: str) -> set[str]:
    return {
        row["name"]
        for row in _inspector(bind).get_indexes(table_name)
        if row.get("name")
    }


def _check_constraints(bind, table_name: str) -> dict[str, str]:
    return {
        row["name"]: str(row.get("sqltext") or "")
        for row in _inspector(bind).get_check_constraints(table_name)
        if row.get("name")
    }


def upgrade() -> None:
    bind = op.get_bind()

    # Existing 0012 databases need the table.  Fresh databases do not: 0001
    # already creates the current SQLAlchemy metadata, including this table.
    if not _has_table(bind, "device_group_nestings"):
        op.create_table(
            "device_group_nestings",
            sa.Column("parent_group_id", sa.UUID(), nullable=False),
            sa.Column("child_group_id", sa.UUID(), nullable=False),
            sa.Column("id", sa.UUID(), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("deletion_batch_id", sa.UUID(), nullable=True),
            sa.CheckConstraint(
                "parent_group_id <> child_group_id",
                name="ck_device_group_nestings_not_self",
            ),
            sa.ForeignKeyConstraint(
                ["parent_group_id"], ["device_groups.id"], ondelete="CASCADE"
            ),
            sa.ForeignKeyConstraint(
                ["child_group_id"], ["device_groups.id"], ondelete="CASCADE"
            ),
            sa.ForeignKeyConstraint(
                ["deletion_batch_id"],
                ["recycle_bin_batches.id"],
                ondelete="RESTRICT",
            ),
            sa.PrimaryKeyConstraint("id"),
        )

    # Indexes are independently guarded because a partially applied/hand-built
    # schema should converge safely instead of failing with DuplicateObject.
    indexes = _index_names(bind, "device_group_nestings")
    if "ix_device_group_nestings_parent" not in indexes:
        op.create_index(
            "ix_device_group_nestings_parent",
            "device_group_nestings",
            ["parent_group_id"],
        )
    if "uq_active_device_group_nestings_child" not in indexes:
        op.create_index(
            "uq_active_device_group_nestings_child",
            "device_group_nestings",
            ["child_group_id"],
            unique=True,
            postgresql_where=sa.text("deleted_at IS NULL"),
        )
    if "uq_active_device_group_nestings_pair" not in indexes:
        op.create_index(
            "uq_active_device_group_nestings_pair",
            "device_group_nestings",
            ["parent_group_id", "child_group_id"],
            unique=True,
            postgresql_where=sa.text("deleted_at IS NULL"),
        )

    group_checks = _check_constraints(bind, "device_groups")
    if "ck_device_groups_sector_role_requires_sector_scope" not in group_checks:
        op.create_check_constraint(
            "ck_device_groups_sector_role_requires_sector_scope",
            "device_groups",
            "sector_role IS NULL OR device_scope = 'SECTOR'",
        )

    # On an existing 0012 database the recycle-bin check must be widened.  On
    # a fresh database current metadata already contains DEVICE_GROUP_NESTING.
    recycle_checks = _check_constraints(bind, "recycle_bin_items")
    recycle_sql = recycle_checks.get("ck_recycle_bin_items_entity_type", "")
    if _NESTING_ENTITY not in recycle_sql:
        if "ck_recycle_bin_items_entity_type" in recycle_checks:
            op.drop_constraint(
                "ck_recycle_bin_items_entity_type",
                "recycle_bin_items",
                type_="check",
            )
        op.create_check_constraint(
            "ck_recycle_bin_items_entity_type",
            "recycle_bin_items",
            "entity_type IN ("
            "'NETWORK','CITY','LOCATION','SECTOR','DEVICE','CUSTOMER',"
            "'CUSTOMER_SERVICE','DEVICE_GROUP','DEVICE_RELATIONSHIP',"
            "'DEVICE_IP','DEVICE_INTERFACE','DEVICE_PLACEMENT',"
            "'DEVICE_HIERARCHY_LINK','DEVICE_GROUP_MEMBERSHIP',"
            "'DEVICE_GROUP_NESTING')",
        )

    code = "discovery.flush"
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
            "id": _id("perm:" + code),
            "code": code,
            "name": "Discovery Flush",
            "description": "Flush unregistered discovery working data",
        },
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
        {"id": _id("roleperm:administrator:" + code), "code": code},
    )


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text("DELETE FROM permissions WHERE code='discovery.flush'"))

    recycle_checks = _check_constraints(bind, "recycle_bin_items")
    if "ck_recycle_bin_items_entity_type" in recycle_checks:
        op.drop_constraint(
            "ck_recycle_bin_items_entity_type",
            "recycle_bin_items",
            type_="check",
        )
    op.create_check_constraint(
        "ck_recycle_bin_items_entity_type",
        "recycle_bin_items",
        "entity_type IN ("
        "'NETWORK','CITY','LOCATION','SECTOR','DEVICE','CUSTOMER',"
        "'CUSTOMER_SERVICE','DEVICE_GROUP','DEVICE_RELATIONSHIP',"
        "'DEVICE_IP','DEVICE_INTERFACE','DEVICE_PLACEMENT',"
        "'DEVICE_HIERARCHY_LINK','DEVICE_GROUP_MEMBERSHIP')",
    )

    group_checks = _check_constraints(bind, "device_groups")
    if "ck_device_groups_sector_role_requires_sector_scope" in group_checks:
        op.drop_constraint(
            "ck_device_groups_sector_role_requires_sector_scope",
            "device_groups",
            type_="check",
        )

    if _has_table(bind, "device_group_nestings"):
        indexes = _index_names(bind, "device_group_nestings")
        if "uq_active_device_group_nestings_pair" in indexes:
            op.drop_index(
                "uq_active_device_group_nestings_pair",
                table_name="device_group_nestings",
            )
        if "uq_active_device_group_nestings_child" in indexes:
            op.drop_index(
                "uq_active_device_group_nestings_child",
                table_name="device_group_nestings",
            )
        if "ix_device_group_nestings_parent" in indexes:
            op.drop_index(
                "ix_device_group_nestings_parent",
                table_name="device_group_nestings",
            )
        op.drop_table("device_group_nestings")
