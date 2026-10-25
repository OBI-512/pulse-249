"""Add recoverable business-row tombstones and recycle-bin ledger.

Revision ID: 0004_recycle_bin
Revises: 0003_movement_rbac

The legacy 0001 migration dynamically imports current metadata.  Every DDL
operation here is therefore explicit but idempotent so both the already-
migrated live database and a temporary fresh database can traverse the same
immutable chain safely.
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "0004_recycle_bin"
down_revision = "0003_movement_rbac"
branch_labels = None
depends_on = None


_NAMESPACE = uuid.UUID("8d3a2d89-4e70-4e36-9b1a-4d0f6e1c1f55")
_RECOVERABLE_TABLES = (
    "networks",
    "cities",
    "locations",
    "devices",
    "sectors",
    "customers",
    "customer_services",
    "device_ips",
    "device_placements",
    "device_hierarchy_links",
    "device_interfaces",
    "device_relationships",
    "device_groups",
    "device_group_memberships",
)
_PERMISSIONS = (
    ("recycle_bin.read", "Recycle Bin Read"),
    ("recycle_bin.restore", "Recycle Bin Restore"),
    ("recycle_bin.purge", "Recycle Bin Purge"),
    ("network.delete", "Network Delete"),
    ("geo.delete", "Geography Delete"),
    ("customer.delete", "Customer Delete"),
)


def _deterministic_id(key: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, key)


def _create_ledger_tables() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("recycle_bin_batches"):
        op.create_table(
            "recycle_bin_batches",
            sa.Column("root_entity_type", sa.String(length=80), nullable=False),
            sa.Column("root_entity_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column(
                "root_display_snapshot",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'{}'::jsonb"),
                nullable=False,
            ),
            sa.Column("status", sa.String(length=30), server_default="RECYCLED", nullable=False),
            sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column(
                "deleted_by_user_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("users.id", ondelete="RESTRICT"),
                nullable=True,
            ),
            sa.Column("deletion_reason", sa.Text(), nullable=True),
            sa.Column("purge_after", sa.DateTime(timezone=True), nullable=False),
            sa.Column("restored_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "restored_by_user_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("users.id", ondelete="RESTRICT"),
                nullable=True,
            ),
            sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_error_code", sa.String(length=120), nullable=True),
            sa.Column("last_error_message", sa.Text(), nullable=True),
            sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.CheckConstraint(
                "status IN ('RECYCLED','RESTORED','PURGE_FAILED')",
                name="ck_recycle_bin_batches_status",
            ),
            sa.CheckConstraint(
                "root_entity_type IN ('NETWORK','CITY','LOCATION','SECTOR','DEVICE','CUSTOMER','CUSTOMER_SERVICE','DEVICE_GROUP','DEVICE_RELATIONSHIP','DEVICE_IP','DEVICE_INTERFACE')",
                name="ck_recycle_bin_batches_root_type",
            ),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_recycle_bin_batches_status", "recycle_bin_batches", ["status"])
        op.create_index(
            "ix_recycle_bin_batches_due_purge",
            "recycle_bin_batches",
            ["purge_after"],
            postgresql_where=sa.text("status IN ('RECYCLED','PURGE_FAILED')"),
        )
        op.create_index(
            "uq_recycle_bin_batches_open_root",
            "recycle_bin_batches",
            ["root_entity_type", "root_entity_id"],
            unique=True,
            postgresql_where=sa.text("status IN ('RECYCLED','PURGE_FAILED')"),
        )

    inspector = sa.inspect(bind)
    if not inspector.has_table("recycle_bin_items"):
        op.create_table(
            "recycle_bin_items",
            sa.Column(
                "batch_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("recycle_bin_batches.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("entity_type", sa.String(length=80), nullable=False),
            sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("item_role", sa.String(length=20), nullable=False),
            sa.Column(
                "display_snapshot",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'{}'::jsonb"),
                nullable=False,
            ),
            sa.Column("restore_order", sa.Integer(), nullable=False),
            sa.Column("purge_order", sa.Integer(), nullable=False),
            sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.CheckConstraint("item_role IN ('ROOT','BUNDLE')", name="ck_recycle_bin_items_role"),
            sa.CheckConstraint(
                "entity_type IN ('NETWORK','CITY','LOCATION','SECTOR','DEVICE','CUSTOMER','CUSTOMER_SERVICE','DEVICE_GROUP','DEVICE_RELATIONSHIP','DEVICE_IP','DEVICE_INTERFACE','DEVICE_PLACEMENT','DEVICE_HIERARCHY_LINK','DEVICE_GROUP_MEMBERSHIP')",
                name="ck_recycle_bin_items_entity_type",
            ),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "batch_id",
                "entity_type",
                "entity_id",
                name="uq_recycle_bin_item_entity",
            ),
        )
        op.create_index("ix_recycle_bin_items_batch_id", "recycle_bin_items", ["batch_id"])
        op.create_index(
            "ix_recycle_bin_items_entity",
            "recycle_bin_items",
            ["entity_type", "entity_id"],
        )


def _add_tombstones() -> None:
    for table_name in _RECOVERABLE_TABLES:
        op.execute(
            sa.text(
                f'ALTER TABLE "{table_name}" ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL'
            )
        )
        op.execute(
            sa.text(
                f'ALTER TABLE "{table_name}" ADD COLUMN IF NOT EXISTS deletion_batch_id UUID NULL'
            )
        )
        op.execute(
            sa.text(
                f"""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1
                        FROM pg_constraint
                        WHERE conrelid = '{table_name}'::regclass
                          AND contype = 'f'
                          AND conkey = ARRAY[
                              (SELECT attnum FROM pg_attribute
                               WHERE attrelid = '{table_name}'::regclass
                                 AND attname = 'deletion_batch_id')
                          ]::smallint[]
                    ) THEN
                        ALTER TABLE "{table_name}"
                        ADD CONSTRAINT "fk_{table_name}_deletion_batch"
                        FOREIGN KEY (deletion_batch_id)
                        REFERENCES recycle_bin_batches(id)
                        ON DELETE RESTRICT;
                    END IF;
                END $$;
                """
            )
        )


def _replace_active_uniqueness() -> None:
    old_constraints = (
        ("networks", "networks_code_key"),
        ("cities", "uq_cities_network_code"),
        ("locations", "uq_locations_city_code"),
        ("sectors", "uq_sectors_location_code"),
        ("customers", "customers_customer_code_key"),
        ("customer_services", "uq_customer_services_customer"),
        ("customer_services", "customer_services_service_code_key"),
        ("customer_services", "customer_services_cpe_device_id_key"),
        ("customer_services", "customer_services_access_point_device_id_key"),
        ("device_ips", "uq_device_ips_address"),
        ("device_hierarchy_links", "uq_device_hierarchy_child"),
        ("device_groups", "device_groups_name_key"),
        ("device_groups", "device_groups_code_key"),
        ("device_relationships", "uq_device_relationship"),
    )
    for table_name, constraint_name in old_constraints:
        op.execute(
            sa.text(
                f'ALTER TABLE "{table_name}" DROP CONSTRAINT IF EXISTS "{constraint_name}"'
            )
        )

    statements = (
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_active_networks_code ON networks (code) WHERE deleted_at IS NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_active_cities_network_code ON cities (network_id, code) WHERE deleted_at IS NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_active_locations_city_code ON locations (city_id, code) WHERE deleted_at IS NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_active_sectors_location_code ON sectors (location_id, code) WHERE deleted_at IS NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_active_customers_code ON customers (customer_code) WHERE deleted_at IS NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_active_customer_services_customer ON customer_services (customer_id) WHERE deleted_at IS NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_active_customer_services_code ON customer_services (service_code) WHERE deleted_at IS NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_active_customer_services_cpe ON customer_services (cpe_device_id) WHERE deleted_at IS NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_active_customer_services_ap ON customer_services (access_point_device_id) WHERE deleted_at IS NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_active_device_ips_address ON device_ips (ip_address) WHERE deleted_at IS NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_active_device_hierarchy_child ON device_hierarchy_links (child_device_id) WHERE deleted_at IS NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_active_device_groups_name ON device_groups (name) WHERE deleted_at IS NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_active_device_groups_code ON device_groups (code) WHERE deleted_at IS NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_active_device_relationship ON device_relationships (source_device_id, target_device_id, relationship_type) WHERE deleted_at IS NULL",
    )
    for statement in statements:
        op.execute(sa.text(statement))

    # The Phase 1 AP limit remains authoritative, but only active links occupy
    # the slot while a recycled AP waits for restore or purge.
    op.execute(sa.text("DROP INDEX IF EXISTS uq_device_hierarchy_cpe_access_point_parent"))
    op.execute(
        sa.text(
            """
            CREATE UNIQUE INDEX uq_device_hierarchy_cpe_access_point_parent
            ON device_hierarchy_links (parent_device_id)
            WHERE relationship_type = 'CPE_ACCESS_POINT'
              AND deleted_at IS NULL
            """
        )
    )


def _seed_permissions() -> None:
    bind = op.get_bind()
    for code, name in _PERMISSIONS:
        bind.execute(
            sa.text(
                """
                INSERT INTO permissions (id, code, name, description)
                VALUES (:id, :code, :name, :description)
                ON CONFLICT (code) DO NOTHING
                """
            ),
            {
                "id": _deterministic_id(f"perm:{code}"),
                "code": code,
                "name": name,
                "description": f"{name} permission",
            },
        )
        bind.execute(
            sa.text(
                """
                INSERT INTO role_permissions (id, role_id, permission_id)
                SELECT :id, roles.id, permissions.id
                FROM roles
                CROSS JOIN permissions
                WHERE roles.code = 'administrator'
                  AND permissions.code = :code
                ON CONFLICT (role_id, permission_id) DO NOTHING
                """
            ),
            {
                "id": _deterministic_id(f"roleperm:administrator:{code}"),
                "code": code,
            },
        )


def upgrade() -> None:
    _create_ledger_tables()
    _add_tombstones()
    _replace_active_uniqueness()
    _seed_permissions()


def downgrade() -> None:
    # Restorable rows must be resolved before the schema that makes them
    # visible/invisible can safely be removed.
    for table_name in _RECOVERABLE_TABLES:
        op.execute(
            sa.text(
                f"""
                DO $$
                BEGIN
                    IF EXISTS (SELECT 1 FROM "{table_name}" WHERE deleted_at IS NOT NULL) THEN
                        RAISE EXCEPTION 'Cannot downgrade recycle schema while {table_name} contains recycled rows';
                    END IF;
                END $$;
                """
            )
        )

    bind = op.get_bind()
    bind.execute(
        sa.text("DELETE FROM permissions WHERE code IN :codes").bindparams(
            sa.bindparam("codes", expanding=True, value=[code for code, _ in _PERMISSIONS])
        )
    )

    op.execute(sa.text("DROP INDEX IF EXISTS uq_device_hierarchy_cpe_access_point_parent"))
    for index_name in (
        "uq_active_networks_code",
        "uq_active_cities_network_code",
        "uq_active_locations_city_code",
        "uq_active_sectors_location_code",
        "uq_active_customers_code",
        "uq_active_customer_services_customer",
        "uq_active_customer_services_code",
        "uq_active_customer_services_cpe",
        "uq_active_customer_services_ap",
        "uq_active_device_ips_address",
        "uq_active_device_hierarchy_child",
        "uq_active_device_groups_name",
        "uq_active_device_groups_code",
        "uq_active_device_relationship",
    ):
        op.execute(sa.text(f'DROP INDEX IF EXISTS "{index_name}"'))

    for table_name in reversed(_RECOVERABLE_TABLES):
        op.execute(
            sa.text(
                f'ALTER TABLE "{table_name}" DROP CONSTRAINT IF EXISTS "fk_{table_name}_deletion_batch"'
            )
        )
        op.execute(sa.text(f'ALTER TABLE "{table_name}" DROP COLUMN IF EXISTS deletion_batch_id'))
        op.execute(sa.text(f'ALTER TABLE "{table_name}" DROP COLUMN IF EXISTS deleted_at'))

    op.execute(sa.text("ALTER TABLE networks ADD CONSTRAINT networks_code_key UNIQUE (code)"))
    op.execute(sa.text("ALTER TABLE cities ADD CONSTRAINT uq_cities_network_code UNIQUE (network_id, code)"))
    op.execute(sa.text("ALTER TABLE locations ADD CONSTRAINT uq_locations_city_code UNIQUE (city_id, code)"))
    op.execute(sa.text("ALTER TABLE sectors ADD CONSTRAINT uq_sectors_location_code UNIQUE (location_id, code)"))
    op.execute(sa.text("ALTER TABLE customers ADD CONSTRAINT customers_customer_code_key UNIQUE (customer_code)"))
    op.execute(sa.text("ALTER TABLE customer_services ADD CONSTRAINT uq_customer_services_customer UNIQUE (customer_id)"))
    op.execute(sa.text("ALTER TABLE customer_services ADD CONSTRAINT customer_services_service_code_key UNIQUE (service_code)"))
    op.execute(sa.text("ALTER TABLE customer_services ADD CONSTRAINT customer_services_cpe_device_id_key UNIQUE (cpe_device_id)"))
    op.execute(sa.text("ALTER TABLE customer_services ADD CONSTRAINT customer_services_access_point_device_id_key UNIQUE (access_point_device_id)"))
    op.execute(sa.text("ALTER TABLE device_ips ADD CONSTRAINT uq_device_ips_address UNIQUE (ip_address)"))
    op.execute(sa.text("ALTER TABLE device_hierarchy_links ADD CONSTRAINT uq_device_hierarchy_child UNIQUE (child_device_id)"))
    op.execute(sa.text("ALTER TABLE device_groups ADD CONSTRAINT device_groups_name_key UNIQUE (name)"))
    op.execute(sa.text("ALTER TABLE device_groups ADD CONSTRAINT device_groups_code_key UNIQUE (code)"))
    op.execute(sa.text("ALTER TABLE device_relationships ADD CONSTRAINT uq_device_relationship UNIQUE (source_device_id, target_device_id, relationship_type)"))
    op.execute(
        sa.text(
            """
            CREATE UNIQUE INDEX uq_device_hierarchy_cpe_access_point_parent
            ON device_hierarchy_links (parent_device_id)
            WHERE relationship_type = 'CPE_ACCESS_POINT'
            """
        )
    )

    op.drop_table("recycle_bin_items")
    op.drop_table("recycle_bin_batches")
