"""Add VLAN documentation and allocation fields.

Revision ID: 0025_vlan_documentation
Revises: 0024_maintenance_targets

Migration 0001 builds current SQLAlchemy metadata on a fresh database, so this
migration is deliberately safe for both an upgraded 0024 database and a fresh
database where these columns/constraints/indexes may already exist.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0025_vlan_documentation"
down_revision = "0024_maintenance_targets"
branch_labels = None
depends_on = None


def _inspector(bind):
    return sa.inspect(bind)


def _column_names(bind, table_name: str) -> set[str]:
    return {row["name"] for row in _inspector(bind).get_columns(table_name)}


def _constraint_names(bind, table_name: str) -> set[str]:
    return {row["name"] for row in _inspector(bind).get_check_constraints(table_name) if row.get("name")}


def _index_names(bind, table_name: str) -> set[str]:
    return {row["name"] for row in _inspector(bind).get_indexes(table_name) if row.get("name")}


def upgrade() -> None:
    bind = op.get_bind()

    city_columns = _column_names(bind, "cities")
    if "service_vlan_id" not in city_columns:
        op.add_column("cities", sa.Column("service_vlan_id", sa.Integer(), nullable=True))
    city_constraints = _constraint_names(bind, "cities")
    if "ck_cities_service_vlan_id" not in city_constraints:
        op.create_check_constraint(
            "ck_cities_service_vlan_id",
            "cities",
            "service_vlan_id IS NULL OR service_vlan_id BETWEEN 2 AND 4094",
        )
    city_indexes = _index_names(bind, "cities")
    if "uq_cities_service_vlan_id" not in city_indexes:
        op.create_index(
            "uq_cities_service_vlan_id",
            "cities",
            ["service_vlan_id"],
            unique=True,
            postgresql_where=sa.text("service_vlan_id IS NOT NULL"),
        )

    sector_columns = _column_names(bind, "sectors")
    if "customer_vlan_start" not in sector_columns:
        op.add_column("sectors", sa.Column("customer_vlan_start", sa.Integer(), nullable=True))
    if "customer_vlan_end" not in sector_columns:
        op.add_column("sectors", sa.Column("customer_vlan_end", sa.Integer(), nullable=True))
    sector_constraints = _constraint_names(bind, "sectors")
    if "ck_sectors_customer_vlan_range" not in sector_constraints:
        op.create_check_constraint(
            "ck_sectors_customer_vlan_range",
            "sectors",
            "(customer_vlan_start IS NULL AND customer_vlan_end IS NULL) OR "
            "(customer_vlan_start BETWEEN 2 AND 4094 AND customer_vlan_end BETWEEN 2 AND 4094 "
            "AND customer_vlan_start <= customer_vlan_end)",
        )

    service_columns = _column_names(bind, "customer_services")
    if "customer_vlan_id" not in service_columns:
        op.add_column("customer_services", sa.Column("customer_vlan_id", sa.Integer(), nullable=True))
    service_constraints = _constraint_names(bind, "customer_services")
    if "ck_customer_services_customer_vlan_id" not in service_constraints:
        op.create_check_constraint(
            "ck_customer_services_customer_vlan_id",
            "customer_services",
            "customer_vlan_id IS NULL OR customer_vlan_id BETWEEN 2 AND 4094",
        )
    service_indexes = _index_names(bind, "customer_services")
    if "ix_customer_services_customer_vlan" not in service_indexes:
        op.create_index(
            "ix_customer_services_customer_vlan",
            "customer_services",
            ["customer_vlan_id"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()

    if "ix_customer_services_customer_vlan" in _index_names(bind, "customer_services"):
        op.drop_index("ix_customer_services_customer_vlan", table_name="customer_services")
    if "ck_customer_services_customer_vlan_id" in _constraint_names(bind, "customer_services"):
        op.drop_constraint("ck_customer_services_customer_vlan_id", "customer_services", type_="check")
    if "customer_vlan_id" in _column_names(bind, "customer_services"):
        op.drop_column("customer_services", "customer_vlan_id")

    if "ck_sectors_customer_vlan_range" in _constraint_names(bind, "sectors"):
        op.drop_constraint("ck_sectors_customer_vlan_range", "sectors", type_="check")
    sector_columns = _column_names(bind, "sectors")
    if "customer_vlan_end" in sector_columns:
        op.drop_column("sectors", "customer_vlan_end")
    sector_columns = _column_names(bind, "sectors")
    if "customer_vlan_start" in sector_columns:
        op.drop_column("sectors", "customer_vlan_start")

    if "uq_cities_service_vlan_id" in _index_names(bind, "cities"):
        op.drop_index("uq_cities_service_vlan_id", table_name="cities")
    if "ck_cities_service_vlan_id" in _constraint_names(bind, "cities"):
        op.drop_constraint("ck_cities_service_vlan_id", "cities", type_="check")
    if "service_vlan_id" in _column_names(bind, "cities"):
        op.drop_column("cities", "service_vlan_id")
