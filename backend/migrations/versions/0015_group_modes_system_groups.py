"""Add dynamic/manual group modes and immutable system groups.

Revision ID: 0015_group_modes_system_groups
Revises: 0014_query_performance_indexes

The clean-install baseline in 0001 builds *current* SQLAlchemy metadata.  A
fresh database can therefore already contain the Phase 22 columns,
constraints, and indexes before Alembic reaches this revision.  Every DDL
operation below is guarded so both clean installs and incremental upgrades
converge safely.
"""
from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op

revision = "0015_group_modes_system_groups"
down_revision = "0014_query_performance_indexes"
branch_labels = None
depends_on = None


# Phase 12/13-era demo data seeded this exact group as a normal manual group.
# Phase 22 reserves the human-facing name for the immutable query-backed
# system group.  Incremental upgrades preserve the old record, memberships,
# nesting, recycle history, and primary key by renaming only that exact
# product-seeded legacy identity before the new system group is inserted.
LEGACY_SYSTEM_GROUP_RENAMES = {
    "DEVICE_TYPE_ACCESS_POINT": {
        "name": "All Access Points",
        "code": "ALL-AP",
        "scope_type": "GLOBAL",
        "device_scope": "ACCESS_POINT",
        "replacement_name": "Legacy All Access Points (Manual)",
    },
}

SYSTEM_GROUPS = [
    ("ALL_DEVICES", "All Devices", "SYS-ALL-DEVICES", "ANY", "All managed devices."),
    ("DEVICE_TYPE_ACCESS_POINT", "All Access Points", "SYS-ALL-ACCESS-POINTS", "ACCESS_POINT", "All managed access points."),
    ("DEVICE_TYPE_CPE", "All CPEs", "SYS-ALL-CPES", "CPE", "All managed CPE devices."),
    ("DEVICE_TYPE_SECTOR", "All Sectors", "SYS-ALL-SECTORS", "SECTOR", "All managed physical SECTOR devices."),
    ("DEVICE_TYPE_SWITCH", "All Switches", "SYS-ALL-SWITCHES", "SWITCH", "All managed switches."),
    ("DEVICE_TYPE_ROUTER", "All Routers", "SYS-ALL-ROUTERS", "ROUTER", "All managed routers."),
    ("DEVICE_TYPE_FIREWALL", "All Firewalls", "SYS-ALL-FIREWALLS", "FIREWALL", "All managed firewalls."),
    ("DEVICE_TYPE_SERVER", "All Servers", "SYS-ALL-SERVERS", "SERVER", "All managed servers."),
    ("DEVICE_TYPE_WIRELESS_BRIDGE", "All Wireless Bridges", "SYS-ALL-WIRELESS-BRIDGES", "WIRELESS_BRIDGE", "All managed wireless bridges."),
    ("DEVICE_TYPE_NETWORK_DEVICE", "All Network Devices", "SYS-ALL-NETWORK-DEVICES", "NETWORK_DEVICE", "All managed generic network devices."),
    ("DEVICE_TYPE_OTHER", "All Other", "SYS-ALL-OTHER", "OTHER", "All managed devices classified as OTHER."),
]


def _inspector(bind):
    return sa.inspect(bind)


def _column_names(bind, table_name: str) -> set[str]:
    return {row["name"] for row in _inspector(bind).get_columns(table_name)}


def _index_names(bind, table_name: str) -> set[str]:
    return {row["name"] for row in _inspector(bind).get_indexes(table_name) if row.get("name")}


def _check_names(bind, table_name: str) -> set[str]:
    return {row["name"] for row in _inspector(bind).get_check_constraints(table_name) if row.get("name")}



def _rename_legacy_system_group_collision(
    bind,
    *,
    system_key: str,
) -> bool:
    """Preserve and rename an exact historical product-seeded manual group.

    Earlier demo baselines created ``ALL-AP / All Access Points`` as an
    ordinary manual group.  Phase 22 needs that display name for the dynamic
    immutable system group.  Renaming the legacy record is safer than
    converting it in place because its stored memberships and recycle history
    must remain manual/custom data.
    """

    legacy = LEGACY_SYSTEM_GROUP_RENAMES.get(system_key)
    if legacy is None:
        return False

    candidate = bind.execute(
        sa.text(
            "SELECT id, name, code FROM device_groups "
            "WHERE deleted_at IS NULL "
            "AND name=:legacy_name AND code=:legacy_code "
            "AND group_kind='CUSTOM' AND membership_mode='MANUAL' AND system_key IS NULL "
            "AND scope_type=:scope_type "
            "AND network_id IS NULL AND city_id IS NULL AND location_id IS NULL AND sector_id IS NULL "
            "AND device_scope=:device_scope AND sector_role IS NULL "
            "LIMIT 1"
        ),
        {
            "legacy_name": legacy["name"],
            "legacy_code": legacy["code"],
            "scope_type": legacy["scope_type"],
            "device_scope": legacy["device_scope"],
        },
    ).mappings().first()
    if candidate is None:
        return False

    replacement_conflict = bind.execute(
        sa.text(
            "SELECT id, name, code FROM device_groups "
            "WHERE deleted_at IS NULL AND id <> :group_id "
            "AND name=:replacement_name LIMIT 1"
        ),
        {
            "group_id": candidate["id"],
            "replacement_name": legacy["replacement_name"],
        },
    ).mappings().first()
    if replacement_conflict:
        raise RuntimeError(
            "Cannot preserve the historical ALL-AP group during migration: "
            f"active group {replacement_conflict['name']!r} "
            f"({replacement_conflict['code']}) already uses the compatibility "
            f"name {legacy['replacement_name']!r}. Rename that conflicting "
            "custom group and rerun migration 0015."
        )

    bind.execute(
        sa.text(
            "UPDATE device_groups SET name=:replacement_name, "
            "description=CASE "
            "WHEN description IS NULL OR btrim(description) = '' THEN :note "
            "ELSE description || ' ' || :note END "
            "WHERE id=:id"
        ),
        {
            "id": candidate["id"],
            "replacement_name": legacy["replacement_name"],
            "note": (
                "Legacy manual group retained during the Phase 22 system-group "
                "migration. The built-in All Access Points group is now dynamic."
            ),
        },
    )
    return True


def _seed_system_groups(bind) -> None:
    table = sa.table(
        "device_groups",
        sa.column("id", sa.UUID()),
        sa.column("name", sa.String()),
        sa.column("code", sa.String()),
        sa.column("description", sa.Text()),
        sa.column("scope_type", sa.String()),
        sa.column("device_scope", sa.String()),
        sa.column("sector_role", sa.String()),
        sa.column("group_kind", sa.String()),
        sa.column("membership_mode", sa.String()),
        sa.column("system_key", sa.String()),
        sa.column("metadata", sa.JSON()),
    )
    rows = []
    for system_key, name, code, device_scope, description in SYSTEM_GROUPS:
        existing = bind.execute(
            sa.text(
                "SELECT id, name, code, group_kind, membership_mode, system_key "
                "FROM device_groups WHERE system_key = :system_key LIMIT 1"
            ),
            {"system_key": system_key},
        ).mappings().first()
        if existing:
            # A partially applied revision may already have seeded the record.
            # Converge its immutable definition instead of inserting a duplicate.
            bind.execute(
                sa.text(
                    "UPDATE device_groups SET name=:name, code=:code, description=:description, "
                    "scope_type='GLOBAL', network_id=NULL, city_id=NULL, location_id=NULL, sector_id=NULL, "
                    "device_scope=:device_scope, sector_role=NULL, group_kind='SYSTEM', membership_mode='DYNAMIC' "
                    "WHERE id=:id"
                ),
                {"id": existing["id"], "name": name, "code": code, "description": description, "device_scope": device_scope},
            )
            continue

        _rename_legacy_system_group_collision(
            bind,
            system_key=system_key,
        )

        conflict = bind.execute(
            sa.text(
                "SELECT id, name, code FROM device_groups "
                "WHERE deleted_at IS NULL AND (name=:name OR code=:code) LIMIT 1"
            ),
            {"name": name, "code": code},
        ).mappings().first()
        if conflict:
            raise RuntimeError(
                "Cannot seed required system group "
                f"{name!r}: active custom group {conflict['name']!r} ({conflict['code']}) "
                "already uses its reserved name or code. Rename that custom group and rerun the migration."
            )

        rows.append({
            "id": uuid.uuid5(uuid.NAMESPACE_URL, f"fttw:system-group:{system_key}"),
            "name": name,
            "code": code,
            "description": description,
            "scope_type": "GLOBAL",
            "device_scope": device_scope,
            "sector_role": None,
            "group_kind": "SYSTEM",
            "membership_mode": "DYNAMIC",
            "system_key": system_key,
            "metadata": {},
        })
    if rows:
        op.bulk_insert(table, rows)


def upgrade() -> None:
    bind = op.get_bind()
    columns = _column_names(bind, "device_groups")
    if "group_kind" not in columns:
        op.add_column("device_groups", sa.Column("group_kind", sa.String(length=20), nullable=False, server_default="CUSTOM"))
    if "membership_mode" not in columns:
        op.add_column("device_groups", sa.Column("membership_mode", sa.String(length=20), nullable=False, server_default="MANUAL"))
    if "system_key" not in columns:
        op.add_column("device_groups", sa.Column("system_key", sa.String(length=80), nullable=True))

    checks = _check_names(bind, "device_groups")
    if "ck_device_groups_group_kind" not in checks:
        op.create_check_constraint("ck_device_groups_group_kind", "device_groups", "group_kind IN ('SYSTEM','CUSTOM')")
    if "ck_device_groups_membership_mode" not in checks:
        op.create_check_constraint("ck_device_groups_membership_mode", "device_groups", "membership_mode IN ('MANUAL','DYNAMIC')")
    if "ck_device_groups_system_dynamic" not in checks:
        op.create_check_constraint(
            "ck_device_groups_system_dynamic",
            "device_groups",
            "(group_kind = 'SYSTEM' AND membership_mode = 'DYNAMIC' AND system_key IS NOT NULL) OR (group_kind = 'CUSTOM' AND system_key IS NULL)",
        )

    indexes = _index_names(bind, "device_groups")
    if "uq_device_groups_system_key" not in indexes:
        op.create_index(
            "uq_device_groups_system_key",
            "device_groups",
            ["system_key"],
            unique=True,
            postgresql_where=sa.text("system_key IS NOT NULL"),
        )
    if "ix_device_groups_kind_mode" not in indexes:
        op.create_index("ix_device_groups_kind_mode", "device_groups", ["group_kind", "membership_mode"])

    _seed_system_groups(bind)


def downgrade() -> None:
    bind = op.get_bind()
    columns = _column_names(bind, "device_groups")
    if "group_kind" in columns:
        bind.execute(sa.text("DELETE FROM device_groups WHERE group_kind = 'SYSTEM'"))
        # Restore the historical demo group's original display identity if this
        # revision had renamed it for compatibility. Its code/PK/memberships
        # were never changed.
        bind.execute(
            sa.text(
                "UPDATE device_groups SET name='All Access Points' "
                "WHERE deleted_at IS NULL AND code='ALL-AP' "
                "AND name='Legacy All Access Points (Manual)' "
                "AND group_kind='CUSTOM' AND system_key IS NULL"
            )
        )

    indexes = _index_names(bind, "device_groups")
    if "ix_device_groups_kind_mode" in indexes:
        op.drop_index("ix_device_groups_kind_mode", table_name="device_groups")
    if "uq_device_groups_system_key" in indexes:
        op.drop_index("uq_device_groups_system_key", table_name="device_groups")

    checks = _check_names(bind, "device_groups")
    for name in ("ck_device_groups_system_dynamic", "ck_device_groups_membership_mode", "ck_device_groups_group_kind"):
        if name in checks:
            op.drop_constraint(name, "device_groups", type_="check")

    columns = _column_names(bind, "device_groups")
    if "system_key" in columns:
        op.drop_column("device_groups", "system_key")
    if "membership_mode" in columns:
        op.drop_column("device_groups", "membership_mode")
    if "group_kind" in columns:
        op.drop_column("device_groups", "group_kind")
