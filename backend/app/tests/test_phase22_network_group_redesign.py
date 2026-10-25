from importlib import import_module

from app.models.relationships import DeviceGroup
from app.schemas.group import DeviceGroupCreate, GroupKind, GroupMembershipMode


CONTROLLED_TYPES = {
    "ACCESS_POINT",
    "CPE",
    "SECTOR",
    "SWITCH",
    "ROUTER",
    "FIREWALL",
    "SERVER",
    "WIRELESS_BRIDGE",
    "NETWORK_DEVICE",
    "OTHER",
}


def test_custom_groups_remain_manual_by_default_for_backward_compatibility():
    group = DeviceGroupCreate(name="Legacy-compatible", code="LEGACY-COMPAT")
    assert group.membership_mode == GroupMembershipMode.MANUAL


def test_custom_group_can_be_declared_dynamic_without_stored_membership_semantics():
    group = DeviceGroupCreate(
        name="Dynamic Routers",
        code="DYN-ROUTERS",
        membership_mode=GroupMembershipMode.DYNAMIC,
        device_scope="ROUTER",
    )
    assert group.membership_mode == GroupMembershipMode.DYNAMIC
    assert group.device_scope.value == "ROUTER"


def test_group_model_exposes_explicit_kind_mode_and_system_identity():
    columns = DeviceGroup.__table__.c
    assert {"group_kind", "membership_mode", "system_key"} <= set(columns.keys())
    checks = {constraint.name for constraint in DeviceGroup.__table__.constraints if constraint.name}
    assert "ck_device_groups_group_kind" in checks
    assert "ck_device_groups_membership_mode" in checks
    assert "ck_device_groups_system_dynamic" in checks


def test_phase22_migration_preserves_and_renames_legacy_seeded_all_access_points_group():
    migration = import_module("migrations.versions.0015_group_modes_system_groups")
    legacy = migration.LEGACY_SYSTEM_GROUP_RENAMES["DEVICE_TYPE_ACCESS_POINT"]
    assert legacy == {
        "name": "All Access Points",
        "code": "ALL-AP",
        "scope_type": "GLOBAL",
        "device_scope": "ACCESS_POINT",
        "replacement_name": "Legacy All Access Points (Manual)",
    }


def test_phase22_seeds_exactly_one_all_devices_group_plus_ten_controlled_type_groups():
    migration = import_module("migrations.versions.0015_group_modes_system_groups")
    rows = migration.SYSTEM_GROUPS
    assert len(rows) == 11
    assert rows[0][0] == "ALL_DEVICES"
    assert rows[0][3] == "ANY"
    type_rows = rows[1:]
    assert {row[3] for row in type_rows} == CONTROLLED_TYPES
    assert len({row[0] for row in rows}) == 11
    assert len({row[1] for row in rows}) == 11
    assert len({row[2] for row in rows}) == 11


def test_group_kind_and_membership_mode_values_are_stable():
    assert GroupKind.SYSTEM.value == "SYSTEM"
    assert GroupKind.CUSTOM.value == "CUSTOM"
    assert GroupMembershipMode.MANUAL.value == "MANUAL"
    assert GroupMembershipMode.DYNAMIC.value == "DYNAMIC"


def test_dynamic_group_population_is_query_backed_not_membership_backed():
    from uuid import uuid4

    from sqlalchemy.dialects import postgresql

    from app.services.groups import direct_group_device_select

    group = DeviceGroup(
        id=uuid4(),
        name="All Routers",
        code="SYS-ALL-ROUTERS",
        group_kind="SYSTEM",
        membership_mode="DYNAMIC",
        system_key="ALL_ROUTERS",
        scope_type="GLOBAL",
        device_scope="ROUTER",
    )
    sql = str(
        direct_group_device_select(group).compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )
    assert "device_group_memberships" not in sql
    assert "device_types" in sql
    assert "ROUTER" in sql


def test_dynamic_cpe_sector_group_uses_authoritative_hierarchy_links():
    from uuid import uuid4

    from sqlalchemy.dialects import postgresql

    from app.services.groups import direct_group_device_select

    group = DeviceGroup(
        id=uuid4(),
        name="Sector CPEs",
        code="SECTOR-CPES",
        group_kind="CUSTOM",
        membership_mode="DYNAMIC",
        scope_type="SECTOR",
        sector_id=uuid4(),
        device_scope="CPE",
    )
    sql = str(
        direct_group_device_select(group).compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )
    assert "group_cpe_link" in sql
    assert "SECTOR_CPE" in sql
    assert "device_placements" not in sql.split("UNION ALL")[2]


def test_group_items_schema_supports_both_group_and_device_rows():
    from uuid import uuid4

    from app.schemas.group import GroupDeviceItem

    child = GroupDeviceItem(
        item_type="GROUP",
        id=uuid4(),
        display_name="Child Group",
        code="CHILD",
        device_type_code="CPE",
        item_count=12,
        source_groups=["Parent Group"],
    )
    assert child.item_type == "GROUP"
    assert child.lifecycle_state is None
    assert child.item_count == 12


def test_group_nesting_has_supported_audit_summary_and_display_snapshot():
    from uuid import uuid4

    from app.models import DeviceGroupNesting
    from app.services.audit_summaries import business_summary, display_snapshot

    parent_id = uuid4()
    child_id = uuid4()
    link = DeviceGroupNesting(parent_group_id=parent_id, child_group_id=child_id)

    expected = {
        "parent_group_id": str(parent_id),
        "child_group_id": str(child_id),
    }
    assert business_summary(link) == expected
    assert display_snapshot(link) == expected


def test_group_child_selection_payloads_are_explicit_and_backward_compatible():
    from uuid import uuid4

    from app.schemas.group import DeviceGroupChildrenUpdate, DeviceGroupUpdate

    child_ids = [uuid4(), uuid4()]
    created = DeviceGroupCreate(name="Parent", code="PARENT", child_group_ids=child_ids)
    assert created.child_group_ids == child_ids
    assert DeviceGroupCreate(name="No Children", code="NO-CHILDREN").child_group_ids == []
    assert DeviceGroupUpdate().child_group_ids is None
    assert DeviceGroupChildrenUpdate(child_group_ids=child_ids).child_group_ids == child_ids


def test_group_children_put_requires_membership_manage_permission():
    from types import SimpleNamespace

    from starlette.requests import Request

    from app.security.authorization import permission_for_request

    scope = {
        "type": "http",
        "method": "PUT",
        "path": "/api/device-groups/00000000-0000-0000-0000-000000000001/children",
        "headers": [],
        "route": SimpleNamespace(path="/api/device-groups/{group_id}/children"),
    }
    request = Request(scope)
    assert permission_for_request(request) == "group.membership.manage"
