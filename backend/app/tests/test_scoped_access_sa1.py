from app.models.security import UserResourceScope, UserScope
from app.security.permission_dependencies import prerequisites_for
from app.security.permissions import Permission


def test_authoritative_scope_model_is_separate_from_legacy_user_scope():
    assert UserResourceScope.__tablename__ == "user_resource_scopes"
    assert UserScope.__tablename__ == "user_scopes"
    assert "Deprecated, non-authoritative legacy data" in (UserScope.__doc__ or "")


def test_scope_model_supports_only_one_typed_target_and_required_fk_delete_rules():
    table = UserResourceScope.__table__
    assert {
        "user_id", "scope_type", "network_id", "city_id", "location_id",
        "sector_id", "group_id", "assigned_by_user_id",
    } <= set(table.columns.keys())
    check_sql = " ".join(str(c.sqltext) for c in table.constraints if c.name == "ck_user_resource_scopes_target")
    for scope_type in ("GLOBAL", "NETWORK", "CITY", "LOCATION", "SECTOR", "GROUP"):
        assert scope_type in check_sql
    fk_rules = {
        fk.parent.name: fk.ondelete
        for constraint in table.foreign_key_constraints
        for fk in constraint.elements
    }
    assert fk_rules["user_id"] == "CASCADE"
    assert fk_rules["assigned_by_user_id"] == "SET NULL"
    for column in ("network_id", "city_id", "location_id", "sector_id", "group_id"):
        assert fk_rules[column] == "CASCADE"


def test_scope_model_has_union_safe_uniqueness_and_query_indexes():
    names = {index.name for index in UserResourceScope.__table__.indexes}
    assert {
        "ix_user_resource_scopes_user_type",
        "uq_user_resource_scopes_global_user",
        "uq_user_resource_scopes_network_user",
        "uq_user_resource_scopes_city_user",
        "uq_user_resource_scopes_location_user",
        "uq_user_resource_scopes_sector_user",
        "uq_user_resource_scopes_group_user",
    } <= names


def test_scope_administration_permissions_are_explicit_and_prerequisite_safe():
    assert Permission.USER_SCOPES_READ == "user.scopes.read"
    assert Permission.USER_SCOPES_MANAGE == "user.scopes.manage"
    assert set(prerequisites_for(Permission.USER_SCOPES_READ)) == {Permission.USER_READ}
    assert set(prerequisites_for(Permission.USER_SCOPES_MANAGE)) == {
        Permission.USER_READ,
        Permission.USER_SCOPES_READ,
    }
