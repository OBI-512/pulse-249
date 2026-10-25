from pathlib import Path

from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex

from app.db.base import Base


def test_intentional_historical_indexes_are_present_in_orm_metadata():
    expected = {
        "ix_customer_services_sector_status": (
            "customer_services",
            ("sector_id", "status"),
            "WHERE deleted_at IS NULL",
        ),
        "ix_device_group_memberships_group": (
            "device_group_memberships",
            ("group_id",),
            "WHERE deleted_at IS NULL",
        ),
        "ix_device_hierarchy_links_parent": (
            "device_hierarchy_links",
            ("parent_device_id",),
            "WHERE deleted_at IS NULL",
        ),
        "ix_restore_points_retention": (
            "restore_points",
            ("retention_until",),
            None,
        ),
        "ix_restore_points_status_created": (
            "restore_points",
            ("status", "created_at"),
            None,
        ),
    }

    for name, (table_name, columns, predicate) in expected.items():
        matches = [index for index in Base.metadata.tables[table_name].indexes if index.name == name]
        assert len(matches) == 1
        index = matches[0]
        assert index.unique is False
        assert tuple(str(expression).split(".")[-1].split()[0] for expression in index.expressions) == columns

        ddl = str(CreateIndex(index).compile(dialect=postgresql.dialect()))
        if predicate is None:
            assert " WHERE " not in ddl
        else:
            assert predicate in ddl
        if name == "ix_restore_points_status_created":
            assert "(status, created_at DESC)" in ddl

def test_clean_initial_migration():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0001_initial_schema.py"
    text = path.read_text(encoding="utf-8-sig")
    assert 'revision = "0001_initial_schema"' in text
    assert "down_revision = None" in text
    assert "Base.metadata.create_all" in text


def test_phase_one_domain_integrity_migration_is_incremental():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0002_domain_hierarchy_phase1.py"
    text = path.read_text(encoding="utf-8-sig")
    assert 'revision = "0002_domain_hierarchy_phase1"' in text
    assert 'down_revision = "0001_initial_schema"' in text
    assert "uq_device_hierarchy_cpe_access_point_parent" in text


def test_phase_three_a_movement_permission_migration_is_incremental():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0003_physical_movement_permissions.py"
    text = path.read_text(encoding="utf-8-sig")
    assert 'revision = "0003_movement_rbac"' in text
    assert 'down_revision = "0002_domain_hierarchy_phase1"' in text
    assert "physical_movement.sector" in text
    assert "physical_movement.cpe" in text
    assert "physical_movement.access_point" in text
    assert "roles.code = 'administrator'" in text


def test_recycle_bin_migration_is_incremental_and_explicit():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0004_recycle_bin.py"
    text = path.read_text(encoding="utf-8-sig")
    assert 'revision = "0004_recycle_bin"' in text
    assert 'down_revision = "0003_movement_rbac"' in text
    assert "recycle_bin_batches" in text
    assert "recycle_bin_items" in text
    assert "deleted_at" in text
    assert "deletion_batch_id" in text
    assert "recycle_bin.read" in text
    assert "recycle_bin.restore" in text
    assert "recycle_bin.purge" in text
    assert "network.delete" in text
    assert "geo.delete" in text
    assert "customer.delete" in text
    assert "roles.code = 'administrator'" in text


def test_recycle_invariants_follow_applied_recycle_migration():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0005_recycle_invariants.py"
    text = path.read_text(encoding="utf-8-sig")
    assert 'revision = "0005_recycle_invariants"' in text
    assert 'down_revision = "0004_recycle_bin"' in text
    assert "recycle_tombstone_pair" in text
    assert "internal.demo_seed.version" in text
    assert "WHERE EXISTS (SELECT 1 FROM networks" in text


def test_immutable_audit_migration_is_incremental_and_idempotent():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0006_immutable_audit.py"
    text = path.read_text(encoding="utf-8-sig")
    assert 'revision = "0006_immutable_audit"' in text
    assert 'down_revision = "0005_recycle_invariants"' in text
    assert "ADD COLUMN IF NOT EXISTS" in text
    assert "CREATE INDEX IF NOT EXISTS" in text
    assert "trg_audit_logs_append_only" in text
    assert "fttw.audit_maintenance" in text
    assert "audit.read" in text
    assert "audit.export" in text
    assert "roles.code = 'administrator'" in text
    assert "custom role grants" in text


def test_user_security_permission_migration_follows_immutable_audit():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0007_user_security_permissions.py"
    text = path.read_text(encoding="utf-8-sig")
    assert 'revision = "0007_user_security_permissions"' in text
    assert 'down_revision = "0006_immutable_audit"' in text
    for code in (
        "user.create",
        "user.update",
        "user.deactivate",
        "user.password.reset",
        "user.roles.manage",
        "user.permissions.manage",
        "settings.secret.read",
    ):
        assert code in text
    assert "roles.code = 'administrator'" in text


def test_restore_point_migration_is_explicit_and_follows_user_security():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0008_restore_points.py"
    text = path.read_text(encoding="utf-8-sig")
    assert 'revision = "0008_restore_points"' in text
    assert 'down_revision = "0007_user_security_permissions"' in text
    assert "CREATE TABLE IF NOT EXISTS restore_points" in text
    assert "restore_points.restore" in text
    assert "r.code = 'administrator'" in text


def test_operational_log_permission_migration_follows_restore_points():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0009_operational_logs.py"
    text = path.read_text(encoding="utf-8-sig")
    assert 'revision = "0009_operational_logs"' in text
    assert 'down_revision = "0008_restore_points"' in text
    assert "logs.read" in text
    assert "logs.export" in text
    assert "r.code = 'administrator'" in text


def test_integrity_hardening_migration_follows_operational_logs():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0010_integrity_hardening.py"
    text = path.read_text(encoding="utf-8-sig")
    assert 'revision = "0010_integrity_hardening"' in text
    assert 'down_revision = "0009_operational_logs"' in text
    assert "ck_device_ips_primary_requires_management" in text
    assert "uq_active_device_ips_primary" in text


def test_typed_settings_migration_follows_integrity_hardening():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0011_typed_settings.py"
    text = path.read_text(encoding="utf-8-sig")
    assert 'revision = "0011_typed_settings"' in text
    assert 'down_revision = "0010_integrity_hardening"' in text
    assert "auth.login_rate_limit" in text
    assert "restore_points.schedule_time" in text
    assert "recycle_bin.retention_days" in text


def test_phase13_migration_supports_metadata_baseline_and_incremental_upgrade():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0013_lifecycle_group_hardening.py"
    text = path.read_text(encoding="utf-8-sig")
    assert 'revision = "0013_lifecycle_group_hardening"' in text
    assert 'down_revision = "0012_backend_closure"' in text
    # 0001 builds current metadata on a fresh DB, so 0013 must not blindly
    # recreate objects already materialized by Base.metadata.create_all().
    assert 'if not _has_table(bind, "device_group_nestings")' in text
    assert 'if "ck_device_groups_sector_role_requires_sector_scope" not in group_checks' in text
    assert 'if _NESTING_ENTITY not in recycle_sql' in text
    assert "ON CONFLICT (code) DO UPDATE" in text

    performance_path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0014_query_performance_indexes.py"
    performance_text = performance_path.read_text(encoding="utf-8-sig")
    assert 'revision = "0014_query_performance_indexes"' in performance_text
    assert 'down_revision = "0013_lifecycle_group_hardening"' in performance_text
    assert "ix_devices_type_display_active" in performance_text
    assert "ix_device_placements_geography_active" in performance_text
    assert "ix_device_hierarchy_parent_type_active" in performance_text
    assert "ix_device_group_memberships_group_active" in performance_text
    assert "ix_customers_status_name_active" in performance_text


def test_phase22_group_modes_migration_follows_query_indexes_and_supports_fresh_metadata():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0015_group_modes_system_groups.py"
    text = path.read_text(encoding="utf-8-sig")
    assert 'revision = "0015_group_modes_system_groups"' in text
    assert 'down_revision = "0014_query_performance_indexes"' in text
    assert 'if "group_kind" not in columns' in text
    assert 'if "membership_mode" not in columns' in text
    assert 'if "system_key" not in columns' in text
    assert "ck_device_groups_system_dynamic" in text
    assert "uq_device_groups_system_key" in text
    assert "SYSTEM_GROUPS" in text
    assert "All Devices" in text
    assert "All CPEs" in text
    assert "All Sectors" in text


def test_session_observability_migration_follows_group_modes():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0016_session_observability.py"
    text = path.read_text(encoding="utf-8-sig")
    assert 'revision = "0016_session_observability"' in text
    assert 'down_revision = "0015_group_modes_system_groups"' in text
    assert "user.sessions.read" in text
    assert "last_seen_at" in text
    assert "browser_name" in text
    assert "login_ip" in text


def test_password_lifecycle_migration_follows_session_observability():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0017_password_lifecycle.py"
    text = path.read_text(encoding="utf-8-sig")
    assert 'revision = "0017_password_lifecycle"' in text
    assert 'down_revision = "0016_session_observability"' in text
    assert "must_change_password" in text
    assert "password_history" in text
    assert "auth.password.history_count" in text
    assert "auth.session_online_window_minutes" in text


def test_user_activity_tracking_migration_extends_password_lifecycle_head():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0018_user_activity_tracking.py"
    text = path.read_text(encoding="utf-8")
    assert 'revision = "0018_user_activity_tracking"' in text
    assert 'down_revision = "0017_password_lifecycle"' in text
    assert 'last_user_activity_at' in text
    assert 'ix_auth_sessions_user_activity' in text


def test_restricted_role_migration_follows_user_activity_head():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0019_restricted_role.py"
    text = path.read_text(encoding="utf-8")
    assert 'revision = "0019_restricted_role"' in text
    assert 'down_revision = "0018_user_activity_tracking"' in text
    assert '_ROLE_CODE = "restricted"' in text
    assert "no operational permissions" in text


def test_user_resource_scope_migration_follows_restricted_role_and_is_fresh_metadata_safe():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0020_user_resource_scopes.py"
    text = path.read_text(encoding="utf-8")
    assert 'revision = "0020_user_resource_scopes"' in text
    assert 'down_revision = "0019_restricted_role"' in text
    assert 'if _has_table(bind, "user_resource_scopes")' in text
    assert "ck_user_resource_scopes_target" in text
    assert "user.scopes.read" in text
    assert "user.scopes.manage" in text
    assert "_backfill_existing_users_global" in text
    assert "Refusing downgrade" in text


def test_device_availability_migration_follows_resource_scope_and_is_fresh_metadata_safe():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0021_device_availability.py"
    text = path.read_text(encoding="utf-8")
    assert 'revision = "0021_device_availability"' in text
    assert 'down_revision = "0020_user_resource_scopes"' in text
    assert 'if not _has_table(bind, "device_availability")' in text
    assert "ck_device_availability_status" in text
    assert "availability.interval_seconds" in text
    assert "ix_device_availability_due" in text


def test_alarm_event_engine_migration_follows_availability_and_is_fresh_metadata_safe():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0022_alarm_event_engine.py"
    text = path.read_text(encoding="utf-8")
    assert 'revision = "0022_alarm_event_engine"' in text
    assert 'down_revision = "0021_device_availability"' in text
    assert 'if _has_table(bind, "operational_events")' in text
    assert 'if _has_table(bind, "alarms")' in text
    assert 'if _has_table(bind, "alarm_history")' in text
    assert "uq_alarms_correlation_key" in text
    assert "alarm.acknowledge" in text
    assert "alarm.assign" in text
    assert "alarm.clear" in text
    assert "C2_MIGRATION_BACKFILL" in text


def test_maintenance_notification_migration_follows_alarm_engine_and_is_fresh_metadata_safe():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0023_maintenance_notification_foundation.py"
    text = path.read_text(encoding="utf-8")
    assert 'revision = "0023_maintenance_notifications"' in text
    assert 'down_revision = "0022_alarm_event_engine"' in text
    assert 'def _has_table(bind, table_name: str)' in text
    assert 'if _has_table(bind, "maintenance_windows"):' in text
    assert 'if not _has_table(bind, "notification_policies"):' in text
    assert 'if not _has_table(bind, "notification_policy_steps"):' in text
    assert 'if _has_table(bind, "notification_deliveries"):' in text
    assert "maintenance.read" in text
    assert "maintenance.manage" in text
    assert "notification.read" in text
    assert "notification.manage" in text
    assert "notifications.enabled" in text
    assert "ck_notification_policy_steps_retry_order" in text
    assert "NOTIFICATION_SUPPRESSED" in text


def test_maintenance_target_expansion_follows_c3():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0024_maintenance_targets.py"
    text = path.read_text(encoding="utf-8")
    assert 'revision = "0024_maintenance_targets"' in text
    assert 'down_revision = "0023_maintenance_notifications"' in text
    assert "CITY" in text
    assert "GROUP" in text


def test_vlan_documentation_migration_follows_c4_and_is_fresh_metadata_safe():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0025_vlan_documentation.py"
    text = path.read_text(encoding="utf-8")
    assert 'revision = "0025_vlan_documentation"' in text
    assert 'down_revision = "0024_maintenance_targets"' in text
    assert 'if "service_vlan_id" not in city_columns' in text
    assert 'if "customer_vlan_start" not in sector_columns' in text
    assert 'if "customer_vlan_id" not in service_columns' in text
    assert "ck_cities_service_vlan_id" in text
    assert "ck_sectors_customer_vlan_range" in text
    assert "ck_customer_services_customer_vlan_id" in text


def test_phase_d_migration_follows_vlan_and_is_fresh_metadata_safe():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0026_phase_d_telemetry_data_reporting.py"
    text = path.read_text(encoding="utf-8")
    assert 'revision = "0026_phase_d_reporting"' in text
    revision_line = next(line for line in text.splitlines() if line.startswith("revision = "))
    revision_id = revision_line.split("\"")[1]
    assert len(revision_id) <= 32
    assert 'down_revision = "0025_vlan_documentation"' in text
    assert "telemetry_profiles" in text
    assert "data_retention_policies" in text
    assert "report_jobs" in text
    assert "data_exchange.import" in text
    assert "checkfirst=True" in text


def test_report_configuration_trash_migration_follows_phase_d_and_is_reversible():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0027_report_config_trash.py"
    text = path.read_text(encoding="utf-8")
    assert 'revision = "0027_report_config_trash"' in text
    assert 'down_revision = "0026_phase_d_reporting"' in text
    revision_line = next(line for line in text.splitlines() if line.startswith("revision = "))
    revision_id = revision_line.split("\"")[1]
    assert len(revision_id) <= 32
    assert "deleted_at" in text
    assert "purge_after" in text
    assert "REPORT_CONFIGURATION_TRASH" in text
    assert 'check_name = f"ck_{prefix}_trash_state"' in text
    assert '_add_lifecycle_columns(bind, "report_definitions", prefix="report_definitions")' in text
    assert '_add_lifecycle_columns(bind, "report_schedules", prefix="report_schedules")' in text
    assert "def downgrade()" in text
