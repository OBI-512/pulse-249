from pathlib import Path

MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations" / "versions"

def test_migration_layout_contains_immutable_recycle_audit_and_user_security_increments():
    files = {p.name for p in MIGRATIONS_DIR.glob("*.py") if p.name != "__init__.py"}
    assert files == {
        "0001_initial_schema.py",
        "0002_domain_hierarchy_phase1.py",
        "0003_physical_movement_permissions.py",
        "0004_recycle_bin.py",
        "0005_recycle_invariants.py",
        "0006_immutable_audit.py",
        "0007_user_security_permissions.py",
        "0008_restore_points.py",
        "0009_operational_logs.py",
        "0010_integrity_hardening.py",
        "0011_typed_settings.py",
        "0012_backend_closure.py",
        "0013_lifecycle_group_hardening.py",
        "0014_query_performance_indexes.py",
        "0015_group_modes_system_groups.py",
        "0016_session_observability.py",
        "0017_password_lifecycle.py",
        "0018_user_activity_tracking.py",
        "0019_restricted_role.py",
        "0020_user_resource_scopes.py",
        "0021_device_availability.py",
        "0022_alarm_event_engine.py",
        "0023_maintenance_notification_foundation.py",
        "0024_maintenance_targets.py",
        "0025_vlan_documentation.py",
        "0026_phase_d_telemetry_data_reporting.py",
        "0027_report_config_trash.py",
        "0028_integration_foundation.py",
        "0029_remote_access_gateway.py",
        "0030_ssh_compat_profile.py",
        "0031_operational_sync.py",
        "0032_web_gui_proxy.py",
        "0033_web_tls_compat.py",
        "0034_web_tls10_compat.py",
        "0035_remove_web_tls10_compat.py",
        "0036_config_foundation.py",
        "0037_web_management_port.py",
        "0038_access_templates.py",
        "0039_web_access_templates.py",
        "0040_remote_access_template_binding.py",
        "0041_configuration_change_batches.py",
    }


def test_0035_removes_tls10_as_active_profile_without_rewriting_0034_history():
    cleanup = (MIGRATIONS_DIR / "0035_remove_web_tls10_compat.py").read_text(encoding="utf-8")
    legacy = (MIGRATIONS_DIR / "0034_web_tls10_compat.py").read_text(encoding="utf-8")
    assert 'down_revision = "0034_web_tls10_compat"' in cleanup
    assert "WHERE web_tls_compat_profile = 'LEGACY_TLS_1_0'" in cleanup
    assert "SET web_tls_compat_profile = 'MODERN'" in cleanup
    assert "IN ('MODERN','LEGACY_WEAK_CERT_KEY')" in cleanup
    assert "LEGACY_TLS_1_0" in legacy


def test_0039_adds_web_access_templates_without_rewriting_0038_history():
    extension = (MIGRATIONS_DIR / "0039_web_access_templates.py").read_text(encoding="utf-8")
    foundation = (MIGRATIONS_DIR / "0038_access_templates.py").read_text(encoding="utf-8")
    assert 'down_revision = "0038_access_templates"' in extension
    assert "'SNMP','SSH','TELNET','WEB'" in extension
    assert "protocol IN ('SNMP','SSH','TELNET')" in foundation


def test_0040_binds_remote_web_sessions_to_explicit_templates_without_rewriting_0039():
    binding = (MIGRATIONS_DIR / "0040_remote_access_template_binding.py").read_text(encoding="utf-8")
    extension = (MIGRATIONS_DIR / "0039_web_access_templates.py").read_text(encoding="utf-8")
    assert 'down_revision = "0039_web_access_templates"' in binding
    assert '"access_template_id"' in binding
    assert '"access_templates"' in binding
    assert "0039_web_access_templates" in extension


def test_0041_adds_f3_batch_orchestration_without_rewriting_0040():
    batch = (MIGRATIONS_DIR / "0041_configuration_change_batches.py").read_text(encoding="utf-8")
    binding = (MIGRATIONS_DIR / "0040_remote_access_template_binding.py").read_text(encoding="utf-8")
    assert 'revision = "0041_config_change_batches"' in batch
    assert len("0041_config_change_batches") <= 32
    assert 'down_revision = "0040_remote_template_binding"' in batch
    assert '"configuration_batches"' in batch
    assert '"configuration_batch_targets"' in batch
    assert 'revision = "0040_remote_template_binding"' in binding
