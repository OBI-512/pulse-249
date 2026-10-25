from __future__ import annotations

import json
from pathlib import Path

from app.configuration.contracts import ConfigurationCapability, ConfigurationTransport
from app.db.base import Base


ROOT = Path(__file__).resolve().parents[1]
F1_TABLES = {
    "configuration_templates",
    "configuration_template_versions",
    "configuration_functions",
    "device_configuration_bindings",
    "configuration_snapshots",
    "configuration_operations",
    "configuration_operation_steps",
    "device_configuration_states",
}
PERMISSIONS = {
    "device.configuration.read",
    "device.configuration.capture",
    "device.configuration.apply",
    "device.configuration.restore",
    "device.configuration.template.read",
    "device.configuration.template.manage",
}


def main() -> int:
    missing = sorted(F1_TABLES - set(Base.metadata.tables))
    if missing:
        raise RuntimeError(f"F1 SQLAlchemy metadata is missing tables: {missing}")

    migration = (ROOT / "migrations" / "versions" / "0036_config_foundation.py").read_text(encoding="utf-8")
    if 'revision = "0036_config_foundation"' not in migration:
        raise RuntimeError("F1 migration revision mismatch")
    if 'down_revision = "0035_remove_web_tls10_compat"' not in migration:
        raise RuntimeError("F1 migration parent mismatch")
    if 'roles.code = \'administrator\'' not in migration:
        raise RuntimeError("F1 migration does not fail closed to administrator defaults")

    migration_layout = (ROOT / "app" / "tests" / "test_migration_layout.py").read_text(encoding="utf-8")
    if '"0036_config_foundation.py"' not in migration_layout:
        raise RuntimeError("F1 migration-layout contract was not advanced to 0036")
    for permission in sorted(PERMISSIONS):
        if permission not in migration:
            raise RuntimeError(f"F1 migration missing permission: {permission}")

    permission_source = (ROOT / "app" / "security" / "permissions.py").read_text(encoding="utf-8")
    seed_source = (ROOT / "scripts" / "seed_demo_data.py").read_text(encoding="utf-8")
    for permission in sorted(PERMISSIONS):
        if permission not in permission_source or permission not in seed_source:
            raise RuntimeError(f"F1 permission catalog mismatch: {permission}")

    route_contract = json.loads((ROOT / "scripts" / "ci_route_permission_contract_baseline.json").read_text(encoding="utf-8"))
    route_count = int(route_contract.get("route_count") or 0)
    if route_count != len(route_contract.get("routes", [])) or route_count < 251:
        raise RuntimeError("F1 reviewed route contract is internally inconsistent")

    if ConfigurationTransport.SSH_CLI.value != "SSH_CLI":
        raise RuntimeError("F1 transport contract mismatch")
    if ConfigurationCapability.PROVISIONAL_COMMIT.value != "PROVISIONAL_COMMIT":
        raise RuntimeError("F1 capability contract mismatch")

    print(json.dumps({
        "phase": "F1",
        "foundation": "PASS",
        "migration": "0036_config_foundation",
        "route_contract_current": route_count,
        "tables": len(F1_TABLES),
        "permissions": len(PERMISSIONS),
        "vendor_neutral": True,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
