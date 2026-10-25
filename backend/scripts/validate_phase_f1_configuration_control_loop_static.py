from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_ROUTE_COUNT = 268
EXPECTED_CONFIGURATION_ROUTES = {
    ("GET", "/api/configuration-templates", "device.configuration.template.read"),
    ("POST", "/api/configuration-templates", "device.configuration.template.manage"),
    ("GET", "/api/configuration-templates/{template_id}", "device.configuration.template.read"),
    ("POST", "/api/configuration-templates/{template_id}/versions", "device.configuration.template.manage"),
    ("PUT", "/api/configuration-templates/{template_id}/versions/{version_id}", "device.configuration.template.manage"),
    ("POST", "/api/configuration-templates/{template_id}/versions/{version_id}/publish", "device.configuration.template.manage"),
    ("POST", "/api/devices/{device_id}/configuration/apply", "device.configuration.apply"),
    ("GET", "/api/devices/{device_id}/configuration/binding", "device.configuration.read"),
    ("PUT", "/api/devices/{device_id}/configuration/binding", "device.configuration.template.manage"),
    ("POST", "/api/devices/{device_id}/configuration/capture", "device.configuration.capture"),
    ("GET", "/api/devices/{device_id}/configuration/diff", "device.configuration.read"),
    ("GET", "/api/devices/{device_id}/configuration/operations", "device.configuration.read"),
    ("GET", "/api/devices/{device_id}/configuration/operations/{operation_id}", "device.configuration.read"),
    ("POST", "/api/devices/{device_id}/configuration/restore", "device.configuration.restore"),
    ("GET", "/api/devices/{device_id}/configuration/snapshots", "device.configuration.read"),
    ("GET", "/api/devices/{device_id}/configuration/state", "device.configuration.read"),
    ("POST", "/api/devices/{device_id}/configuration/verify", "device.configuration.capture"),
}


def source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def main() -> int:
    migration = source("migrations/versions/0036_config_foundation.py")
    if 'revision = "0036_config_foundation"' not in migration:
        raise RuntimeError("Package 2 lost the accepted 0036 foundation migration")
    versions = sorted(
        path.name
        for path in (ROOT / "migrations/versions").glob("*.py")
        if path.name != "__init__.py"
    )
    if any(name.startswith("0037_") for name in versions):
        raise RuntimeError("Package 2 must not introduce an unnecessary 0037 migration")

    contract = json.loads(
        (ROOT / "scripts/ci_route_permission_contract_baseline.json").read_text(encoding="utf-8")
    )
    if contract.get("route_count") != EXPECTED_ROUTE_COUNT or len(contract.get("routes", [])) != EXPECTED_ROUTE_COUNT:
        raise RuntimeError("Package 2 reviewed route contract must be exactly 268 operations")
    actual = {
        (row["method"], row["path"], row.get("permission"))
        for row in contract["routes"]
        if "configuration" in row["path"]
    }
    if actual != EXPECTED_CONFIGURATION_ROUTES:
        raise RuntimeError("Package 2 configuration route/permission contract mismatch")
    templates = [
        row for row in contract["routes"]
        if row["path"].startswith("/api/configuration-templates")
    ]
    if len(templates) != 6 or not all(row.get("global_scope") is True for row in templates):
        raise RuntimeError("Configuration-template routes must remain GLOBAL-scoped")

    service = source("app/services/configuration.py")
    tasks = source("app/tasks/configuration.py")
    artifacts = source("app/configuration/artifacts.py")
    ssh = source("app/configuration/ssh_cli.py")
    schemas = source("app/schemas/configuration.py")
    authz = source("app/security/authorization.py")
    router = source("app/api/routers/configuration.py")
    templating = source("app/configuration/templating.py")
    operational_logging = source("app/observability/logging.py")
    operational_logs_router = source("app/api/routers/operational_logs.py")
    ssh_transport = source("app/remote_gateway/ssh_transport.py")

    if '"configuration-worker"' not in operational_logging:
        raise RuntimeError("Dedicated configuration-worker is not allow-listed for operational logging")
    if "OPERATIONAL_LOG_SERVICES" not in operational_logs_router or "_SERVICES = OPERATIONAL_LOG_SERVICES" not in operational_logs_router:
        raise RuntimeError("Operational-log API must share the authoritative service allow-list")
    # docker-compose.yml is intentionally outside the backend image build context.
    # Compose service identity is validated by VALIDATE.ps1 and DEPLOY.ps1.

    required_service_markers = (
        "request_fingerprint",
        "CONFIGURATION_IDEMPOTENCY_KEY_REUSED",
        "CONFIGURATION_SNAPSHOT_TEMPLATE_VERSION_MISMATCH",
        "CONFIGURATION_RESTORABLE_CAPTURE_BOUNDARIES_REQUIRED",
        "await db.commit()",
        "await _reauthorize(db, operation)",
        "ROLLBACK_FAILED",
        "CONFIGURATION_ROLLBACK_WORKER_INTERRUPTED",
        "_validate_operation_capabilities",
        "CONFIGURATION_TEMPLATE_CAPABILITY_UNAVAILABLE",
        "_assert_version_integrity",
        "definition_sha256(definition) != version.content_sha256",
        "_execution_target_fingerprint",
        "CONFIGURATION_EXECUTION_TARGET_CHANGED",
        "CONFIGURATION_DEVICE_OPERATION_ACTIVE",
        "CONFIGURATION_QUEUE_EXPIRED",
    )
    combined = service + ssh
    for marker in required_service_markers:
        if marker not in combined:
            raise RuntimeError(f"Package 2 safety marker missing: {marker}")

    if "AESGCM" not in artifacts or "env://FTTW_CONFIGURATION_ARTIFACT_KEY" not in source("app/settings.py"):
        raise RuntimeError("Package 2 encrypted-artifact contract missing")
    if "logger.exception" in tasks:
        raise RuntimeError("Configuration worker must not log exception traces containing device text")
    if 'current.status in {"RUNNING", "ROLLING_BACK"}' not in tasks:
        raise RuntimeError("Package 2 redelivery fail-closed contract missing")
    if "credential_reference_configured" not in schemas or "public_parameter_summary" not in schemas:
        raise RuntimeError("Package 2 browser secret-reference redaction contract missing")
    if "DEVICE_CONFIGURATION_TEMPLATE_MANAGE" not in authz or "DEVICE_CONFIGURATION_RESTORE" not in authz:
        raise RuntimeError("Package 2 authorization mapping missing")
    if "subprocess" in ssh or "shell=True" in ssh:
        raise RuntimeError("Generic configuration adapter must not expose host shell execution")
    if "for_update=True" not in router:
        raise RuntimeError("Package 2 must serialize queue/binding mutations on the device row")
    if "expires=1800" in router:
        raise RuntimeError("Broker expiry must not strand queued configuration operations")
    if service.count("await _assert_version_integrity(db, version)") < 4:
        raise RuntimeError("Execution and display paths must fail closed on published-version drift")
    if "secret_resolver(reference)" not in templating or "_validate_scalar(" not in templating:
        raise RuntimeError("Resolved sensitive parameters must be validated before CLI rendering")
    if "function.verification_spec" not in ssh or "CONFIGURATION_SSH_LITERAL_SECRET_FORBIDDEN" not in ssh:
        raise RuntimeError("Verification commands must participate in literal-secret rejection")

    file_upload_markers = (
        '"FILE_UPLOAD"',
        '"SCP_LEGACY"',
        "CONFIGURATION_RESTORE_UPLOAD_CHECKSUM_MISMATCH",
        "CONFIGURATION_RESTORE_STAGING_CLEANUP_FAILED",
        "upload_file_scp",
    )
    for marker in file_upload_markers:
        if marker not in ssh:
            raise RuntimeError(f"Generic SSH FILE_UPLOAD safety marker missing: {marker}")
    for marker in (
        '"-O"',
        '"StrictHostKeyChecking=yes"',
        'env["SSHPASS"] = password',
        'command = ["sshpass", "-e", *command]',
    ):
        if marker not in ssh_transport:
            raise RuntimeError(f"Pinned SCP transport safety marker missing: {marker}")
    if "password, *command" in ssh_transport or "shell=True" in ssh_transport:
        raise RuntimeError("SCP transport must keep credentials out of argv and avoid shell execution")

    requirements = source("requirements.lock")
    for dependency in ("cryptography==50.0.1", "cffi==2.1.1", "pycparser==3.0"):
        if dependency not in requirements:
            raise RuntimeError(f"Package 2 dependency lock missing {dependency}")

    print(json.dumps({
        "phase": "F1",
        "package": 2,
        "control_loop_static": "PASS",
        "migration": "0036_config_foundation",
        "route_contract_expected": EXPECTED_ROUTE_COUNT,
        "configuration_routes": len(EXPECTED_CONFIGURATION_ROUTES),
        "vendor_neutral": True,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
