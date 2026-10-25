import json
from pathlib import Path

import pytest

from app.availability.credentials import AvailabilityCredentialError, resolve_snmp_credential


def test_snmp_credential_reference_resolves_json_from_environment(monkeypatch):
    monkeypatch.setenv("FTTW_TEST_SNMP", json.dumps({"version": "2c", "community": "not-persisted"}))
    result = resolve_snmp_credential("env://FTTW_TEST_SNMP")
    assert result["version"] == "2c"
    assert result["community"] == "not-persisted"


def test_snmp_credential_reference_rejects_non_environment_sources():
    with pytest.raises(AvailabilityCredentialError, match="SNMP_CREDENTIAL_REFERENCE_INVALID"):
        resolve_snmp_credential("database://secret")


def test_compose_workers_support_optional_git_ignored_snmp_env_file_when_repository_root_is_available():
    # The backend Docker image is built from ./backend, so repository-level
    # compose files and .gitignore are intentionally not copied into /app.
    # APPLY/VALIDATE hash-guard those files and `docker compose config` checks
    # them on the host. Keep this source assertion active for checkout-based
    # pytest runs without making containerized backend tests depend on files
    # outside their build context.
    root = Path(__file__).resolve().parents[3]
    compose_paths = [root / "docker-compose.yml", root / "docker-compose.prod.yml"]
    gitignore_path = root / ".gitignore"
    if not all(path.is_file() for path in [*compose_paths, gitignore_path]):
        pytest.skip("Repository-level Compose files are outside the backend image build context.")

    for path in compose_paths:
        compose = path.read_text(encoding="utf-8")
        worker = compose.split("  worker:", 1)[1].split("  scheduler:", 1)[0]
        assert "FTTW_SNMP_ENV_FILE:-./.env.snmp" in worker
        assert "required: false" in worker
    gitignore = gitignore_path.read_text(encoding="utf-8")
    assert ".env.*" in gitignore
