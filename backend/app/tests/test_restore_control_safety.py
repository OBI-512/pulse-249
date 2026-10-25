from __future__ import annotations

import asyncio
from pathlib import Path
from uuid import uuid4

import pytest

from app.main import app
from app.services import restore_control


def _run(coro):
    return asyncio.run(coro)


def test_sanitize_rendered_restore_sql_removes_only_transaction_timeout(tmp_path):
    source = tmp_path / "rendered.sql"
    destination = tmp_path / "sanitized.sql"
    source.write_text(
        "SET statement_timeout = 0;\n"
        "SET transaction_timeout = 0;\n"
        "SET lock_timeout = 0;\n"
        "SELECT 1;\n",
        encoding="utf-8",
    )

    removed = restore_control._sanitize_rendered_restore_sql(source, destination)

    assert removed == 1
    content = destination.read_text(encoding="utf-8")
    assert "transaction_timeout" not in content
    assert "SET statement_timeout = 0;" in content
    assert "SET lock_timeout = 0;" in content
    assert "SELECT 1;" in content


def test_restore_archive_renders_filters_and_replays_with_psql(monkeypatch, tmp_path):
    artifact = tmp_path / "selected.dump"
    artifact.write_bytes(b"not-empty")
    commands: list[tuple[str, ...]] = []

    monkeypatch.setattr(restore_control, "_artifact_path", lambda _name: artifact)
    monkeypatch.setattr(restore_control, "_restore_work_root", lambda: tmp_path)
    monkeypatch.setattr(
        restore_control,
        "_connection_details",
        lambda: (["-h", "postgres", "-p", "5432", "-U", "fttw"], {}, "fttw"),
    )

    async def fake_run(*command: str, environment):
        commands.append(tuple(command))
        if command[0] == "pg_restore" and "--file" in command:
            output = Path(command[command.index("--file") + 1])
            output.write_text(
                "SET statement_timeout = 0;\n"
                "SET transaction_timeout = 0;\n"
                "CREATE TABLE example (id integer);\n",
                encoding="utf-8",
            )
        if command[0] == "psql":
            sql_file = Path(command[command.index("-f") + 1])
            sql = sql_file.read_text(encoding="utf-8")
            assert "transaction_timeout" not in sql
            assert "CREATE TABLE example" in sql
        return 0, "", ""

    monkeypatch.setattr(restore_control, "_run_command", fake_run)

    removed = _run(restore_control._restore_archive_into_database("selected.dump", "probe"))

    assert removed == 1
    assert [command[0] for command in commands] == ["pg_restore", "psql"]


def test_replace_database_uses_preflighted_render_filter_replay_path(monkeypatch, tmp_path):
    artifact = tmp_path / "selected.dump"
    artifact.write_bytes(b"not-empty")
    commands: list[tuple[str, ...]] = []

    monkeypatch.setattr(restore_control.settings, "enable_database_restore", True)
    monkeypatch.setattr(restore_control, "_artifact_path", lambda _name: artifact)
    monkeypatch.setattr(restore_control, "_restore_work_root", lambda: tmp_path)
    monkeypatch.setattr(
        restore_control,
        "_connection_details",
        lambda: (["-h", "postgres", "-p", "5432", "-U", "fttw"], {}, "fttw"),
    )

    async def fake_run(*command: str, environment):
        commands.append(tuple(command))
        if command[0] == "pg_restore" and "--file" in command:
            output = Path(command[command.index("--file") + 1])
            output.write_text(
                "SET transaction_timeout = 0;\nSELECT 1;\n",
                encoding="utf-8",
            )
        return 0, "", ""

    monkeypatch.setattr(restore_control, "_run_command", fake_run)

    _run(restore_control._replace_database("selected.dump"))

    assert [command[0] for command in commands] == [
        "dropdb",
        "createdb",
        "pg_restore",
        "psql",
    ]
    assert "--force" in commands[0]
    assert commands[-1][commands[-1].index("-d") + 1] == "fttw"


def test_restore_preflight_performs_isolated_restore_and_validation_for_both_archives(monkeypatch, tmp_path):
    selected = tmp_path / "selected.dump"
    emergency = tmp_path / "emergency.dump"
    selected.write_bytes(b"selected")
    emergency.write_bytes(b"emergency")
    commands: list[tuple[str, ...]] = []
    restores: list[tuple[str, str]] = []
    validations: list[tuple[str | None, str | None, str | None]] = []

    monkeypatch.setattr(restore_control.settings, "enable_database_restore", True)
    monkeypatch.setattr(
        restore_control,
        "_artifact_path",
        lambda name: selected if name == "selected.dump" else emergency,
    )
    monkeypatch.setattr(
        restore_control,
        "_connection_details",
        lambda: (["-h", "postgres", "-p", "5432", "-U", "fttw"], {}, "fttw"),
    )

    async def fake_run(*command: str, environment):
        commands.append(tuple(command))
        return 0, "ok", ""

    async def fake_restore(name: str, database_name: str):
        restores.append((name, database_name))
        return 1

    async def fake_validate(revision, fingerprint, *, database_name=None):
        validations.append((revision, fingerprint, database_name))

    monkeypatch.setattr(restore_control, "_run_command", fake_run)
    monkeypatch.setattr(restore_control, "_restore_archive_into_database", fake_restore)
    monkeypatch.setattr(restore_control, "_validate_database", fake_validate)

    _run(
        restore_control._preflight_restore_environment(
            ("selected.dump", "0020_user_resource_scopes", "selected-fingerprint"),
            ("emergency.dump", "0020_user_resource_scopes", "emergency-fingerprint"),
        )
    )

    names = [command[0] for command in commands]
    assert names[:4] == ["psql", "dropdb", "createdb", "pg_restore"]
    assert names.count("pg_restore") == 3  # --version + --list for each archive
    assert names.count("createdb") == 3  # --version + one isolated DB per archive
    assert names.count("dropdb") == 3  # --version + cleanup for each isolated DB
    assert len(restores) == 2
    assert len(validations) == 2
    assert restores[0][0] == "selected.dump"
    assert restores[1][0] == "emergency.dump"
    assert all(database.startswith("fttw_restore_probe_") for _, database in restores)
    assert all(database != "fttw" for _, database in restores)
    assert [item[2] for item in validations] == [restores[0][1], restores[1][1]]


def test_preflight_failure_never_replaces_database_and_clears_restore_guard(monkeypatch):
    restore_id = uuid4()
    emergency_id = uuid4()
    events: list[tuple[str, dict]] = []
    marked: list[dict] = []
    released: list[str] = []

    def fake_manifest(name: str, **_kwargs):
        return {
            "restore_point_id": str(restore_id if name == "selected.dump" else emergency_id)
        }

    async def fail_preflight(*_names):
        raise RuntimeError("RESTORE_PREFLIGHT_COMMAND_FAILED:psql")

    async def forbidden_replace(_name):
        raise AssertionError("destructive replacement must not run after a preflight failure")

    async def fake_mark(**kwargs):
        marked.append(kwargs)

    async def fake_release(*, lock_token: str):
        released.append(lock_token)

    monkeypatch.setattr(restore_control, "_read_manifest", fake_manifest)
    monkeypatch.setattr(restore_control, "_preflight_restore_environment", fail_preflight)
    monkeypatch.setattr(restore_control, "_replace_database", forbidden_replace)
    monkeypatch.setattr(restore_control, "_mark_restore_failed_state", fake_mark)
    monkeypatch.setattr(restore_control, "_release_restore_guard", fake_release)
    monkeypatch.setattr(
        restore_control,
        "write_restore_journal",
        lambda event, **fields: events.append((event, fields)),
    )

    with pytest.raises(RuntimeError, match="SYSTEM_RESTORE_PREFLIGHT_FAILED"):
        _run(
            restore_control.execute_restore_control(
                restore_point_id=restore_id,
                emergency_point_id=emergency_id,
                artifact_name="selected.dump",
                emergency_artifact_name="emergency.dump",
                expected_revision="0020_user_resource_scopes",
                expected_fingerprint="fingerprint",
                expected_sha256=None,
                expected_manifest_checksum=None,
                emergency_expected_sha256=None,
                emergency_expected_manifest_checksum=None,
                lock_token="lock",
                actor_user_id=None,
                actor_username_snapshot=None,
                actor_display_name_snapshot=None,
                request_id="request",
            )
        )

    assert len(marked) == 1
    assert marked[0]["error_code"] == "RESTORE_PREFLIGHT_COMMAND_FAILED:PSQL"
    assert released == ["lock"]
    failed = [fields for event, fields in events if event == "SYSTEM_RESTORE_FAILED"]
    assert failed and failed[-1]["stage"] == "PREFLIGHT"
    assert failed[-1]["destructive_started"] is False


def test_selected_restore_failure_recovers_emergency_before_clearing_guard(monkeypatch):
    restore_id = uuid4()
    emergency_id = uuid4()
    replacements: list[str] = []
    marked: list[dict] = []
    released: list[str] = []
    health_checks: list[bool] = []

    def fake_manifest(name: str, **_kwargs):
        return {
            "restore_point_id": str(restore_id if name == "selected.dump" else emergency_id)
        }

    async def fake_preflight(*_names):
        return None

    async def fake_replace(name: str):
        replacements.append(name)
        if name == "selected.dump":
            raise RuntimeError("RESTORE_COMMAND_FAILED:pg_restore")

    async def fake_noop(*_args, **_kwargs):
        return None

    async def fake_health(*_args, **_kwargs):
        health_checks.append(True)

    async def fake_mark(**kwargs):
        marked.append(kwargs)

    async def fake_release(*, lock_token: str):
        released.append(lock_token)

    monkeypatch.setattr(restore_control, "_read_manifest", fake_manifest)
    monkeypatch.setattr(restore_control, "_preflight_restore_environment", fake_preflight)
    monkeypatch.setattr(restore_control, "_replace_database", fake_replace)
    monkeypatch.setattr(restore_control, "_validate_restored_database", fake_noop)
    monkeypatch.setattr(restore_control, "_rehydrate_emergency_after_recovery", fake_noop)
    monkeypatch.setattr(restore_control, "_validate_backend_health", fake_health)
    monkeypatch.setattr(restore_control, "_mark_restore_failed_state", fake_mark)
    monkeypatch.setattr(restore_control, "_release_restore_guard", fake_release)
    monkeypatch.setattr(restore_control, "write_restore_journal", lambda *_args, **_kwargs: None)

    with pytest.raises(RuntimeError, match="SYSTEM_RESTORE_FAILED_EMERGENCY_RECOVERED"):
        _run(
            restore_control.execute_restore_control(
                restore_point_id=restore_id,
                emergency_point_id=emergency_id,
                artifact_name="selected.dump",
                emergency_artifact_name="emergency.dump",
                expected_revision="0020_user_resource_scopes",
                expected_fingerprint="fingerprint",
                expected_sha256=None,
                expected_manifest_checksum=None,
                emergency_expected_sha256=None,
                emergency_expected_manifest_checksum=None,
                lock_token="lock",
                actor_user_id=None,
                actor_username_snapshot=None,
                actor_display_name_snapshot=None,
                request_id="request",
            )
        )

    assert replacements == ["selected.dump", "emergency.dump"]
    assert health_checks == [True]
    assert len(marked) == 1
    assert marked[0]["error_code"] == "RESTORE_COMMAND_FAILED:PG_RESTORE"
    assert released == ["lock"]


def test_double_destructive_failure_keeps_maintenance_guard_asserted(monkeypatch):
    restore_id = uuid4()
    emergency_id = uuid4()
    replacements: list[str] = []
    released: list[str] = []
    events: list[str] = []

    def fake_manifest(name: str, **_kwargs):
        return {
            "restore_point_id": str(restore_id if name == "selected.dump" else emergency_id)
        }

    async def fake_preflight(*_names):
        return None

    async def fail_replace(name: str):
        replacements.append(name)
        raise RuntimeError(f"RESTORE_COMMAND_FAILED:{name}")

    async def fake_release(*, lock_token: str):
        released.append(lock_token)

    monkeypatch.setattr(restore_control, "_read_manifest", fake_manifest)
    monkeypatch.setattr(restore_control, "_preflight_restore_environment", fake_preflight)
    monkeypatch.setattr(restore_control, "_replace_database", fail_replace)
    monkeypatch.setattr(restore_control, "_release_restore_guard", fake_release)
    monkeypatch.setattr(
        restore_control,
        "write_restore_journal",
        lambda event, **_fields: events.append(event),
    )

    with pytest.raises(RuntimeError, match="SYSTEM_RESTORE_FAILED_EMERGENCY_RECOVERY_FAILED"):
        _run(
            restore_control.execute_restore_control(
                restore_point_id=restore_id,
                emergency_point_id=emergency_id,
                artifact_name="selected.dump",
                emergency_artifact_name="emergency.dump",
                expected_revision="0020_user_resource_scopes",
                expected_fingerprint="fingerprint",
                expected_sha256=None,
                expected_manifest_checksum=None,
                emergency_expected_sha256=None,
                emergency_expected_manifest_checksum=None,
                lock_token="lock",
                actor_user_id=None,
                actor_username_snapshot=None,
                actor_display_name_snapshot=None,
                request_id="request",
            )
        )

    assert replacements == ["selected.dump", "emergency.dump"]
    assert released == []
    assert "EMERGENCY_RESTORE_FAILED" in events


def test_emergency_recovery_bookkeeping_failure_does_not_leave_healthy_system_in_maintenance(monkeypatch):
    restore_id = uuid4()
    emergency_id = uuid4()
    released: list[str] = []

    def fake_manifest(name: str, **_kwargs):
        return {
            "restore_point_id": str(restore_id if name == "selected.dump" else emergency_id)
        }

    async def fake_preflight(*_names):
        return None

    async def fake_replace(name: str):
        if name == "selected.dump":
            raise RuntimeError("RESTORE_COMMAND_FAILED:pg_restore")

    async def fake_noop(*_args, **_kwargs):
        return None

    async def fail_mark(**_kwargs):
        raise RuntimeError("RESTORE_FAILURE_STATUS_WRITE_FAILED")

    async def fake_release(*, lock_token: str):
        released.append(lock_token)

    monkeypatch.setattr(restore_control, "_read_manifest", fake_manifest)
    monkeypatch.setattr(restore_control, "_preflight_restore_environment", fake_preflight)
    monkeypatch.setattr(restore_control, "_replace_database", fake_replace)
    monkeypatch.setattr(restore_control, "_validate_restored_database", fake_noop)
    monkeypatch.setattr(restore_control, "_rehydrate_emergency_after_recovery", fake_noop)
    monkeypatch.setattr(restore_control, "_validate_backend_health", fake_noop)
    monkeypatch.setattr(restore_control, "_mark_restore_failed_state", fail_mark)
    monkeypatch.setattr(restore_control, "_release_restore_guard", fake_release)
    monkeypatch.setattr(restore_control, "write_restore_journal", lambda *_args, **_kwargs: None)

    with pytest.raises(RuntimeError, match="SYSTEM_RESTORE_FAILED_EMERGENCY_RECOVERED"):
        _run(
            restore_control.execute_restore_control(
                restore_point_id=restore_id,
                emergency_point_id=emergency_id,
                artifact_name="selected.dump",
                emergency_artifact_name="emergency.dump",
                expected_revision="0020_user_resource_scopes",
                expected_fingerprint="fingerprint",
                expected_sha256=None,
                expected_manifest_checksum=None,
                emergency_expected_sha256=None,
                emergency_expected_manifest_checksum=None,
                lock_token="lock",
                actor_user_id=None,
                actor_username_snapshot=None,
                actor_display_name_snapshot=None,
                request_id="request",
            )
        )

    assert released == ["lock"]


def test_restore_request_endpoint_is_async_accepted_not_success_confirmation():
    route = next(
        route
        for route in app.routes
        if getattr(route, "path", None) == "/api/restore-points/{restore_point_id}/restore"
        and "POST" in getattr(route, "methods", set())
    )
    assert route.status_code == 202
