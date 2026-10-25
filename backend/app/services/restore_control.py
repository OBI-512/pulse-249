"""Privileged restore-control orchestration.

This module is imported by the dedicated ``restore-control`` Celery worker.  It
never accepts a caller supplied filesystem path or database name.  Restore
artifacts are resolved from server-generated RestorePoint metadata and the
configured application database URL only.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import text, update
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from ..models import AuthSession, RestorePoint
from ..settings import settings
from .audit import record_audit
from .maintenance import clear_maintenance_mode, release_restore_lock
from .settings_registry import get_typed_setting
from .restore_points import (
    RESTORE_POINT_READY,
    _artifact_path,
    _manifest_path,
    _run_command,
    _schema_fingerprint,
    _sha256,
)

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _journal_path() -> Path:
    path = Path(settings.data_root).resolve() / "logs" / "restore_control.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def write_restore_journal(event: str, **safe_fields: object) -> None:
    payload = {
        "timestamp": _utcnow().isoformat(),
        "event": event,
        **{key: value for key, value in safe_fields.items() if value is not None},
    }
    with _journal_path().open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, sort_keys=True, default=str) + "\n")


def _connection_details() -> tuple[list[str], dict[str, str], str]:
    url = make_url(settings.database_url)
    if not url.database:
        raise RuntimeError("RESTORE_DATABASE_URL_INVALID")
    env = os.environ.copy()
    if url.password:
        env["PGPASSWORD"] = url.password
    prefix = ["-h", url.host or "localhost", "-p", str(url.port or 5432), "-U", url.username or ""]
    return prefix, env, str(url.database)


_TRANSACTION_TIMEOUT_SET = re.compile(
    r"^\s*SET\s+transaction_timeout\s*=\s*0\s*;\s*$",
    re.IGNORECASE,
)


def _restore_work_root() -> Path:
    root = Path(os.getenv("FTTW_RESTORE_WORK_ROOT", "/tmp/fttw_restore_work")).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    return root


def _sanitize_rendered_restore_sql(source: Path, destination: Path) -> int:
    """Remove only explicitly supported client/server compatibility statements.

    PostgreSQL 17+ dump tooling can emit ``SET transaction_timeout = 0`` while
    PostgreSQL 16 does not recognize that setting. The archive is first
    rendered to SQL by pg_restore, then only that exact statement is removed.
    Any other server incompatibility remains visible to psql and therefore
    fails the isolated preflight before the live database is touched.
    """

    removed = 0
    with source.open("r", encoding="utf-8", errors="strict") as reader:
        with destination.open("w", encoding="utf-8", newline="") as writer:
            for line in reader:
                candidate = line.rstrip("\r\n")
                if _TRANSACTION_TIMEOUT_SET.fullmatch(candidate):
                    removed += 1
                    continue
                writer.write(line)
    return removed


async def _restore_archive_into_database(artifact_name: str, database_name: str) -> int:
    """Restore one server-owned custom archive into an existing empty database.

    The custom archive is rendered with the installed pg_restore client, then
    passed through the narrow PostgreSQL-16 compatibility filter before psql
    executes it with ON_ERROR_STOP. This same path is used by both isolated
    preflight probes and the destructive restore, so passing preflight proves
    the exact restore mechanism against the exact archive.
    """

    artifact = _artifact_path(artifact_name)
    if not artifact.exists() or artifact.stat().st_size <= 0:
        raise RuntimeError("RESTORE_ARTIFACT_MISSING")

    prefix, env, _configured_database = _connection_details()
    work_root = _restore_work_root()
    token = uuid4().hex
    rendered = work_root / f"{token}.rendered.sql"
    sanitized = work_root / f"{token}.sanitized.sql"

    try:
        code, _stdout, _stderr = await _run_command(
            "pg_restore",
            "--no-owner",
            "--no-privileges",
            "--file",
            str(rendered),
            str(artifact),
            environment=env,
        )
        if code != 0 or not rendered.exists() or rendered.stat().st_size <= 0:
            raise RuntimeError("RESTORE_COMMAND_FAILED:PG_RESTORE_RENDER")
        os.chmod(rendered, 0o600)

        try:
            removed = await asyncio.to_thread(
                _sanitize_rendered_restore_sql,
                rendered,
                sanitized,
            )
        except (OSError, UnicodeError) as exc:
            raise RuntimeError("RESTORE_SQL_COMPATIBILITY_FILTER_FAILED") from exc

        if not sanitized.exists() or sanitized.stat().st_size <= 0:
            raise RuntimeError("RESTORE_SQL_COMPATIBILITY_FILTER_FAILED")
        os.chmod(sanitized, 0o600)

        code, _stdout, _stderr = await _run_command(
            "psql",
            *prefix,
            "-d",
            database_name,
            "-v",
            "ON_ERROR_STOP=1",
            "-X",
            "-f",
            str(sanitized),
            environment=env,
        )
        if code != 0:
            raise RuntimeError("RESTORE_COMMAND_FAILED:PSQL_RESTORE")

        return removed
    finally:
        rendered.unlink(missing_ok=True)
        sanitized.unlink(missing_ok=True)


async def _validate_database(
    expected_revision: str | None,
    expected_fingerprint: str | None,
    *,
    database_name: str | None = None,
) -> None:
    url = make_url(settings.database_url)
    if database_name:
        url = url.set(database=database_name)

    engine = create_async_engine(url, pool_pre_ping=True, poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with factory() as db:
            revision = await db.scalar(text("SELECT version_num FROM alembic_version LIMIT 1"))
            if expected_revision and str(revision) != expected_revision:
                raise RuntimeError("RESTORED_ALEMBIC_REVISION_MISMATCH")
            fingerprint = await _schema_fingerprint(db)
            if expected_fingerprint and fingerprint != expected_fingerprint:
                raise RuntimeError("RESTORED_SCHEMA_FINGERPRINT_MISMATCH")

            checks = {
                "ORPHAN_HIERARCHY_CHILD": """
                    SELECT count(*) FROM device_hierarchy_links h
                    LEFT JOIN devices p ON p.id = h.parent_device_id
                    LEFT JOIN devices c ON c.id = h.child_device_id
                    WHERE p.id IS NULL OR c.id IS NULL
                """,
                "BACKHAUL_CUSTOMER_SERVICE": """
                    SELECT count(*) FROM customer_services cs
                    JOIN sectors s ON s.id = cs.sector_id
                    WHERE s.role = 'BACKHAUL'
                """,
            }
            for code, query in checks.items():
                count = int(await db.scalar(text(query)) or 0)
                if count:
                    raise RuntimeError(code)
    finally:
        await engine.dispose()


async def _preflight_restore_environment(
    *artifact_specs: tuple[str, str | None, str | None],
) -> list[dict[str, object]]:
    """Perform a real isolated restore of every archive before live replacement.

    This gate goes beyond ``pg_restore --list``. Each archive is restored into
    a uniquely generated temporary PostgreSQL database using the exact same
    compatibility/filter/replay path that will later be used against the live
    application database. The restored schema/revision and critical domain
    invariants are validated, then the probe database is removed.

    No configured/live application database is dropped or replaced here.
    """

    if not settings.enable_database_restore:
        raise RuntimeError("DATABASE_RESTORE_NOT_ENABLED_IN_CONTROL_SERVICE")
    if not artifact_specs:
        raise RuntimeError("RESTORE_PREFLIGHT_NO_ARTIFACTS")

    prefix, env, configured_database = _connection_details()
    results: list[dict[str, object]] = []

    checks: tuple[tuple[str, ...], ...] = (
        ("psql", *prefix, "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-A", "-t", "-q", "-c", "SELECT 1"),
        ("dropdb", "--version"),
        ("createdb", "--version"),
        ("pg_restore", "--version"),
    )
    for command in checks:
        code, _stdout, _stderr = await _run_command(*command, environment=env)
        if code != 0:
            raise RuntimeError(f"RESTORE_PREFLIGHT_COMMAND_FAILED:{command[0]}")

    for artifact_name, expected_revision, expected_fingerprint in artifact_specs:
        artifact = _artifact_path(artifact_name)
        if not artifact.exists() or artifact.stat().st_size <= 0:
            raise RuntimeError("RESTORE_ARTIFACT_MISSING")

        code, _stdout, _stderr = await _run_command(
            "pg_restore",
            "--list",
            str(artifact),
            environment=env,
        )
        if code != 0:
            raise RuntimeError("RESTORE_PREFLIGHT_ARCHIVE_INVALID")

        probe_database = f"fttw_restore_probe_{uuid4().hex[:16]}"
        if probe_database == configured_database:
            raise RuntimeError("RESTORE_PREFLIGHT_DATABASE_NAME_COLLISION")

        created = False
        primary_error: Exception | None = None
        try:
            code, _stdout, _stderr = await _run_command(
                "createdb",
                *prefix,
                probe_database,
                environment=env,
            )
            if code != 0:
                raise RuntimeError("RESTORE_PREFLIGHT_PROBE_CREATE_FAILED")
            created = True

            removed = await _restore_archive_into_database(artifact_name, probe_database)
            await _validate_database(
                expected_revision,
                expected_fingerprint,
                database_name=probe_database,
            )
        except Exception as exc:
            primary_error = exc
            raise
        finally:
            if created:
                code, _stdout, _stderr = await _run_command(
                    "dropdb",
                    *prefix,
                    "--if-exists",
                    "--force",
                    probe_database,
                    environment=env,
                )
                if code != 0 and primary_error is None:
                    raise RuntimeError("RESTORE_PREFLIGHT_PROBE_CLEANUP_FAILED")

        results.append(
            {
                "artifact_name": artifact_name,
                "compatibility_statements_removed": removed,
                "probe_database": probe_database,
            }
        )

    return results


async def _replace_database(artifact_name: str) -> None:
    """Replace only the configured application database using the preflighted path."""

    if not settings.enable_database_restore:
        raise RuntimeError("DATABASE_RESTORE_NOT_ENABLED_IN_CONTROL_SERVICE")
    artifact = _artifact_path(artifact_name)
    if not artifact.exists() or artifact.stat().st_size <= 0:
        raise RuntimeError("RESTORE_ARTIFACT_MISSING")

    prefix, env, database_name = _connection_details()

    code, _stdout, _stderr = await _run_command(
        "dropdb",
        *prefix,
        "--if-exists",
        "--force",
        database_name,
        environment=env,
    )
    if code != 0:
        raise RuntimeError("RESTORE_COMMAND_FAILED:DROPDB")

    code, _stdout, _stderr = await _run_command(
        "createdb",
        *prefix,
        database_name,
        environment=env,
    )
    if code != 0:
        raise RuntimeError("RESTORE_COMMAND_FAILED:CREATEDB")

    await _restore_archive_into_database(artifact_name, database_name)


async def _validate_restored_database(
    expected_revision: str | None,
    expected_fingerprint: str | None,
) -> None:
    await _validate_database(expected_revision, expected_fingerprint)


def _read_manifest(
    artifact_name: str,
    *,
    expected_sha256: str | None = None,
    expected_manifest_checksum: str | None = None,
) -> dict[str, object]:
    """Read and validate a server-owned restore manifest.

    Restore-point rows are created in the same transaction that invokes
    ``pg_dump``. PostgreSQL therefore cannot see that new metadata row inside
    its own dump. After restoring such a dump we deliberately rehydrate the
    metadata row from the independently persisted, checksummed manifest.
    """

    artifact = _artifact_path(artifact_name)
    manifest_path = _manifest_path(artifact_name)
    if not artifact.exists() or artifact.stat().st_size <= 0 or not manifest_path.exists():
        raise RuntimeError("RESTORE_ARTIFACT_OR_MANIFEST_MISSING")
    artifact_sha = _sha256(artifact)
    if expected_sha256 and artifact_sha != expected_sha256:
        raise RuntimeError("RESTORE_ARTIFACT_CHECKSUM_MISMATCH")
    raw = manifest_path.read_text(encoding="utf-8")
    manifest_checksum = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    if expected_manifest_checksum and manifest_checksum != expected_manifest_checksum:
        raise RuntimeError("RESTORE_MANIFEST_CHECKSUM_MISMATCH")
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("RESTORE_MANIFEST_INVALID") from exc
    if manifest.get("artifact_name") != artifact_name:
        raise RuntimeError("RESTORE_MANIFEST_ARTIFACT_MISMATCH")
    if manifest.get("sha256") != artifact_sha:
        raise RuntimeError("RESTORE_ARTIFACT_CHECKSUM_MISMATCH")
    return manifest


async def _rehydrate_restore_point(
    db: AsyncSession,
    *,
    restore_point_id: UUID,
    artifact_name: str,
    status: str,
    pinned: bool,
    request_id: str | None,
    expected_sha256: str | None = None,
    expected_manifest_checksum: str | None = None,
) -> RestorePoint:
    manifest = _read_manifest(
        artifact_name,
        expected_sha256=expected_sha256,
        expected_manifest_checksum=expected_manifest_checksum,
    )
    if manifest.get("restore_point_id") != str(restore_point_id):
        raise RuntimeError("RESTORE_MANIFEST_POINT_MISMATCH")

    point = await db.get(RestorePoint, restore_point_id)
    retention_days = int((await get_typed_setting(db, "restore_points.retention_days"))["value"])
    now = _utcnow()
    if point is None:
        point = RestorePoint(
            id=restore_point_id,
            source=str(manifest.get("source") or "MANUAL"),
            status=status,
            artifact_name=artifact_name,
            metadata_={},
        )
        db.add(point)

    point.status = status
    point.artifact_name = artifact_name
    point.artifact_size = int(manifest.get("artifact_size") or _artifact_path(artifact_name).stat().st_size)
    point.sha256 = str(manifest.get("sha256") or _sha256(_artifact_path(artifact_name)))
    raw_manifest = _manifest_path(artifact_name).read_text(encoding="utf-8")
    point.manifest_checksum = hashlib.sha256(raw_manifest.encode("utf-8")).hexdigest()
    point.postgres_major_version = str(manifest.get("postgres_major_version") or "unknown")
    point.pg_dump_version = str(manifest.get("pg_dump_version") or "unknown")
    point.application_version = str(manifest.get("application_version") or "unknown")
    point.image_identifier = str(manifest.get("image_identifier") or "unknown")
    point.alembic_revision = str(manifest.get("alembic_revision") or "unknown")
    point.schema_fingerprint = str(manifest.get("schema_fingerprint") or "")
    point.retention_until = now + timedelta(days=retention_days)
    point.pinned = pinned
    point.completed_at = now
    point.failure_code = None
    point.failure_message = None
    point.request_id = point.request_id or request_id
    point.metadata_ = {
        **(point.metadata_ or {}),
        "manifest_name": _manifest_path(artifact_name).name,
        "rehydrated_after_restore": True,
    }
    return point


async def _validate_backend_health(*, attempts: int = 12, delay_seconds: float = 1.0) -> None:
    """Confirm the running API reconnects successfully to restored PostgreSQL."""

    def check_once() -> bool:
        request = urllib.request.Request(settings.restore_health_url, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                if response.status != 200:
                    return False
                payload = json.loads(response.read().decode("utf-8"))
                return payload.get("status") == "online" and payload.get("database") == "online"
        except Exception:
            return False

    for _ in range(attempts):
        if await asyncio.to_thread(check_once):
            return
        await asyncio.sleep(delay_seconds)
    raise RuntimeError("RESTORED_API_HEALTH_CHECK_FAILED")


async def _post_restore_finalize(
    *,
    restore_point_id: UUID,
    emergency_point_id: UUID,
    artifact_name: str,
    emergency_artifact_name: str,
    expected_sha256: str | None,
    expected_manifest_checksum: str | None,
    emergency_expected_sha256: str | None,
    emergency_expected_manifest_checksum: str | None,
    actor_user_id: UUID | None,
    actor_username_snapshot: str | None,
    actor_display_name_snapshot: str | None,
    request_id: str | None,
) -> None:
    engine = create_async_engine(settings.database_url, pool_pre_ping=True, poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with factory() as db:
            now = _utcnow()
            await db.execute(update(AuthSession).where(AuthSession.revoked_at.is_(None)).values(revoked_at=now))
            point = await _rehydrate_restore_point(
                db, restore_point_id=restore_point_id, artifact_name=artifact_name,
                status="RESTORED", pinned=False, request_id=request_id,
                expected_sha256=expected_sha256,
                expected_manifest_checksum=expected_manifest_checksum,
            )
            point.metadata_ = {**(point.metadata_ or {}), "last_restored_at": now.isoformat()}
            await _rehydrate_restore_point(
                db, restore_point_id=emergency_point_id, artifact_name=emergency_artifact_name,
                status=RESTORE_POINT_READY, pinned=False, request_id=request_id,
                expected_sha256=emergency_expected_sha256,
                expected_manifest_checksum=emergency_expected_manifest_checksum,
            )
            # Reconstruct start evidence because the pre-restore audit row may
            # have been rolled back with the database state itself. The
            # external journal remains the independent continuity record.
            await record_audit(
                db,
                action="SYSTEM_RESTORE_STARTED",
                entity_type="RestorePoint",
                entity_id=restore_point_id,
                actor_user_id=actor_user_id,
                actor_username_snapshot=actor_username_snapshot,
                actor_display_name_snapshot=actor_display_name_snapshot,
                request_id=request_id,
                description="Full-system restore was initiated (reconstructed after database replacement).",
                metadata={"emergency_restore_point_id": str(emergency_point_id), "reconstructed": True},
            )
            await record_audit(
                db,
                action="SYSTEM_RESTORE_COMPLETED",
                entity_type="RestorePoint",
                entity_id=restore_point_id,
                actor_user_id=actor_user_id,
                actor_username_snapshot=actor_username_snapshot,
                actor_display_name_snapshot=actor_display_name_snapshot,
                request_id=request_id,
                description="Full-system database restore completed and post-restore validation passed.",
                metadata={"emergency_restore_point_id": str(emergency_point_id)},
            )
            await db.commit()
    finally:
        await engine.dispose()


async def _rehydrate_emergency_after_recovery(
    *,
    emergency_point_id: UUID,
    emergency_artifact_name: str,
    request_id: str | None,
    expected_sha256: str | None,
    expected_manifest_checksum: str | None,
) -> None:
    """Ensure the emergency artifact remains represented after rollback."""

    engine = create_async_engine(settings.database_url, pool_pre_ping=True, poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with factory() as db:
            await _rehydrate_restore_point(
                db, restore_point_id=emergency_point_id, artifact_name=emergency_artifact_name,
                status=RESTORE_POINT_READY, pinned=True, request_id=request_id,
                expected_sha256=expected_sha256,
                expected_manifest_checksum=expected_manifest_checksum,
            )
            await db.commit()
    finally:
        await engine.dispose()


def _stable_restore_error_code(exc: Exception | None) -> str:
    """Return a safe stable code without persisting subprocess output."""

    if exc is None:
        return "RESTORE_FAILURE_UNKNOWN"
    value = str(exc).strip()
    if value and all(ch.isalnum() or ch in "_:-." for ch in value):
        return value.upper()[:100]
    detail = getattr(exc, "detail", None)
    if isinstance(detail, dict):
        code = detail.get("code")
        if isinstance(code, str) and code:
            return code[:100]
    return type(exc).__name__[:100]


async def _mark_restore_failed_state(
    *,
    restore_point_id: UUID,
    emergency_point_id: UUID,
    artifact_name: str,
    expected_sha256: str | None,
    expected_manifest_checksum: str | None,
    actor_user_id: UUID | None,
    actor_username_snapshot: str | None,
    actor_display_name_snapshot: str | None,
    request_id: str | None,
    error_code: str,
    description: str,
) -> None:
    """Persist a failed restore result in whichever safe database is active."""

    engine = create_async_engine(settings.database_url, pool_pre_ping=True, poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with factory() as db:
            point = await db.get(RestorePoint, restore_point_id)
            if point is None:
                point = await _rehydrate_restore_point(
                    db,
                    restore_point_id=restore_point_id,
                    artifact_name=artifact_name,
                    status="FAILED",
                    pinned=False,
                    request_id=request_id,
                    expected_sha256=expected_sha256,
                    expected_manifest_checksum=expected_manifest_checksum,
                )
            point.status = "FAILED"
            point.completed_at = _utcnow()
            point.failure_code = error_code[:100]
            point.failure_message = description
            point.metadata_ = {
                **(point.metadata_ or {}),
                "emergency_restore_point_id": str(emergency_point_id),
                "restore_failure_recorded_at": _utcnow().isoformat(),
            }

            emergency = await db.get(RestorePoint, emergency_point_id)
            if emergency is not None:
                emergency.pinned = True

            await record_audit(
                db,
                action="SYSTEM_RESTORE_FAILED",
                entity_type="RestorePoint",
                entity_id=restore_point_id,
                actor_user_id=actor_user_id,
                actor_username_snapshot=actor_username_snapshot,
                actor_display_name_snapshot=actor_display_name_snapshot,
                request_id=request_id,
                description=description,
                metadata={
                    "emergency_restore_point_id": str(emergency_point_id),
                    "error_code": error_code,
                },
                result="FAILURE",
            )
            await db.commit()
    finally:
        await engine.dispose()


async def _release_restore_guard(*, lock_token: str) -> None:
    """Clear maintenance first, then release only this restore's lock."""

    await clear_maintenance_mode()
    await release_restore_lock(token=lock_token)


async def execute_restore_control(
    *,
    restore_point_id: UUID,
    emergency_point_id: UUID,
    artifact_name: str,
    emergency_artifact_name: str,
    expected_revision: str | None,
    expected_fingerprint: str | None,
    expected_sha256: str | None,
    expected_manifest_checksum: str | None,
    emergency_expected_sha256: str | None,
    emergency_expected_manifest_checksum: str | None,
    lock_token: str,
    actor_user_id: UUID | None,
    actor_username_snapshot: str | None,
    actor_display_name_snapshot: str | None,
    request_id: str | None,
) -> dict[str, object]:
    """Replace PostgreSQL and recover automatically from the emergency point.

    Predictable/tooling/archive failures are resolved before any destructive
    database command. Once destructive replacement begins, any failure triggers
    emergency recovery and maintenance is cleared only after the recovered API
    is healthy.
    """

    write_restore_journal(
        "SYSTEM_RESTORE_EXECUTOR_STARTED",
        restore_point_id=str(restore_point_id),
        emergency_point_id=str(emergency_point_id),
        request_id=request_id,
    )
    logger.warning(
        "system_restore_started",
        extra={"event": "SYSTEM_RESTORE_STARTED", "entity_id": restore_point_id},
    )

    # -----------------------------
    # Phase 1: non-destructive gate
    # -----------------------------
    try:
        selected_manifest = _read_manifest(
            artifact_name,
            expected_sha256=expected_sha256,
            expected_manifest_checksum=expected_manifest_checksum,
        )
        emergency_manifest = _read_manifest(
            emergency_artifact_name,
            expected_sha256=emergency_expected_sha256,
            expected_manifest_checksum=emergency_expected_manifest_checksum,
        )
        if selected_manifest.get("restore_point_id") != str(restore_point_id):
            raise RuntimeError("RESTORE_MANIFEST_POINT_MISMATCH")
        if emergency_manifest.get("restore_point_id") != str(emergency_point_id):
            raise RuntimeError("EMERGENCY_RESTORE_MANIFEST_POINT_MISMATCH")

        preflight_results = (
            await _preflight_restore_environment(
                (
                    artifact_name,
                    str(selected_manifest.get("alembic_revision") or expected_revision or "") or None,
                    str(selected_manifest.get("schema_fingerprint") or expected_fingerprint or "") or None,
                ),
                (
                    emergency_artifact_name,
                    str(emergency_manifest.get("alembic_revision") or expected_revision or "") or None,
                    str(emergency_manifest.get("schema_fingerprint") or expected_fingerprint or "") or None,
                ),
            )
        ) or []
        write_restore_journal(
            "SYSTEM_RESTORE_PREFLIGHT_PASSED",
            restore_point_id=str(restore_point_id),
            emergency_point_id=str(emergency_point_id),
            request_id=request_id,
            isolated_restore_tested=True,
            compatibility_path="render_filter_psql",
            compatibility_statements_removed=sum(
                int(item.get("compatibility_statements_removed") or 0)
                for item in preflight_results
            ),
        )
    except Exception as exc:
        error_code = _stable_restore_error_code(exc)
        logger.exception(
            "system_restore_preflight_failed",
            extra={"event": "SYSTEM_RESTORE_PREFLIGHT_FAILED", "entity_id": restore_point_id},
        )
        write_restore_journal(
            "SYSTEM_RESTORE_FAILED",
            restore_point_id=str(restore_point_id),
            emergency_point_id=str(emergency_point_id),
            request_id=request_id,
            stage="PREFLIGHT",
            error_type=type(exc).__name__,
            error_code=error_code,
            destructive_started=False,
        )
        try:
            await _mark_restore_failed_state(
                restore_point_id=restore_point_id,
                emergency_point_id=emergency_point_id,
                artifact_name=artifact_name,
                expected_sha256=expected_sha256,
                expected_manifest_checksum=expected_manifest_checksum,
                actor_user_id=actor_user_id,
                actor_username_snapshot=actor_username_snapshot,
                actor_display_name_snapshot=actor_display_name_snapshot,
                request_id=request_id,
                error_code=error_code,
                description=(
                    "The restore could not start because its safety checks failed. "
                    "The running database was not replaced."
                ),
            )
        finally:
            await _release_restore_guard(lock_token=lock_token)
        raise RuntimeError("SYSTEM_RESTORE_PREFLIGHT_FAILED") from exc

    # -------------------------------------
    # Phase 2: destructive selected restore
    # -------------------------------------
    restore_error: Exception | None = None
    try:
        write_restore_journal(
            "SYSTEM_RESTORE_DATABASE_REPLACEMENT_STARTED",
            restore_point_id=str(restore_point_id),
            request_id=request_id,
        )
        await _replace_database(artifact_name)
        await _validate_restored_database(expected_revision, expected_fingerprint)
        await _post_restore_finalize(
            restore_point_id=restore_point_id,
            emergency_point_id=emergency_point_id,
            artifact_name=artifact_name,
            emergency_artifact_name=emergency_artifact_name,
            expected_sha256=expected_sha256,
            expected_manifest_checksum=expected_manifest_checksum,
            emergency_expected_sha256=emergency_expected_sha256,
            emergency_expected_manifest_checksum=emergency_expected_manifest_checksum,
            actor_user_id=actor_user_id,
            actor_username_snapshot=actor_username_snapshot,
            actor_display_name_snapshot=actor_display_name_snapshot,
            request_id=request_id,
        )
        await _validate_backend_health()

        write_restore_journal(
            "SYSTEM_RESTORE_COMPLETED",
            restore_point_id=str(restore_point_id),
            emergency_point_id=str(emergency_point_id),
            request_id=request_id,
        )
        logger.warning(
            "system_restore_completed",
            extra={"event": "SYSTEM_RESTORE_COMPLETED", "entity_id": restore_point_id},
        )
        await _release_restore_guard(lock_token=lock_token)
        return {"status": "RESTORED", "restore_point_id": str(restore_point_id)}
    except Exception as exc:
        restore_error = exc
        error_code = _stable_restore_error_code(exc)
        logger.exception(
            "system_restore_failed",
            extra={"event": "SYSTEM_RESTORE_FAILED", "entity_id": restore_point_id},
        )
        write_restore_journal(
            "SYSTEM_RESTORE_FAILED",
            restore_point_id=str(restore_point_id),
            emergency_point_id=str(emergency_point_id),
            request_id=request_id,
            stage="SELECTED_RESTORE",
            error_type=type(exc).__name__,
            error_code=error_code,
            destructive_started=True,
        )

    # ---------------------------------
    # Phase 3: emergency recovery
    # ---------------------------------
    recovery_error: Exception | None = None
    try:
        write_restore_journal(
            "EMERGENCY_RESTORE_STARTED",
            emergency_point_id=str(emergency_point_id),
            request_id=request_id,
        )
        await _replace_database(emergency_artifact_name)
        await _validate_restored_database(expected_revision, expected_fingerprint)
        await _rehydrate_emergency_after_recovery(
            emergency_point_id=emergency_point_id,
            emergency_artifact_name=emergency_artifact_name,
            request_id=request_id,
            expected_sha256=emergency_expected_sha256,
            expected_manifest_checksum=emergency_expected_manifest_checksum,
        )
        await _validate_backend_health()
    except Exception as exc:
        recovery_error = exc

    if recovery_error is None:
        # Recovery safety is established by database validation + API health.
        # Failure-status/audit persistence is useful evidence, but it must not
        # re-lock an otherwise healthy recovered system if that bookkeeping
        # write has its own problem.
        error_code = _stable_restore_error_code(restore_error)
        failure_state_recorded = True
        try:
            await _mark_restore_failed_state(
                restore_point_id=restore_point_id,
                emergency_point_id=emergency_point_id,
                artifact_name=artifact_name,
                expected_sha256=expected_sha256,
                expected_manifest_checksum=expected_manifest_checksum,
                actor_user_id=actor_user_id,
                actor_username_snapshot=actor_username_snapshot,
                actor_display_name_snapshot=actor_display_name_snapshot,
                request_id=request_id,
                error_code=error_code,
                description=(
                    "The selected restore failed, but the emergency pre-restore "
                    "snapshot was recovered successfully."
                ),
            )
        except Exception as state_exc:
            failure_state_recorded = False
            logger.exception(
                "restore_failure_state_record_failed",
                extra={"event": "RESTORE_FAILURE_STATE_RECORD_FAILED", "entity_id": restore_point_id},
            )
            write_restore_journal(
                "RESTORE_FAILURE_STATE_RECORD_FAILED",
                restore_point_id=str(restore_point_id),
                emergency_point_id=str(emergency_point_id),
                request_id=request_id,
                error_type=type(state_exc).__name__,
                error_code=_stable_restore_error_code(state_exc),
            )

        write_restore_journal(
            "EMERGENCY_RESTORE_COMPLETED",
            emergency_point_id=str(emergency_point_id),
            restore_point_id=str(restore_point_id),
            request_id=request_id,
            failure_state_recorded=failure_state_recorded,
        )
        await _release_restore_guard(lock_token=lock_token)
        raise RuntimeError("SYSTEM_RESTORE_FAILED_EMERGENCY_RECOVERED") from restore_error

    recovery_code = _stable_restore_error_code(recovery_error)
    write_restore_journal(
        "EMERGENCY_RESTORE_FAILED",
        emergency_point_id=str(emergency_point_id),
        restore_point_id=str(restore_point_id),
        request_id=request_id,
        stage="EMERGENCY_RECOVERY",
        error_type=type(recovery_error).__name__ if recovery_error else "Unknown",
        error_code=recovery_code,
    )
    logger.critical(
        "emergency_restore_failed",
        exc_info=recovery_error,
        extra={"event": "EMERGENCY_RESTORE_FAILED", "entity_id": emergency_point_id},
    )

    # Unsafe double failure: keep maintenance asserted. The restore lock has a
    # TTL, but maintenance intentionally persists until an operator verifies
    # database integrity and explicitly recovers access.
    raise RuntimeError("SYSTEM_RESTORE_FAILED_EMERGENCY_RECOVERY_FAILED") from restore_error
