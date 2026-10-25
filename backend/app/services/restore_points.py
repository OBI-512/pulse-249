"""Safe restore-point creation, verification, retention, and restore control.

Restore metadata is in PostgreSQL; artifacts and maintenance state are outside
the database being protected.  A full pg_restore is intentionally disabled by
default and only runs when a deliberately configured control environment sets
``ENABLE_DATABASE_RESTORE=true``.  This prevents a normal API container from
becoming an accidental destructive restore mechanism.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.audit_context import get_audit_context
from ..core.exceptions import APIError
from ..models import AuthSession, RestorePoint
from ..settings import settings
from .audit import record_audit, record_failure_audit
from .maintenance import (
    acquire_restore_lock,
    clear_maintenance_mode,
    release_restore_lock,
    set_maintenance_mode,
)
from .settings_registry import get_typed_setting

import logging

logger = logging.getLogger(__name__)


RESTORE_POINT_READY = "READY"
RESTORE_POINT_FAILED = "FAILED"
_VALID_SOURCES = {"MANUAL", "AUTOMATIC", "EMERGENCY"}
_SAFE_NAME = re.compile(r"^[0-9a-f-]{36}\.dump$")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def restore_point_root() -> Path:
    root = Path(settings.data_root).resolve() / "restore_points"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _artifact_path(name: str) -> Path:
    if not _SAFE_NAME.fullmatch(name):
        raise APIError(409, "RESTORE_POINT_ARTIFACT_INVALID", "Restore-point artifact reference is invalid.")
    root = restore_point_root()
    path = (root / name).resolve()
    if path.parent != root:
        raise APIError(409, "RESTORE_POINT_ARTIFACT_INVALID", "Restore-point artifact reference is invalid.")
    return path


def _manifest_path(name: str) -> Path:
    artifact = _artifact_path(name)
    return artifact.with_suffix(".manifest.json")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _database_command_prefix() -> tuple[list[str], dict[str, str]]:
    url = make_url(settings.database_url)
    if not url.database:
        raise APIError(409, "RESTORE_POINT_DATABASE_URL_INVALID", "Database configuration is invalid.")
    environment = os.environ.copy()
    if url.password:
        environment["PGPASSWORD"] = url.password
    return ["-h", url.host or "localhost", "-p", str(url.port or 5432), "-U", url.username or ""], environment


async def _run_command(*command: str, environment: dict[str, str]) -> tuple[int, str, str]:
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=environment,
        )
    except FileNotFoundError as exc:
        raise APIError(409, "RESTORE_POINT_TOOL_UNAVAILABLE", "PostgreSQL backup tooling is unavailable.") from exc
    stdout, stderr = await process.communicate()
    # Error text can contain a host/user/database value. Persist only its
    # presence/class through stable errors, never the subprocess output.
    return (
        process.returncode,
        stdout.decode("utf-8", errors="replace")[:1024],
        stderr.decode("utf-8", errors="replace")[:1024],
    )


async def _schema_fingerprint(db: AsyncSession) -> str:
    rows = list(
        (
            await db.execute(
                text(
                    """
                SELECT table_name || ':' || column_name || ':' || data_type
                FROM information_schema.columns
                WHERE table_schema = 'public'
                ORDER BY table_name, ordinal_position
                    """
                )
            )
        ).scalars().all()
    )
    return hashlib.sha256("\n".join(rows).encode("utf-8")).hexdigest()


async def _compatibility_metadata(db: AsyncSession) -> dict[str, str]:
    pg_version = await db.scalar(text("SHOW server_version"))
    revision = await db.scalar(text("SELECT version_num FROM alembic_version LIMIT 1"))
    _, environment = _database_command_prefix()
    exit_code, output, _ = await _run_command("pg_dump", "--version", environment=environment)
    pg_dump_version = output.strip() if exit_code == 0 else "unavailable"
    return {
        "postgres_major_version": str(pg_version).split(".", 1)[0],
        "pg_dump_version": pg_dump_version,
        "application_version": "1.4.0",
        "image_identifier": os.getenv("FTTW_IMAGE_IDENTIFIER", "unknown"),
        "alembic_revision": str(revision or "unknown"),
        "schema_fingerprint": await _schema_fingerprint(db),
    }


async def create_restore_point(
    db: AsyncSession,
    *,
    source: str,
    created_by_user_id: UUID | None,
    description: str | None = None,
) -> RestorePoint:
    if source not in _VALID_SOURCES:
        raise APIError(422, "RESTORE_POINT_SOURCE_INVALID", "Restore-point source is invalid.")
    restore_enabled = bool((await get_typed_setting(db, "restore_points.enabled"))["value"])
    if not restore_enabled and source == "AUTOMATIC":
        raise APIError(409, "RESTORE_POINTS_DISABLED", "Automatic restore points are disabled.")
    context = get_audit_context()
    point = RestorePoint(
        source=source,
        status="CREATING",
        created_by_user_id=created_by_user_id,
        description=description,
        started_at=_utcnow(),
        retention_until=_utcnow() + timedelta(days=int((await get_typed_setting(db, "restore_points.retention_days"))["value"])),
        request_id=context.request_id,
        metadata_={},
    )
    db.add(point)
    await db.flush()
    artifact_name = f"{point.id}.dump"
    path = _artifact_path(artifact_name)
    manifest_path = _manifest_path(artifact_name)
    point.artifact_name = artifact_name
    await record_audit(
        db, action="RESTORE_POINT_CREATE_STARTED", entity_type="RestorePoint", entity_id=point.id,
        entity_display_snapshot={"source": source, "artifact_name": artifact_name},
        description="Restore-point creation started.", metadata={"source": source},
    )
    await db.flush()

    try:
        prefix, environment = _database_command_prefix()
        url = make_url(settings.database_url)
        code, _, _ = await _run_command(
            "pg_dump", *prefix, "--format=custom", "--no-owner", "--no-privileges",
            "--file", str(path), str(url.database), environment=environment,
        )
        if code != 0 or not path.exists() or path.stat().st_size <= 0:
            raise APIError(409, "RESTORE_POINT_BACKUP_FAILED", "PostgreSQL backup command failed safely.")
        compatibility = await _compatibility_metadata(db)
        checksum = _sha256(path)
        manifest = {
            "restore_point_id": str(point.id), "source": source,
            "artifact_name": artifact_name, "artifact_size": path.stat().st_size,
            "sha256": checksum, "created_at": _utcnow().isoformat(), **compatibility,
        }
        manifest_payload = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
        manifest_path.write_text(manifest_payload, encoding="utf-8")
        point.status = RESTORE_POINT_READY
        point.completed_at = _utcnow()
        point.artifact_size = path.stat().st_size
        point.sha256 = checksum
        point.manifest_checksum = hashlib.sha256(manifest_payload.encode("utf-8")).hexdigest()
        for field, value in compatibility.items():
            setattr(point, field, value)
        point.metadata_ = {"manifest_name": manifest_path.name}
        await record_audit(
            db, action="RESTORE_POINT_CREATED", entity_type="RestorePoint", entity_id=point.id,
            entity_display_snapshot={"source": source, "artifact_name": artifact_name},
            description="Restore-point creation completed.",
            after_summary={"status": RESTORE_POINT_READY, "artifact_size": point.artifact_size},
        )
        logger.info("restore_point_created", extra={"event": "RESTORE_POINT_CREATED", "entity_id": point.id})
        return point
    except Exception as exc:
        path.unlink(missing_ok=True)
        manifest_path.unlink(missing_ok=True)
        point.status = RESTORE_POINT_FAILED
        point.completed_at = _utcnow()
        point.failure_code = getattr(exc, "detail", {}).get("code", "RESTORE_POINT_CREATION_FAILED")
        point.failure_message = "Restore-point creation failed safely; inspect operational evidence."
        await record_audit(
            db, action="RESTORE_POINT_CREATE_FAILED", entity_type="RestorePoint", entity_id=point.id,
            entity_display_snapshot={"source": source}, description="Restore-point creation failed.",
            metadata={"error_code": point.failure_code}, result="FAILURE",
        )
        logger.exception("restore_point_creation_failed", extra={"event": "RESTORE_POINT_CREATE_FAILED", "entity_id": point.id})
        raise


async def get_restore_point(db: AsyncSession, restore_point_id: UUID, *, lock: bool = False) -> RestorePoint:
    statement = select(RestorePoint).where(RestorePoint.id == restore_point_id)
    if lock:
        statement = statement.with_for_update().execution_options(populate_existing=True)
    point = await db.scalar(statement)
    if point is None or point.status == "DELETED":
        raise APIError(404, "RESTORE_POINT_NOT_FOUND", "Restore point not found.")
    return point


async def verify_restore_point(db: AsyncSession, *, restore_point_id: UUID) -> RestorePoint:
    point = await get_restore_point(db, restore_point_id, lock=True)
    if point.status not in {RESTORE_POINT_READY, "RESTORED"} or not point.artifact_name:
        raise APIError(409, "RESTORE_POINT_NOT_READY", "Restore point is not ready for verification.")
    path = _artifact_path(point.artifact_name)
    manifest_path = _manifest_path(point.artifact_name)
    if not path.exists() or not manifest_path.exists() or path.stat().st_size <= 0:
        raise APIError(409, "RESTORE_POINT_ARTIFACT_MISSING", "Restore-point artifact is missing.")
    if _sha256(path) != point.sha256:
        raise APIError(409, "RESTORE_POINT_CHECKSUM_MISMATCH", "Restore-point checksum does not match.")
    raw_manifest = manifest_path.read_text(encoding="utf-8")
    if hashlib.sha256(raw_manifest.encode("utf-8")).hexdigest() != point.manifest_checksum:
        raise APIError(409, "RESTORE_POINT_MANIFEST_MISMATCH", "Restore-point manifest checksum does not match.")
    try:
        manifest = json.loads(raw_manifest)
    except json.JSONDecodeError as exc:
        raise APIError(409, "RESTORE_POINT_MANIFEST_INVALID", "Restore-point manifest is invalid.") from exc
    if manifest.get("restore_point_id") != str(point.id) or manifest.get("sha256") != point.sha256:
        raise APIError(409, "RESTORE_POINT_MANIFEST_INVALID", "Restore-point manifest is incompatible.")
    current = await _compatibility_metadata(db)
    for key in ("postgres_major_version", "alembic_revision", "schema_fingerprint"):
        if manifest.get(key) != current[key]:
            raise APIError(409, "RESTORE_POINT_INCOMPATIBLE", "Restore point is incompatible with the running system.")
    await record_audit(
        db, action="RESTORE_POINT_VERIFIED", entity_type="RestorePoint", entity_id=point.id,
        entity_display_snapshot={"source": point.source, "artifact_name": point.artifact_name},
        description="Restore-point checksums and compatibility verified.",
    )
    return point


async def delete_restore_point(db: AsyncSession, *, restore_point_id: UUID) -> RestorePoint:
    """Stage metadata deletion; filesystem removal happens after DB commit.

    The database state is authoritative.  Deleting an artifact before the
    surrounding transaction commits could leave a READY row pointing to a
    missing dump if commit fails.  Callers commit first, then invoke
    ``delete_restore_point_artifacts``.
    """

    point = await get_restore_point(db, restore_point_id, lock=True)
    if point.pinned:
        raise APIError(409, "RESTORE_POINT_PINNED", "Pinned restore point cannot be deleted.")
    if point.status in {"CREATING", "RESTORING"}:
        raise APIError(409, "RESTORE_POINT_BUSY", "Restore point is busy.")
    point.status = "DELETED"
    await record_audit(
        db, action="RESTORE_POINT_DELETED", entity_type="RestorePoint", entity_id=point.id,
        entity_display_snapshot={"source": point.source, "artifact_name": point.artifact_name},
        description="Restore point deleted.",
    )
    return point


def delete_restore_point_artifacts(artifact_name: str | None) -> bool:
    """Best-effort removal for artifacts whose metadata is already deleted."""

    if not artifact_name:
        return True
    try:
        _artifact_path(artifact_name).unlink(missing_ok=True)
        _manifest_path(artifact_name).unlink(missing_ok=True)
        return True
    except OSError:
        logger.exception("restore_point_artifact_cleanup_failed", extra={"event": "RESTORE_POINT_ARTIFACT_CLEANUP_FAILED"})
        return False


async def request_database_restore(
    db: AsyncSession,
    *,
    restore_point_id: UUID,
    confirmation: str,
    actor_user_id: UUID,
    actor_username_snapshot: str | None = None,
    actor_display_name_snapshot: str | None = None,
) -> dict[str, str | None]:
    """Prepare a controlled restore and return immutable task arguments.

    The API process never executes pg_restore.  It verifies both artifacts,
    creates and pins the emergency snapshot, enters Redis maintenance mode, and
    stages audit/status changes.  The caller commits this transaction before
    dispatching the returned arguments to the dedicated restore-control queue.
    """

    if confirmation != str(restore_point_id):
        raise APIError(422, "RESTORE_POINT_CONFIRMATION_REQUIRED", "Confirmation must equal the restore-point ID.")
    if not settings.enable_database_restore:
        raise APIError(
            409, "RESTORE_OPERATION_DISABLED",
            "Database restore is disabled until the dedicated restore-control service is enabled.",
        )

    token = secrets.token_urlsafe(32)
    try:
        if not await acquire_restore_lock(token=token, ttl_seconds=7200):
            raise APIError(409, "RESTORE_ALREADY_IN_PROGRESS", "A restore operation is already in progress.")
    except APIError:
        raise
    except Exception as exc:
        logger.exception("restore_lock_unavailable", extra={"event": "RESTORE_LOCK_UNAVAILABLE", "entity_id": restore_point_id})
        raise APIError(409, "RESTORE_LOCK_UNAVAILABLE", "Restore lock is unavailable.") from exc

    context = get_audit_context()
    emergency: RestorePoint | None = None
    try:
        point = await get_restore_point(db, restore_point_id, lock=True)
        if point.status not in {RESTORE_POINT_READY, "RESTORED"}:
            raise APIError(409, "RESTORE_POINT_NOT_READY", "Restore point is not ready for restoration.")
        await verify_restore_point(db, restore_point_id=point.id)
        await set_maintenance_mode(restore_point_id=str(point.id), request_id=context.request_id)

        emergency = await create_restore_point(
            db, source="EMERGENCY", created_by_user_id=actor_user_id,
            description=f"Emergency snapshot before restore {point.id}",
        )
        if emergency.status != RESTORE_POINT_READY or not emergency.artifact_name:
            raise APIError(409, "EMERGENCY_RESTORE_POINT_FAILED", "Emergency restore point was not created.")
        emergency.pinned = True
        await verify_restore_point(db, restore_point_id=emergency.id)

        point.status = "RESTORING"
        point.started_at = _utcnow()
        point.failure_code = None
        point.failure_message = None
        point.metadata_ = {
            **(point.metadata_ or {}),
            "emergency_restore_point_id": str(emergency.id),
            "restore_requested_at": _utcnow().isoformat(),
        }
        await record_audit(
            db,
            action="SYSTEM_RESTORE_STARTED",
            entity_type="RestorePoint",
            entity_id=point.id,
            actor_user_id=actor_user_id,
            actor_username_snapshot=actor_username_snapshot,
            actor_display_name_snapshot=actor_display_name_snapshot,
            entity_display_snapshot={"source": point.source, "artifact_name": point.artifact_name},
            description="Full-system restore prepared and queued for the dedicated restore-control worker.",
            metadata={"emergency_restore_point_id": str(emergency.id)},
        )
        await db.flush()
        logger.warning("system_restore_prepared", extra={"event": "SYSTEM_RESTORE_STARTED", "entity_id": point.id})
        return {
            "restore_point_id": str(point.id),
            "emergency_point_id": str(emergency.id),
            "artifact_name": point.artifact_name,
            "emergency_artifact_name": emergency.artifact_name,
            "expected_revision": point.alembic_revision,
            "expected_fingerprint": point.schema_fingerprint,
            "expected_sha256": point.sha256,
            "expected_manifest_checksum": point.manifest_checksum,
            "emergency_expected_sha256": emergency.sha256,
            "emergency_expected_manifest_checksum": emergency.manifest_checksum,
            "lock_token": token,
            "actor_user_id": str(actor_user_id),
            "actor_username_snapshot": actor_username_snapshot,
            "actor_display_name_snapshot": actor_display_name_snapshot,
            "request_id": context.request_id,
        }
    except Exception as exc:
        await db.rollback()
        await record_failure_audit(
            action="SYSTEM_RESTORE_FAILED", entity_type="RestorePoint", entity_id=restore_point_id,
            actor_user_id=actor_user_id, actor_username_snapshot=actor_username_snapshot,
            actor_display_name_snapshot=actor_display_name_snapshot,
            request_id=context.request_id,
            description="Restore workflow failed before database replacement.",
            metadata={"error_code": getattr(exc, "detail", {}).get("code", "RESTORE_PREPARATION_FAILED")},
        )
        await clear_maintenance_mode()
        try:
            await release_restore_lock(token=token)
        except Exception:
            logger.exception("restore_lock_release_failed", extra={"event": "RESTORE_LOCK_RELEASE_FAILED", "entity_id": restore_point_id})
        raise


async def automatic_restore_point_due(db: AsyncSession, *, now: datetime | None = None) -> bool:
    if not bool((await get_typed_setting(db, "restore_points.enabled"))["value"]):
        return False
    try:
        zone = ZoneInfo((await get_typed_setting(db, "restore_points.timezone"))["value"])
    except ZoneInfoNotFoundError:
        return False
    current = (now or _utcnow()).astimezone(zone)
    try:
        schedule_time = (await get_typed_setting(db, "restore_points.schedule_time"))["value"]
        hour, minute = (int(part) for part in schedule_time.split(":", 1))
    except ValueError:
        return False
    if current.hour != hour or current.minute != minute:
        return False
    latest = await db.scalar(
        select(RestorePoint)
        .where(RestorePoint.source == "AUTOMATIC", RestorePoint.status.in_((RESTORE_POINT_READY, "RESTORED")))
        .order_by(RestorePoint.completed_at.desc())
        .limit(1)
    )
    return (
        latest is None
        or latest.completed_at is None
        or latest.completed_at.astimezone(zone).date() < current.date()
    )


async def set_restore_point_pin(
    db: AsyncSession,
    *,
    restore_point_id: UUID,
    pinned: bool,
) -> RestorePoint:
    point = await get_restore_point(db, restore_point_id, lock=True)
    if point.status in {"CREATING", "RESTORING"}:
        raise APIError(409, "RESTORE_POINT_BUSY", "Restore point is busy.")
    if point.pinned == pinned:
        return point
    point.pinned = pinned
    await record_audit(
        db,
        action="RESTORE_POINT_PINNED" if pinned else "RESTORE_POINT_UNPINNED",
        entity_type="RestorePoint",
        entity_id=point.id,
        entity_display_snapshot={"source": point.source, "artifact_name": point.artifact_name},
        description="Restore point retention protection changed.",
        after_summary={"pinned": pinned},
    )
    return point


async def cleanup_expired_restore_points(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    limit: int = 100,
) -> dict[str, object]:
    """Delete expired unpinned restore points in a lock-safe bounded batch."""

    cutoff = now or _utcnow()
    rows = list(
        (
            await db.scalars(
                select(RestorePoint)
                .where(
                    RestorePoint.status.in_((RESTORE_POINT_READY, "RESTORED", RESTORE_POINT_FAILED)),
                    RestorePoint.pinned.is_(False),
                    RestorePoint.retention_until.is_not(None),
                    RestorePoint.retention_until <= cutoff,
                )
                .order_by(RestorePoint.retention_until, RestorePoint.id)
                .with_for_update(skip_locked=True)
                .limit(max(1, min(limit, 500)))
                .execution_options(populate_existing=True)
            )
        ).all()
    )
    deleted: list[str] = []
    artifacts: list[str] = []
    for point in rows:
        # Work against the locked object directly; calling get_restore_point
        # again is unnecessary and can obscure the SKIP LOCKED behavior.
        if point.artifact_name:
            artifacts.append(point.artifact_name)
        point.status = "DELETED"
        await record_audit(
            db,
            action="RESTORE_POINT_RETENTION_DELETED",
            entity_type="RestorePoint",
            entity_id=point.id,
            entity_display_snapshot={"source": point.source, "artifact_name": point.artifact_name},
            description="Expired unpinned restore point removed by retention policy.",
        )
        deleted.append(str(point.id))
    return {
        "considered": len(rows),
        "deleted": len(deleted),
        "restore_point_ids": deleted,
        "artifact_names": artifacts,
    }
