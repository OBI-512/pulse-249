"""Dedicated privileged restore-control Celery task."""
from __future__ import annotations

import asyncio
from uuid import UUID

from app.celery_app.config import celery_app
from app.services.restore_control import execute_restore_control


@celery_app.task(name="fttw.restore_points.execute_restore", queue="restore_control")
def execute_database_restore(
    restore_point_id: str,
    emergency_point_id: str,
    artifact_name: str,
    emergency_artifact_name: str,
    expected_revision: str | None,
    expected_fingerprint: str | None,
    expected_sha256: str | None,
    expected_manifest_checksum: str | None,
    emergency_expected_sha256: str | None,
    emergency_expected_manifest_checksum: str | None,
    lock_token: str,
    actor_user_id: str | None,
    actor_username_snapshot: str | None,
    actor_display_name_snapshot: str | None,
    request_id: str | None,
):
    return asyncio.run(
        execute_restore_control(
            restore_point_id=UUID(restore_point_id),
            emergency_point_id=UUID(emergency_point_id),
            artifact_name=artifact_name,
            emergency_artifact_name=emergency_artifact_name,
            expected_revision=expected_revision,
            expected_fingerprint=expected_fingerprint,
            expected_sha256=expected_sha256,
            expected_manifest_checksum=expected_manifest_checksum,
            emergency_expected_sha256=emergency_expected_sha256,
            emergency_expected_manifest_checksum=emergency_expected_manifest_checksum,
            lock_token=lock_token,
            actor_user_id=UUID(actor_user_id) if actor_user_id else None,
            actor_username_snapshot=actor_username_snapshot,
            actor_display_name_snapshot=actor_display_name_snapshot,
            request_id=request_id,
        )
    )
