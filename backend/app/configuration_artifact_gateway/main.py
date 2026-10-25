from __future__ import annotations

import hashlib
import logging
from uuid import UUID

from fastapi import FastAPI, Request
from fastapi.responses import Response

from app.configuration.artifact_edge import (
    ConfigurationArtifactEdgeError,
    resolve_effective_artifact_source,
)
from app.configuration.artifact_leases import (
    ArtifactLease,
    ArtifactLeaseStore,
    ConfigurationArtifactLeaseError,
    redis_client,
)
from app.configuration.artifacts import ConfigurationArtifactError, decrypt_snapshot
from app.db.session import AsyncSessionLocal
from app.models.configuration import ConfigurationOperation, ConfigurationSnapshot


logger = logging.getLogger(__name__)

app = FastAPI(
    title="FTTW Configuration Artifact Gateway",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


_NOT_FOUND_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}


def _not_found() -> Response:
    return Response(status_code=404, headers=_NOT_FOUND_HEADERS)


def _lease_matches_active_operation(
    lease: ArtifactLease,
    operation: ConfigurationOperation,
    snapshot: ConfigurationSnapshot,
) -> bool:
    if (
        str(operation.id) != lease.operation_id
        or str(operation.device_id) != lease.device_id
        or str(operation.template_version_id) != lease.template_version_id
        or str(snapshot.id) != lease.snapshot_id
        or snapshot.device_id != operation.device_id
        or snapshot.template_version_id != operation.template_version_id
        or snapshot.artifact_status != "READY"
        or not snapshot.is_restorable
        or snapshot.plaintext_sha256 != lease.expected_plaintext_sha256
        or snapshot.normalized_sha256 != lease.expected_plaintext_sha256
    ):
        return False
    if operation.status == "RUNNING":
        return (
            operation.operation_type == "RESTORE"
            and operation.candidate_snapshot_id == snapshot.id
        )
    if operation.status == "ROLLING_BACK":
        return operation.pre_change_snapshot_id == snapshot.id
    return False


async def _load_authorized_payload(lease: ArtifactLease) -> bytes:
    try:
        operation_id = UUID(lease.operation_id)
        snapshot_id = UUID(lease.snapshot_id)
    except ValueError as exc:
        raise ConfigurationArtifactLeaseError(
            "CONFIGURATION_ARTIFACT_LEASE_CORRUPT"
        ) from exc

    async with AsyncSessionLocal() as db:
        operation = await db.get(ConfigurationOperation, operation_id)
        snapshot = await db.get(ConfigurationSnapshot, snapshot_id)
        if operation is None or snapshot is None:
            raise ConfigurationArtifactLeaseError(
                "CONFIGURATION_ARTIFACT_LEASE_BINDING_INVALID"
            )
        if not _lease_matches_active_operation(lease, operation, snapshot):
            raise ConfigurationArtifactLeaseError(
                "CONFIGURATION_ARTIFACT_LEASE_BINDING_INVALID"
            )
        if (
            not snapshot.artifact_path
            or not snapshot.artifact_sha256
            or not snapshot.encryption_key_reference
        ):
            raise ConfigurationArtifactError(
                "CONFIGURATION_SNAPSHOT_ARTIFACT_INCOMPLETE"
            )
        payload = decrypt_snapshot(
            device_id=snapshot.device_id,
            snapshot_id=snapshot.id,
            artifact_path=snapshot.artifact_path,
            expected_sha256=snapshot.artifact_sha256,
            key_reference=snapshot.encryption_key_reference,
        )
        digest = hashlib.sha256(payload).hexdigest()
        if (
            digest != lease.expected_plaintext_sha256
            or digest != snapshot.plaintext_sha256
            or digest != snapshot.normalized_sha256
        ):
            raise ConfigurationArtifactError(
                "CONFIGURATION_ARTIFACT_PLAINTEXT_CHECKSUM_MISMATCH"
            )
        return payload


@app.get("/configuration-artifacts/{token}", include_in_schema=False)
async def configuration_artifact(token: str, request: Request) -> Response:
    # The token is bearer capability material. Uvicorn access logging is disabled
    # for this service and neither direct nor trusted-edge source resolution logs
    # the request path/token.
    direct_peer = request.client.host if request.client else ""
    client = redis_client()
    store = ArtifactLeaseStore(client)
    try:
        effective_source = await resolve_effective_artifact_source(
            direct_peer=direct_peer,
            method=request.method,
            path=request.url.path,
            headers=request.headers,
            redis=client,
        )
        lease = await store.consume(token, source_ip=effective_source)
        payload = await _load_authorized_payload(lease)
        # Record a source-bound served receipt only after operation/snapshot
        # binding, decryption and plaintext checksum verification succeed. This
        # is intentionally stronger than a consume/read receipt, but it does not
        # claim transport-level acknowledgement by the router.
        await store.mark_served(token, source_ip=effective_source)
        return Response(
            content=payload,
            media_type="text/plain",
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
                "Content-Disposition": "attachment; filename=fttw-configuration.cfg",
            },
        )
    except (
        ConfigurationArtifactEdgeError,
        ConfigurationArtifactLeaseError,
        ConfigurationArtifactError,
    ):
        try:
            await store.revoke(token)
        except Exception:
            pass
        return _not_found()
    except Exception:
        # Handle unexpected failures inside the application so the ASGI server
        # never logs the bearer-token URL as part of an unhandled request error.
        logger.exception("configuration_artifact_gateway_request_failed")
        try:
            await store.revoke(token)
        except Exception:
            pass
        return _not_found()
    finally:
        try:
            await client.aclose()
        except Exception:
            pass
