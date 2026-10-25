from __future__ import annotations

import base64
from urllib.parse import parse_qs

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.core.error_handlers import integrity_error_handler, sqlalchemy_error_handler
from app.core.exceptions import APIError
from app.integrations.auth import authenticate_client_secret, authenticate_integration_request, issue_access_token, require_scope
from app.integrations.rate_limit import check_fixed_window
from app.integrations.schemas import CustomerSyncEvent, EventReceiptRead, TokenResponse
from app.integrations.sync import process_event
from app.models import IntegrationConnector
from app.services.audit import record_audit
from app.settings import settings
from sqlalchemy.exc import IntegrityError, SQLAlchemyError


integration_app = FastAPI(
    title="FTTW External Integration API",
    version="1.0.0",
    description="Optional versioned machine-to-machine integration boundary. Core FTTW operation never depends on this API.",
    docs_url="/docs",
    redoc_url=None,
)
integration_app.add_exception_handler(IntegrityError, integrity_error_handler)
integration_app.add_exception_handler(SQLAlchemyError, sqlalchemy_error_handler)


@integration_app.middleware("http")
async def integration_limits(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > 1024 * 1024:
                return JSONResponse(status_code=413, content={"detail": {"code": "REQUEST_TOO_LARGE", "message": "Integration requests are limited to 1 MiB."}})
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": {"code": "INVALID_CONTENT_LENGTH", "message": "Invalid Content-Length header."}})
    return await call_next(request)


def _require_enabled() -> None:
    if not settings.integrations_enabled:
        raise APIError(503, "INTEGRATIONS_DISABLED", "External integrations are disabled. Core FTTW operation remains available.")


def _basic_credentials(request: Request) -> tuple[str, str]:
    value = request.headers.get("authorization") or ""
    if not value.startswith("Basic "):
        raise APIError(401, "INVALID_CLIENT", "HTTP Basic client authentication is required.")
    try:
        decoded = base64.b64decode(value[6:].strip(), validate=True).decode("utf-8")
        client_id, secret = decoded.split(":", 1)
    except Exception as exc:
        raise APIError(401, "INVALID_CLIENT", "Client authentication is invalid.") from exc
    return client_id, secret


@integration_app.get("/")
async def root():
    return {
        "application": "FTTW",
        "api": "external-integration",
        "version": "v1",
        "integration_optional": True,
    }


@integration_app.get("/health")
async def health():
    return {
        "status": "enabled" if settings.integrations_enabled else "disabled",
        "integration_optional": True,
        "core_dependency": False,
    }


@integration_app.post("/oauth/token", response_model=TokenResponse)
async def token(request: Request, db: AsyncSession = Depends(get_db)):
    _require_enabled()
    client_id, client_secret = _basic_credentials(request)
    source_ip = request.client.host if request.client else None
    limited = await check_fixed_window(
        prefix="token",
        identity=f"{client_id}|{source_ip or 'unknown'}",
        limit=settings.integration_token_rate_limit_attempts,
        window_seconds=settings.integration_token_rate_limit_window_seconds,
    )
    if limited:
        raise APIError(429, "INTEGRATION_RATE_LIMITED", "Too many integration authentication attempts.")
    body = await request.body()
    if len(body) > 4096:
        raise APIError(413, "TOKEN_REQUEST_TOO_LARGE", "Token request is too large.")
    params = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    if (params.get("grant_type") or [None])[0] != "client_credentials":
        raise APIError(400, "UNSUPPORTED_GRANT_TYPE", "Only client_credentials is supported.")
    client = await authenticate_client_secret(db, client_id=client_id, client_secret=client_secret)
    if client is None:
        await record_audit(db, action="INTEGRATION_AUTH_FAILED", entity_type="IntegrationClient", description="Integration client authentication failed.", result="FAILURE", metadata={"client_id": client_id[:160]})
        await db.commit()
        raise APIError(401, "INVALID_CLIENT", "Client authentication failed.")
    requested = set(filter(None, ((params.get("scope") or [""])[0].split())))
    plaintext, access = await issue_access_token(db, client=client, requested_scopes=requested, source_ip=source_ip)
    await record_audit(db, action="INTEGRATION_TOKEN_ISSUED", entity_type="IntegrationClient", entity_id=client.id, description="Short-lived integration access token issued.", metadata={"scopes": access.scopes})
    await db.commit()
    return TokenResponse(access_token=plaintext, expires_in=max(60, min(int(client.token_ttl_seconds or 900), 3600)), scope=" ".join(access.scopes))


@integration_app.post("/customer-sync/events", response_model=EventReceiptRead)
async def customer_sync_event(payload: CustomerSyncEvent, request: Request, db: AsyncSession = Depends(get_db)):
    _require_enabled()
    principal = await authenticate_integration_request(request, db)
    require_scope(principal, "customer-sync.write")
    source_ip = request.client.host if request.client else None
    if await check_fixed_window(
        prefix="event",
        identity=f"{principal.client.client_id}|{source_ip or 'unknown'}",
        limit=settings.integration_event_rate_limit_per_minute,
        window_seconds=60,
    ):
        raise APIError(429, "INTEGRATION_RATE_LIMITED", "Integration event rate limit exceeded.")
    if principal.client.connector_id is None:
        raise APIError(403, "CONNECTOR_BINDING_REQUIRED", "The integration client is not bound to a connector.")
    connector = await db.get(IntegrationConnector, principal.client.connector_id)
    if connector is None or not connector.enabled:
        raise APIError(503, "CONNECTOR_DISABLED", "The integration connector is disabled or unavailable.")
    try:
        status, changed = await process_event(db, connector, payload)
        await db.commit()
    except ValueError as exc:
        await db.rollback()
        raise APIError(422, str(exc), "The integration event payload is incomplete.") from exc
    return EventReceiptRead(event_id=payload.event_id, status=status, changed=changed)
