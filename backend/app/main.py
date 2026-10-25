import logging
from contextlib import asynccontextmanager
from time import perf_counter

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import create_async_engine

# Register optional operator-table extensions before the API router is mounted.
# This module adds only non-secret Access Template metadata to the export registry.
from .services import access_template_table_exports as _access_template_table_exports  # noqa: F401
from .api.router import api_router
from .api_v1 import integration_app
from .core.audit_context import (
    REQUEST_ID_HEADER,
    bind_request_context,
    reset_audit_context,
    resolve_request_id,
)
from .core.error_handlers import integrity_error_handler, sqlalchemy_error_handler
from .settings import settings
from .services.maintenance import maintenance_mode_active
from .observability.logging import configure_operational_logging


logger = logging.getLogger(__name__)
configure_operational_logging()


@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info("backend_started", extra={"event": "BACKEND_STARTED"})
    try:
        yield
    finally:
        logger.info("backend_stopped", extra={"event": "BACKEND_STOPPED"})


app = FastAPI(
    title="FTTW Network Management API",
    version="1.4.0",
    description="On-premises API for the FTTW Wi-Fi network management system.",
    lifespan=lifespan,
)

app.add_exception_handler(IntegrityError, integrity_error_handler)
app.add_exception_handler(SQLAlchemyError, sqlalchemy_error_handler)

_cors_origins = [x.strip() for x in settings.cors_origins.split(",") if x.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=[REQUEST_ID_HEADER],
)


@app.middleware("http")
async def request_correlation_middleware(request, call_next):
    """Bind a safe correlation ID/source and return the ID on every response."""

    request_id = resolve_request_id(request.headers.get(REQUEST_ID_HEADER))
    source_ip = request.client.host if request.client else None
    token = bind_request_context(request_id=request_id, source_ip=source_ip)
    request.state.request_id = request_id
    started = perf_counter()
    try:
        if (
            request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
            and await maintenance_mode_active()
        ):
            response = JSONResponse(
                status_code=503,
                content={
                    "detail": {
                        "code": "MAINTENANCE_MODE_ACTIVE",
                        "message": "System maintenance is in progress. Sign-in and changes are temporarily unavailable while the restore is running. Please try again after maintenance finishes.",
                    }
                },
            )
            response.headers[REQUEST_ID_HEADER] = request_id
            # This middleware is intentionally outside Starlette's CORS
            # middleware, so direct maintenance responses must carry the same
            # CORS headers themselves. Otherwise browsers misreport the 503 as
            # a CORS/network failure and hide the real maintenance message.
            origin = request.headers.get("origin")
            if origin and origin in _cors_origins:
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Credentials"] = "true"
                response.headers["Vary"] = "Origin"
            return response
        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = request_id
        logger.info(
            "request_completed request_id=%s method=%s path=%s status=%s duration_ms=%.2f",
            request_id,
            request.method,
            request.url.path,
            response.status_code,
            (perf_counter() - started) * 1000,
        )
        return response
    except Exception:
        logger.exception(
            "request_failed request_id=%s method=%s path=%s duration_ms=%.2f",
            request_id,
            request.method,
            request.url.path,
            (perf_counter() - started) * 1000,
        )
        raise
    finally:
        reset_audit_context(token)

app.include_router(api_router)
app.mount("/api/v1", integration_app)

engine = create_async_engine(settings.database_url, pool_pre_ping=True)


@app.get("/api/health", tags=["System"])
async def health():
    database = "offline"
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
            database = "online"
    except Exception:
        pass

    return {
        "application": "FTTW",
        "status": "online" if database == "online" else "degraded",
        "database": database,
        "version": "1.4.0",
    }


@app.get("/api", tags=["System"])
async def api_root():
    return {
        "application": "FTTW",
        "message": "FTTW Network Management API",
        "version": "1.4.0",
    }
