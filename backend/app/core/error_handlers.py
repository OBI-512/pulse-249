import logging

from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError, SQLAlchemyError


logger = logging.getLogger(__name__)


async def integrity_error_handler(request: Request, exc: IntegrityError):
    logger.warning(
        "database_integrity_conflict",
        exc_info=True,
        extra={"event": "DATABASE_INTEGRITY_CONFLICT", "error_code": "DATA_CONFLICT"},
    )
    return JSONResponse(
        status_code=409,
        content={
            "detail": {
                "code": "DATA_CONFLICT",
                "message": "The requested operation conflicts with existing database data.",
            }
        },
    )


async def sqlalchemy_error_handler(request: Request, exc: SQLAlchemyError):
    logger.exception(
        "database_operation_failed",
        extra={"event": "DATABASE_ERROR", "error_code": "DATABASE_ERROR"},
    )
    return JSONResponse(
        status_code=500,
        content={
            "detail": {
                "code": "DATABASE_ERROR",
                "message": "The database operation could not be completed.",
            }
        },
    )
