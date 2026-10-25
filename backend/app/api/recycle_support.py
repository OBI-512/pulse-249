"""Shared HTTP transaction boundary for entity recycle DELETE endpoints."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..services.recycle_bin import RecycleBinError, recycle_entity


async def recycle_from_delete_endpoint(
    db: AsyncSession,
    *,
    entity_type: str,
    entity_id: UUID,
    actor: Any = None,
    reason: str | None = None,
    confirmed: bool = False,
    before_commit: Callable[[], Awaitable[None]] | None = None,
) -> None:
    """Recycle one root entity atomically and translate domain errors.

    ``before_commit`` is an optional same-transaction hook for domain state
    that must be retired only after recycle mutation succeeds but before the
    shared transaction commits. Existing callers do not provide it.
    """

    # Direct function-level tests bypass FastAPI and therefore leave dependency
    # marker objects in optional parameters. Only accept a real string reason.
    normalized_reason = reason if isinstance(reason, str) else None
    try:
        await recycle_entity(
            db,
            entity_type=entity_type,
            entity_id=entity_id,
            actor_user_id=getattr(actor, "id", None),
            reason=normalized_reason,
            confirmed=confirmed if isinstance(confirmed, bool) else False,
        )
        if before_commit is not None:
            await before_commit()
        await db.commit()
    except RecycleBinError as exc:
        await db.rollback()
        detail = {"code": exc.code, "message": exc.message}
        if exc.conflicts:
            detail["conflicts"] = exc.conflicts
        raise HTTPException(status_code=exc.status_code, detail=detail) from exc
    except Exception:
        await db.rollback()
        raise
