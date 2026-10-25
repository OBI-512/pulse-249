from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from ..core.audit_context import get_audit_context, resolve_request_id
from ..core.audit_redaction import redact_audit_value
from ..models import AuditLog
from ..settings import settings


logger = logging.getLogger(__name__)
AUDIT_RESULTS = frozenset({"SUCCESS", "FAILURE", "ATTEMPT"})

# Failure evidence is written from request handlers and from Celery tasks that
# repeatedly create short-lived event loops with ``asyncio.run``.  A normal
# async connection pool can retain a connection bound to a previous loop.
# NullPool gives every isolated audit transaction its own connection and is
# therefore safe across those loop boundaries.  The public name is retained
# so focused tests can substitute a deterministic fake session factory.
_failure_audit_engine = create_async_engine(
    settings.database_url,
    pool_pre_ping=True,
    poolclass=NullPool,
)
AsyncSessionLocal = async_sessionmaker(
    _failure_audit_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def record_audit(
    db: AsyncSession,
    *,
    action: str,
    entity_type: str | None = None,
    entity_id: UUID | None = None,
    description: str | None = None,
    metadata: Mapping[str, Any] | None = None,
    actor_user_id: UUID | None = None,
    actor_username_snapshot: str | None = None,
    actor_display_name_snapshot: str | None = None,
    entity_display_snapshot: Mapping[str, Any] | None = None,
    result: str = "SUCCESS",
    request_id: str | None = None,
    source_ip: str | None = None,
    before_summary: Mapping[str, Any] | None = None,
    after_summary: Mapping[str, Any] | None = None,
) -> AuditLog:
    """Stage a redacted audit event in the caller's current transaction.

    This function intentionally neither flushes nor commits. Successful event
    evidence therefore commits atomically with the business mutation, while
    failed operations use :func:`record_failure_audit` after rollback.
    """

    normalized_action = action.strip().upper()
    normalized_result = result.strip().upper()
    if not normalized_action:
        raise ValueError("Audit action must not be empty.")
    if normalized_result not in AUDIT_RESULTS:
        raise ValueError(
            f"Unsupported audit result '{normalized_result}'. "
            f"Expected one of {sorted(AUDIT_RESULTS)}."
        )

    context = get_audit_context()
    resolved_actor_id = actor_user_id if actor_user_id is not None else context.actor_user_id
    resolved_username = (
        actor_username_snapshot
        if actor_username_snapshot is not None
        else (
            context.actor_username_snapshot
            if resolved_actor_id is None or resolved_actor_id == context.actor_user_id
            else None
        )
    )
    resolved_display_name = (
        actor_display_name_snapshot
        if actor_display_name_snapshot is not None
        else (
            context.actor_display_name_snapshot
            if resolved_actor_id is None or resolved_actor_id == context.actor_user_id
            else None
        )
    )
    audit = AuditLog(
        occurred_at=datetime.now(timezone.utc),
        actor_user_id=resolved_actor_id,
        actor_username_snapshot=(resolved_username[:150] if resolved_username else None),
        actor_display_name_snapshot=(resolved_display_name[:200] if resolved_display_name else None),
        action=normalized_action,
        entity_type=entity_type,
        entity_id=entity_id,
        entity_display_snapshot=redact_audit_value(entity_display_snapshot),
        result=normalized_result,
        request_id=(
            resolve_request_id(request_id)
            if request_id is not None
            else context.request_id
        ),
        source_ip=(source_ip[:64] if source_ip is not None else context.source_ip),
        description=redact_audit_value(description),
        before_summary=redact_audit_value(before_summary),
        after_summary=redact_audit_value(after_summary),
        metadata_=redact_audit_value(metadata or {}),
    )
    db.add(audit)
    return audit


async def record_failure_audit(
    *,
    action: str,
    entity_type: str | None = None,
    entity_id: UUID | None = None,
    description: str | None = None,
    metadata: Mapping[str, Any] | None = None,
    actor_user_id: UUID | None = None,
    actor_username_snapshot: str | None = None,
    actor_display_name_snapshot: str | None = None,
    entity_display_snapshot: Mapping[str, Any] | None = None,
    request_id: str | None = None,
    source_ip: str | None = None,
    before_summary: Mapping[str, Any] | None = None,
    after_summary: Mapping[str, Any] | None = None,
) -> bool:
    """Persist failure evidence in an isolated transaction without raising.

    Callers must first roll back/close the failed business transaction. This
    helper owns and commits only its short-lived audit session so failure
    evidence cannot accidentally commit partial domain state.
    """

    async with AsyncSessionLocal() as audit_db:
        try:
            await record_audit(
                audit_db,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                description=description,
                metadata=metadata,
                actor_user_id=actor_user_id,
                actor_username_snapshot=actor_username_snapshot,
                actor_display_name_snapshot=actor_display_name_snapshot,
                entity_display_snapshot=entity_display_snapshot,
                result="FAILURE",
                request_id=request_id,
                source_ip=source_ip,
                before_summary=before_summary,
                after_summary=after_summary,
            )
            await audit_db.commit()
            return True
        except Exception:
            await audit_db.rollback()
            context = get_audit_context()
            logger.exception(
                "Failed to persist independent audit event action=%s request_id=%s",
                action,
                request_id or context.request_id,
            )
            return False


async def enable_audit_maintenance(db: AsyncSession) -> None:
    """Enable the explicit transaction-local append-only maintenance bypass."""

    await db.execute(text("SET LOCAL fttw.audit_maintenance = 'on'"))
