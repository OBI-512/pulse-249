"""Request-scoped correlation and actor context for audit events."""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass, replace
import re
from uuid import UUID, uuid4


REQUEST_ID_HEADER = "X-Request-ID"
_REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


@dataclass(frozen=True, slots=True)
class AuditRequestContext:
    request_id: str | None = None
    source_ip: str | None = None
    actor_user_id: UUID | None = None
    actor_username_snapshot: str | None = None
    actor_display_name_snapshot: str | None = None


_audit_context: ContextVar[AuditRequestContext] = ContextVar(
    "fttw_audit_context",
    default=AuditRequestContext(),
)


def valid_request_id(value: str | None) -> bool:
    """Return whether an inbound correlation ID is safe for headers/logs."""

    return bool(value and _REQUEST_ID_PATTERN.fullmatch(value))


def resolve_request_id(value: str | None) -> str:
    """Use a valid caller correlation ID, otherwise generate an opaque UUID."""

    candidate = value.strip() if value else None
    return candidate if valid_request_id(candidate) else str(uuid4())


def bind_request_context(
    *,
    request_id: str,
    source_ip: str | None,
) -> Token[AuditRequestContext]:
    """Bind the request/source portion of the context for one ASGI request."""

    return _audit_context.set(
        AuditRequestContext(
            request_id=request_id,
            source_ip=source_ip[:64] if source_ip else None,
        )
    )


def bind_audit_actor(
    actor_user_id: UUID,
    actor_username_snapshot: str,
    actor_display_name_snapshot: str | None = None,
) -> Token[AuditRequestContext]:
    """Add the authenticated actor without discarding request correlation."""

    current = _audit_context.get()
    return _audit_context.set(
        replace(
            current,
            actor_user_id=actor_user_id,
            actor_username_snapshot=actor_username_snapshot[:150],
            actor_display_name_snapshot=(actor_display_name_snapshot[:200] if actor_display_name_snapshot else None),
        )
    )


def get_audit_context() -> AuditRequestContext:
    return _audit_context.get()


def reset_audit_context(token: Token[AuditRequestContext]) -> None:
    _audit_context.reset(token)
