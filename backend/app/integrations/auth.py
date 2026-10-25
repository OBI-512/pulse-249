from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import APIError
from app.models import IntegrationAccessToken, IntegrationClient
from app.security.authentication import extract_bearer_token
from app.security.passwords import verify_password


@dataclass(frozen=True)
class IntegrationPrincipal:
    client: IntegrationClient
    scopes: frozenset[str]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_access_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def authenticate_client_secret(
    db: AsyncSession, *, client_id: str, client_secret: str
) -> IntegrationClient | None:
    client = await db.scalar(select(IntegrationClient).where(IntegrationClient.client_id == client_id))
    if client is None or not client.is_active:
        return None
    if not verify_password(client_secret, client.client_secret_hash):
        return None
    return client


async def issue_access_token(
    db: AsyncSession,
    *,
    client: IntegrationClient,
    requested_scopes: set[str],
    source_ip: str | None,
) -> tuple[str, IntegrationAccessToken]:
    allowed = set(client.scopes or [])
    scopes = requested_scopes or allowed
    if not scopes.issubset(allowed):
        raise APIError(403, "INVALID_SCOPE", "The requested integration scope is not allowed for this client.")
    ttl = max(60, min(int(client.token_ttl_seconds or 900), 3600))
    plaintext = secrets.token_urlsafe(32)
    row = IntegrationAccessToken(
        client_id=client.id,
        token_hash=hash_access_token(plaintext),
        scopes=sorted(scopes),
        expires_at=utcnow() + timedelta(seconds=ttl),
        source_ip=(source_ip or "")[:64] or None,
    )
    client.last_used_at = utcnow()
    db.add(row)
    await db.flush()
    return plaintext, row


async def authenticate_integration_request(request: Request, db: AsyncSession) -> IntegrationPrincipal:
    token = extract_bearer_token(request)
    if not token:
        raise APIError(401, "INTEGRATION_AUTH_REQUIRED", "A valid integration bearer token is required.")
    now = utcnow()
    row = await db.scalar(
        select(IntegrationAccessToken).where(
            IntegrationAccessToken.token_hash == hash_access_token(token),
            IntegrationAccessToken.revoked_at.is_(None),
            IntegrationAccessToken.expires_at > now,
        )
    )
    if row is None:
        raise APIError(401, "INTEGRATION_TOKEN_INVALID", "The integration access token is invalid or expired.")
    client = await db.get(IntegrationClient, row.client_id)
    if client is None or not client.is_active:
        raise APIError(401, "INTEGRATION_CLIENT_DISABLED", "The integration client is disabled.")
    client.last_used_at = now
    return IntegrationPrincipal(client=client, scopes=frozenset(row.scopes or []))


def require_scope(principal: IntegrationPrincipal, scope: str) -> None:
    if scope not in principal.scopes:
        raise APIError(403, "INTEGRATION_SCOPE_DENIED", f"Integration scope '{scope}' is required.")
