from __future__ import annotations

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import User
from .passwords import verify_password
from .sessions import get_session_user


AUTHENTICATION_HEADER = "Authorization"
BEARER_PREFIX = "Bearer "


def extract_bearer_token(request: Request) -> str | None:
    """Extract a Bearer session token from the Authorization header."""

    value = request.headers.get(AUTHENTICATION_HEADER)

    if not value:
        return None

    if not value.startswith(BEARER_PREFIX):
        return None

    token = value[len(BEARER_PREFIX):].strip()

    return token or None


async def authenticate_credentials(
    db: AsyncSession,
    *,
    username: str,
    password: str,
) -> User | None:
    """
    Authenticate a local FTTW user using username and password.

    Authentication deliberately returns None for invalid credentials
    instead of exposing whether the username or password was incorrect.
    """

    user = await db.scalar(
        select(User).where(
            User.username == username,
        )
    )

    if user is None:
        return None

    if not user.is_active:
        return None

    if not user.password_hash:
        return None

    if not verify_password(
        password,
        user.password_hash,
    ):
        return None

    return user


async def authenticate_request(
    request: Request,
    db: AsyncSession,
) -> User | None:
    """
    Resolve an HTTP request to an authenticated active FTTW user.

    The request must contain a valid server-side session token in:

        Authorization: Bearer <token>

    Only the token hash is persisted by the session layer.
    """

    token = extract_bearer_token(request)

    if token is None:
        return None

    return await get_session_user(
        db,
        session_token=token,
        source_ip=request.client.host if request.client else None,
    )
