"""Central password policy, history, and password-change lifecycle helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import APIError
from ..models import PasswordHistory, User
from ..services.settings_registry import get_typed_setting
from .passwords import hash_password, verify_password


DEFAULT_MINIMUM_LENGTH = 8
MAXIMUM_LENGTH = 200


@dataclass(frozen=True)
class PasswordPolicy:
    minimum_length: int = DEFAULT_MINIMUM_LENGTH
    require_complexity: bool = True
    history_count: int = 5
    minimum_edit_distance: int = 3
    maximum_age_days: int = 0
    expiry_warning_days: int = 14


@dataclass(frozen=True)
class PasswordRequirement:
    required: bool
    reason: str | None
    expires_at: datetime | None
    expires_in_days: int | None
    warning: bool


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def get_password_policy(db: AsyncSession) -> PasswordPolicy:
    minimum = await get_typed_setting(db, "auth.password.min_length")
    complexity = await get_typed_setting(db, "auth.password.require_complexity")
    history = await get_typed_setting(db, "auth.password.history_count")
    distance = await get_typed_setting(db, "auth.password.min_edit_distance")
    max_age = await get_typed_setting(db, "auth.password.max_age_days")
    warning = await get_typed_setting(db, "auth.password.expiry_warning_days")
    return PasswordPolicy(
        minimum_length=int(minimum["value"]),
        require_complexity=bool(complexity["value"]),
        history_count=int(history["value"]),
        minimum_edit_distance=int(distance["value"]),
        maximum_age_days=int(max_age["value"]),
        expiry_warning_days=int(warning["value"]),
    )


async def validate_password_policy(db: AsyncSession, password: str) -> None:
    """Reject unsuitable passwords without ever including their value."""
    policy = await get_password_policy(db)
    if len(password) < policy.minimum_length:
        raise APIError(
            422,
            "PASSWORD_POLICY_VIOLATION",
            f"Password must be at least {policy.minimum_length} characters long.",
        )
    if len(password) > MAXIMUM_LENGTH:
        raise APIError(
            422,
            "PASSWORD_POLICY_VIOLATION",
            f"Password must not exceed {MAXIMUM_LENGTH} characters.",
        )
    if policy.require_complexity:
        requirements = (
            any(character.islower() for character in password),
            any(character.isupper() for character in password),
            any(character.isdigit() for character in password),
            any(not character.isalnum() and not character.isspace() for character in password),
        )
        if not all(requirements):
            raise APIError(
                422,
                "PASSWORD_POLICY_VIOLATION",
                "Password must include uppercase, lowercase, number, and symbol characters.",
            )


def levenshtein_distance(left: str, right: str) -> int:
    """Return edit distance using O(min(n,m)) memory."""
    if left == right:
        return 0
    if len(left) < len(right):
        left, right = right, left
    previous = list(range(len(right) + 1))
    for row_index, left_char in enumerate(left, start=1):
        current = [row_index]
        for column_index, right_char in enumerate(right, start=1):
            insert_cost = current[column_index - 1] + 1
            delete_cost = previous[column_index] + 1
            replace_cost = previous[column_index - 1] + (left_char != right_char)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current
    return previous[-1]


async def validate_password_change(
    db: AsyncSession,
    *,
    user: User,
    new_password: str,
    current_password: str | None = None,
) -> None:
    """Validate policy, exact reuse/history, and edit distance when knowable.

    Edit distance can only be evaluated when the caller possesses the current
    plaintext password (self-service and mandatory-change flows).  Admin reset
    flows never have access to the user's current plaintext, so they enforce
    policy and hash-history reuse but cannot safely calculate string distance.
    """
    await validate_password_policy(db, new_password)
    policy = await get_password_policy(db)

    if user.password_hash and verify_password(new_password, user.password_hash):
        raise APIError(422, "PASSWORD_REUSED", "New password must differ from the current password.")

    if current_password is not None and policy.minimum_edit_distance > 0:
        if levenshtein_distance(current_password, new_password) < policy.minimum_edit_distance:
            raise APIError(
                422,
                "PASSWORD_TOO_SIMILAR",
                f"New password must differ from the current password by at least {policy.minimum_edit_distance} edits.",
            )

    if policy.history_count > 0:
        hashes = (
            await db.scalars(
                select(PasswordHistory.password_hash)
                .where(PasswordHistory.user_id == user.id)
                .order_by(PasswordHistory.created_at.desc(), PasswordHistory.id.desc())
                .limit(policy.history_count)
            )
        ).all()
        if any(verify_password(new_password, password_hash) for password_hash in hashes):
            raise APIError(
                422,
                "PASSWORD_HISTORY_REUSE",
                f"Password cannot match any of the previous {policy.history_count} passwords.",
            )


async def remember_current_password(db: AsyncSession, *, user: User) -> None:
    """Store the outgoing hash and trim history to the configured depth."""
    if not user.password_hash:
        return
    policy = await get_password_policy(db)
    if policy.history_count <= 0:
        return

    db.add(PasswordHistory(user_id=user.id, password_hash=user.password_hash))
    await db.flush()
    obsolete = (
        await db.scalars(
            select(PasswordHistory.id)
            .where(PasswordHistory.user_id == user.id)
            .order_by(PasswordHistory.created_at.desc(), PasswordHistory.id.desc())
            .offset(policy.history_count)
        )
    ).all()
    if obsolete:
        await db.execute(delete(PasswordHistory).where(PasswordHistory.id.in_(obsolete)))


async def apply_password_change(
    db: AsyncSession,
    *,
    user: User,
    new_password: str,
    current_password: str | None = None,
    must_change_password: bool = False,
    change_reason: str | None = None,
) -> None:
    await validate_password_change(
        db,
        user=user,
        new_password=new_password,
        current_password=current_password,
    )
    await remember_current_password(db, user=user)
    user.password_hash = hash_password(new_password)
    user.password_changed_at = _utcnow()
    user.must_change_password = must_change_password
    user.password_change_reason = change_reason if must_change_password else None
    await db.flush()


async def password_requirement(db: AsyncSession, user: User) -> PasswordRequirement:
    """Return explicit or age-derived password-change requirements."""
    policy = await get_password_policy(db)
    if user.must_change_password:
        return PasswordRequirement(
            required=True,
            reason=user.password_change_reason or "REQUIRED",
            expires_at=None,
            expires_in_days=None,
            warning=False,
        )

    if policy.maximum_age_days <= 0 or user.password_changed_at is None:
        return PasswordRequirement(False, None, None, None, False)

    expires_at = user.password_changed_at + timedelta(days=policy.maximum_age_days)
    now = _utcnow()
    remaining_seconds = (expires_at - now).total_seconds()
    remaining_days = max(0, int((remaining_seconds + 86399) // 86400))
    if expires_at <= now:
        return PasswordRequirement(True, "PASSWORD_EXPIRED", expires_at, 0, True)
    return PasswordRequirement(
        required=False,
        reason=None,
        expires_at=expires_at,
        expires_in_days=remaining_days,
        warning=remaining_days <= policy.expiry_warning_days,
    )
