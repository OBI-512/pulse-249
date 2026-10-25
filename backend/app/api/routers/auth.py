from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..deps import get_db
from ...core.exceptions import APIError
from ...schemas.auth import (
    CurrentUserResponse,
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    PasswordChangeRequest,
    RequiredPasswordChangeRequest,
    PasswordPolicyResponse,
    AuthSessionRead,
    RevokeSessionsResponse,
    SessionStatusResponse,
    SessionExtendResponse,
    ClientSessionMetadataRequest,
)
from ...security.authentication import (
    authenticate_credentials,
    extract_bearer_token,
)
from ...security.sessions import (
    create_session,
    hash_session_token,
    revoke_session,
    revoke_user_sessions,
    list_user_sessions,
    revoke_session_by_id,
    current_session,
    session_state,
    record_user_activity,
    extend_session,
    session_idle_seconds,
    session_extension_eligible,
    SESSION_IDLE_TIMEOUT_MINUTES,
    SESSION_EXTENSION_WINDOW_SECONDS,
    update_session_client_metadata,
)
from ...security.authorization import get_authenticated_user, get_current_user
from ...security.login_throttle import (
    clear_login_failures,
    login_is_rate_limited,
    record_login_failure,
)
from ...security.password_policy import apply_password_change, get_password_policy, password_requirement
from ...security.passwords import verify_password
from ...core.audit_context import get_audit_context
from ...models import AuthSession, Permission, Role, RolePermission, User, UserPermission, UserRole
from ...services.audit import record_audit, record_failure_audit
from ...services.settings_registry import get_typed_setting


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post(
    "/login",
    response_model=LoginResponse,
)
async def login(
    request: Request,
    payload: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    context = get_audit_context()
    rate_limit = await get_typed_setting(db, "auth.login_rate_limit")
    attempted_user = await db.scalar(
        select(User).where(User.username == payload.username)
    )
    attempted_user_id = getattr(attempted_user, "id", None)
    if await login_is_rate_limited(
        username=payload.username,
        source_ip=context.source_ip,
        limit=rate_limit["attempts"],
    ):
        await db.rollback()
        await record_failure_audit(
            action="LOGIN_FAILED",
            entity_type="User",
            entity_id=attempted_user_id,
            actor_username_snapshot=payload.username,
            entity_display_snapshot={"username": payload.username},
            description="Authentication attempt was rate limited.",
            metadata={"reason": "RATE_LIMITED"},
        )
        raise APIError(429, "LOGIN_RATE_LIMITED", "Too many failed login attempts. Try again later.")
    user = await authenticate_credentials(
        db,
        username=payload.username,
        password=payload.password,
    )

    if user is None:
        await record_login_failure(
            username=payload.username,
            source_ip=context.source_ip,
            window_seconds=rate_limit["window_seconds"],
        )
        await db.rollback()
        await record_failure_audit(
            action="LOGIN_FAILED",
            entity_type="User",
            entity_id=attempted_user_id,
            actor_username_snapshot=payload.username,
            entity_display_snapshot={"username": payload.username},
            description="Authentication failed with invalid credentials.",
            metadata={"reason": "INVALID_CREDENTIALS"},
        )
        raise APIError(
            401,
            "INVALID_CREDENTIALS",
            "Invalid username or password.",
        )

    access_token, session = await create_session(
        db,
        user_id=user.id,
        source_ip=context.source_ip,
        user_agent=request.headers.get("user-agent"),
    )

    await record_audit(
        db,
        action="LOGIN_SUCCESS",
        entity_type="User",
        entity_id=user.id,
        actor_user_id=user.id,
        actor_username_snapshot=user.username,
        entity_display_snapshot={
            "username": user.username,
            "display_name": user.display_name,
        },
        description="User authenticated successfully.",
        metadata={"session_id": str(session.id), "source_ip": session.login_ip, "browser": session.browser_name, "os": session.os_name, "device_type": session.device_type},
    )

    await db.commit()
    await clear_login_failures(username=payload.username, source_ip=context.source_ip)

    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
    )


@router.post("/password/change", status_code=204)
async def change_own_password(
    payload: PasswordChangeRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change the authenticated user's password and revoke every session.

    The current session is intentionally revoked too, requiring a fresh login
    with the new secret and avoiding ambiguity about which credential remains
    authoritative after the change.
    """

    locked_user = await db.scalar(
        select(User)
        .where(User.id == user.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if locked_user is None or not locked_user.is_active:
        raise APIError(401, "AUTHENTICATION_REQUIRED", "Authentication is required.")
    if not locked_user.password_hash or not verify_password(
        payload.current_password, locked_user.password_hash
    ):
        raise APIError(422, "CURRENT_PASSWORD_INVALID", "Current password is incorrect.")
    await apply_password_change(
        db,
        user=locked_user,
        new_password=payload.new_password,
        current_password=payload.current_password,
    )
    revoked_count = await revoke_user_sessions(
        db, user_id=locked_user.id, reason="PASSWORD_CHANGED"
    )
    await record_audit(
        db,
        action="PASSWORD_CHANGED",
        entity_type="User",
        entity_id=locked_user.id,
        actor_user_id=locked_user.id,
        actor_username_snapshot=locked_user.username,
        entity_display_snapshot={"username": locked_user.username},
        description="User changed their own password.",
        metadata={"password_value_logged": False},
    )
    if revoked_count:
        await record_audit(
            db,
            action="SESSION_REVOKED",
            entity_type="User",
            entity_id=locked_user.id,
            actor_user_id=locked_user.id,
            actor_username_snapshot=locked_user.username,
            entity_display_snapshot={"username": locked_user.username},
            description="Sessions revoked after password change.",
            metadata={"reason": "PASSWORD_CHANGED", "revoked_session_count": revoked_count},
        )
    await db.commit()
    return None


@router.post("/password/change-required", response_model=LoginResponse)
async def change_required_password(
    request: Request,
    payload: RequiredPasswordChangeRequest,
    user: User = Depends(get_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    requirement = await password_requirement(db, user)
    if not requirement.required:
        raise APIError(409, "PASSWORD_CHANGE_NOT_REQUIRED", "This account does not require a password change.")

    locked_user = await db.scalar(
        select(User)
        .where(User.id == user.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if locked_user is None or not locked_user.is_active:
        raise APIError(401, "AUTHENTICATION_REQUIRED", "Authentication is required.")
    if not locked_user.password_hash or not verify_password(payload.current_password, locked_user.password_hash):
        raise APIError(422, "CURRENT_PASSWORD_INVALID", "Current or temporary password is incorrect.")

    await apply_password_change(
        db,
        user=locked_user,
        new_password=payload.new_password,
        current_password=payload.current_password,
    )

    bearer = extract_bearer_token(request)
    previous_session = await current_session(db, session_token=bearer) if bearer else None
    revoked_count = await revoke_user_sessions(
        db, user_id=locked_user.id, reason="REQUIRED_PASSWORD_CHANGED"
    )
    source_ip = request.client.host if request.client else None
    new_token, new_session = await create_session(
        db,
        user_id=locked_user.id,
        source_ip=source_ip or getattr(previous_session, "last_ip", None),
        user_agent=request.headers.get("user-agent") or getattr(previous_session, "user_agent", None),
    )
    await record_audit(
        db,
        action="PASSWORD_CHANGED",
        entity_type="User",
        entity_id=locked_user.id,
        actor_user_id=locked_user.id,
        actor_username_snapshot=locked_user.username,
        entity_display_snapshot={"username": locked_user.username},
        description="User completed a mandatory password change.",
        metadata={
            "password_value_logged": False,
            "reason": requirement.reason,
            "revoked_session_count": revoked_count,
            "new_session_id": str(new_session.id),
        },
    )
    await db.commit()
    return LoginResponse(access_token=new_token, token_type="bearer")


@router.post(
    "/logout",
    response_model=LogoutResponse,
)
async def logout(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    token = extract_bearer_token(request)

    if token is None:
        raise APIError(
            401,
            "AUTHENTICATION_REQUIRED",
            "Authentication is required.",
        )

    session = await db.scalar(
        select(AuthSession).where(
            AuthSession.token_hash == hash_session_token(token)
        )
    )
    actor = await db.get(User, session.user_id) if session is not None else None

    revoked = await revoke_session(
        db,
        session_token=token,
        reason="LOGOUT",
    )

    if not revoked:
        raise APIError(
            401,
            "AUTHENTICATION_REQUIRED",
            "Authentication is required.",
        )

    await record_audit(
        db,
        action="SESSION_REVOKED",
        entity_type="AuthSession",
        entity_id=session.id if session is not None else None,
        actor_user_id=getattr(actor, "id", None),
        actor_username_snapshot=getattr(actor, "username", None),
        entity_display_snapshot={"user_id": str(session.user_id)} if session is not None else None,
        description="Authentication session revoked during logout.",
        metadata={"reason": "LOGOUT"},
    )
    await record_audit(
        db,
        action="LOGOUT",
        entity_type="User",
        entity_id=getattr(actor, "id", None),
        actor_user_id=getattr(actor, "id", None),
        actor_username_snapshot=getattr(actor, "username", None),
        entity_display_snapshot={"username": actor.username} if actor is not None else None,
        description="User logged out successfully.",
    )
    await db.commit()

    return LogoutResponse(
        message="Successfully logged out.",
    )


@router.get("/session/status", response_model=SessionStatusResponse)
async def session_status(
    request: Request,
    user: User = Depends(get_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    token = extract_bearer_token(request)
    session = await current_session(db, session_token=token) if token else None
    if session is None or session.revoked_at is not None or session.expires_at <= datetime.now(timezone.utc):
        raise APIError(401, "AUTHENTICATION_REQUIRED", "Authentication is required.")
    now = datetime.now(timezone.utc)
    remaining = max(0, int((session.expires_at - now).total_seconds()))
    renewal_minutes = int((await get_typed_setting(db, "auth.session_lifetime_minutes"))["value"])
    requirement = await password_requirement(db, user)
    return SessionStatusResponse(
        session_id=str(session.id),
        expires_at=session.expires_at,
        seconds_remaining=remaining,
        idle_seconds=session_idle_seconds(session, now=now),
        idle_timeout_seconds=SESSION_IDLE_TIMEOUT_MINUTES * 60,
        extension_window_seconds=SESSION_EXTENSION_WINDOW_SECONDS,
        extension_eligible=session_extension_eligible(session, now=now),
        renewal_minutes=renewal_minutes,
        must_change_password=requirement.required,
        password_change_reason=requirement.reason,
    )


@router.post("/session/extend", response_model=SessionExtendResponse)
async def session_extend(
    request: Request,
    user: User = Depends(get_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    token = extract_bearer_token(request)
    if not token:
        raise APIError(401, "AUTHENTICATION_REQUIRED", "Authentication is required.")
    try:
        session = await extend_session(
            db,
            session_token=token,
            source_ip=request.client.host if request.client else None,
        )
    except ValueError as exc:
        code = str(exc)
        if code in {"SESSION_INVALID", "SESSION_IDLE_EXPIRED"}:
            raise APIError(401, "AUTHENTICATION_REQUIRED", "Authentication is required.") from exc
        raise APIError(409, "SESSION_EXTENSION_NOT_AVAILABLE", "Session extension is available only during the final five minutes after recent user activity.") from exc

    renewal_minutes = int((await get_typed_setting(db, "auth.session_lifetime_minutes"))["value"])
    await record_audit(
        db,
        action="SESSION_EXTENDED",
        entity_type="AuthSession",
        entity_id=session.id,
        actor_user_id=user.id,
        actor_username_snapshot=user.username,
        entity_display_snapshot={"user_id": str(user.id), "username": user.username},
        description="Authenticated user explicitly extended the current session.",
        metadata={"renewal_minutes": renewal_minutes},
    )
    await db.commit()
    now = datetime.now(timezone.utc)
    return SessionExtendResponse(
        session_id=str(session.id),
        expires_at=session.expires_at,
        seconds_remaining=max(0, int((session.expires_at - now).total_seconds())),
        renewal_minutes=renewal_minutes,
    )


@router.post("/session/activity", status_code=204)
async def session_activity(
    request: Request,
    user: User = Depends(get_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    del user
    token = extract_bearer_token(request)
    if not token or not await record_user_activity(
        db,
        session_token=token,
        source_ip=request.client.host if request.client else None,
    ):
        raise APIError(401, "AUTHENTICATION_REQUIRED", "Authentication is required.")
    await db.commit()
    return None


@router.post("/session/client-metadata", status_code=204)
async def session_client_metadata(
    request: Request,
    payload: ClientSessionMetadataRequest,
    user: User = Depends(get_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    del user
    token = extract_bearer_token(request)
    if not token or not await update_session_client_metadata(
        db,
        session_token=token,
        user_agent=payload.user_agent or request.headers.get("user-agent"),
        browser_name=payload.browser_name,
        browser_version=payload.browser_version,
        os_name=payload.os_name,
        os_version=payload.os_version,
        device_type=payload.device_type,
    ):
        raise APIError(401, "AUTHENTICATION_REQUIRED", "Authentication is required.")
    await db.commit()
    return None


@router.get("/password-policy", response_model=PasswordPolicyResponse)
async def password_policy(
    user: User = Depends(get_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    del user  # Authentication is the only requirement; policy contains no secrets.
    policy = await get_password_policy(db)
    return PasswordPolicyResponse(
        minimum_length=policy.minimum_length,
        require_complexity=policy.require_complexity,
        history_count=policy.history_count,
        minimum_edit_distance=policy.minimum_edit_distance,
        maximum_age_days=policy.maximum_age_days,
        expiry_warning_days=policy.expiry_warning_days,
    )


@router.get("/sessions", response_model=list[AuthSessionRead])
async def list_own_sessions(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    token = extract_bearer_token(request)
    current = await current_session(db, session_token=token) if token else None
    sessions = await list_user_sessions(db, user_id=user.id, include_revoked=False)
    online_window = int((await get_typed_setting(db, "auth.session_online_window_minutes"))["value"])
    return [
        AuthSessionRead(
            id=str(session.id),
            user_id=str(session.user_id),
            created_at=session.created_at,
            last_seen_at=session.last_seen_at,
            last_user_activity_at=session.last_user_activity_at,
            expires_at=session.expires_at,
            revoked_at=session.revoked_at,
            revoked_reason=session.revoked_reason,
            is_current=bool(current and current.id == session.id),
            status=session_state(session, online_window_minutes=online_window),
            login_ip=session.login_ip,
            last_ip=session.last_ip,
            browser_name=session.browser_name,
            browser_version=session.browser_version,
            os_name=session.os_name,
            os_version=session.os_version,
            device_type=session.device_type,
            user_agent=session.user_agent,
        )
        for session in sessions
    ]


@router.delete("/sessions/{session_id}", response_model=RevokeSessionsResponse)
async def revoke_own_session(
    session_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from uuid import UUID
    try:
        parsed_id = UUID(session_id)
    except ValueError as exc:
        raise APIError(422, "SESSION_ID_INVALID", "Session ID is invalid.") from exc
    revoked = await revoke_session_by_id(db, user_id=user.id, session_id=parsed_id, reason="SELF_SESSION_REVOKE")
    if not revoked:
        raise APIError(404, "SESSION_NOT_FOUND", "Active session not found.")
    await record_audit(
        db,
        action="SESSION_REVOKED",
        entity_type="AuthSession",
        entity_id=parsed_id,
        actor_user_id=user.id,
        actor_username_snapshot=user.username,
        actor_display_name_snapshot=user.display_name,
        entity_display_snapshot={"user_id": str(user.id)},
        description="User revoked one of their authentication sessions.",
        metadata={"reason": "SELF_SESSION_REVOKE"},
    )
    await db.commit()
    return RevokeSessionsResponse(revoked_count=1)


@router.post("/sessions/revoke-others", response_model=RevokeSessionsResponse)
async def revoke_other_sessions(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    token = extract_bearer_token(request)
    current = await current_session(db, session_token=token) if token else None
    if current is None:
        raise APIError(401, "AUTHENTICATION_REQUIRED", "Authentication is required.")
    count = await revoke_user_sessions(db, user_id=user.id, except_session_id=current.id, reason="SELF_REVOKE_OTHERS")
    await record_audit(
        db,
        action="SESSION_REVOKED",
        entity_type="User",
        entity_id=user.id,
        actor_user_id=user.id,
        actor_username_snapshot=user.username,
        actor_display_name_snapshot=user.display_name,
        entity_display_snapshot={"username": user.username},
        description="User revoked all other active sessions.",
        metadata={"reason": "SELF_REVOKE_OTHERS", "revoked_session_count": count},
    )
    await db.commit()
    return RevokeSessionsResponse(revoked_count=count)


@router.get("/me", response_model=CurrentUserResponse)
async def me(user: User = Depends(get_authenticated_user), db: AsyncSession = Depends(get_db)):
    roles = sorted(
        set(
            await db.scalars(
                select(Role.code)
                .join(UserRole, UserRole.role_id == Role.id)
                .where(UserRole.user_id == user.id)
            )
        )
    )
    role_permissions = await db.scalars(
        select(Permission.code)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(UserRole, UserRole.role_id == RolePermission.role_id)
        .where(UserRole.user_id == user.id)
    )
    direct_permissions = await db.scalars(
        select(Permission.code)
        .join(UserPermission, UserPermission.permission_id == Permission.id)
        .where(UserPermission.user_id == user.id)
    )
    permissions = sorted(set(role_permissions) | set(direct_permissions))
    requirement = await password_requirement(db, user)
    return CurrentUserResponse(
        id=str(user.id),
        username=user.username,
        display_name=user.display_name,
        roles=roles,
        permissions=permissions,
        must_change_password=requirement.required,
        password_change_reason=requirement.reason,
        password_changed_at=user.password_changed_at,
        password_expires_at=requirement.expires_at,
        password_expires_in_days=requirement.expires_in_days,
        password_expiry_warning=requirement.warning,
    )

