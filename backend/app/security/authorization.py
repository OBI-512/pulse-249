from __future__ import annotations

from uuid import UUID

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..api.deps import get_db
from ..core.audit_context import bind_audit_actor
from .authentication import authenticate_request
from ..core.exceptions import APIError
from ..models import Permission, RolePermission, User, UserRole, UserPermission
from .permissions import Permission as PermissionCode
from .password_policy import password_requirement


async def get_authenticated_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Resolve any valid authenticated user, including restricted sessions."""
    user = await authenticate_request(request, db)
    if user is None:
        raise APIError(401, "AUTHENTICATION_REQUIRED", "Authentication is required.")
    bind_audit_actor(user.id, user.username, user.display_name)
    return user


async def get_current_user(
    user: User = Depends(get_authenticated_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Resolve an authenticated user who has completed password requirements.

    New-user, administrator-reset, and expired-password sessions are valid
    authentication sessions but are deliberately restricted to /auth/me,
    /auth/password/change-required, and logout until the password is replaced.
    """
    requirement = await password_requirement(db, user)
    if requirement.required:
        raise APIError(403, "PASSWORD_CHANGE_REQUIRED", "Password change is required before accessing the application.")
    return user


async def user_has_permission(
    db: AsyncSession,
    *,
    user_id: UUID,
    permission_code: str,
) -> bool:
    """
    Return whether a user receives a permission through a role or direct grant.
    """
    role_statement = (
        select(Permission.id)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(UserRole, UserRole.role_id == RolePermission.role_id)
        .where(UserRole.user_id == user_id, Permission.code == permission_code)
        .limit(1)
    )
    if (await db.execute(role_statement)).scalar_one_or_none() is not None:
        return True

    direct_statement = (
        select(Permission.id)
        .join(UserPermission, UserPermission.permission_id == Permission.id)
        .where(UserPermission.user_id == user_id, Permission.code == permission_code)
        .limit(1)
    )
    return (await db.execute(direct_statement)).scalar_one_or_none() is not None


def require_permission(permission_code: str):
    """
    Build a FastAPI dependency that requires one permission.

    Authentication is resolved first. Authorization is then evaluated
    against the user's database-backed roles and permissions.
    """

    async def dependency(
        user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> User:
        allowed = await user_has_permission(
            db,
            user_id=user.id,
            permission_code=permission_code,
        )

        if not allowed:
            raise APIError(
                403,
                "PERMISSION_DENIED",
                f"Permission '{permission_code}' is required.",
            )

        return user

    return dependency


# Central endpoint authorization map. Keeping this in one place makes the
# security boundary auditable while preserving the existing endpoint code.
def permission_for_request(request: Request) -> str | None:
    path = request.scope.get("route").path if request.scope.get("route") else request.url.path
    method = request.method.upper()

    if path.startswith("/api/auth/") or path in {"/api", "/api/health"}:
        return None

    # More specific paths must precede their parent resources.
    if path.startswith("/api/admin/users"):
        # The router enforces compound role/direct-permission checks where the
        # payload determines the required authority.  Keep this map explicit
        # for future router-level protection and never fall back to user.manage.
        if method == "GET":
            return PermissionCode.USER_READ
        if method == "POST":
            return PermissionCode.USER_CREATE
        if method == "DELETE":
            return PermissionCode.USER_DEACTIVATE
        return PermissionCode.USER_UPDATE
    if path.startswith("/api/admin/settings"):
        return "settings.read" if method == "GET" else "settings.manage"
    if path.startswith("/api/system-information"):
        return "settings.read"
    if path.startswith("/api/operations-dashboard"):
        return PermissionCode.DEVICE_READ
    if path.startswith("/api/alarms"):
        if path.endswith("/acknowledge"):
            return PermissionCode.ALARM_ACKNOWLEDGE
        if path.endswith("/owner"):
            return PermissionCode.ALARM_ASSIGN
        if path.endswith("/clear"):
            return PermissionCode.ALARM_CLEAR
        if method == "GET":
            return PermissionCode.ALARM_READ
        return None
    if path.startswith("/api/maintenance-windows"):
        return PermissionCode.MAINTENANCE_READ if method == "GET" else PermissionCode.MAINTENANCE_MANAGE
    if path.startswith("/api/notifications"):
        return PermissionCode.NOTIFICATION_READ if method == "GET" else PermissionCode.NOTIFICATION_MANAGE
    if path.startswith("/api/telemetry"):
        if path == "/api/telemetry/collect-now" or (path.startswith("/api/telemetry/profiles/") and method == "PATCH"):
            return PermissionCode.TELEMETRY_MANAGE
        return PermissionCode.TELEMETRY_READ
    if path.startswith("/api/data-lifecycle"):
        return PermissionCode.DATA_LIFECYCLE_MANAGE if method in {"POST", "PATCH", "PUT", "DELETE"} else PermissionCode.DATA_LIFECYCLE_READ
    if path.startswith("/api/data-exchange"):
        if path.startswith("/api/data-exchange/imports") and method == "POST":
            return PermissionCode.DATA_EXCHANGE_IMPORT
        if path == "/api/data-exchange/exports" and method == "POST":
            return PermissionCode.DATA_EXCHANGE_EXPORT
        return PermissionCode.DATA_EXCHANGE_READ
    if path.startswith("/api/reports"):
        if path == "/api/reports/run" and method == "POST":
            return PermissionCode.REPORT_EXPORT
        if path == "/api/reports/jobs" and method == "DELETE":
            return PermissionCode.REPORT_MANAGE
        if path.endswith("/download") and method == "GET":
            return PermissionCode.REPORT_EXPORT
        if path.startswith("/api/reports/schedules"):
            return PermissionCode.REPORT_SCHEDULE
        if path == "/api/reports/definitions" and method == "GET" and (request.query_params.get("state") or "active").strip().lower() == "deleted":
            return PermissionCode.REPORT_MANAGE
        if path.startswith("/api/reports/definitions") and method in {"POST", "PATCH", "DELETE"}:
            return PermissionCode.REPORT_MANAGE
        return PermissionCode.REPORT_READ
    if path.startswith("/api/audit/export"):
        return PermissionCode.AUDIT_EXPORT
    if path.startswith("/api/audit"):
        return PermissionCode.AUDIT_READ
    if path.startswith("/api/operational-logs/export"):
        return PermissionCode.LOGS_EXPORT
    if path.startswith("/api/operational-logs"):
        return PermissionCode.LOGS_READ
    if path == "/api/device-candidates" or path.startswith("/api/device-candidates/"):
        if path.endswith("/register"):
            return "candidate.register"
        if path.endswith("/audit") or method == "GET":
            return "candidate.read"
        return "candidate.review"
    if path.startswith("/api/discovery/batch"):
        return "discovery.run" if method == "POST" else "discovery.read"
    if path.startswith("/api/discovery/flush"):
        return PermissionCode.DISCOVERY_FLUSH if method == "POST" else PermissionCode.DISCOVERY_READ
    if path.startswith("/api/discovery"):
        return "discovery.run" if method == "POST" else "discovery.read"
    if path.startswith("/api/onboarding"):
        if path.endswith("/register"):
            return "onboarding.register"
        return "onboarding.create" if method == "POST" else "onboarding.read"
    if path.startswith("/api/recycle-bin"):
        if path == "/api/recycle-bin/preview":
            # Delete-preview is part of the entity deletion workflow. Requiring
            # recycle_bin.read here would force administrators to grant broad
            # recycle-bin visibility merely so a user can exercise entity.delete.
            preview_permissions = {
                "NETWORK": PermissionCode.NETWORK_DELETE,
                "CITY": PermissionCode.GEO_DELETE,
                "LOCATION": PermissionCode.GEO_DELETE,
                "SECTOR": PermissionCode.GEO_DELETE,
                "DEVICE": PermissionCode.DEVICE_DELETE,
                "CUSTOMER": PermissionCode.CUSTOMER_DELETE,
                "CUSTOMER_SERVICE": PermissionCode.CUSTOMER_DELETE,
                "DEVICE_GROUP": PermissionCode.GROUP_DELETE,
                "DEVICE_RELATIONSHIP": PermissionCode.RELATIONSHIP_DELETE,
                "DEVICE_IP": PermissionCode.DEVICE_DELETE,
                "DEVICE_INTERFACE": PermissionCode.DEVICE_DELETE,
            }
            entity_type = (request.query_params.get("entity_type") or "").strip().upper()
            return preview_permissions.get(entity_type, PermissionCode.RECYCLE_BIN_READ)
        if path.endswith("/restore"):
            return PermissionCode.RECYCLE_BIN_RESTORE
        if method == "DELETE":
            return PermissionCode.RECYCLE_BIN_PURGE
        return PermissionCode.RECYCLE_BIN_READ
    if path.startswith("/api/restore-points"):
        if path.endswith("/restore"):
            return PermissionCode.RESTORE_POINTS_RESTORE
        if path.endswith("/pin"):
            return PermissionCode.RESTORE_POINTS_DELETE
        if method == "DELETE":
            return PermissionCode.RESTORE_POINTS_DELETE
        if method == "POST" and not path.endswith("/verify"):
            return PermissionCode.RESTORE_POINTS_CREATE
        return PermissionCode.RESTORE_POINTS_READ
    if path.startswith("/api/physical-movements/sectors/"):
        return PermissionCode.PHYSICAL_MOVEMENT_SECTOR
    if path.startswith("/api/physical-movements/cpes/"):
        return PermissionCode.PHYSICAL_MOVEMENT_CPE
    if path.startswith("/api/physical-movements/access-points/"):
        return PermissionCode.PHYSICAL_MOVEMENT_ACCESS_POINT
    if path.startswith("/api/device-groups/") and ("/devices" in path or "/children" in path):
        return "group.membership.manage" if method in {"POST", "PUT", "DELETE"} else "group.read"
    if path.startswith("/api/device-groups"):
        return {"GET": "group.read", "POST": "group.create", "PATCH": "group.update", "DELETE": "group.delete"}.get(method)
    if path.startswith("/api/device-relationships"):
        return {"GET": "relationship.read", "POST": "relationship.create", "DELETE": "relationship.delete"}.get(method)
    if path.startswith("/api/device-summary"):
        return "device.read"
    if path.startswith("/api/placements") or (path.startswith("/api/devices/") and path.endswith("/placement")):
        return "placement.read" if method == "GET" else "placement.update"
    if path.startswith("/api/sectors/") and path.endswith("/role-transition"):
        return "geo.update"
    if path.startswith("/api/geo") or (path.startswith("/api/networks/") and "/cities" in path) or path.startswith("/api/cities") or path.startswith("/api/locations") or path.startswith("/api/sectors"):
        return {"GET": "geo.read", "POST": "geo.create", "PATCH": "geo.update", "DELETE": PermissionCode.GEO_DELETE}.get(method)
    if path.startswith("/api/assignment-options/locations") or path.startswith("/api/assignment-options/logical-sectors") or path.startswith("/api/assignment-options/sectors"):
        return "geo.read"
    if path.startswith("/api/assignment-options/customer-service-sectors"):
        return "customer.read"
    if path.startswith("/api/assignment-options"):
        return "device.read"
    if path.startswith("/api/template-assignment-options/access"):
        return PermissionCode.ACCESS_TEMPLATE_READ
    if path.startswith("/api/template-assignment-options/configuration"):
        return PermissionCode.DEVICE_CONFIGURATION_TEMPLATE_READ
    if path.startswith("/api/template-assignment-batches"):
        # TP4 uses device.read only as the HTTP boundary. The service enforces
        # payload-dependent Access/Configuration management permissions plus
        # effective resource scope at preview and apply time.
        return PermissionCode.DEVICE_READ
    if path.startswith("/api/access-templates"):
        if path.endswith("/test") and method == "POST":
            return PermissionCode.ACCESS_TEMPLATE_TEST
        return (
            PermissionCode.ACCESS_TEMPLATE_READ
            if method == "GET"
            else PermissionCode.ACCESS_TEMPLATE_MANAGE
        )
    if path.startswith("/api/configuration-batches"):
        # Batch read/control routes require configuration visibility at the
        # HTTP boundary. The F3 service then enforces the exact operation-type
        # permission (capture/apply/restore) at request time and dispatch time.
        return PermissionCode.DEVICE_CONFIGURATION_READ
    if path.startswith("/api/configuration-templates"):
        return (
            PermissionCode.DEVICE_CONFIGURATION_TEMPLATE_READ
            if method == "GET"
            else PermissionCode.DEVICE_CONFIGURATION_TEMPLATE_MANAGE
        )
    if path.startswith("/api/devices/") and "/configuration" in path:
        if path.endswith("/capture") and method == "POST":
            return PermissionCode.DEVICE_CONFIGURATION_CAPTURE
        if path.endswith("/apply") and method == "POST":
            return PermissionCode.DEVICE_CONFIGURATION_APPLY
        if path.endswith("/verify") and method == "POST":
            return PermissionCode.DEVICE_CONFIGURATION_CAPTURE
        if path.endswith("/restore") and method == "POST":
            return PermissionCode.DEVICE_CONFIGURATION_RESTORE
        if path.endswith("/binding") and method == "PUT":
            return PermissionCode.DEVICE_CONFIGURATION_TEMPLATE_MANAGE
        if method == "GET":
            return PermissionCode.DEVICE_CONFIGURATION_READ
        return None
    if path.startswith("/api/devices/") and "/remote-access/web/tls/" in path:
        if path.endswith("/inspect") and method == "POST":
            return PermissionCode.DEVICE_REMOTE_ACCESS_WEB
        if path.endswith(("/trust", "/replace")) and method == "POST":
            return PermissionCode.DEVICE_REMOTE_ACCESS_WEB_TRUST
        return None
    if path.startswith("/api/devices/") and "/remote-access/telnet-sessions" in path:
        return PermissionCode.DEVICE_REMOTE_ACCESS_TELNET
    if path.startswith("/api/devices/") and (
        path.endswith("/remote-access/web") or "/remote-access/web-sessions" in path
    ):
        return PermissionCode.DEVICE_REMOTE_ACCESS_WEB
    if path.startswith("/api/devices/") and "/remote-access" in path:
        return PermissionCode.DEVICE_REMOTE_ACCESS_SSH
    if path.startswith("/api/devices"):
        if method == "GET":
            return PermissionCode.DEVICE_READ
        if method == "DELETE":
            return PermissionCode.DEVICE_DELETE
        if method == "PATCH":
            return PermissionCode.DEVICE_UPDATE
        if method == "POST":
            if path == "/api/devices":
                return PermissionCode.DEVICE_CREATE
            if path.endswith("/test-accessibility"):
                return PermissionCode.DEVICE_READ
            if path.endswith(("/decommission", "/reactivate", "/ips", "/interfaces")):
                return PermissionCode.DEVICE_UPDATE
            return None
    if path.startswith("/api/topology"):
        return "topology.read"
    if path.startswith("/api/customers"):
        return {"GET": "customer.read", "POST": "customer.create", "PATCH": "customer.update", "DELETE": PermissionCode.CUSTOMER_DELETE}.get(method)
    if path.startswith("/api/networks"):
        return {"GET": "network.read", "POST": "network.create", "PATCH": "network.update", "DELETE": PermissionCode.NETWORK_DELETE}.get(method)
    return None


async def authorize_request(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    permission_code = permission_for_request(request)
    if permission_code is None:
        # Routers using this dependency are protected resources. Every method,
        # including GET, fails closed when a new route has no explicit mapping.
        raise APIError(
            403,
            "PERMISSION_DENIED",
            "An explicit permission is required for this operation.",
        )
    if not await user_has_permission(db, user_id=user.id, permission_code=permission_code):
        raise APIError(403, "PERMISSION_DENIED", f"Permission '{permission_code}' is required.")

    # WHERE authorization is an independent dimension. Whole-system control
    # plane operations are deliberately GLOBAL-only until their data carries
    # immutable resource-scope provenance. Import locally to keep the WHAT
    # authorization module as the compatibility boundary without a cycle.
    from .resource_scope import request_requires_global_scope, require_global_scope
    if request_requires_global_scope(request):
        await require_global_scope(db, user)
    return user