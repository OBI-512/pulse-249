"""Central RBAC prerequisite graph.

Only genuine authorization prerequisites belong here. Internal implementation
dependencies (for example, a delete operation creating a recycle-bin tombstone)
must never be represented as extra user privileges.
"""
from __future__ import annotations

from .permissions import ALL_PERMISSIONS, Permission as P


PERMISSION_PREREQUISITES: dict[str, frozenset[str]] = {
    P.USER_CREATE: frozenset({P.USER_READ}),
    P.USER_UPDATE: frozenset({P.USER_READ}),
    P.USER_DEACTIVATE: frozenset({P.USER_READ}),
    P.USER_PASSWORD_RESET: frozenset({P.USER_READ}),
    P.USER_ROLES_MANAGE: frozenset({P.USER_READ}),
    P.USER_PERMISSIONS_MANAGE: frozenset({P.USER_READ}),
    P.USER_SCOPES_READ: frozenset({P.USER_READ}),
    P.USER_SCOPES_MANAGE: frozenset({P.USER_READ, P.USER_SCOPES_READ}),
    P.USER_SESSIONS_READ: frozenset({P.USER_READ}),
    P.USER_SESSIONS_MANAGE: frozenset({P.USER_READ, P.USER_SESSIONS_READ}),

    P.SETTINGS_MANAGE: frozenset({P.SETTINGS_READ}),
    P.SETTINGS_SECRET_READ: frozenset({P.SETTINGS_READ}),

    P.DEVICE_CREATE: frozenset({P.DEVICE_READ}),
    P.DEVICE_UPDATE: frozenset({P.DEVICE_READ}),
    P.DEVICE_DELETE: frozenset({P.DEVICE_READ}),
    P.DEVICE_REMOTE_ACCESS_SSH: frozenset({P.DEVICE_READ}),
    P.DEVICE_REMOTE_ACCESS_WEB: frozenset({P.DEVICE_READ}),
    P.DEVICE_REMOTE_ACCESS_TELNET: frozenset({P.DEVICE_READ}),
    P.ACCESS_TEMPLATE_MANAGE: frozenset({P.ACCESS_TEMPLATE_READ}),
    P.ACCESS_TEMPLATE_TEST: frozenset({P.ACCESS_TEMPLATE_READ, P.DEVICE_READ}),
    P.DEVICE_CONFIGURATION_READ: frozenset({P.DEVICE_READ}),
    P.DEVICE_CONFIGURATION_CAPTURE: frozenset({P.DEVICE_READ}),
    P.DEVICE_CONFIGURATION_APPLY: frozenset({P.DEVICE_READ}),
    P.DEVICE_CONFIGURATION_RESTORE: frozenset({P.DEVICE_READ}),
    P.DEVICE_CONFIGURATION_TEMPLATE_MANAGE: frozenset({P.DEVICE_CONFIGURATION_TEMPLATE_READ}),

    P.GROUP_CREATE: frozenset({P.GROUP_READ}),
    P.GROUP_UPDATE: frozenset({P.GROUP_READ}),
    P.GROUP_DELETE: frozenset({P.GROUP_READ}),
    P.GROUP_MEMBERSHIP_MANAGE: frozenset({P.GROUP_READ, P.DEVICE_READ}),

    P.PLACEMENT_CREATE: frozenset({P.PLACEMENT_READ, P.DEVICE_READ}),
    P.PLACEMENT_UPDATE: frozenset({P.PLACEMENT_READ, P.DEVICE_READ}),
    P.RELATIONSHIP_CREATE: frozenset({P.RELATIONSHIP_READ, P.DEVICE_READ}),
    P.RELATIONSHIP_DELETE: frozenset({P.RELATIONSHIP_READ, P.DEVICE_READ}),

    P.DISCOVERY_RUN: frozenset({P.DISCOVERY_READ}),
    P.DISCOVERY_FLUSH: frozenset({P.DISCOVERY_READ}),
    P.CANDIDATE_REVIEW: frozenset({P.CANDIDATE_READ}),
    P.CANDIDATE_REGISTER: frozenset({P.CANDIDATE_READ}),
    P.AUDIT_EXPORT: frozenset({P.AUDIT_READ}),
    P.ALARM_ACKNOWLEDGE: frozenset({P.ALARM_READ}),
    P.ALARM_ASSIGN: frozenset({P.ALARM_READ}),
    P.ALARM_CLEAR: frozenset({P.ALARM_READ}),
    P.LOGS_EXPORT: frozenset({P.LOGS_READ}),

    P.NETWORK_CREATE: frozenset({P.NETWORK_READ}),
    P.NETWORK_UPDATE: frozenset({P.NETWORK_READ}),
    P.NETWORK_DELETE: frozenset({P.NETWORK_READ}),
    P.GEO_CREATE: frozenset({P.GEO_READ}),
    P.GEO_UPDATE: frozenset({P.GEO_READ}),
    P.GEO_DELETE: frozenset({P.GEO_READ}),
    P.CUSTOMER_CREATE: frozenset({P.CUSTOMER_READ}),
    P.CUSTOMER_UPDATE: frozenset({P.CUSTOMER_READ}),
    P.CUSTOMER_DELETE: frozenset({P.CUSTOMER_READ}),
    P.ONBOARDING_CREATE: frozenset({P.ONBOARDING_READ}),
    P.ONBOARDING_REGISTER: frozenset({P.ONBOARDING_READ}),

    P.RECYCLE_BIN_RESTORE: frozenset({P.RECYCLE_BIN_READ}),
    P.RECYCLE_BIN_PURGE: frozenset({P.RECYCLE_BIN_READ}),
    P.RESTORE_POINTS_CREATE: frozenset({P.RESTORE_POINTS_READ}),
    P.RESTORE_POINTS_RESTORE: frozenset({P.RESTORE_POINTS_READ}),
    P.RESTORE_POINTS_DELETE: frozenset({P.RESTORE_POINTS_READ}),

    P.PHYSICAL_MOVEMENT_SECTOR: frozenset({P.DEVICE_READ, P.GEO_READ}),
    P.PHYSICAL_MOVEMENT_CPE: frozenset({P.DEVICE_READ, P.GEO_READ}),
    P.PHYSICAL_MOVEMENT_ACCESS_POINT: frozenset({P.DEVICE_READ, P.GEO_READ}),

    P.TELEMETRY_MANAGE: frozenset({P.TELEMETRY_READ}),
    P.DATA_LIFECYCLE_MANAGE: frozenset({P.DATA_LIFECYCLE_READ}),
    P.DATA_EXCHANGE_IMPORT: frozenset({P.DATA_EXCHANGE_READ}),
    P.DATA_EXCHANGE_EXPORT: frozenset({P.DATA_EXCHANGE_READ}),
    P.REPORT_MANAGE: frozenset({P.REPORT_READ}),
    P.REPORT_EXPORT: frozenset({P.REPORT_READ}),
    P.REPORT_SCHEDULE: frozenset({P.REPORT_READ, P.REPORT_EXPORT}),
    P.REPORT_SENSITIVE: frozenset({P.REPORT_READ, P.REPORT_EXPORT}),
}


def prerequisites_for(permission_code: str) -> tuple[str, ...]:
    return tuple(sorted(PERMISSION_PREREQUISITES.get(permission_code, ())))


def expand_permission_codes(
    requested_codes: list[str] | tuple[str, ...] | set[str],
    *,
    satisfied_codes: list[str] | tuple[str, ...] | set[str] = (),
) -> list[str]:
    """Return requested direct grants plus missing transitive prerequisites.

    ``satisfied_codes`` are effective grants already supplied by a role. They
    satisfy prerequisites but are not duplicated as direct grants.
    """
    direct = set(requested_codes)
    satisfied = set(satisfied_codes)
    effective = direct | satisfied
    pending = list(effective)
    while pending:
        code = pending.pop()
        for prerequisite in PERMISSION_PREREQUISITES.get(code, ()):  # transitive closure
            if prerequisite in effective:
                continue
            effective.add(prerequisite)
            pending.append(prerequisite)
            if prerequisite not in satisfied:
                direct.add(prerequisite)
    return sorted(direct)


def dependency_catalog_errors() -> list[str]:
    errors: list[str] = []
    for code, requirements in PERMISSION_PREREQUISITES.items():
        if code not in ALL_PERMISSIONS:
            errors.append(f"Unknown dependent permission: {code}")
        for requirement in requirements:
            if requirement not in ALL_PERMISSIONS:
                errors.append(f"Unknown prerequisite permission: {requirement} (required by {code})")
    return errors
