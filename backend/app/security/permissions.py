from __future__ import annotations


class Permission:
    DEVICE_READ = "device.read"
    DEVICE_CREATE = "device.create"
    DEVICE_UPDATE = "device.update"
    DEVICE_DELETE = "device.delete"

    DEVICE_REMOTE_ACCESS_SSH = "device.remote_access.ssh"
    DEVICE_REMOTE_ACCESS_WEB = "device.remote_access.web"
    DEVICE_REMOTE_ACCESS_WEB_TRUST = "device.remote_access.web.trust"
    DEVICE_REMOTE_ACCESS_TELNET = "device.remote_access.telnet"

    ACCESS_TEMPLATE_READ = "access_template.read"
    ACCESS_TEMPLATE_MANAGE = "access_template.manage"
    ACCESS_TEMPLATE_TEST = "access_template.test"

    DEVICE_CONFIGURATION_READ = "device.configuration.read"
    DEVICE_CONFIGURATION_CAPTURE = "device.configuration.capture"
    DEVICE_CONFIGURATION_APPLY = "device.configuration.apply"
    DEVICE_CONFIGURATION_RESTORE = "device.configuration.restore"
    DEVICE_CONFIGURATION_TEMPLATE_READ = "device.configuration.template.read"
    DEVICE_CONFIGURATION_TEMPLATE_MANAGE = "device.configuration.template.manage"

    NETWORK_READ = "network.read"
    NETWORK_CREATE = "network.create"
    NETWORK_UPDATE = "network.update"
    NETWORK_DELETE = "network.delete"

    GEO_READ = "geo.read"
    GEO_CREATE = "geo.create"
    GEO_UPDATE = "geo.update"
    GEO_DELETE = "geo.delete"

    CUSTOMER_READ = "customer.read"
    CUSTOMER_CREATE = "customer.create"
    CUSTOMER_UPDATE = "customer.update"
    CUSTOMER_DELETE = "customer.delete"

    ONBOARDING_READ = "onboarding.read"
    ONBOARDING_CREATE = "onboarding.create"
    ONBOARDING_REGISTER = "onboarding.register"

    GROUP_READ = "group.read"
    GROUP_CREATE = "group.create"
    GROUP_UPDATE = "group.update"
    GROUP_DELETE = "group.delete"
    GROUP_MEMBERSHIP_MANAGE = "group.membership.manage"

    PLACEMENT_READ = "placement.read"
    PLACEMENT_CREATE = "placement.create"
    PLACEMENT_UPDATE = "placement.update"

    RELATIONSHIP_READ = "relationship.read"
    RELATIONSHIP_CREATE = "relationship.create"
    RELATIONSHIP_DELETE = "relationship.delete"

    RECYCLE_BIN_READ = "recycle_bin.read"
    RECYCLE_BIN_RESTORE = "recycle_bin.restore"
    RECYCLE_BIN_PURGE = "recycle_bin.purge"

    DISCOVERY_READ = "discovery.read"
    DISCOVERY_RUN = "discovery.run"
    DISCOVERY_FLUSH = "discovery.flush"

    CANDIDATE_READ = "candidate.read"
    CANDIDATE_REVIEW = "candidate.review"
    CANDIDATE_REGISTER = "candidate.register"

    AUDIT_READ = "audit.read"
    AUDIT_EXPORT = "audit.export"

    ALARM_READ = "alarm.read"
    ALARM_ACKNOWLEDGE = "alarm.acknowledge"
    ALARM_ASSIGN = "alarm.assign"
    ALARM_CLEAR = "alarm.clear"

    MAINTENANCE_READ = "maintenance.read"
    MAINTENANCE_MANAGE = "maintenance.manage"
    NOTIFICATION_READ = "notification.read"
    NOTIFICATION_MANAGE = "notification.manage"

    TOPOLOGY_READ = "topology.read"

    PHYSICAL_MOVEMENT_SECTOR = "physical_movement.sector"
    PHYSICAL_MOVEMENT_CPE = "physical_movement.cpe"
    PHYSICAL_MOVEMENT_ACCESS_POINT = "physical_movement.access_point"

    USER_READ = "user.read"
    USER_CREATE = "user.create"
    USER_UPDATE = "user.update"
    USER_DEACTIVATE = "user.deactivate"
    USER_PASSWORD_RESET = "user.password.reset"
    USER_ROLES_MANAGE = "user.roles.manage"
    USER_PERMISSIONS_MANAGE = "user.permissions.manage"
    USER_SCOPES_READ = "user.scopes.read"
    USER_SCOPES_MANAGE = "user.scopes.manage"
    USER_SESSIONS_READ = "user.sessions.read"
    USER_SESSIONS_MANAGE = "user.sessions.manage"
    SETTINGS_SECRET_READ = "settings.secret.read"
    RESTORE_POINTS_READ = "restore_points.read"
    RESTORE_POINTS_CREATE = "restore_points.create"
    RESTORE_POINTS_RESTORE = "restore_points.restore"
    RESTORE_POINTS_DELETE = "restore_points.delete"
    LOGS_READ = "logs.read"
    LOGS_EXPORT = "logs.export"
    # Legacy compatibility identifier only.  New endpoints use the explicit
    # permissions above and never treat this as blanket authority.
    USER_MANAGE = "user.manage"
    SETTINGS_READ = "settings.read"
    SETTINGS_MANAGE = "settings.manage"

    TELEMETRY_READ = "telemetry.read"
    TELEMETRY_MANAGE = "telemetry.manage"
    DATA_LIFECYCLE_READ = "data_lifecycle.read"
    DATA_LIFECYCLE_MANAGE = "data_lifecycle.manage"
    DATA_EXCHANGE_READ = "data_exchange.read"
    DATA_EXCHANGE_IMPORT = "data_exchange.import"
    DATA_EXCHANGE_EXPORT = "data_exchange.export"
    REPORT_READ = "report.read"
    REPORT_MANAGE = "report.manage"
    REPORT_EXPORT = "report.export"
    REPORT_SCHEDULE = "report.schedule"
    REPORT_SENSITIVE = "report.sensitive"


ALL_PERMISSIONS = frozenset(
    {
        value
        for name, value in vars(Permission).items()
        if name.isupper()
    }
)
