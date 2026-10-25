import type { Page } from "../types";

export const PERMISSION = {
  DEVICE_READ: "device.read",
  DEVICE_CREATE: "device.create",
  DEVICE_UPDATE: "device.update",
  DEVICE_DELETE: "device.delete",
  DEVICE_CONFIGURATION_READ: "device.configuration.read",
  DEVICE_CONFIGURATION_CAPTURE: "device.configuration.capture",
  DEVICE_CONFIGURATION_APPLY: "device.configuration.apply",
  DEVICE_CONFIGURATION_RESTORE: "device.configuration.restore",
  DEVICE_CONFIGURATION_TEMPLATE_READ: "device.configuration.template.read",
  DEVICE_CONFIGURATION_TEMPLATE_MANAGE: "device.configuration.template.manage",
  ALARM_READ: "alarm.read",
  ALARM_ACKNOWLEDGE: "alarm.acknowledge",
  ALARM_ASSIGN: "alarm.assign",
  ALARM_CLEAR: "alarm.clear",
  MAINTENANCE_READ: "maintenance.read",
  MAINTENANCE_MANAGE: "maintenance.manage",
  NOTIFICATION_READ: "notification.read",
  NOTIFICATION_MANAGE: "notification.manage",
  PLACEMENT_UPDATE: "placement.update",
  PHYSICAL_MOVEMENT_SECTOR: "physical_movement.sector",
  PHYSICAL_MOVEMENT_CPE: "physical_movement.cpe",
  PHYSICAL_MOVEMENT_ACCESS_POINT: "physical_movement.access_point",
  DISCOVERY_READ: "discovery.read",
  DISCOVERY_RUN: "discovery.run",
  DISCOVERY_FLUSH: "discovery.flush",
  CANDIDATE_READ: "candidate.read",
  CANDIDATE_REVIEW: "candidate.review",
  CANDIDATE_REGISTER: "candidate.register",
  NETWORK_READ: "network.read",
  NETWORK_CREATE: "network.create",
  NETWORK_DELETE: "network.delete",
  GEO_READ: "geo.read",
  GEO_CREATE: "geo.create",
  GEO_DELETE: "geo.delete",
  GROUP_READ: "group.read",
  GROUP_CREATE: "group.create",
  GROUP_DELETE: "group.delete",
  GROUP_MEMBERSHIP_MANAGE: "group.membership.manage",
  CUSTOMER_READ: "customer.read",
  CUSTOMER_CREATE: "customer.create",
  CUSTOMER_UPDATE: "customer.update",
  CUSTOMER_DELETE: "customer.delete",
  TOPOLOGY_READ: "topology.read",
  RECYCLE_BIN_READ: "recycle_bin.read",
  RESTORE_POINTS_READ: "restore_points.read",
  AUDIT_READ: "audit.read",
  LOGS_READ: "logs.read",
  USER_READ: "user.read",
  SETTINGS_READ: "settings.read",
  TELEMETRY_READ: "telemetry.read",
  DATA_LIFECYCLE_READ: "data_lifecycle.read",
  DATA_EXCHANGE_READ: "data_exchange.read",
  REPORT_READ: "report.read",
} as const;

export function hasPermission(permissions: readonly string[] | null | undefined, permission: string): boolean {
  return Boolean(permissions?.includes(permission));
}

export function canAccessPage(page: Page, permissions: readonly string[]): boolean {
  switch (page) {
    case "overview":
    case "account":
      return true;
    case "alarms":
      return hasPermission(permissions, PERMISSION.ALARM_READ);
    case "maintenance":
      return hasPermission(permissions, PERMISSION.MAINTENANCE_READ);
    case "discovery":
      return hasPermission(permissions, PERMISSION.DISCOVERY_READ);
    case "candidates":
      return hasPermission(permissions, PERMISSION.CANDIDATE_READ);
    case "devices":
      return hasPermission(permissions, PERMISSION.DEVICE_READ);
    case "configuration":
      return hasPermission(permissions, PERMISSION.DEVICE_READ) && hasPermission(permissions, PERMISSION.DEVICE_CONFIGURATION_READ);
    case "networks":
      return hasPermission(permissions, PERMISSION.NETWORK_READ) || hasPermission(permissions, PERMISSION.GEO_READ);
    case "groups":
      return hasPermission(permissions, PERMISSION.GROUP_READ);
    case "customers":
      return hasPermission(permissions, PERMISSION.CUSTOMER_READ);
    case "topology":
      return hasPermission(permissions, PERMISSION.TOPOLOGY_READ);
    case "data-reporting":
      return hasPermission(permissions, PERMISSION.TELEMETRY_READ) || hasPermission(permissions, PERMISSION.DATA_LIFECYCLE_READ) || hasPermission(permissions, PERMISSION.DATA_EXCHANGE_READ) || hasPermission(permissions, PERMISSION.REPORT_READ);
    case "recycle":
      return hasPermission(permissions, PERMISSION.RECYCLE_BIN_READ);
    case "restore-points":
      return hasPermission(permissions, PERMISSION.RESTORE_POINTS_READ);
    case "logs":
      return hasPermission(permissions, PERMISSION.AUDIT_READ) || hasPermission(permissions, PERMISSION.LOGS_READ);
    case "users":
      return hasPermission(permissions, PERMISSION.USER_READ);
    case "settings":
      return hasPermission(permissions, PERMISSION.SETTINGS_READ);
    default:
      return false;
  }
}
