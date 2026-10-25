import { viewDefinition, type ViewDefinition } from "../config/views";

export function buildNavigation(permissions: readonly string[]): ViewDefinition[] {
  return [
    viewDefinition("overview"),
    ...(permissions.includes("alarm.read") ? [viewDefinition("alarms")] : []),
    ...(permissions.includes("maintenance.read") ? [viewDefinition("maintenance")] : []),
    ...(permissions.includes("discovery.read") ? [viewDefinition("discovery")] : []),
    ...(permissions.includes("candidate.read") ? [viewDefinition("candidates")] : []),
    ...(permissions.includes("device.read") ? [viewDefinition("devices")] : []),
    ...((permissions.includes("device.read") && permissions.includes("device.configuration.read")) ? [viewDefinition("configuration")] : []),
    ...((permissions.includes("network.read") || permissions.includes("geo.read")) ? [viewDefinition("networks")] : []),
    ...(permissions.includes("group.read") ? [viewDefinition("groups")] : []),
    ...(permissions.includes("customer.read") ? [viewDefinition("customers")] : []),
    ...(permissions.includes("topology.read") ? [viewDefinition("topology")] : []),
    ...((permissions.includes("telemetry.read") || permissions.includes("data_lifecycle.read") || permissions.includes("data_exchange.read") || permissions.includes("report.read")) ? [viewDefinition("data-reporting")] : []),
    viewDefinition("account"),
    ...(permissions.includes("recycle_bin.read") ? [viewDefinition("recycle")] : []),
    ...(permissions.includes("restore_points.read") ? [viewDefinition("restore-points")] : []),
    ...((permissions.includes("audit.read") || permissions.includes("logs.read")) ? [viewDefinition("logs")] : []),
    ...(permissions.includes("user.read") ? [viewDefinition("users")] : []),
    ...(permissions.includes("settings.read") ? [viewDefinition("settings")] : []),
  ];
}
