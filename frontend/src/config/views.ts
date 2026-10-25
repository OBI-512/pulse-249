import type { Page } from "../types";

export type ViewDefinition = {
  id: Page;
  label: string;
  description: string;
  icon: string;
  area: "operations" | "administration" | "account";
};

export const VIEW_DEFINITIONS: Record<Page, ViewDefinition> = {
  overview: { id:"overview", label:"Overview", description:"System status and workload", icon:"overview", area:"operations" },
  alarms: { id:"alarms", label:"Alarms", description:"Active NOC alarms and ownership", icon:"alarms", area:"operations" },
  maintenance: { id:"maintenance", label:"Maintenance", description:"Maintenance windows and notification suppression", icon:"maintenance", area:"operations" },
  discovery: { id:"discovery", label:"Discovery", description:"Run and monitor discovery", icon:"discovery", area:"operations" },
  candidates: { id:"candidates", label:"Candidate Review", description:"Engineer review workflow", icon:"candidates", area:"operations" },
  devices: { id:"devices", label:"Devices", description:"Inventory and lifecycle", icon:"devices", area:"operations" },
  configuration: { id:"configuration", label:"Configuration", description:"Guarded device configuration lifecycle", icon:"settings", area:"operations" },
  networks: { id:"networks", label:"Networks", description:"Network and geography", icon:"network", area:"operations" },
  groups: { id:"groups", label:"Groups", description:"Organizational grouping", icon:"groups", area:"operations" },
  customers: { id:"customers", label:"Customers", description:"Customers and services", icon:"customers", area:"operations" },
  topology: { id:"topology", label:"Topology", description:"Network hierarchy view", icon:"topology", area:"operations" },
  "data-reporting": { id:"data-reporting", label:"Data & Reports", description:"Telemetry, lifecycle, data exchange and reporting", icon:"data-reporting", area:"operations" },
  recycle: { id:"recycle", label:"Recycle Bin", description:"Recover deleted objects", icon:"recycle", area:"administration" },
  "restore-points": { id:"restore-points", label:"Restore Points", description:"Backup and full-system restore", icon:"restore", area:"administration" },
  logs: { id:"logs", label:"Logs", description:"Audit and runtime logs", icon:"logs", area:"administration" },
  users: { id:"users", label:"User Management", description:"Accounts and access", icon:"users", area:"administration" },
  settings: { id:"settings", label:"Settings", description:"System configuration", icon:"settings", area:"administration" },
  account: { id:"account", label:"My Account", description:"Password and active sessions", icon:"account", area:"account" },
};

export function viewDefinition(page: Page): ViewDefinition {
  return VIEW_DEFINITIONS[page];
}
