import { ApiError } from "../api/client";

export type ErrorContext = {
  action?: string;
  entityType?: string;
  entityName?: string;
};

export type FriendlyNotice = { title: string; message: string };

type Conflict = { code?: string; entity_type?: string; entity_id?: string; message?: string };

const STATIC: Record<string, string> = {
  NETWORK_REQUEST_FAILED: "The application cannot reach the server. Check the network connection and try again.",
  INVALID_CREDENTIALS: "The username or password is incorrect. Check both fields and try again.",
  AUTHENTICATION_REQUIRED: "Your session has expired. Sign in again to continue.",
  PERMISSION_DENIED: "Your account does not have access to this action. Ask an administrator if you need it.",
  RESOURCE_SCOPE_DENIED: "Your account is limited to specific areas. This action requires access to the whole system.",
  RESOURCE_NOT_FOUND: "The requested item no longer exists or is no longer available.",
  DEVICE_NOT_FOUND: "The selected device no longer exists. Refresh the device list before continuing.",
  PARENT_DEVICE_NOT_FOUND: "The selected parent device is no longer available. Choose another parent and try again.",
  INVALID_PARENT_DEVICE_TYPE: "This device cannot be attached to the selected parent. Choose the parent type shown for this device and try again.",
  INVALID_PARENT_DEVICE: "The selected parent device cannot be used for this operation.",
  PARENT_DEVICE_REQUIRED: "Select the required physical parent device before continuing.",
  HIERARCHY_INPUT_FORBIDDEN: "This device gets its location from its parent device. Choose the parent device instead of entering the location manually.",
  HIERARCHY_MANAGED_PARENT: "This device is attached to a parent device and cannot be moved on its own. Move or change the parent device instead.",
  HIERARCHY_RELATIONSHIP_TYPE_REQUIRED: "The selected parent is not compatible with this device. Choose the correct parent device and try again.",
  RELATIONSHIP_TYPE_REQUIRED: "Choose the device this item is physically connected to before registering it.",
  SECTOR_ID_REQUIRED: "Select the sector represented by this physical SECTOR device.",
  SECTOR_ALREADY_HAS_DEVICE: "That sector is already represented by another physical SECTOR device. Choose a different sector.",
  SECTOR_DEVICE_BINDING_NOT_FOUND: "The selected physical SECTOR device is not bound to a sector. Correct its sector assignment before attaching child devices.",
  BACKHAUL_SECTOR_NOT_CUSTOMER_SERVING: "A CPE cannot be attached to a backhaul-only sector. Select a customer-access SECTOR device.",
  CPE_ALREADY_HAS_ACCESS_POINT: "The selected CPE already has an access point. A CPE can have only one access point in the current hierarchy.",
  IP_ALREADY_REGISTERED: "Another managed device already uses this management IP address. Use a different IP or update the existing device.",
  UNIQUE_IDENTITY_IN_USE: "Another active record already uses the same unique identity. Change the conflicting name, code, serial number, IP address, or other unique value.",
  INVALID_IPV4: "Enter a valid IPv4 address, for example 192.168.1.10.",
  IPV4_REQUIRED: "This field accepts IPv4 addresses only.",
  DISCOVERED_IP_IMMUTABLE: "The management IP came from discovery and cannot be changed. Other review fields remain editable.",
  CANDIDATE_IP_ALREADY_EXISTS: "Another candidate already uses this IPv4 address. Search the review queue before continuing.",
  INVALID_CPE_PARENT: "Select an active physical SECTOR device assigned to a CUSTOMER_ACCESS logical sector.",
  INVALID_AP_PARENT: "Select an active CPE as the access point parent.",
  LOCATION_NOT_AVAILABLE: "The selected location is no longer active or available. Search for another location.",
  SECTOR_NOT_AVAILABLE: "The selected logical sector is no longer active or available. Search for another sector.",
  INVALID_MANAGEMENT_IP: "Enter a valid IPv4 management address, for example 192.168.1.10.",
  MANAGEMENT_IP_REQUIRED: "Enter a management IP address before continuing.",
  ADDRESS_FAMILY_MISMATCH: "The IP address does not match IPv4 format. Correct the address and try again.",
  PRIMARY_IP_MUST_BE_MANAGEMENT: "A primary IP address must also be marked as a management IP address.",
  IP_NOT_FOUND: "The selected IP address no longer exists on this device. Refresh the device details and try again.",
  INTERFACE_NOT_FOUND: "The selected interface no longer exists on this device. Refresh the device details and try again.",
  DEVICE_TYPE_REQUIRED: "Select a device type before continuing.",
  DEVICE_TYPE_INACTIVE: "The selected device type is inactive and cannot be used for new registrations.",
  UNSUPPORTED_DEVICE_TYPE: "The selected device type is not supported by this system.",
  DEVICE_TYPE_CHANGE_RELATIONSHIP_PROTECTED: "The device type cannot be changed while it is attached to another device. Detach or reassign the connected devices first.",
  CANDIDATE_NOT_APPROVED: "Approve this candidate before registering it as a managed device.",
  CANDIDATE_REGISTERED: "This candidate has already been registered and can no longer be edited as a candidate.",
  INVALID_CANDIDATE_TRANSITION: "That candidate action is not available in the current review state. Refresh the candidate and choose an available action.",
  REGISTERED_WITHOUT_RESULT: "This candidate was registered previously, but its saved registration result is incomplete. An administrator should review the candidate record before retrying.",
  ONBOARDING_CANDIDATE_NOT_FOUND: "The candidate no longer exists or is no longer available for registration.",
  INCOMPLETE_PLACEMENT: "The physical placement is incomplete. Select the required location or physical parent device.",
  LOCATION_REQUIRED: "Select a location before continuing.",
  PLACEMENT_NOT_FOUND: "This device does not currently have a physical placement record.",
  NETWORK_REQUIRED: "Select a network before continuing.",
  CITY_REQUIRED: "Select a city before continuing.",
  LOCATION_NOT_FOUND: "The selected location no longer exists. Refresh the geography list and choose another location.",
  CITY_NOT_FOUND: "The selected city no longer exists. Refresh the geography list and choose another city.",
  NETWORK_NOT_FOUND: "The selected network no longer exists. Refresh the network list and choose another network.",
  SECTOR_NOT_FOUND: "The selected sector no longer exists. Refresh the sector list and choose another sector.",
  CITY_NETWORK_MISMATCH: "The selected city does not belong to the selected network. Choose a city from that network.",
  LOCATION_CITY_MISMATCH: "The selected location does not belong to the selected city. Choose a location from that city.",
  SECTOR_LOCATION_MISMATCH: "The selected sector does not belong to the selected location. Choose a sector from that location.",
  GROUP_NOT_FOUND: "The selected group no longer exists. Refresh the group list and try again.",
  GROUP_CONTEXT_REQUIRED: "This group requires a geographic context. Select the required network, city, location, or sector.",
  INVALID_GROUP_SCOPE: "The selected group scope is not valid. Review the group geography and device scope.",
  GROUP_SCOPE_MISMATCH: "This device is outside the geographic or device-type scope of the selected group.",
  MEMBERSHIP_EXISTS: "This device is already a direct member of the selected group.",
  MEMBERSHIP_NOT_FOUND: "This direct group membership no longer exists. Refresh the group and try again.",
  GROUP_CONTEXT_MEMBERSHIP_EXISTS: "Devices are still directly assigned to this group in the selected area. Remove or move those device assignments first.",
  GROUP_CRITERIA_HAS_INCOMPATIBLE_MEMBERS: "The new group rules would exclude devices that are currently assigned to the group. Remove or move those devices first.",
  GROUP_SECTOR_ROLE_REQUIRES_SECTOR_SCOPE: "A sector-role filter can be used only with a group whose device scope is SECTOR.",
  DEVICE_DECOMMISSIONED: "This device is decommissioned and cannot be modified. Restore it to an allowed lifecycle state before making this change.",
  DEVICE_ALREADY_DECOMMISSIONED: "This device is already decommissioned; no additional decommission action is required.",
  INVALID_INITIAL_LIFECYCLE_STATE: "The selected lifecycle state cannot be used when creating a new device.",
  INVALID_LIFECYCLE_TRANSITION: "The requested lifecycle change is not allowed from the device's current state.",
  DEVICE_NOT_DECOMMISSIONED: "This device cannot be moved to the Recycle Bin until it is decommissioned first.",
  DEVICE_HAS_CUSTOMER_SERVICE_DEPENDENCIES: "This device cannot be deleted because an active customer service is still using it. Move that service to another device or remove the service first.",
  DEVICE_HAS_HIERARCHY_DEPENDENCIES: "This device cannot be deleted because other devices are still attached to it. Move or detach those devices first.",
  SECTOR_DEVICE_IS_BOUND: "This physical SECTOR device is still assigned to a sector. Assign another device to that sector or remove the assignment first.",
  SECTOR_HAS_CUSTOMER_DEPENDENCIES: "This sector is still being used by CPEs or active customer services. Move or remove those items before continuing.",
  RECYCLE_DEPENDENCIES_PRESENT: "This item cannot be moved to the Recycle Bin because other items still need it. Review the listed items and move or remove them first.",
  RECYCLE_CONFIRMATION_REQUIRED: "This deletion also affects related records and requires explicit confirmation before it can continue.",
  INVALID_RECYCLE_STATUS: "This Recycle Bin action is not available for the item's current status.",
  UNSUPPORTED_RECYCLE_ENTITY_TYPE: "This type of item is not supported by the Recycle Bin.",
  RECYCLE_BATCH_NOT_FOUND: "This Recycle Bin item no longer exists. Refresh the Recycle Bin and try again.",
  RECYCLE_RETENTION_NOT_EXPIRED: "This item is still inside its retention period and cannot be permanently deleted yet. Wait until the purge date or use an authorized override.",
  RECYCLE_PURGE_CONFIRMATION_INVALID: "Permanent deletion was not confirmed correctly. Repeat the purge action and enter the requested confirmation value.",
  RECYCLE_PURGE_DEVICE_CANDIDATE_DEPENDENCY: "This device cannot be permanently deleted because discovery/candidate history still references it. Resolve or remove the referencing candidate history before purging the device.",
  RECYCLE_RESTORE_CONFLICT: "This item cannot be restored because another active item now uses the same identity, or something it needs has changed. Resolve the conflicting item first.",
  RECYCLE_RESTORE_VALIDATION_FAILED: "This item cannot be restored in its previous setup. Check its parent device, location, group, and customer service, then try again.",
  BATCH_DEVICE_SELECTION_REQUIRED: "Select at least one device before running a batch action.",
  BATCH_ACTION_NOT_SUPPORTED: "The selected devices cannot all perform this batch action in their current states.",
  OPERATION_NOT_ALLOWED: "This action is not available for the selected item in its current state.",
  DISCOVERY_FLUSH_ACTIVE_JOBS: "Discovery data cannot be cleared while a discovery job is still running. Wait for active jobs to finish or stop them first.",
  DISCOVERY_JOB_NOT_FOUND: "The selected discovery job no longer exists. Refresh the discovery page and try again.",
  DISCOVERY_QUEUE_UNAVAILABLE: "The discovery worker queue is unavailable. No job was started. Check the worker service and try again.",
  INVALID_DISCOVERY_SCOPE: "The discovery scope is incomplete or invalid. Review the target network, range, or source before starting discovery.",
  NO_DISCOVERY_TARGETS: "No valid discovery targets were produced from the selected scope. Adjust the target range or discovery source.",
  UNSUPPORTED_DISCOVERY_METHOD: "The selected discovery method is not supported.",
  BATCH_JOB_NOT_FOUND: "The selected batch discovery job no longer exists. Refresh the batch list and try again.",
  SNMP_BATCH_CREDENTIAL_REFERENCE_REQUIRED: "Select a stored SNMP credential reference before starting this SNMP batch discovery.",
  SNMP_COMMUNITY_REQUIRED: "Enter an SNMP community string for SNMP v1/v2c discovery.",
  SNMP_V3_USERNAME_REQUIRED: "Enter the SNMPv3 username before starting discovery.",
  SNMP_V3_AUTH_PASSWORD_REQUIRED: "Enter the SNMPv3 authentication password for the selected security level.",
  SNMP_V3_PRIV_PASSWORD_REQUIRED: "Enter the SNMPv3 privacy password for the selected security level.",
  INVALID_SNMP_VERSION: "Select a supported SNMP version.",
  INVALID_SNMP_V3_SECURITY_LEVEL: "Select a valid SNMPv3 security level.",
  INVALID_SNMP_V3_AUTH_PROTOCOL: "Select a supported SNMPv3 authentication protocol.",
  INVALID_SNMP_V3_PRIV_PROTOCOL: "Select a supported SNMPv3 privacy protocol.",
  SNMP_SECRET_TOO_LONG: "The supplied SNMP secret is longer than the supported maximum length.",
  AUDIT_EVENT_NOT_FOUND: "The selected audit event no longer exists or is outside the available audit history.",
  AUDIT_RESULT_INVALID: "Select a valid audit result filter.",
  AUDIT_TIME_RANGE_INVALID: "The audit start time must be earlier than the end time.",
  LOG_LEVEL_INVALID: "Select a valid operational log level.",
  LOG_SERVICE_INVALID: "Select a valid application service for the operational log view.",
  MAINTENANCE_MODE_ACTIVE: "The system is currently in maintenance mode. This action is temporarily unavailable until maintenance finishes.",
  CUSTOMER_ID_MISMATCH: "The selected customer does not match the customer service being changed. Refresh the customer record and try again.",
  DATA_CONFLICT: "The record changed or conflicts with another active record. Refresh the page, review the latest values, and try again.",
  DATABASE_ERROR: "The system could not save this change. No partial change was intentionally applied. Try again; if the problem repeats, contact an administrator.",
};

function plainLanguage(message: string): string {
  return message
    .replace(/\bdependencies\b/gi, "related items")
    .replace(/\bdependency\b/gi, "related item")
    .replace(/\bhierarchy\b/gi, "parent/child device structure")
    .replace(/\brelationships\b/gi, "connections")
    .replace(/\brelationship\b/gi, "connection")
    .replace(/\bbindings\b/gi, "assignments")
    .replace(/\bbinding\b/gi, "assignment")
    .replace(/\bresource scopes\b/gi, "allowed areas")
    .replace(/\bresource scope\b/gi, "allowed area")
    .replace(/\bpermissions\b/gi, "access rights")
    .replace(/\bpermission\b/gi, "access right")
    .replace(/\bconstraints\b/gi, "rules")
    .replace(/\bconstraint\b/gi, "rule")
    .replace(/\bvalidation\b/gi, "check")
    .replace(/\bforeign key\b/gi, "linked item");
}

function titleFromFallback(fallback: string): string {
  const clean = fallback.replace(/[.!]+$/, "").trim();
  if (!clean) return "Unable to complete action";
  if (/^unable to /i.test(clean)) return clean.replace(/^unable to /i, "Unable to ");
  if (/failed$/i.test(clean)) return clean;
  return "Unable to complete action";
}

function entityLabel(context?: ErrorContext): string {
  if (!context?.entityName) return context?.entityType?.toLowerCase() || "item";
  return `${context.entityType ? `${context.entityType.toLowerCase()} ` : ""}\u201c${context.entityName}\u201d`;
}

export function friendlyConflict(conflict: Conflict, context?: ErrorContext): string {
  const code = conflict?.code || "";
  const target = entityLabel(context);
  switch (code) {
    case "DEVICE_NOT_DECOMMISSIONED": return `${target} must be decommissioned before it can be moved to the Recycle Bin.`;
    case "DEVICE_HAS_CUSTOMER_SERVICE_DEPENDENCIES": return `${target} is still used by an active customer service. Move that service to another device or remove it first.`;
    case "DEVICE_HAS_HIERARCHY_DEPENDENCIES": return `${target} still has other devices attached to it. Move or detach those devices first.`;
    case "SECTOR_DEVICE_IS_BOUND": return `${target} is still assigned as the physical device for a sector. Assign another device or remove that assignment first.`;
    case "SECTOR_HAS_CUSTOMER_DEPENDENCIES": return `${target} still has attached CPEs or active customer services. Move or remove them first.`;
    case "GROUP_CONTEXT_MEMBERSHIP_EXISTS": return `${target} is still used by direct device assignments in a group. Remove or move those assignments first.`;
    case "RECYCLE_PURGE_DEVICE_CANDIDATE_DEPENDENCY": return `${target} is still referenced by discovery/candidate history. Resolve that history before permanent deletion.`;
    case "RECYCLE_RESTORE_CONFLICT": return `${target} conflicts with an active item, or something it needs has changed. Resolve that issue before restoring it.`;
    default: return STATIC[code] || "Another item is preventing this action. Review the related items and resolve the one shown before continuing.";
  }
}

function conflictsFrom(error: ApiError): Conflict[] {
  const details = error.details as { conflicts?: unknown } | null;
  return Array.isArray(details?.conflicts) ? details!.conflicts.filter(Boolean) as Conflict[] : [];
}

export function friendlyErrorNotice(
  error: unknown,
  fallback = "The requested action could not be completed.",
  context?: ErrorContext,
): FriendlyNotice {
  if (!(error instanceof ApiError)) return { title: titleFromFallback(fallback), message: fallback };

  const code = error.code || "";
  const conflicts = conflictsFrom(error);
  let message = STATIC[code] || plainLanguage(error.message || fallback);

  if (code === "DEVICE_HAS_HIERARCHY_DEPENDENCIES" && context?.entityType?.toUpperCase() === "SECTOR") {
    message = `${entityLabel(context)} cannot be deleted because CPE devices are still attached to its physical SECTOR device. Move or detach those CPEs first.`;
  } else if (code === "DEVICE_HAS_HIERARCHY_DEPENDENCIES" && context?.entityType?.toUpperCase() === "CPE") {
    message = `${entityLabel(context)} cannot be deleted because an access point is still attached to it. Move or detach the access point first.`;
  } else if (code === "SECTOR_HAS_CUSTOMER_DEPENDENCIES" && context?.action?.toLowerCase().includes("delete")) {
    message = `${entityLabel(context)} cannot be deleted because it still has attached CPEs or active customer services. Move or remove those items first.`;
  }

  if (conflicts.length) {
    const unique = Array.from(new Set(conflicts.map((item) => friendlyConflict(item, context))));
    message = `${message} ${unique.slice(0, 3).join(" ")}${unique.length > 3 ? ` ${unique.length - 3} additional related issue(s) also need attention.` : ""}`.trim();
  }

  if (error.status === 401 && !code) message = "Your session is no longer valid. Sign in again to continue.";
  if (error.status === 403 && !code) message = "Your account does not have access to this action. Ask an administrator if you need it.";
  if (error.status === 404 && !code) message = "The requested item could not be found. Refresh the page and try again.";
  if (error.status === 409 && !code) message = "The item changed, or another item is preventing this action. Refresh the page, review the current information, and try again.";
  if ((error.status === 422 || error.status === 400) && !code) message = "Some supplied information is not valid. Review the selected values and try again.";

  return { title: titleFromFallback(fallback), message };
}

export function friendlyError(error: unknown, fallback = "The requested action could not be completed.", context?: ErrorContext): string {
  return friendlyErrorNotice(error, fallback, context).message;
}

export function friendlyCode(code: string | null | undefined, fallback = "Action requires attention"): string {
  if (!code) return fallback;
  return STATIC[code] || fallback;
}
