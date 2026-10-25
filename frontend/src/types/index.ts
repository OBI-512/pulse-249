export type PageResult<T> = { items: T[]; total: number; page: number; page_size: number };

export type AuthUser = {
  id: string;
  username: string;
  display_name: string | null;
  roles: string[];
  permissions: string[];
  must_change_password: boolean;
  password_change_reason: string | null;
  password_changed_at: string | null;
  password_expires_at: string | null;
  password_expires_in_days: number | null;
  password_expiry_warning: boolean;
};

export type Health = {
  application: string;
  status: string;
  database: string;
  version: string;
};

export type DeviceType = {
  id: string;
  name: string;
  code: string;
  description?: string | null;
  is_active: boolean;
};

export type CandidateSummary = {
  total: number;
  counts: { NEW: number; APPROVED: number; REJECTED: number; REGISTERED: number };
};

export type Candidate = {
  id: string;
  discovery_result_id: string | null;
  ip_address: string;
  state: string;
  confidence: number;
  suggested_device_type_id: string | null;
  display_name_suggestion: string | null;
  hostname: string | null;
  vendor: string | null;
  model: string | null;
  serial_number: string | null;
  management_protocol: string | null;
  duplicate_device_id: string | null;
  review_note: string | null;
  network_id: string | null;
  city_id: string | null;
  location_id: string | null;
  sector_id: string | null;
  relationship_target_device_id: string | null;
  relationship_type: string | null;
  relationship_direction: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type DeviceOperationalBreakdown = {
  total: number;
  states: { UP: number; DOWN: number; DEGRADED: number; UNKNOWN: number };
};

export type DeviceOperationalSummary = DeviceOperationalBreakdown & {
  by_type: Record<string, DeviceOperationalBreakdown>;
};

export type Device = {
  id: string;
  device_type_id: string;
  display_name: string;
  hostname: string | null;
  vendor: string | null;
  model: string | null;
  serial_number: string | null;
  description?: string | null;
  lifecycle_state: string;
  operational_state: string;
  manual_degraded_override?: boolean;
  management_protocol: string | null;
  credential_reference?: string | null;
  metadata?: Record<string, unknown>;
  management_ip?: string | null;
  service_vlan_id?: number | null;
  customer_vlan_id?: number | null;
  customer_vlan_start?: number | null;
  customer_vlan_end?: number | null;
  customer_vlan_display?: string | null;
};


export type DeviceManagementRow = {
  id: string;
  device_type_id: string;
  device_type_code: string;
  display_name: string;
  management_ip: string | null;
  lifecycle_state: string;
  operational_state: string;
  manual_degraded_override?: boolean;
  network_id: string | null;
  network_name: string | null;
  city_id: string | null;
  city_name: string | null;
  location_id: string | null;
  location_name: string | null;
  sector_id: string | null;
  sector_name: string | null;
  sector_role: string | null;
  physical_sector_device_id: string | null;
  physical_sector_device_name: string | null;
  parent_device_id: string | null;
  parent_device_name: string | null;
  customer_id: string | null;
  customer_name: string | null;
  service_vlan_id: number | null;
  customer_vlan_id: number | null;
  customer_vlan_start: number | null;
  customer_vlan_end: number | null;
};

export type DeviceIP = {
  id: string;
  device_id: string;
  ip_address: string;
  address_family: number;
  is_management: boolean;
  is_primary: boolean;
  source: string | null;
};

export type DeviceInterface = {
  id: string;
  device_id: string;
  interface_name: string;
  interface_index: number | null;
  mac_address: string | null;
  description: string | null;
  operational_status: string | null;
  administrative_status: string | null;
  metadata?: Record<string, unknown>;
};

export type Network = {
  id: string;
  name: string;
  code: string;
  description?: string | null;
  status: string;
  city_count?: number;
};

export type City = {
  id: string;
  network_id: string;
  name: string;
  code: string;
  description?: string | null;
  status: string;
  service_vlan_id?: number | null;
  network_name?: string;
  location_count?: number;
};

export type Location = {
  id: string;
  city_id: string;
  name: string;
  code: string;
  address?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  description?: string | null;
  status: string;
  network_id?: string;
  network_name?: string;
  city_name?: string;
  service_vlan_id?: number | null;
  sector_count?: number;
};

export type Sector = {
  id: string;
  location_id: string;
  sector_device_id?: string | null;
  name: string;
  code: string;
  sequence_number?: number | null;
  description?: string | null;
  status: string;
  role?: string;
  customer_vlan_start?: number | null;
  customer_vlan_end?: number | null;
  network_id?: string;
  network_name?: string;
  city_id?: string;
  city_name?: string;
  service_vlan_id?: number | null;
  location_name?: string;
  physical_sector_device_name?: string | null;
};

export type Customer = {
  id: string;
  customer_code: string;
  name: string;
  status: string;
  metadata?: Record<string, unknown>;
};

export type CustomerListRow = Customer & {
  service_code: string | null;
  sector_id: string | null;
  sector_name: string | null;
  service_vlan_id: number | null;
  customer_vlan_id: number | null;
};

export type Service = {
  id: string;
  customer_id: string;
  sector_id: string;
  service_code: string;
  status: string;
  cpe_device_id: string;
  access_point_device_id: string;
  sector_name?: string | null;
  cpe_name?: string | null;
  access_point_name?: string | null;
  service_vlan_id?: number | null;
  customer_vlan_id?: number | null;
};

export type ServiceEndpointOption = {
  access_point_device_id: string;
  access_point_name: string;
  cpe_device_id: string;
  cpe_name: string;
  sector_id: string;
  sector_name: string;
  city_id: string;
  city_name: string;
  service_vlan_id: number | null;
  customer_vlan_start: number | null;
  customer_vlan_end: number | null;
};

export type Group = {
  id: string;
  name: string;
  code: string;
  description: string | null;
  scope_type: string;
  network_id: string | null;
  city_id: string | null;
  location_id: string | null;
  sector_id: string | null;
  device_scope?: string;
  sector_role?: string | null;
  group_kind?: "SYSTEM" | "CUSTOM";
  membership_mode?: "MANUAL" | "DYNAMIC";
  system_key?: string | null;
  context_name?: string | null;
  parent_group_id?: string | null;
  parent_group_name?: string | null;
  child_count?: number;
  device_count?: number;
};

export type GroupDeviceItem = {
  item_type: "GROUP" | "DEVICE";
  id: string;
  display_name: string;
  code: string | null;
  hostname: string | null;
  device_type_code: string;
  management_ip: string | null;
  lifecycle_state: string | null;
  operational_state: string | null;
  item_count: number | null;
  source_groups: string[];
};

export type GroupItemsPage = {
  child_groups: Group[];
  items: GroupDeviceItem[];
  total: number;
  page: number;
  page_size: number;
};

export type DiscoveryAggregate = {
  ip_address: string;
  reachable: boolean;
  hostname: string | null;
  vendor: string | null;
  model: string | null;
  serial_number: string | null;
  management_protocol: string | null;
  confidence: number;
  protocol_status: Record<string, string>;
  field_sources: Record<string, string>;
};

export type DiscoveryResult = {
  id: string;
  discovery_job_id: string;
  ip_address: string;
  discovery_method: string;
  status: string;
  vendor: string | null;
  model: string | null;
  hostname: string | null;
  serial_number: string | null;
  raw_data: Record<string, unknown>;
  created_at: string;
};

export type DiscoveryJob = {
  id: string;
  scope_type: string;
  scope_value: string;
  status: string;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type BatchJobDetail = {
  job: DiscoveryJob;
  target_count: number;
  result_count: number;
  celery_task_id?: string | null;
  results: DiscoveryResult[];
};

export type AuditEntry = {
  id: string;
  occurred_at: string;
  action: string;
  description: string;
  metadata: Record<string, unknown>;
};

export type RegistrationResult = {
  candidate_id: string;
  device_id: string;
  ip_id: string;
  state: string;
  idempotent: boolean;
};

export type NetworkTopology = {
  id: string; name: string; code: string;
  cities: Array<{ id:string; name:string; code:string; locations:Array<{ id:string; name:string; code:string; devices:Array<TopologyDevice>; sectors:Array<{id:string;name:string;code:string;sequence_number:number|null;role:string;devices:Array<TopologyDevice>;services:Array<{id:string;service_code:string;customer_id:string;cpe_device_id:string;access_point_device_id:string;router_device_id:string|null;status:string}>}> }> }>;
  networks?: Array<{ id:string; name:string; code:string; cities: NetworkTopology["cities"] }>;
};
export type TopologyDevice = { id:string; display_name:string; device_type_id:string; device_type_code:string; hostname:string|null; vendor:string|null; model:string|null; operational_state:string; lifecycle_state:string; management_ip:string|null; management_protocol:string|null; remote_ssh_ready?:boolean; parent_device_id?:string|null; live_state?:string|null; live_state_source?:string|null; live_checked_at?:string|null; live_response_time_ms?:number|null; children?:TopologyDevice[] };


export type SectorLiveTopology = {
  network: { id:string; name:string; code:string };
  city: { id:string; name:string; code:string };
  location: { id:string; name:string; code:string };
  sector: NetworkTopology["cities"][number]["locations"][number]["sectors"][number];
};


export type AlarmSummary = {
  active_total: number;
  unacknowledged: number;
  info: number;
  warning: number;
  minor: number;
  major: number;
  critical: number;
};

export type AlarmRow = {
  id: string;
  device_id: string;
  alarm_type: string;
  correlation_key: string;
  severity: string;
  state: string;
  summary: string;
  first_raised_at: string;
  last_raised_at: string;
  last_cleared_at: string | null;
  acknowledged_at: string | null;
  acknowledged_by_user_id: string | null;
  owner_user_id: string | null;
  occurrence_count: number;
  last_event_id: string | null;
  created_at: string;
  updated_at: string;
  device_display_name: string;
  availability_status: string | null;
  management_ip: string | null;
  owner_display_name: string | null;
  acknowledged_by_display_name: string | null;
};

export type AlarmHistoryEntry = {
  id: string;
  alarm_id: string;
  event_id: string | null;
  occurred_at: string;
  action: string;
  actor_user_id: string | null;
  actor_display_name: string | null;
  note: string | null;
  before_summary: Record<string, unknown> | null;
  after_summary: Record<string, unknown> | null;
  metadata: Record<string, unknown>;
};

export type OperationalEventEntry = {
  id: string;
  device_id: string;
  event_type: string;
  severity: string;
  correlation_key: string;
  occurred_at: string;
  summary: string;
  metadata: Record<string, unknown>;
};

export type SortDirection = "asc" | "desc";
export type SortState = { key: string; direction: SortDirection };
export type PlacementForm = { network_id: string; city_id: string; location_id: string; sector_id: string };

export type MaintenanceTargetOption = { id:string; target_type:"DEVICE"|"LOCATION"|"CITY"|"GROUP"|"NETWORK"; label:string; context:string|null };
export type MaintenanceWindow = {
  id:string; name:string; reason:string|null; target_type:"DEVICE"|"LOCATION"|"CITY"|"GROUP"|"NETWORK"; target_id:string;
  target_display_name:string; starts_at:string; ends_at:string; enabled:boolean; cancelled_at:string|null;
  created_by_user_id:string|null; cancelled_by_user_id:string|null; state:"ACTIVE"|"UPCOMING"|"PAST"|"CANCELLED";
  created_at:string; updated_at:string;
};
export type NotificationDelivery = {
  id:string; alarm_id:string; event_id:string|null; policy_id:string; policy_step_id:string; occurrence_number:number;
  channel_type:"EMAIL"|"WEBHOOK"; destination:string; status:"PENDING"|"SUPPRESSED"|"CLAIMED"|"SENT"|"FAILED"|"CANCELLED";
  scheduled_at:string; next_attempt_at:string; attempt_count:number; last_attempt_at:string|null; delivered_at:string|null;
  last_error_code:string|null; response_status:number|null; maintenance_window_id:string|null; metadata:Record<string,unknown>;
  created_at:string; updated_at:string;
};

export type Page =
  | "overview"
  | "alarms"
  | "maintenance"
  | "discovery"
  | "candidates"
  | "devices"
  | "networks"
  | "groups"
  | "customers"
  | "topology"
  | "data-reporting"
  | "users"
  | "account"
  | "recycle"
  | "restore-points"
  | "logs"
  | "settings"
  | "configuration"
;

export type DashboardAvailabilityCounts = {
  total: number;
  online: number;
  suspect: number;
  offline: number;
  unknown: number;
  maintenance: number;
};

export type DashboardAlarmCounts = {
  active_total: number;
  unacknowledged: number;
  info: number;
  warning: number;
  minor: number;
  major: number;
  critical: number;
};

export type DashboardBreakdown = DashboardAvailabilityCounts & {
  key: string;
  label: string;
  context: string | null;
};

export type DashboardOutage = {
  event_id: string;
  device_id: string;
  device_display_name: string;
  occurred_at: string;
  summary: string;
  current_status: string | null;
  network_name: string | null;
  location_name: string | null;
};

export type DashboardPollingHealth = {
  enabled: boolean;
  status: string;
  interval_seconds: number;
  worker_concurrency: number;
  dispatch_limit_per_tick: number;
  task_batch_size: number;
  max_outstanding_devices: number;
  monitored_devices: number;
  due_now: number;
  overdue: number;
  active_leases: number;
  checked_last_interval: number;
  latest_check_at: string | null;
  latest_dispatch_at: string | null;
  worker_heartbeat_at: string | null;
  worker_heartbeat_age_seconds: number | null;
  redis_status: string;
};

export type OperationsDashboard = {
  generated_at: string;
  availability: DashboardAvailabilityCounts;
  alarms: DashboardAlarmCounts | null;
  authorized_device_categories: string[];
  by_device_type: DashboardBreakdown[];
  by_network: DashboardBreakdown[];
  top_locations: DashboardBreakdown[];
  recent_outages: DashboardOutage[];
  polling: DashboardPollingHealth;
};
