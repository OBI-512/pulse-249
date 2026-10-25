import { PageLayout } from "../design-system/layouts";
import { useCallback, useEffect, useMemo, useState, type Dispatch, type SetStateAction } from "react";
import { useDebouncedValue } from "../hooks/useDebouncedValue";
import { apiDownload, apiFetch, saveDownloadedBlob } from "../api/client";
import { SearchableCombobox, type ComboboxOption, type ComboboxPage } from "../design-system/composites/SearchableSelect";
import { StatusBadge as Badge } from "../design-system/composites/Status";
import { StatCard } from "../design-system/composites/Metric";
import { PageHeader as WorkspacePageHeader, SectionHeader as WorkspaceSectionHeader } from "../design-system/layouts";
import { Tabs as WorkspaceTabs } from "../design-system/composites/Tabs";
import { useFeedback } from "../components/common/FeedbackSystem";
import { useDialog } from "../components/common/DialogSystem";
import { friendlyError } from "../utils/feedback";
import { nextSort, sortRows } from "../utils/sorting";
import type { SortState } from "../types";

import { DataTable } from "../design-system/data/DataTable";
import { ServerPagination, PaginatedTableRows } from "../design-system/data/Pagination";
import { SortHeader } from "../design-system/data/SortHeader";
import { TableExportButton } from "../design-system/data/TableExport";
import { ClearFiltersButton } from "../design-system/composites/FilterBar";
import { Button, Checkbox, Input, Select, Textarea } from "../design-system/primitives";
type Props = { token:string; permissions:string[]; refreshKey:number };
type ReportEditorKey = `definition:${string}` | `schedule:${string}`;
type Tab = "telemetry" | "lifecycle" | "exchange" | "reports" | ReportEditorKey;
type PageResult<T> = { items:T[]; total:number; page:number; page_size:number };
type MetricDefinition = { key:string; oid:string; unit?:string|null; kind:"GAUGE"|"COUNTER"|"STATE"; transform:"raw"|"float"|"int"|"timeticks_seconds"; vendor_key?:string|null };
type TelemetryProfile = { id:string; device_type_id:string; device_type_code?:string|null; device_type_name?:string|null; name:string; enabled:boolean; protocol:string; interval_seconds:number; timeout_seconds:number; retries:number; max_metrics:number; metric_definitions:MetricDefinition[]; vendor_extensions:Record<string,unknown>; description:string|null };
type TelemetrySummary = { total:number; enabled:number; due:number; ok:number; error:number; pending:number; disabled:number; oldest_due_at:string|null };
type TelemetryState = { id:string; device_id:string; device_display_name?:string|null; profile_id:string|null; enabled:boolean; status:string; last_collect_at:string|null; last_success_at:string|null; last_failure_at:string|null; next_collect_at:string|null; consecutive_failures:number; last_error_code:string|null; last_duration_ms:number|null };
type SeriesPoint = { at:string; value:number|string|null; sample_count:number; unit:string|null; source:string };
type TelemetrySeries = { device_id:string; metric_key:string; start:string; end:string; resolution:"raw"|"hour"; points:SeriesPoint[] };
type TelemetrySnapshotItem = { definition:MetricDefinition; point:SeriesPoint|null };
type RetentionPolicy = { id:string; data_class:string; enabled:boolean; retain_days:number; rollup_after_days:number|null; batch_hours:number; description:string|null };
type CapacityModel = { generated_at:string; estimates:Array<{device_count:number;metrics_per_device:number;interval_seconds:number;raw_samples_per_day:number;estimated_raw_bytes_per_day:number;estimated_raw_storage_bytes:number;estimated_rollup_storage_bytes:number;assumptions:Record<string,unknown>}> };
type LifecycleRun = { id:string; data_class:string; status:string; started_at:string; completed_at:string|null; scanned_rows:number; rolled_up_rows:number; purged_rows:number; error_code:string|null };
type ImportRecord = { id:string; row_number:number; status:string; error_code:string|null; error_message:string|null; source_data:Record<string,unknown>; normalized_data:Record<string,unknown> };
type ImportJob = { id:string; entity_type:string|null; file_format:string|null; filename:string|null; file_sha256:string|null; status:string; total_records:number; imported_records:number; error_records:number; preview_expires_at:string|null; committed_at:string|null; validation_summary:Record<string,unknown>; created_at:string };
type ImportPreview = { job:ImportJob; records:ImportRecord[] };
type CatalogItem = { code:string; name:string; description:string; sensitive_fields:string[]; supported_formats:string[]; filters:string[] };
type ReportScheduleLink = { id:string; name:string; deleted_at:string|null };
type ReportDefinition = { id:string; name:string; report_type:string; format:string; filters:Record<string,unknown>; include_sensitive:boolean; description:string|null; deleted_at:string|null; purge_after:string|null; linked_schedules:ReportScheduleLink[] };
type ReportJob = { id:string; definition_id:string|null; schedule_id:string|null; report_type:string; display_name:string; format:string; status:string; filters:Record<string,unknown>; include_sensitive:boolean; requested_at:string; completed_at:string|null; row_count:number; artifact_name:string|null; artifact_size:number|null; error_code:string|null; error_message:string|null };
type ReportSchedule = { id:string; definition_id:string|null; definition_name:string|null; definition_deleted_at:string|null; name:string; report_type:string; format:string; filters:Record<string,unknown>; include_sensitive:boolean; interval_minutes:number; enabled:boolean; next_run_at:string; last_run_at:string|null; channel_type:string|null; destination:string|null; max_attempts:number; retry_base_seconds:number; deleted_at:string|null; purge_after:string|null };
type ReportDelivery = { id:string; report_job_id:string; channel_type:string; destination:string; status:string; attempt_count:number; next_attempt_at:string; delivered_at:string|null; last_error_code:string|null };
type ReportDefinitionDraft = { id:string; name:string; report_type:string; format:string; filters:Record<string,string>; include_sensitive:boolean; description:string };
type ReportScheduleDraft = { id:string; definition_id:string; definition_name:string; name:string; report_type:string; format:string; filters:Record<string,string>; include_sensitive:boolean; interval_minutes:number; enabled:boolean; next_run_at:string; channel_type:string; destination:string; max_attempts:number; retry_base_seconds:number };
type ReportConfigView = "definitions" | "schedules" | "deleted";
type DeletedConfigKind = "definitions" | "schedules";
type ReportEditorTab =
  | { key:ReportEditorKey; kind:"definition"; label:string; draft:ReportDefinitionDraft }
  | { key:ReportEditorKey; kind:"schedule"; label:string; draft:ReportScheduleDraft };

const formats = ["CSV","XLSX","JSON"] as const;
type ExchangeEntity = "geography"|"devices"|"customers"|"customer_services"|"groups";
type ScopeBasis = "NETWORK"|"GROUP";
type ScopeValues = { scope_basis:ScopeBasis; network_id:string; city_id:string; location_id:string; sector_id:string; group_id:string; service_vlan_id:string; customer_vlan_id:string };
type RefOption = { id:string; name:string; code?:string };
type NetworkScopeRow = RefOption;
type CityScopeRow = RefOption & { network_id:string; network_name:string; service_vlan_id?:number|null };
type LocationScopeRow = RefOption & { city_id:string; city_name:string; network_id:string; network_name:string; service_vlan_id?:number|null };
type SectorScopeRow = RefOption & { location_id:string; location_name:string; city_id:string; city_name:string; network_id:string; network_name:string; service_vlan_id?:number|null };
type VlanScopeRow = { id:string; label:string; description?:string|null; city_id?:string; city_name?:string; network_id?:string; network_name?:string };
const EMPTY_SCOPE:ScopeValues={scope_basis:"NETWORK",network_id:"",city_id:"",location_id:"",sector_id:"",group_id:"",service_vlan_id:"",customer_vlan_id:""};
const DEVICE_SUBTYPES = ["ACCESS_POINT","CPE","SECTOR","SWITCH","ROUTER","FIREWALL","SERVER","WIRELESS_BRIDGE","NETWORK_DEVICE","OTHER"] as const;
const EXCHANGE_TYPES:Array<{value:ExchangeEntity;label:string;subtypes:Array<{value:string;label:string}>}> = [
  {value:"geography",label:"Geography",subtypes:[{value:"ALL",label:"All geography"},{value:"NETWORK",label:"Networks"},{value:"CITY",label:"Cities"},{value:"LOCATION",label:"Locations"},{value:"SECTOR",label:"Sectors"}]},
  {value:"devices",label:"Devices",subtypes:[{value:"ALL",label:"All device types"},...DEVICE_SUBTYPES.map(value=>({value,label:value.replace(/_/g," ").replace(/\b\w/g,c=>c.toUpperCase())}))]},
  {value:"customers",label:"Customers",subtypes:[{value:"ALL",label:"Customers"}]},
  {value:"customer_services",label:"Customer Services",subtypes:[{value:"ALL",label:"Customer Services"}]},
  {value:"groups",label:"Groups",subtypes:[{value:"ALL",label:"Groups"}]},
];
const REPORT_SCOPE_KEYS=["network_id","city_id","location_id","sector_id","group_id","service_vlan_id","customer_vlan_id"] as const;

function when(value:string|null|undefined) { return value ? new Date(value).toLocaleString() : "—"; }
function bytes(value:number|null|undefined) {
  if (!value) return "—";
  const units=["B","KB","MB","GB","TB"]; let size=value; let i=0;
  while(size>=1024&&i<units.length-1){size/=1024;i++;}
  return `${size.toFixed(i ? 1 : 0)} ${units[i]}`;
}
function safeFilename(value:string|null, fallback:string) { return (value || fallback).replace(/[\\/:*?"<>|]+/g,"_"); }
function telemetryMetricLabel(definition:MetricDefinition) {
  const labels:Record<string,string>={sys_name:"System name",if_count:"Interface count",sys_uptime_seconds:"Uptime"};
  return labels[definition.key] || definition.key.replace(/_/g," ").replace(/\b\w/g,char=>char.toUpperCase());
}
function telemetrySnapshotOnly(definition:MetricDefinition) {
  return definition.kind === "STATE" || definition.key === "sys_name" || definition.key === "if_count";
}
function telemetryHistoryMetric(definition:MetricDefinition) { return !telemetrySnapshotOnly(definition); }
function formatTelemetryDuration(seconds:number) {
  const safe=Math.max(0,Math.floor(seconds));
  const days=Math.floor(safe/86400); const hours=Math.floor((safe%86400)/3600); const minutes=Math.floor((safe%3600)/60);
  const parts=[] as string[];
  if(days)parts.push(`${days}d`); if(hours||days)parts.push(`${hours}h`); parts.push(`${minutes}m`);
  return parts.join(" ");
}
function formatTelemetrySnapshotValue(item:TelemetrySnapshotItem) {
  const value=item.point?.value;
  if(value==null)return "-";
  if(item.definition.key==="sys_uptime_seconds"&&typeof value==="number")return formatTelemetryDuration(value);
  if(typeof value==="number"){
    const formatted=Number.isInteger(value)?value.toLocaleString():value.toLocaleString(undefined,{maximumFractionDigits:2});
    return item.point?.unit?`${formatted} ${item.point.unit}`:formatted;
  }
  return String(value);
}

const REPORT_FILTER_LABELS:Record<string,string> = {
  device_type:"Device type", lifecycle_state:"Lifecycle state", operational_state:"Operational state",
  start:"From", end:"To", event_type:"Event", state:"Alarm state", severity:"Severity",
  action:"Action", result:"Result", status:"Service status",
};
const REPORT_FILTER_OPTIONS:Record<string,Array<{value:string;label:string}>> = {
  device_type:[
    {value:"ACCESS_POINT",label:"Access Point"},{value:"CPE",label:"CPE"},{value:"SECTOR",label:"Sector"},
    {value:"SWITCH",label:"Switch"},{value:"ROUTER",label:"Router"},{value:"FIREWALL",label:"Firewall"},
    {value:"SERVER",label:"Server"},{value:"WIRELESS_BRIDGE",label:"Wireless Bridge"},
    {value:"NETWORK_DEVICE",label:"Network Device"},{value:"OTHER",label:"Other"},
  ],
  lifecycle_state:[{value:"REGISTERED",label:"Registered"},{value:"ACTIVE",label:"Active"},{value:"MAINTENANCE",label:"Maintenance"},{value:"DECOMMISSIONED",label:"Decommissioned"}],
  operational_state:[{value:"UNKNOWN",label:"Unknown"},{value:"UP",label:"Up"},{value:"DOWN",label:"Down"},{value:"DEGRADED",label:"Degraded"}],
  event_type:[{value:"DEVICE_AVAILABILITY_OFFLINE",label:"Offline"},{value:"DEVICE_AVAILABILITY_RESTORED",label:"Restored"}],
  state:[{value:"ACTIVE",label:"Active"},{value:"CLEARED",label:"Cleared"}],
  severity:[{value:"INFO",label:"Info"},{value:"WARNING",label:"Warning"},{value:"MINOR",label:"Minor"},{value:"MAJOR",label:"Major"},{value:"CRITICAL",label:"Critical"}],
  result:[{value:"SUCCESS",label:"Success"},{value:"FAILURE",label:"Failure"},{value:"ATTEMPT",label:"Attempt"},{value:"UNKNOWN",label:"Unknown"}],
};
function toLocalDateTime(value:unknown) {
  if (!value) return "";
  const date=new Date(String(value));
  if (Number.isNaN(date.getTime())) return String(value);
  const local=new Date(date.getTime()-date.getTimezoneOffset()*60000);
  return local.toISOString().slice(0,16);
}
function reportFiltersToForm(filters:Record<string,unknown>) {
  const values:Record<string,string>={};
  Object.entries(filters||{}).forEach(([key,value])=>{
    if(value==null)return;
    values[key]=key==="start"||key==="end" ? toLocalDateTime(value) : String(value);
  });
  return values;
}
function reportFiltersToRequest(supported:string[], values:Record<string,string>) {
  const filters:Record<string,unknown>={};
  supported.forEach(key=>{
    const raw=(values[key]||"").trim();
    if(!raw)return;
    if(key==="start"||key==="end") {
      const date=new Date(raw);
      filters[key]=Number.isNaN(date.getTime()) ? raw : date.toISOString();
    } else filters[key]=raw;
  });
  return filters;
}
function friendlyFieldName(key:string) { return key.replace(/_/g," ").replace(/\b\w/g,char=>char.toUpperCase()); }
function RecordSummary({data}:{data:Record<string,unknown>}) {
  const entries=Object.entries(data||{}).filter(([,value])=>value!==null&&value!==undefined&&String(value)!=="");
  if(!entries.length)return <span>—</span>;
  return <div className="phase-d-record-summary">{entries.map(([key,value])=><span key={key}><strong>{friendlyFieldName(key)}:</strong> {String(value)}</span>)}</div>;
}
function ReportFilterField({filter,value,onChange}:{filter:string;value:string;onChange:(value:string)=>void}) {
  const label=REPORT_FILTER_LABELS[filter]||friendlyFieldName(filter);
  if(filter==="start"||filter==="end") return <label>{label}<Input unstyled type="datetime-local" value={value} onChange={e=>onChange(e.target.value)}/></label>;
  const options=REPORT_FILTER_OPTIONS[filter];
  if(options) return <label>{label}<Select unstyled value={value} onChange={e=>onChange(e.target.value)}><option value="">All</option>{options.map(option=><option key={option.value} value={option.value}>{option.label}</option>)}</Select></label>;
  return <label>{label}<Input unstyled value={value} onChange={e=>onChange(e.target.value)} placeholder={filter==="action"?"Any action":"Any status"}/></label>;
}

function ScopeSelector({token,value,onChange,canGeo,canGroup,maxDepth="SECTOR"}:{token:string;value:ScopeValues;onChange:(value:ScopeValues)=>void;canGeo:boolean;canGroup:boolean;maxDepth?:"NETWORK"|"CITY"|"LOCATION"|"SECTOR"}) {
  const [networkOption,setNetworkOption]=useState<ComboboxOption<NetworkScopeRow>|null>(null);
  const [cityOption,setCityOption]=useState<ComboboxOption<CityScopeRow>|null>(null);
  const [locationOption,setLocationOption]=useState<ComboboxOption<LocationScopeRow>|null>(null);
  const [sectorOption,setSectorOption]=useState<ComboboxOption<SectorScopeRow>|null>(null);
  const [groupOption,setGroupOption]=useState<ComboboxOption<RefOption>|null>(null);
  const [serviceVlanOption,setServiceVlanOption]=useState<ComboboxOption<VlanScopeRow>|null>(null);
  const [customerVlanOption,setCustomerVlanOption]=useState<ComboboxOption<VlanScopeRow>|null>(null);
  const depth={NETWORK:1,CITY:2,LOCATION:3,SECTOR:4}[maxDepth];
  const groupMode=canGroup&&value.scope_basis==="GROUP";
  const activeGroupId=groupMode?value.group_id:"";

  useEffect(()=>{if(!value.network_id)setNetworkOption(null);},[value.network_id]);
  useEffect(()=>{if(!value.city_id)setCityOption(null);},[value.city_id]);
  useEffect(()=>{if(!value.location_id)setLocationOption(null);},[value.location_id]);
  useEffect(()=>{if(!value.sector_id)setSectorOption(null);},[value.sector_id]);
  useEffect(()=>{if(!value.group_id)setGroupOption(null);},[value.group_id]);
  useEffect(()=>{if(!value.service_vlan_id)setServiceVlanOption(null);},[value.service_vlan_id]);
  useEffect(()=>{if(!value.customer_vlan_id)setCustomerVlanOption(null);},[value.customer_vlan_id]);

  const appendContext=(q:URLSearchParams,{exclude=""}:{exclude?:string}={})=>{
    if(activeGroupId&&exclude!=="group_id")q.set("group_id",activeGroupId);
    if(value.network_id&&exclude!=="network_id")q.set("network_id",value.network_id);
    if(value.city_id&&exclude!=="city_id")q.set("city_id",value.city_id);
    if(value.location_id&&exclude!=="location_id")q.set("location_id",value.location_id);
    if(value.sector_id&&exclude!=="sector_id")q.set("sector_id",value.sector_id);
    if(value.service_vlan_id&&exclude!=="service_vlan_id")q.set("service_vlan_id",value.service_vlan_id);
    if(value.customer_vlan_id&&exclude!=="customer_vlan_id")q.set("customer_vlan_id",value.customer_vlan_id);
  };
  const networkFrom=(row:{network_id:string;network_name:string}):ComboboxOption<NetworkScopeRow>=>({id:row.network_id,label:row.network_name,data:{id:row.network_id,name:row.network_name}});
  const cityFrom=(row:{city_id:string;city_name:string;network_id:string;network_name:string;service_vlan_id?:number|null}):ComboboxOption<CityScopeRow>=>({id:row.city_id,label:row.city_name,description:row.network_name,data:{id:row.city_id,name:row.city_name,network_id:row.network_id,network_name:row.network_name,service_vlan_id:row.service_vlan_id}});
  const locationFrom=(row:{location_id:string;location_name:string;city_id:string;city_name:string;network_id:string;network_name:string;service_vlan_id?:number|null}):ComboboxOption<LocationScopeRow>=>({id:row.location_id,label:row.location_name,description:`${row.network_name} / ${row.city_name}`,data:{id:row.location_id,name:row.location_name,city_id:row.city_id,city_name:row.city_name,network_id:row.network_id,network_name:row.network_name,service_vlan_id:row.service_vlan_id}});

  const loadNetworks=useCallback(async(query:string,page:number,pageSize:number):Promise<ComboboxPage<NetworkScopeRow>>=>{
    const q=new URLSearchParams({page:String(page),page_size:String(pageSize)});if(query)q.set("search",query);appendContext(q,{exclude:"network_id"});
    const result=await apiFetch<PageResult<NetworkScopeRow>>(`/networks/page?${q}`,{},token);
    return {items:result.items.map(row=>({id:row.id,label:row.name,description:row.code,data:row})),total:result.total,page:result.page,page_size:result.page_size};
  },[token,activeGroupId,value.city_id,value.location_id,value.sector_id,value.service_vlan_id,value.customer_vlan_id]);
  const loadCities=useCallback(async(query:string,page:number,pageSize:number):Promise<ComboboxPage<CityScopeRow>>=>{
    const q=new URLSearchParams({page:String(page),page_size:String(pageSize)});if(query)q.set("search",query);appendContext(q,{exclude:"city_id"});
    const result=await apiFetch<PageResult<CityScopeRow>>(`/cities/page?${q}`,{},token);
    return {items:result.items.map(row=>({id:row.id,label:row.name,description:`${row.network_name}${row.code?` · ${row.code}`:""}`,data:row})),total:result.total,page:result.page,page_size:result.page_size};
  },[token,activeGroupId,value.network_id,value.location_id,value.sector_id,value.service_vlan_id,value.customer_vlan_id]);
  const loadLocations=useCallback(async(query:string,page:number,pageSize:number):Promise<ComboboxPage<LocationScopeRow>>=>{
    const q=new URLSearchParams({page:String(page),page_size:String(pageSize)});if(query)q.set("search",query);appendContext(q,{exclude:"location_id"});
    const result=await apiFetch<PageResult<LocationScopeRow>>(`/locations/page?${q}`,{},token);
    return {items:result.items.map(row=>({id:row.id,label:row.name,description:`${row.network_name} / ${row.city_name}${row.code?` · ${row.code}`:""}`,data:row})),total:result.total,page:result.page,page_size:result.page_size};
  },[token,activeGroupId,value.network_id,value.city_id,value.sector_id,value.service_vlan_id,value.customer_vlan_id]);
  const loadSectors=useCallback(async(query:string,page:number,pageSize:number):Promise<ComboboxPage<SectorScopeRow>>=>{
    const q=new URLSearchParams({page:String(page),page_size:String(pageSize)});if(query)q.set("search",query);appendContext(q,{exclude:"sector_id"});
    const result=await apiFetch<PageResult<SectorScopeRow>>(`/sectors/page?${q}`,{},token);
    return {items:result.items.map(row=>({id:row.id,label:row.name,description:`${row.network_name} / ${row.city_name} / ${row.location_name}${row.code?` · ${row.code}`:""}`,data:row})),total:result.total,page:result.page,page_size:result.page_size};
  },[token,activeGroupId,value.network_id,value.city_id,value.location_id,value.service_vlan_id,value.customer_vlan_id]);
  const loadGroups=useCallback(async(query:string,page:number,pageSize:number):Promise<ComboboxPage<RefOption>>=>{
    const q=new URLSearchParams({page:String(page),page_size:String(pageSize)});if(query)q.set("search",query);
    const result=await apiFetch<PageResult<RefOption>>(`/device-groups/page?${q}`,{},token);
    return {items:result.items.map(row=>({id:row.id,label:row.name,description:row.code,data:row})),total:result.total,page:result.page,page_size:result.page_size};
  },[token]);
  const loadServiceVlans=useCallback(async(query:string,page:number,pageSize:number):Promise<ComboboxPage<VlanScopeRow>>=>{
    const q=new URLSearchParams({page:String(page),page_size:String(pageSize),service_vlan_only:"true"});if(query)q.set("search",query);appendContext(q,{exclude:"service_vlan_id"});
    const result=await apiFetch<PageResult<CityScopeRow>>(`/cities/page?${q}`,{},token);
    const items=result.items.filter(row=>row.service_vlan_id!=null).map(row=>({id:String(row.service_vlan_id),label:String(row.service_vlan_id),description:`${row.network_name} / ${row.name}`,data:{id:String(row.service_vlan_id),label:String(row.service_vlan_id),city_id:row.id,city_name:row.name,network_id:row.network_id,network_name:row.network_name}}));
    return {items,total:result.total,page:result.page,page_size:result.page_size};
  },[token,activeGroupId,value.network_id,value.city_id,value.location_id,value.sector_id,value.customer_vlan_id]);
  const loadCustomerVlans=useCallback(async(query:string,page:number,pageSize:number):Promise<ComboboxPage<VlanScopeRow>>=>{
    const q=new URLSearchParams({kind:"customer",page:String(page),page_size:String(pageSize)});if(query)q.set("search",query);appendContext(q,{exclude:"customer_vlan_id"});
    const result=await apiFetch<PageResult<{id:string;label:string;description?:string|null}>>(`/devices/management/vlan-options?${q}`,{},token);
    return {items:result.items.map(row=>({id:row.id,label:row.label,description:row.description||undefined,data:{id:row.id,label:row.label,description:row.description}})),total:result.total,page:result.page,page_size:result.page_size};
  },[token,activeGroupId,value.network_id,value.city_id,value.location_id,value.sector_id,value.service_vlan_id]);

  const clearScope=(basis:ScopeBasis=value.scope_basis)=>{setNetworkOption(null);setCityOption(null);setLocationOption(null);setSectorOption(null);setGroupOption(null);setServiceVlanOption(null);setCustomerVlanOption(null);onChange({...EMPTY_SCOPE,scope_basis:basis});};
  const chooseBasis=(basis:ScopeBasis)=>clearScope(basis);
  const chooseGroup=(option:ComboboxOption<RefOption>|null)=>{setGroupOption(option);setNetworkOption(null);setCityOption(null);setLocationOption(null);setSectorOption(null);setServiceVlanOption(null);setCustomerVlanOption(null);onChange({...EMPTY_SCOPE,scope_basis:"GROUP",group_id:option?.id||""});};
  const chooseNetwork=(option:ComboboxOption<NetworkScopeRow>|null)=>{setNetworkOption(option);setCityOption(null);setLocationOption(null);setSectorOption(null);setServiceVlanOption(null);setCustomerVlanOption(null);onChange({...value,network_id:option?.id||"",city_id:"",location_id:"",sector_id:"",service_vlan_id:"",customer_vlan_id:""});};
  const chooseCity=(option:ComboboxOption<CityScopeRow>|null)=>{setCityOption(option);setLocationOption(null);setSectorOption(null);setCustomerVlanOption(null);if(!option?.data){onChange({...value,city_id:"",location_id:"",sector_id:"",customer_vlan_id:""});return;}const row=option.data;setNetworkOption(networkFrom(row));if(row.service_vlan_id!=null)setServiceVlanOption({id:String(row.service_vlan_id),label:String(row.service_vlan_id),data:{id:String(row.service_vlan_id),label:String(row.service_vlan_id)}});onChange({...value,network_id:row.network_id,city_id:row.id,location_id:"",sector_id:"",service_vlan_id:row.service_vlan_id==null?value.service_vlan_id:String(row.service_vlan_id),customer_vlan_id:""});};
  const chooseLocation=(option:ComboboxOption<LocationScopeRow>|null)=>{setLocationOption(option);setSectorOption(null);setCustomerVlanOption(null);if(!option?.data){onChange({...value,location_id:"",sector_id:"",customer_vlan_id:""});return;}const row=option.data;setNetworkOption(networkFrom(row));setCityOption(cityFrom({city_id:row.city_id,city_name:row.city_name,network_id:row.network_id,network_name:row.network_name,service_vlan_id:row.service_vlan_id}));if(row.service_vlan_id!=null)setServiceVlanOption({id:String(row.service_vlan_id),label:String(row.service_vlan_id),data:{id:String(row.service_vlan_id),label:String(row.service_vlan_id)}});onChange({...value,network_id:row.network_id,city_id:row.city_id,location_id:row.id,sector_id:"",service_vlan_id:row.service_vlan_id==null?value.service_vlan_id:String(row.service_vlan_id),customer_vlan_id:""});};
  const chooseSector=(option:ComboboxOption<SectorScopeRow>|null)=>{setSectorOption(option);if(!option?.data){onChange({...value,sector_id:""});return;}const row=option.data;setNetworkOption(networkFrom(row));setCityOption(cityFrom(row));setLocationOption(locationFrom({location_id:row.location_id,location_name:row.location_name,city_id:row.city_id,city_name:row.city_name,network_id:row.network_id,network_name:row.network_name,service_vlan_id:row.service_vlan_id}));if(row.service_vlan_id!=null)setServiceVlanOption({id:String(row.service_vlan_id),label:String(row.service_vlan_id),data:{id:String(row.service_vlan_id),label:String(row.service_vlan_id)}});onChange({...value,network_id:row.network_id,city_id:row.city_id,location_id:row.location_id,sector_id:row.id,service_vlan_id:row.service_vlan_id==null?value.service_vlan_id:String(row.service_vlan_id)});};
  const chooseServiceVlan=(option:ComboboxOption<VlanScopeRow>|null)=>{setServiceVlanOption(option);setCustomerVlanOption(null);const row=option?.data;const networkId=row?.network_id;const networkName=row?.network_name;const cityId=row?.city_id;const cityName=row?.city_name;if(!option||!networkId||!networkName||!cityId||!cityName){onChange({...value,service_vlan_id:option?.id||"",customer_vlan_id:""});return;}setNetworkOption({id:networkId,label:networkName,data:{id:networkId,name:networkName}});setCityOption({id:cityId,label:cityName,description:networkName,data:{id:cityId,name:cityName,network_id:networkId,network_name:networkName,service_vlan_id:Number(option.id)}});setLocationOption(null);setSectorOption(null);onChange({...value,network_id:networkId,city_id:cityId,location_id:"",sector_id:"",service_vlan_id:option.id,customer_vlan_id:""});};
  const chooseCustomerVlan=(option:ComboboxOption<VlanScopeRow>|null)=>{setCustomerVlanOption(option);onChange({...value,customer_vlan_id:option?.id||""});};
  const hasFilters=Boolean(value.network_id||value.city_id||value.location_id||value.sector_id||value.group_id||value.service_vlan_id||value.customer_vlan_id);

  return <div className="phase-d-scope-block"><div className="phase-d-scope-title-row"><div className="phase-d-scope-title">Scope</div><ClearFiltersButton onClick={()=>clearScope()} disabled={!hasFilters}/></div><div className="form-grid three phase-d-scope-grid">
    {canGroup&&<label>Scope basis<Select unstyled value={value.scope_basis} onChange={e=>chooseBasis(e.target.value as ScopeBasis)}><option value="NETWORK">Network hierarchy</option><option value="GROUP">Device group</option></Select></label>}
    {groupMode&&<label>Group<SearchableCombobox value={value.group_id} selectedOption={groupOption} onChange={chooseGroup} loadPage={loadGroups} ariaLabel="Group" placeholder="Select a device group / search..." emptyText="No groups match this search." /></label>}
    {canGeo&&<label>Network<SearchableCombobox value={value.network_id} selectedOption={networkOption} onChange={chooseNetwork} loadPage={loadNetworks} ariaLabel="Network" placeholder="All eligible networks / search..." emptyText="No eligible networks match this search." /></label>}
    {canGeo&&depth>=2&&<label>City<SearchableCombobox value={value.city_id} selectedOption={cityOption} onChange={chooseCity} loadPage={loadCities} ariaLabel="City" placeholder="All eligible cities / search..." emptyText="No eligible cities match this search." /></label>}
    {canGeo&&depth>=3&&<label>Location<SearchableCombobox value={value.location_id} selectedOption={locationOption} onChange={chooseLocation} loadPage={loadLocations} ariaLabel="Location" placeholder="All eligible locations / search..." emptyText="No eligible locations match this search." /></label>}
    {canGeo&&depth>=4&&<label>Sector<SearchableCombobox value={value.sector_id} selectedOption={sectorOption} onChange={chooseSector} loadPage={loadSectors} ariaLabel="Sector" placeholder="All eligible sectors / search..." emptyText="No eligible sectors match this search." /></label>}
    {canGeo&&<label>S-VLAN<SearchableCombobox value={value.service_vlan_id} selectedOption={serviceVlanOption} onChange={chooseServiceVlan} loadPage={loadServiceVlans} ariaLabel="S-VLAN" placeholder="All eligible S-VLANs / search..." emptyText="No eligible S-VLANs match this search." /></label>}
    {canGeo&&<label>C-VLAN<SearchableCombobox value={value.customer_vlan_id} selectedOption={customerVlanOption} onChange={chooseCustomerVlan} loadPage={loadCustomerVlans} ariaLabel="C-VLAN" placeholder="All allocated C-VLANs / search..." emptyText="No allocated C-VLANs match this search." /></label>}
  </div></div>;
}

function scopeFromFilters(filters:Record<string,string>):ScopeValues { return {scope_basis:(filters.scope_basis==="GROUP"||filters.group_id)?"GROUP":"NETWORK",network_id:filters.network_id||"",city_id:filters.city_id||"",location_id:filters.location_id||"",sector_id:filters.sector_id||"",group_id:filters.group_id||"",service_vlan_id:filters.service_vlan_id||"",customer_vlan_id:filters.customer_vlan_id||""}; }
function cleanScope(scope:ScopeValues) { const out:Record<string,string>={}; for(const key of ["network_id","city_id","location_id","sector_id","group_id","service_vlan_id","customer_vlan_id"] as const){const value=scope[key];if(value)out[key]=value;} return out; }
function exchangeDomainAllowed(permissions:readonly string[], entity:ExchangeEntity, subtype:string, operation:"import"|"export") {
  const selected=(subtype||"ALL").toUpperCase();
  if(entity==="geography") {
    if(operation==="import") return selected==="ALL" ? permissions.includes("network.create")&&permissions.includes("geo.create") : permissions.includes(selected==="NETWORK"?"network.create":"geo.create");
    return selected==="ALL" ? permissions.includes("network.read")&&permissions.includes("geo.read") : permissions.includes(selected==="NETWORK"?"network.read":"geo.read");
  }
  const code = entity==="devices" ? `device.${operation==="import"?"create":"read"}` : entity==="groups" ? `group.${operation==="import"?"create":"read"}` : `customer.${operation==="import"?"create":"read"}`;
  return permissions.includes(code);
}

/* TELEMETRY_HISTORY_PRESENTATION_20260830 */
/* TELEMETRY_SNAPSHOT_HISTORY_SEMANTICS_20260830 */
function NumericChart({series,deviceName}:{series:TelemetrySeries|null;deviceName:string|null}) {
  const numeric = useMemo(()=>series?.points.filter((point):point is SeriesPoint & {value:number}=>typeof point.value === "number" && Number.isFinite(point.value)) ?? [],[series]);
  if (!series) return <div className="empty-state">Select a telemetry state, metric, and time range, then load history.</div>;
  if (!series.points.length) return <div className="empty-state">No telemetry samples are available for this metric and time range.</div>;

  const ordered=[...series.points].sort((a,b)=>new Date(a.at).getTime()-new Date(b.at).getTime());
  const latest=ordered.at(-1)!;
  const unit=latest.unit||numeric.find(point=>point.unit)?.unit||"";
  const latestValue=latest.value==null?"-":typeof latest.value==="number"?(Number.isInteger(latest.value)?latest.value.toLocaleString():latest.value.toLocaleString(undefined,{maximumFractionDigits:2})):String(latest.value);
  const values=numeric.map(point=>point.value);
  const min=values.length?Math.min(...values):null;
  const max=values.length?Math.max(...values):null;
  const ySpan=min!=null&&max!=null?Math.max(max-min,1e-9):1;
  const times=numeric.map(point=>new Date(point.at).getTime()).filter(Number.isFinite);
  const minTime=times.length?Math.min(...times):0;
  const maxTime=times.length?Math.max(...times):minTime;
  const timeSpan=Math.max(maxTime-minTime,1);
  const xFor=(at:string)=>20+((new Date(at).getTime()-minTime)/timeSpan)*660;
  const yFor=(value:number)=>max===min?110:190-((value-(min??0))/ySpan)*160;
  const polyline=numeric.map(point=>`${xFor(point.at)},${yFor(point.value)}`).join(" ");
  const detailRows=[...ordered].reverse().slice(0,50);
  const formatNumber=(value:number)=>Number.isInteger(value)?value.toLocaleString():value.toLocaleString(undefined,{maximumFractionDigits:2});

  return <div className="phase-d-chart-wrap">
    <div className="phase-d-history-context" aria-label="Loaded telemetry context">
      <div><span>Device</span><strong>{deviceName||series.device_id}</strong></div>
      <div><span>Metric</span><strong>{series.metric_key}</strong></div>
      <div><span>Resolution</span><strong>{series.resolution==="hour"?"Hourly":"Raw"}</strong></div>
      <div><span>Loaded range</span><strong>{when(series.start)} to {when(series.end)}</strong></div>
    </div>

    <div className="phase-d-history-summary">
      <div><span>Samples</span><strong>{series.points.length.toLocaleString()}</strong></div>
      <div><span>Latest</span><strong>{latestValue}{unit?` ${unit}`:""}</strong><small>{when(latest.at)}</small></div>
      {min!=null&&<div><span>Minimum</span><strong>{formatNumber(min)}{unit?` ${unit}`:""}</strong></div>}
      {max!=null&&<div><span>Maximum</span><strong>{formatNumber(max)}{unit?` ${unit}`:""}</strong></div>}
    </div>

    {numeric.length?<div className="phase-d-chart-frame">
      <svg className="phase-d-chart" viewBox="0 0 700 230" role="img" aria-label={`${deviceName||series.device_id} ${series.metric_key} telemetry chart`}>
        <line className="phase-d-chart-grid" x1="20" y1="30" x2="680" y2="30"/>
        <line className="phase-d-chart-grid" x1="20" y1="110" x2="680" y2="110"/>
        <line className="phase-d-chart-grid" x1="20" y1="190" x2="680" y2="190"/>
        <line x1="20" y1="190" x2="680" y2="190"/><line x1="20" y1="30" x2="20" y2="190"/>
        <polyline points={polyline}/>
        {numeric.length<=120&&numeric.map((point,index)=><circle key={`${point.at}-${index}`} cx={xFor(point.at)} cy={yFor(point.value)} r="3"><title>{`${when(point.at)} | ${formatNumber(point.value)}${point.unit?` ${point.unit}`:""} | ${point.source}`}</title></circle>)}
        {max!=null&&<text x="26" y="24">{formatNumber(max)}{unit?` ${unit}`:""}</text>}
        {min!=null&&<text x="26" y="207">{formatNumber(min)}{unit?` ${unit}`:""}</text>}
        <text x="20" y="224">{when(numeric[0].at)}</text>
        <text className="phase-d-chart-end-label" x="680" y="224">{when(numeric.at(-1)!.at)}</text>
      </svg>
    </div>:<div className="empty-state phase-d-history-text-note">This metric does not contain numeric samples for this time range.</div>}

    <div className="phase-d-history-table-header">
      <div><strong>Sample details</strong><small>Showing latest {detailRows.length.toLocaleString()} of {series.points.length.toLocaleString()} samples.</small></div>
    </div>
    <DataTable viewportClassName="table-wrap phase-d-history-table-wrap">
      <thead><tr><th>Timestamp</th><th>Value</th><th>Unit</th><th>Source</th><th>Samples</th></tr></thead>
      <tbody>{detailRows.map((point,index)=><tr key={`${point.at}-${index}`}><td>{when(point.at)}</td><td><strong>{point.value==null?"-":typeof point.value==="number"?formatNumber(point.value):String(point.value)}</strong></td><td>{point.unit||"-"}</td><td>{point.source||"-"}</td><td>{point.sample_count}</td></tr>)}</tbody>
    </DataTable>
  </div>;
}

export function DataReportingPage({token,permissions,refreshKey}:Props) {
  const feedback=useFeedback();
  const canTelemetry=permissions.includes("telemetry.read");
  const canTelemetryManage=permissions.includes("telemetry.manage");
  const canLifecycle=permissions.includes("data_lifecycle.read");
  const canLifecycleManage=permissions.includes("data_lifecycle.manage");
  const canExchange=permissions.includes("data_exchange.read");
  const canImport=permissions.includes("data_exchange.import");
  const canExport=permissions.includes("data_exchange.export");
  const canReports=permissions.includes("report.read");
  const canReportManage=permissions.includes("report.manage");
  const canReportExport=permissions.includes("report.export");
  const canReportSchedule=permissions.includes("report.schedule");
  const canSensitive=permissions.includes("report.sensitive");
  const canGeoFilter=permissions.includes("geo.read");
  const canGroupFilter=permissions.includes("group.read");
  const allowedTabs = useMemo<Tab[]>(()=>[
    ...(canTelemetry ? ["telemetry" as Tab] : []),
    ...(canLifecycle ? ["lifecycle" as Tab] : []),
    ...(canExchange ? ["exchange" as Tab] : []),
    ...(canReports ? ["reports" as Tab] : []),
  ],[canTelemetry,canLifecycle,canExchange,canReports]);
  const [reportEditors,setReportEditors]=useState<ReportEditorTab[]>([]);
  const [tab,setTab]=useState<Tab>(allowedTabs[0] || "telemetry");
  useEffect(()=>{
    const validBase=allowedTabs.includes(tab);
    const validEditor=canReports&&reportEditors.some(editor=>editor.key===tab);
    if(!validBase&&!validEditor&&allowedTabs.length)setTab(allowedTabs[0]);
  },[allowedTabs,tab,reportEditors,canReports]);
  const closeReportEditor=(key:Tab)=>{
    setReportEditors(current=>current.filter(editor=>editor.key!==key));
    setTab(current=>current===key?"reports":current);
  };

  return <PageLayout className="page phase-d-page">
    <WorkspacePageHeader
      title="Data & Reports"
      help="Monitor data, exchange files, and create reports."
    />
    <WorkspaceTabs<Tab>
      className="phase-d-tabs"
      value={tab}
      onChange={setTab}
      onClose={closeReportEditor}
      tabs={[
        { id: "telemetry", label: "Telemetry", visible: canTelemetry },
        { id: "lifecycle", label: "Data Lifecycle", visible: canLifecycle },
        { id: "exchange", label: "Import / Export", visible: canExchange },
        { id: "reports", label: "Reports", visible: canReports },
        ...reportEditors.map(editor=>({id:editor.key,label:editor.label,visible:canReports,closable:true,title:editor.label})),
      ]}
    />
    {tab==="telemetry"&&canTelemetry&&<TelemetryPanel token={token} canManage={canTelemetryManage} refreshKey={refreshKey} feedback={feedback}/>} 
    {tab==="lifecycle"&&canLifecycle&&<LifecyclePanel token={token} canManage={canLifecycleManage} refreshKey={refreshKey} feedback={feedback}/>} 
    {tab==="exchange"&&canExchange&&<ExchangePanel token={token} permissions={permissions} canImport={canImport} canExport={canExport} canGeoFilter={canGeoFilter} canGroupFilter={canGroupFilter} refreshKey={refreshKey} feedback={feedback}/>} 
    {canReports&&(tab==="reports"||reportEditors.some(editor=>editor.key===tab))&&<ReportsPanel token={token} canManage={canReportManage} canExport={canReportExport} canSchedule={canReportSchedule} canSensitive={canSensitive} canGeoFilter={canGeoFilter} canGroupFilter={canGroupFilter} refreshKey={refreshKey} feedback={feedback} activeView={tab} editorTabs={reportEditors} setEditorTabs={setReportEditors} setActiveView={setTab}/>} 
  </PageLayout>;
}

function TelemetryPanel({token,canManage,refreshKey,feedback}:{token:string;canManage:boolean;refreshKey:number;feedback:ReturnType<typeof useFeedback>}) {
  const [summary,setSummary]=useState<TelemetrySummary|null>(null);
  const [profiles,setProfiles]=useState<TelemetryProfile[]>([]);
  const [profileSort,setProfileSort]=useState<SortState>({key:"device_type_name",direction:"asc"});
  const [profileSearch,setProfileSearch]=useState("");
  const [profileEnabled,setProfileEnabled]=useState("");

  const [states,setStates]=useState<TelemetryState[]>([]);
  const [total,setTotal]=useState(0);
  const [page,setPage]=useState(1);
  const [pageSize,setPageSize]=useState(50);
  const [stateSearch,setStateSearch]=useState("");
  const [status,setStatus]=useState("");
  const [stateEnabled,setStateEnabled]=useState("");
  const [stateDeviceType,setStateDeviceType]=useState("");
  const [stateSort,setStateSort]=useState<SortState>({key:"next_collect_at",direction:"asc"});

  const [selected,setSelected]=useState<TelemetryState|null>(null);
  const [metric,setMetric]=useState("");
  const [resolution,setResolution]=useState<"raw"|"hour">("raw");
  const [rangePreset,setRangePreset]=useState("24h");
  const [customStart,setCustomStart]=useState(()=>toLocalDateTime(new Date(Date.now()-24*60*60*1000).toISOString()));
  const [customEnd,setCustomEnd]=useState(()=>toLocalDateTime(new Date().toISOString()));
  const [series,setSeries]=useState<TelemetrySeries|null>(null);
  const [snapshot,setSnapshot]=useState<TelemetrySnapshotItem[]>([]);
  const [snapshotBusy,setSnapshotBusy]=useState(false);
  const [busy,setBusy]=useState(false);

  const debouncedStateSearch=useDebouncedValue(stateSearch,300);

  const load=useCallback(async()=>{
    const q=new URLSearchParams({page:String(page),page_size:String(pageSize),sort_by:stateSort.key,sort_direction:stateSort.direction});
    if(debouncedStateSearch)q.set("search",debouncedStateSearch);
    if(status)q.set("status",status);
    if(stateEnabled)q.set("enabled",stateEnabled);
    if(stateDeviceType)q.set("device_type",stateDeviceType);
    const [sum,pro,sta]=await Promise.all([
      apiFetch<TelemetrySummary>("/telemetry/summary",{},token),
      apiFetch<TelemetryProfile[]>("/telemetry/profiles",{},token),
      apiFetch<PageResult<TelemetryState>>(`/telemetry/states?${q}`,{},token),
    ]);
    setSummary(sum);setProfiles(pro);setStates(sta.items);setTotal(sta.total);
  },[token,page,pageSize,debouncedStateSearch,status,stateEnabled,stateDeviceType,stateSort]);

  useEffect(()=>{void load().catch(error=>feedback.error(friendlyError(error,"Unable to load telemetry.")));},[load,refreshKey]);

  const filteredProfiles=useMemo(()=>{
    const needle=profileSearch.trim().toLowerCase();
    return profiles.filter(row=>{
      if(profileEnabled==="true"&&!row.enabled)return false;
      if(profileEnabled==="false"&&row.enabled)return false;
      if(!needle)return true;
      return [row.name,row.device_type_name,row.device_type_code,row.protocol,row.description]
        .some(value=>String(value||"").toLowerCase().includes(needle));
    });
  },[profiles,profileSearch,profileEnabled]);
  const sortedProfiles=useMemo(()=>sortRows(filteredProfiles,profileSort,(row,key)=>{if(key==="metrics")return row.metric_definitions.length;return row[key as keyof TelemetryProfile];}),[filteredProfiles,profileSort]);

  const telemetryDeviceTypes=useMemo(()=>{
    const values=new Map<string,string>();
    profiles.forEach(row=>{
      const code=(row.device_type_code||"").trim();
      if(code)values.set(code,row.device_type_name||code.replace(/_/g," "));
    });
    return Array.from(values.entries()).sort((a,b)=>a[1].localeCompare(b[1]));
  },[profiles]);

  const selectedProfile=profiles.find(row=>row.id===selected?.profile_id);
  const metrics=selectedProfile?.metric_definitions||[];
  const historyMetrics=useMemo(()=>metrics.filter(telemetryHistoryMetric),[selectedProfile]);

  useEffect(()=>{
    if(!selected){if(metric)setMetric("");return;}
    if(!historyMetrics.length){if(metric)setMetric("");return;}
    if(!historyMetrics.some(row=>row.key===metric))setMetric(historyMetrics[0].key);
  },[selected?.id,selectedProfile?.id,historyMetrics,metric]);

  useEffect(()=>{
    let cancelled=false;
    setSnapshot([]);
    if(!selected||!metrics.length||!selected.last_collect_at){setSnapshotBusy(false);return()=>{cancelled=true;};}
    const collectedAt=new Date(selected.last_collect_at);
    if(Number.isNaN(collectedAt.getTime())){setSnapshotBusy(false);return()=>{cancelled=true;};}
    const start=new Date(collectedAt.getTime()-10*60*1000).toISOString();
    const end=new Date(collectedAt.getTime()+10*60*1000).toISOString();
    setSnapshotBusy(true);
    void Promise.all(metrics.map(async definition=>{
      try{
        const q=new URLSearchParams({start,end,resolution:"raw",limit:"200"});
        const result=await apiFetch<TelemetrySeries>(`/telemetry/devices/${selected.device_id}/metrics/${encodeURIComponent(definition.key)}?${q}`,{},token);
        const ordered=[...result.points].sort((a,b)=>new Date(a.at).getTime()-new Date(b.at).getTime());
        return {definition,point:ordered.at(-1)||null} satisfies TelemetrySnapshotItem;
      }catch{
        return {definition,point:null} satisfies TelemetrySnapshotItem;
      }
    })).then(rows=>{if(!cancelled)setSnapshot(rows);}).finally(()=>{if(!cancelled)setSnapshotBusy(false);});
    return()=>{cancelled=true;};
  },[selected?.id,selected?.last_collect_at,selectedProfile,token]);

  const loadSeries=async()=>{
    if(!selected||!metric)return;
    let end:Date;
    let start:Date;
    if(rangePreset==="custom"){
      if(!customStart||!customEnd){feedback.error("Choose both From and To for a custom telemetry range.");return;}
      start=new Date(customStart);end=new Date(customEnd);
    } else {
      end=new Date();
      const durationMs:Record<string,number>={"1h":60*60*1000,"6h":6*60*60*1000,"24h":24*60*60*1000,"7d":7*24*60*60*1000,"30d":30*24*60*60*1000};
      start=new Date(end.getTime()-(durationMs[rangePreset]||durationMs["24h"]));
    }
    if(Number.isNaN(start.getTime())||Number.isNaN(end.getTime())||start>=end){feedback.error("Telemetry history requires a valid From time earlier than To.");return;}
    try{
      setBusy(true);
      const q=new URLSearchParams({start:start.toISOString(),end:end.toISOString(),resolution,limit:"10000"});
      setSeries(await apiFetch<TelemetrySeries>(`/telemetry/devices/${selected.device_id}/metrics/${encodeURIComponent(metric)}?${q}`,{},token));
    }catch(error){feedback.error(friendlyError(error,"Unable to load telemetry series."));}
    finally{setBusy(false);}
  };

  const collect=async()=>{if(!selected)return;try{setBusy(true);await apiFetch("/telemetry/collect-now",{method:"POST",body:JSON.stringify({device_ids:[selected.device_id]})},token);feedback.success("Telemetry collection queued independently of availability.");await load();}catch(error){feedback.error(friendlyError(error,"Unable to queue telemetry collection."));}finally{setBusy(false);}};
  const updateProfile=async(row:TelemetryProfile,patch:Partial<TelemetryProfile>)=>{const next={...row,...patch};try{setBusy(true);await apiFetch(`/telemetry/profiles/${row.id}`,{method:"PATCH",body:JSON.stringify({name:next.name,enabled:next.enabled,protocol:"SNMP",interval_seconds:next.interval_seconds,timeout_seconds:next.timeout_seconds,retries:next.retries,max_metrics:next.max_metrics,metric_definitions:next.metric_definitions,vendor_extensions:next.vendor_extensions,description:next.description})},token);feedback.success("Telemetry profile updated.");await load();}catch(error){feedback.error(friendlyError(error,"Unable to update telemetry profile."));}finally{setBusy(false);}};

  return <div className="phase-d-stack">
    <section className="stat-grid phase-d-summary-grid"><StatCard label="Total states" value={summary?.total??"—"}/><StatCard label="Enabled" value={summary?.enabled??"—"}/><StatCard label="OK" value={summary?.ok??"—"}/><StatCard label="Errors" value={summary?.error??"—"}/><StatCard label="Due" value={summary?.due??"—"}/></section>

    <section className="panel">
      <WorkspaceSectionHeader className="phase-d-panel-header" title="Per-device-type profiles" help="Choose how monitoring works for each device type." actions={<div className="button-row"><TableExportButton token={token} tableId="telemetry_profiles" filters={{search:profileSearch,enabled:profileEnabled,sort_by:profileSort.key,sort_direction:profileSort.direction}}/><Button unstyled className="secondary" onClick={()=>void load()}>Refresh</Button></div>} />
      <div className="filter-row compact telemetry-filter-row telemetry-filter-row--profiles">
        <Input unstyled aria-label="Search telemetry profiles" value={profileSearch} onChange={e=>setProfileSearch(e.target.value)} placeholder="Search device type or profile..."/>
        <Select unstyled aria-label="Telemetry profile enabled" value={profileEnabled} onChange={e=>setProfileEnabled(e.target.value)}><option value="">All enablement</option><option value="true">Enabled</option><option value="false">Disabled</option></Select>
        <ClearFiltersButton disabled={!profileSearch&&!profileEnabled} onClick={()=>{setProfileSearch("");setProfileEnabled("");}}/>
      </div>
      <DataTable viewportClassName="table-wrap"><thead><tr><SortHeader label="Device type" sortKey="device_type_name" sort={profileSort} onSort={key=>setProfileSort(current=>nextSort(current,key))}/><SortHeader label="Enabled" sortKey="enabled" sort={profileSort} onSort={key=>setProfileSort(current=>nextSort(current,key))}/><SortHeader label="Interval" sortKey="interval_seconds" sort={profileSort} onSort={key=>setProfileSort(current=>nextSort(current,key))}/><SortHeader label="Timeout" sortKey="timeout_seconds" sort={profileSort} onSort={key=>setProfileSort(current=>nextSort(current,key))}/><SortHeader label="Retries" sortKey="retries" sort={profileSort} onSort={key=>setProfileSort(current=>nextSort(current,key))}/><SortHeader label="Metrics" sortKey="metrics" sort={profileSort} onSort={key=>setProfileSort(current=>nextSort(current,key))}/>{canManage&&<th>Action</th>}</tr></thead><tbody><PaginatedTableRows items={sortedProfiles} colSpan={canManage?7:6} resetKey={`${profileSearch}|${profileEnabled}`} itemLabel="telemetry profiles" renderRow={row=><tr key={row.id}><td><strong>{row.device_type_name||row.device_type_code||row.name}</strong><small className="table-subtext">{row.device_type_code}</small></td><td>{canManage?<Input unstyled type="checkbox" checked={row.enabled} onChange={event=>setProfiles(current=>current.map(item=>item.id===row.id?{...item,enabled:event.target.checked}:item))}/>:row.enabled?"Yes":"No"}</td><td>{canManage?<Input unstyled className="compact-input" type="number" min={60} max={86400} value={row.interval_seconds} onChange={event=>setProfiles(current=>current.map(item=>item.id===row.id?{...item,interval_seconds:Number(event.target.value)}:item))}/>:row.interval_seconds+"s"}</td><td>{row.timeout_seconds}s</td><td>{row.retries}</td><td>{row.metric_definitions.length}</td>{canManage&&<td><Button unstyled disabled={busy} onClick={()=>void updateProfile(row,profiles.find(item=>item.id===row.id) || row)}>Save</Button></td>}</tr>}/>{!sortedProfiles.length&&<tr><td colSpan={canManage?7:6}>No telemetry profiles match the current filters.</td></tr>}</tbody></DataTable>
    </section>

    <section className="panel">
      <WorkspaceSectionHeader className="phase-d-panel-header" title="Device telemetry state" help="See the latest monitoring result for each device." actions={<div className="button-row"><TableExportButton token={token} tableId="telemetry_states" filters={{search:stateSearch,status,enabled:stateEnabled,device_type:stateDeviceType,sort_by:stateSort.key,sort_direction:stateSort.direction}}/></div>} />
      <div className="filter-row compact telemetry-filter-row telemetry-filter-row--states">
        <Input unstyled aria-label="Search telemetry devices" value={stateSearch} onChange={e=>{setStateSearch(e.target.value);setPage(1);}} placeholder="Search device name, hostname, or IP..."/>
        <Select unstyled aria-label="Telemetry device type" value={stateDeviceType} onChange={e=>{setStateDeviceType(e.target.value);setPage(1);}}><option value="">All device types</option>{telemetryDeviceTypes.map(([code,label])=><option key={code} value={code}>{label}</option>)}</Select>
        <Select unstyled aria-label="Telemetry state" value={status} onChange={e=>{setStatus(e.target.value);setPage(1);}}><option value="">All states</option><option>OK</option><option>ERROR</option><option>PENDING</option><option>DISABLED</option></Select>
        <Select unstyled aria-label="Telemetry enabled" value={stateEnabled} onChange={e=>{setStateEnabled(e.target.value);setPage(1);}}><option value="">All enablement</option><option value="true">Enabled</option><option value="false">Disabled</option></Select>
        <ClearFiltersButton disabled={!stateSearch&&!status&&!stateEnabled&&!stateDeviceType} onClick={()=>{setStateSearch("");setStatus("");setStateEnabled("");setStateDeviceType("");setPage(1);}}/>
      </div>
      <DataTable viewportClassName="table-wrap"><thead><tr><SortHeader label="Device" sortKey="device_name" sort={stateSort} onSort={key=>{setStateSort(current=>nextSort(current,key));setPage(1);}}/><SortHeader label="Status" sortKey="status" sort={stateSort} onSort={key=>{setStateSort(current=>nextSort(current,key));setPage(1);}}/><SortHeader label="Last collection" sortKey="last_collect_at" sort={stateSort} onSort={key=>{setStateSort(current=>nextSort(current,key));setPage(1);}}/><SortHeader label="Next due" sortKey="next_collect_at" sort={stateSort} onSort={key=>{setStateSort(current=>nextSort(current,key));setPage(1);}}/><SortHeader label="Failures" sortKey="consecutive_failures" sort={stateSort} onSort={key=>{setStateSort(current=>nextSort(current,key));setPage(1);}}/><SortHeader label="Duration" sortKey="last_duration_ms" sort={stateSort} onSort={key=>{setStateSort(current=>nextSort(current,key));setPage(1);}}/><SortHeader label="Error" sortKey="last_error_code" sort={stateSort} onSort={key=>{setStateSort(current=>nextSort(current,key));setPage(1);}}/></tr></thead><tbody>{states.map(row=><tr key={row.id} className={selected?.id===row.id?"selected-row":""} onClick={()=>{setSelected(row);setSeries(null);}}><td><strong>{row.device_display_name||row.device_id}</strong><small className="table-subtext">{row.device_id}</small></td><td><Badge value={row.status}/></td><td>{when(row.last_collect_at)}</td><td>{when(row.next_collect_at)}</td><td>{row.consecutive_failures}</td><td>{row.last_duration_ms==null?"—":`${row.last_duration_ms.toFixed(1)} ms`}</td><td>{row.last_error_code||"—"}</td></tr>)}{!states.length&&<tr><td colSpan={7}>No telemetry state rows match the current filters in your scope.</td></tr>}</tbody></DataTable><ServerPagination page={page} pageSize={pageSize} total={total} onPage={setPage} onPageSize={value=>{setPageSize(value);setPage(1);}} itemLabel="telemetry states"/>
    </section>

    <section className="panel">
      <WorkspaceSectionHeader className="phase-d-panel-header" title="Latest telemetry snapshot" help="Show the latest collected identity, inventory, and operational values for the selected device." />
      <div className="phase-d-history-selected"><span>Selected device</span><strong>{selected?.device_display_name||selected?.device_id||"No device selected"}</strong></div>
      {!selected?<div className="empty-state">Select a device from Device telemetry state to inspect its latest telemetry values.</div>:
      snapshotBusy?<div className="empty-state">Loading latest telemetry snapshot...</div>:
      <div className="phase-d-telemetry-snapshot-grid">
        {metrics.map(definition=>{const item=snapshot.find(row=>row.definition.key===definition.key)||{definition,point:null};return <article className="phase-d-telemetry-snapshot-card" key={definition.key}>
          <span>{telemetryMetricLabel(definition)}</span>
          <strong>{formatTelemetrySnapshotValue(item)}</strong>
          <small>{definition.key}{item.point?` | ${item.point.source} | ${when(item.point.at)}`:" | No collected sample"}</small>
        </article>;})}
        {!metrics.length&&<div className="empty-state">This telemetry profile has no configured metrics.</div>}
      </div>}
      {selected&&metrics.some(telemetrySnapshotOnly)&&<small className="table-subtext phase-d-telemetry-semantics-note">Identity and inventory metrics are intentionally presented as current values here instead of being charted over time.</small>}
    </section>

    <section className="panel">
      <WorkspaceSectionHeader className="phase-d-panel-header" title="Metric history" help="Trend time-series telemetry over preset or exact custom date/time ranges." actions={canManage?<Button unstyled disabled={!selected||busy} onClick={()=>void collect()}>Collect now</Button>:undefined} />
      <div className="phase-d-history-selected"><span>Selected device</span><strong>{selected?.device_display_name||selected?.device_id||"No device selected"}</strong></div>
      <div className="inline-form phase-d-inline-form">
        <label>Metric<Select unstyled aria-label="Metric" value={metric} onChange={e=>{setMetric(e.target.value);setSeries(null);}} disabled={!selected||!historyMetrics.length}>{historyMetrics.map(row=><option key={row.key} value={row.key}>{telemetryMetricLabel(row)}</option>)}</Select></label>
        <label>Resolution<Select unstyled value={resolution} onChange={e=>{setResolution(e.target.value as typeof resolution);setSeries(null);}}><option value="raw">Raw</option><option value="hour">Hourly</option></Select></label>
        <label>Time range<Select unstyled aria-label="Telemetry time range" value={rangePreset} onChange={e=>{setRangePreset(e.target.value);setSeries(null);}}><option value="1h">Last 1 hour</option><option value="6h">Last 6 hours</option><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option><option value="custom">Custom range</option></Select></label>
        {rangePreset==="custom"&&<><label>From<Input unstyled aria-label="Telemetry history from" type="datetime-local" value={customStart} onChange={e=>{setCustomStart(e.target.value);setSeries(null);}}/></label><label>To<Input unstyled aria-label="Telemetry history to" type="datetime-local" value={customEnd} onChange={e=>{setCustomEnd(e.target.value);setSeries(null);}}/></label></>}
        <Button unstyled disabled={!selected||!metric||busy} onClick={()=>void loadSeries()}>Load history</Button>
      </div>
      <small className="table-subtext">Only time-series metrics are offered here. Snapshot-only values such as system name and interface count are shown in Latest telemetry snapshot. Raw history returns up to 10,000 samples per request; use Hourly for longer ranges when rollups are available.</small>
      {!selected||historyMetrics.length?<NumericChart series={series} deviceName={selected?.device_display_name||selected?.device_id||null}/>:<div className="empty-state">This telemetry profile has no metrics intended for historical trending.</div>}
    </section>
  </div>;
}

function LifecyclePanel({token,canManage,refreshKey,feedback}:{token:string;canManage:boolean;refreshKey:number;feedback:ReturnType<typeof useFeedback>}) {
  const [policies,setPolicies]=useState<RetentionPolicy[]>([]); const [policySort,setPolicySort]=useState<SortState>({key:"data_class",direction:"asc"}); const [policySearch,setPolicySearch]=useState(""); const [policyEnabled,setPolicyEnabled]=useState(""); const [capacity,setCapacity]=useState<CapacityModel|null>(null); const [runs,setRuns]=useState<LifecycleRun[]>([]); const [total,setTotal]=useState(0); const [page,setPage]=useState(1); const [pageSize,setPageSize]=useState(50); const [runSort,setRunSort]=useState<SortState>({key:"started_at",direction:"desc"}); const [runSearch,setRunSearch]=useState(""); const [runClass,setRunClass]=useState(""); const [runStatus,setRunStatus]=useState(""); const [busy,setBusy]=useState(false);
  const load=useCallback(async()=>{const q=new URLSearchParams({page:String(page),page_size:String(pageSize),sort_by:runSort.key,sort_direction:runSort.direction});if(runSearch.trim())q.set("search",runSearch.trim());if(runClass)q.set("data_class",runClass);if(runStatus)q.set("status",runStatus);const [p,c,r]=await Promise.all([apiFetch<RetentionPolicy[]>("/data-lifecycle/policies",{},token),apiFetch<CapacityModel>("/data-lifecycle/capacity",{},token),apiFetch<PageResult<LifecycleRun>>(`/data-lifecycle/runs?${q}`,{},token)]);setPolicies(p);setCapacity(c);setRuns(r.items);setTotal(r.total);},[token,page,pageSize,runSort,runSearch,runClass,runStatus]);
  const filteredPolicies=useMemo(()=>policies.filter(row=>{const term=policySearch.trim().toLowerCase();const searchOk=!term||row.data_class.toLowerCase().includes(term)||(row.description||"").toLowerCase().includes(term);const enabledOk=!policyEnabled||String(row.enabled)===policyEnabled;return searchOk&&enabledOk;}),[policies,policySearch,policyEnabled]);
  const sortedPolicies=useMemo(()=>sortRows(filteredPolicies,policySort,(row,key)=>row[key as keyof RetentionPolicy]),[filteredPolicies,policySort]);
  useEffect(()=>{void load().catch(error=>feedback.error(friendlyError(error,"Unable to load data lifecycle.")));},[load,refreshKey]);
  const save=async(row:RetentionPolicy)=>{try{setBusy(true);await apiFetch(`/data-lifecycle/policies/${row.id}`,{method:"PATCH",body:JSON.stringify({enabled:row.enabled,retain_days:row.retain_days,rollup_after_days:row.rollup_after_days,batch_hours:row.batch_hours})},token);feedback.success("Retention policy updated.");await load();}catch(error){feedback.error(friendlyError(error,"Unable to update retention policy."));}finally{setBusy(false);}};
  return <div className="phase-d-stack"><section className="panel"><WorkspaceSectionHeader className="phase-d-panel-header" title="Retention policies" help="Choose how long historical data is kept." actions={<TableExportButton token={token} tableId="retention_policies" filters={{ search:policySearch.trim()||undefined, enabled:policyEnabled||undefined, sort_by:policySort.key, sort_direction:policySort.direction }}/>} /><div className="filter-row compact lifecycle-filter-row lifecycle-filter-row--policies"><Input unstyled aria-label="Search retention policies" placeholder="Search data class or description..." value={policySearch} onChange={e=>setPolicySearch(e.target.value)}/><Select unstyled aria-label="Retention policy enablement" value={policyEnabled} onChange={e=>setPolicyEnabled(e.target.value)}><option value="">All enablement</option><option value="true">Enabled</option><option value="false">Disabled</option></Select><ClearFiltersButton disabled={!policySearch&&!policyEnabled} onClick={()=>{setPolicySearch("");setPolicyEnabled("");}}/></div><DataTable viewportClassName="table-wrap"><thead><tr><SortHeader label="Data class" sortKey="data_class" sort={policySort} onSort={key=>setPolicySort(current=>nextSort(current,key))}/><SortHeader label="Enabled" sortKey="enabled" sort={policySort} onSort={key=>setPolicySort(current=>nextSort(current,key))}/><SortHeader label="Retain days" sortKey="retain_days" sort={policySort} onSort={key=>setPolicySort(current=>nextSort(current,key))}/><SortHeader label="Roll up after" sortKey="rollup_after_days" sort={policySort} onSort={key=>setPolicySort(current=>nextSort(current,key))}/><SortHeader label="Batch hours" sortKey="batch_hours" sort={policySort} onSort={key=>setPolicySort(current=>nextSort(current,key))}/>{canManage&&<th>Action</th>}</tr></thead><tbody><PaginatedTableRows items={sortedPolicies} colSpan={canManage?6:5} itemLabel="retention policies" renderRow={row=><tr key={row.id}><td><strong>{row.data_class}</strong><small className="table-subtext">{row.description}</small></td><td>{canManage?<Input unstyled type="checkbox" checked={row.enabled} onChange={e=>setPolicies(cur=>cur.map(x=>x.id===row.id?{...x,enabled:e.target.checked}:x))}/>:row.enabled?"Yes":"No"}</td><td>{canManage?<Input unstyled className="compact-input" type="number" min={1} max={3650} value={row.retain_days} onChange={e=>setPolicies(cur=>cur.map(x=>x.id===row.id?{...x,retain_days:Number(e.target.value)}:x))}/>:row.retain_days}</td><td>{row.rollup_after_days??"—"}</td><td>{row.batch_hours}</td>{canManage&&<td><Button unstyled disabled={busy} onClick={()=>void save(row)}>Save</Button></td>}</tr>}/></tbody></DataTable></section>
    <section className="panel"><WorkspaceSectionHeader className="phase-d-panel-header" title="10K / 20K capacity model" help="Estimate storage needs as the network grows." /><div className="phase-d-capacity-grid">{capacity?.estimates.map(row=><article className="stat-card" key={row.device_count}><span className="stat-label">{row.device_count.toLocaleString()} devices</span><strong className="stat-value">{bytes(row.estimated_raw_storage_bytes)}</strong><span className="stat-detail">Raw retention estimate · {row.metrics_per_device} metrics every {row.interval_seconds}s</span><span className="stat-detail">Rollups {bytes(row.estimated_rollup_storage_bytes)}</span></article>)}</div></section>
    <section className="panel"><WorkspaceSectionHeader className="phase-d-panel-header" title="Lifecycle execution evidence" help="Review recent data cleanup runs." actions={<TableExportButton token={token} tableId="lifecycle_runs" filters={{ search:runSearch.trim()||undefined, data_class:runClass||undefined, status:runStatus||undefined, sort_by:runSort.key, sort_direction:runSort.direction }}/>} /><div className="filter-row compact lifecycle-filter-row lifecycle-filter-row--runs"><Input unstyled aria-label="Search lifecycle runs" placeholder="Search class or error..." value={runSearch} onChange={e=>{setRunSearch(e.target.value);setPage(1);}}/><Select unstyled aria-label="Lifecycle run data class" value={runClass} onChange={e=>{setRunClass(e.target.value);setPage(1);}}><option value="">All data classes</option>{[...new Set(policies.map(row=>row.data_class))].sort().map(value=><option key={value} value={value}>{value}</option>)}</Select><Select unstyled aria-label="Lifecycle run status" value={runStatus} onChange={e=>{setRunStatus(e.target.value);setPage(1);}}><option value="">All statuses</option><option value="RUNNING">Running</option><option value="COMPLETED">Completed</option><option value="FAILED">Failed</option><option value="SKIPPED">Skipped</option></Select><ClearFiltersButton disabled={!runSearch&&!runClass&&!runStatus} onClick={()=>{setRunSearch("");setRunClass("");setRunStatus("");setPage(1);}}/></div><DataTable viewportClassName="table-wrap"><thead><tr><SortHeader label="Class" sortKey="data_class" sort={runSort} onSort={key=>{setRunSort(current=>nextSort(current,key));setPage(1);}}/><SortHeader label="Status" sortKey="status" sort={runSort} onSort={key=>{setRunSort(current=>nextSort(current,key));setPage(1);}}/><SortHeader label="Started" sortKey="started_at" sort={runSort} onSort={key=>{setRunSort(current=>nextSort(current,key));setPage(1);}}/><SortHeader label="Scanned" sortKey="scanned_rows" sort={runSort} onSort={key=>{setRunSort(current=>nextSort(current,key));setPage(1);}}/><SortHeader label="Rolled up" sortKey="rolled_up_rows" sort={runSort} onSort={key=>{setRunSort(current=>nextSort(current,key));setPage(1);}}/><SortHeader label="Purged" sortKey="purged_rows" sort={runSort} onSort={key=>{setRunSort(current=>nextSort(current,key));setPage(1);}}/><SortHeader label="Error" sortKey="error_code" sort={runSort} onSort={key=>{setRunSort(current=>nextSort(current,key));setPage(1);}}/></tr></thead><tbody>{runs.map(row=><tr key={row.id}><td>{row.data_class}</td><td><Badge value={row.status}/></td><td>{when(row.started_at)}</td><td>{row.scanned_rows}</td><td>{row.rolled_up_rows}</td><td>{row.purged_rows}</td><td>{row.error_code||"—"}</td></tr>)}{!runs.length&&<tr><td colSpan={7}>No lifecycle runs recorded yet.</td></tr>}</tbody></DataTable><ServerPagination page={page} pageSize={pageSize} total={total} onPage={setPage} onPageSize={v=>{setPageSize(v);setPage(1);}} itemLabel="lifecycle runs"/></section></div>;
}

function ExchangePanel({token,permissions,canImport,canExport,canGeoFilter,canGroupFilter,refreshKey,feedback}:{token:string;permissions:readonly string[];canImport:boolean;canExport:boolean;canGeoFilter:boolean;canGroupFilter:boolean;refreshKey:number;feedback:ReturnType<typeof useFeedback>}) {
  const [entity,setEntity]=useState<ExchangeEntity>("devices"); const [subtype,setSubtype]=useState("ALL"); const [format,setFormat]=useState<typeof formats[number]>("CSV"); const [scope,setScope]=useState<ScopeValues>(EMPTY_SCOPE); const [file,setFile]=useState<File|null>(null); const [preview,setPreview]=useState<ImportPreview|null>(null); const [previewSort,setPreviewSort]=useState<SortState>({key:"row_number",direction:"asc"}); const [jobs,setJobs]=useState<ImportJob[]>([]); const [total,setTotal]=useState(0); const [page,setPage]=useState(1); const [pageSize,setPageSize]=useState(50); const [jobSort,setJobSort]=useState<SortState>({key:"created_at",direction:"desc"}); const [busy,setBusy]=useState(false);
  const typeConfig=EXCHANGE_TYPES.find(row=>row.value===entity)!;
  const maxDepth = entity==="geography" && subtype!=="ALL" ? subtype as "NETWORK"|"CITY"|"LOCATION"|"SECTOR" : "SECTOR";
  const loadJobs=useCallback(async()=>{const q=new URLSearchParams({page:String(page),page_size:String(pageSize),sort_by:jobSort.key,sort_direction:jobSort.direction});const result=await apiFetch<PageResult<ImportJob>>(`/data-exchange/imports?${q}`,{},token);setJobs(result.items);setTotal(result.total);},[token,page,pageSize,jobSort]);
  const previewRows=useMemo(()=>sortRows(preview?.records||[],previewSort,(row,key)=>key==="source_data"?JSON.stringify(row.source_data):row[key as keyof ImportRecord]),[preview,previewSort]);
  useEffect(()=>{void loadJobs().catch(error=>feedback.error(friendlyError(error,"Unable to load import history.")));},[loadJobs,refreshKey]);
  const download=async(path:string,fallback:string,options:RequestInit={})=>{try{setBusy(true);const result=await apiDownload(path,options,token);saveDownloadedBlob(result.blob,safeFilename(result.filename,fallback));}catch(error){feedback.error(friendlyError(error,"Unable to download file."));}finally{setBusy(false);}};
  const previewFile=async()=>{if(!file)return;try{setBusy(true);const ext=(file.name.split(".").pop()||format).toUpperCase();const q=new URLSearchParams({filename:file.name,file_format:ext,idempotency_key:crypto.randomUUID(),subtype});const result=await apiFetch<ImportPreview>(`/data-exchange/imports/${entity}/preview?${q}`,{method:"POST",headers:{"Content-Type":"application/octet-stream"},body:file},token);setPreview(result);feedback.success(result.job.error_records?"Preview completed with validation errors.":"Preview validated. Review before commit.");await loadJobs();}catch(error){feedback.error(friendlyError(error,"Unable to validate import preview."));}finally{setBusy(false);}};
  const confirm=async()=>{if(!preview?.job.file_sha256)return;try{setBusy(true);const job=await apiFetch<ImportJob>(`/data-exchange/imports/${preview.job.id}/confirm`,{method:"POST",body:JSON.stringify({expected_file_sha256:preview.job.file_sha256})},token);setPreview({...preview,job});feedback.success("Import committed transactionally.");await loadJobs();}catch(error){feedback.error(friendlyError(error,"Import commit failed; business-data writes were rolled back."));}finally{setBusy(false);}};
  const openJob=async(job:ImportJob)=>{try{setPreview(await apiFetch<ImportPreview>(`/data-exchange/imports/${job.id}`,{},token));}catch(error){feedback.error(friendlyError(error,"Unable to load import evidence."));}};
  const changeEntity=(value:ExchangeEntity)=>{setEntity(value);setSubtype("ALL");setScope(EMPTY_SCOPE);setPreview(null);setFile(null);};
  const templatePath=`/data-exchange/templates/${entity}?${new URLSearchParams({format,subtype}).toString()}`;
  const exportFilters={...cleanScope(scope),subtype};
  const importAllowed=canImport&&exchangeDomainAllowed(permissions,entity,subtype,"import");
  const exportAllowed=canExport&&exchangeDomainAllowed(permissions,entity,subtype,"export");
  return <div className="phase-d-stack"><section className="panel"><WorkspaceSectionHeader className="phase-d-panel-header" title="Controlled data exchange" help="Choose the data you want to import or export." /><div className="form-grid three phase-d-exchange-selector">
    <label>Data type<Select unstyled value={entity} onChange={e=>changeEntity(e.target.value as ExchangeEntity)}>{EXCHANGE_TYPES.map(row=><option key={row.value} value={row.value}>{row.label}</option>)}</Select></label>
    <label>Subtype<Select unstyled value={subtype} onChange={e=>{setSubtype(e.target.value);setScope(EMPTY_SCOPE);setPreview(null);}}>{typeConfig.subtypes.map(row=><option key={row.value} value={row.value}>{row.label}</option>)}</Select></label>
    <label>Format<Select unstyled value={format} onChange={e=>setFormat(e.target.value as typeof format)}>{formats.map(v=><option key={v}>{v}</option>)}</Select></label>
  </div>
  {exportAllowed&&<><ScopeSelector token={token} value={scope} onChange={setScope} canGeo={canGeoFilter} canGroup={canGroupFilter&&entity!=="geography"} maxDepth={maxDepth}/><div className="button-row phase-d-builder-actions"><Button unstyled disabled={busy} onClick={()=>void download("/data-exchange/exports",`${entity}_${subtype.toLowerCase()}_export.${format.toLowerCase()}`,{method:"POST",body:JSON.stringify({entity_type:entity,format,filters:exportFilters})})}>Export selected data</Button></div></>}
  {canExport&&!exportAllowed&&<div className="empty-state">You do not have permission to export this data type.</div>}
  {importAllowed&&<div className="phase-d-import-block"><div className="button-row"><Button unstyled className="secondary" disabled={busy} onClick={()=>void download(templatePath,`${entity}_${subtype.toLowerCase()}_template.${format.toLowerCase()}`)}>Download import template</Button></div><div className="inline-form phase-d-file-row"><Input unstyled type="file" accept=".csv,.xlsx,.json" onChange={e=>{setFile(e.target.files?.[0]||null);setPreview(null);}}/><Button unstyled disabled={!file||busy} onClick={()=>void previewFile()}>Validate preview</Button></div></div>}
  {canImport&&!importAllowed&&<div className="empty-state">You do not have permission to import this data type.</div>}
  </section>
    {preview&&<section className="panel"><WorkspaceSectionHeader className="phase-d-panel-header" title="Import preview" help="Review the file before applying any changes." actions={<div className="button-row"><TableExportButton token={token} tableId="import_preview_records" filters={{ job_id:preview.job.id, record_limit:10000, sort_by:previewSort.key, sort_direction:previewSort.direction }}/>{canImport&&preview.job.status==="PREVIEWED"&&preview.job.error_records===0?<Button unstyled disabled={busy} onClick={()=>void confirm()}>Confirm import</Button>:null}</div>} /><DataTable viewportClassName="table-wrap"><thead><tr><SortHeader label="Row" sortKey="row_number" sort={previewSort} onSort={key=>setPreviewSort(current=>nextSort(current,key))}/><SortHeader label="Status" sortKey="status" sort={previewSort} onSort={key=>setPreviewSort(current=>nextSort(current,key))}/><SortHeader label="Error code" sortKey="error_code" sort={previewSort} onSort={key=>setPreviewSort(current=>nextSort(current,key))}/><SortHeader label="Message" sortKey="error_message" sort={previewSort} onSort={key=>setPreviewSort(current=>nextSort(current,key))}/><SortHeader label="Input data" sortKey="source_data" sort={previewSort} onSort={key=>setPreviewSort(current=>nextSort(current,key))}/></tr></thead><tbody><PaginatedTableRows items={previewRows} colSpan={5} itemLabel="import preview rows" renderRow={row=><tr key={row.id}><td>{row.row_number}</td><td><Badge value={row.status}/></td><td>{row.error_code||"—"}</td><td>{row.error_message||"—"}</td><td><RecordSummary data={row.source_data}/></td></tr>}/></tbody></DataTable>{preview.records.length>=500&&<p className="muted-note">Preview UI is capped at the first 500 evidence rows; the server validates the full file.</p>}</section>}
    <section className="panel"><WorkspaceSectionHeader className="phase-d-panel-header" title="Your import history" help="Review your recent imports and results." actions={<TableExportButton token={token} tableId="import_jobs" filters={{ sort_by:jobSort.key, sort_direction:jobSort.direction }}/>} /><DataTable viewportClassName="table-wrap"><thead><tr><SortHeader label="Created" sortKey="created_at" sort={jobSort} onSort={key=>{setJobSort(current=>nextSort(current,key));setPage(1);}}/><SortHeader label="Entity" sortKey="entity_type" sort={jobSort} onSort={key=>{setJobSort(current=>nextSort(current,key));setPage(1);}}/><SortHeader label="File" sortKey="filename" sort={jobSort} onSort={key=>{setJobSort(current=>nextSort(current,key));setPage(1);}}/><SortHeader label="Status" sortKey="status" sort={jobSort} onSort={key=>{setJobSort(current=>nextSort(current,key));setPage(1);}}/><SortHeader label="Rows" sortKey="total_records" sort={jobSort} onSort={key=>{setJobSort(current=>nextSort(current,key));setPage(1);}}/><SortHeader label="Errors" sortKey="error_records" sort={jobSort} onSort={key=>{setJobSort(current=>nextSort(current,key));setPage(1);}}/></tr></thead><tbody>{jobs.map(row=><tr key={row.id} onDoubleClick={()=>void openJob(row)}><td>{when(row.created_at)}</td><td>{row.entity_type?.replace(/_/g," ")||"—"}</td><td>{row.filename||"—"}</td><td><Badge value={row.status}/></td><td>{row.total_records}</td><td>{row.error_records}</td></tr>)}{!jobs.length&&<tr><td colSpan={6}>No import jobs.</td></tr>}</tbody></DataTable><ServerPagination page={page} pageSize={pageSize} total={total} onPage={setPage} onPageSize={v=>{setPageSize(v);setPage(1);}} itemLabel="import jobs"/></section></div>;
}

function ReportsPanel({token,canManage,canExport,canSchedule,canSensitive,canGeoFilter,canGroupFilter,refreshKey,feedback,activeView,editorTabs,setEditorTabs,setActiveView}:{token:string;canManage:boolean;canExport:boolean;canSchedule:boolean;canSensitive:boolean;canGeoFilter:boolean;canGroupFilter:boolean;refreshKey:number;feedback:ReturnType<typeof useFeedback>;activeView:Tab;editorTabs:ReportEditorTab[];setEditorTabs:Dispatch<SetStateAction<ReportEditorTab[]>>;setActiveView:(value:Tab)=>void}) {
  const dialog=useDialog();
  const [catalog,setCatalog]=useState<CatalogItem[]>([]);
  const [definitions,setDefinitions]=useState<ReportDefinition[]>([]);
  const [schedules,setSchedules]=useState<ReportSchedule[]>([]);
  const [configTotal,setConfigTotal]=useState(0);
  const [configView,setConfigView]=useState<ReportConfigView>(canManage?"definitions":canSchedule?"schedules":"deleted");
  const [deletedKind,setDeletedKind]=useState<DeletedConfigKind>(canManage?"definitions":"schedules");
  const [configPage,setConfigPage]=useState(1);
  const [configPageSize,setConfigPageSize]=useState(50);
  const [configSearch,setConfigSearch]=useState("");
  const configSearchDebounced=useDebouncedValue(configSearch,280);
  const [configReportType,setConfigReportType]=useState("");
  const [configFormat,setConfigFormat]=useState("");
  const [configLink,setConfigLink]=useState("any");
  const [configEnabled,setConfigEnabled]=useState("");
  const [definitionSort,setDefinitionSort]=useState<SortState>({key:"name",direction:"asc"});
  const [scheduleSort,setScheduleSort]=useState<SortState>({key:"name",direction:"asc"});
  const [jobs,setJobs]=useState<ReportJob[]>([]);
  const [jobTotal,setJobTotal]=useState(0);
  const [jobPage,setJobPage]=useState(1);
  const [jobPageSize,setJobPageSize]=useState(50);
  const [jobSort,setJobSort]=useState<SortState>({key:"requested_at",direction:"desc"});
  const [selectedJobs,setSelectedJobs]=useState<Set<string>>(new Set());
  const [deliveries,setDeliveries]=useState<ReportDelivery[]>([]);
  const [deliveryPage,setDeliveryPage]=useState(1);
  const [deliveryPageSize,setDeliveryPageSize]=useState(50);
  const [deliveryTotal,setDeliveryTotal]=useState(0);
  const [deliverySort,setDeliverySort]=useState<SortState>({key:"created_at",direction:"desc"});
  const [reportType,setReportType]=useState("inventory");
  const [format,setFormat]=useState("CSV");
  const [reportFilters,setReportFilters]=useState<Record<string,string>>({});
  const [sensitive,setSensitive]=useState(false);
  const [definitionName,setDefinitionName]=useState("");
  const [scheduleName,setScheduleName]=useState("");
  const [interval,setInterval]=useState(1440);
  const [channel,setChannel]=useState("");
  const [destination,setDestination]=useState("");
  const [busy,setBusy]=useState(false);

  const normalizePage=<T,>(value:PageResult<T>|T[],page:number,pageSize:number):PageResult<T>=>Array.isArray(value)?{items:value,total:value.length,page,page_size:pageSize}:value;
  const configIsDefinitions=configView==="definitions"||(configView==="deleted"&&deletedKind==="definitions");
  const configState=configView==="deleted"?"deleted":"active";
  const currentSort=configIsDefinitions?definitionSort:scheduleSort;
  const configFiltersActive=Boolean(configSearch||configReportType||configFormat||configLink!=="any"||(!configIsDefinitions&&configEnabled));

  const configQuery=useCallback(()=>{
    const query=new URLSearchParams({state:configState,page:String(configPage),page_size:String(configPageSize),sort_by:currentSort.key,sort_direction:currentSort.direction});
    if(configSearchDebounced.trim())query.set("search",configSearchDebounced.trim());
    if(configReportType)query.set("report_type",configReportType);
    if(configFormat)query.set("format",configFormat);
    if(configLink!=="any")query.set("link_state",configLink);
    if(!configIsDefinitions&&configEnabled)query.set("enabled",configEnabled);
    return query;
  },[configState,configPage,configPageSize,currentSort,configSearchDebounced,configReportType,configFormat,configLink,configIsDefinitions,configEnabled]);

  const load=useCallback(async()=>{
    const jobQuery=new URLSearchParams({page:String(jobPage),page_size:String(jobPageSize),sort_by:jobSort.key,sort_direction:jobSort.direction});
    const deliveryQuery=new URLSearchParams({page:String(deliveryPage),page_size:String(deliveryPageSize),sort_by:deliverySort.key,sort_direction:deliverySort.direction});
    const emptyDelivery:PageResult<ReportDelivery>={items:[],total:0,page:1,page_size:50};
    const configRequest=configIsDefinitions
      ? apiFetch<PageResult<ReportDefinition>|ReportDefinition[]>(`/reports/definitions?${configQuery()}`,{},token)
      : apiFetch<PageResult<ReportSchedule>|ReportSchedule[]>(`/reports/schedules?${configQuery()}`,{},token);
    const [catalogRows,jobRows,configRows,deliveryRows]=await Promise.all([
      apiFetch<CatalogItem[]>("/reports/catalog",{},token),
      apiFetch<PageResult<ReportJob>>(`/reports/jobs?${jobQuery}`,{},token),
      configRequest,
      canSchedule?apiFetch<PageResult<ReportDelivery>>(`/reports/deliveries?${deliveryQuery}`,{},token):Promise.resolve(emptyDelivery),
    ]);
    setCatalog(catalogRows);setJobs(jobRows.items);setJobTotal(jobRows.total);
    setSelectedJobs(current=>new Set([...current].filter(id=>jobRows.items.some(row=>row.id===id))));
    if(configIsDefinitions){const page=normalizePage(configRows as PageResult<ReportDefinition>|ReportDefinition[],configPage,configPageSize);setDefinitions(page.items);setSchedules([]);setConfigTotal(page.total);}
    else{const page=normalizePage(configRows as PageResult<ReportSchedule>|ReportSchedule[],configPage,configPageSize);setSchedules(page.items);setDefinitions([]);setConfigTotal(page.total);}
    setDeliveries(deliveryRows.items);setDeliveryTotal(deliveryRows.total);
  },[token,jobPage,jobPageSize,jobSort,deliveryPage,deliveryPageSize,deliverySort,canSchedule,configIsDefinitions,configQuery,configPage,configPageSize]);

  useEffect(()=>{void load().catch(error=>feedback.error(friendlyError(error,"Unable to load reports.")));},[load,refreshKey]);
  useEffect(()=>{const item=catalog.find(x=>x.code===reportType);if(item&&!item.supported_formats.includes(format))setFormat(item.supported_formats[0]||"CSV");},[catalog,reportType,format]);

  const selected=catalog.find(x=>x.code===reportType);
  const currentFilters=()=>reportFiltersToRequest([...(selected?.filters||[]),...(reportType==="audit"?[]:REPORT_SCOPE_KEYS)],reportFilters);
  const changeReportType=(value:string)=>{setReportType(value);setReportFilters({});};
  const setFilter=(key:string,value:string)=>setReportFilters(current=>({...current,[key]:value}));
  const deletableJobs=jobs.filter(row=>!["QUEUED","RUNNING"].includes(row.status));
  const allDeletableSelected=deletableJobs.length>0&&deletableJobs.every(row=>selectedJobs.has(row.id));
  const activeEditor=editorTabs.find(editor=>editor.key===activeView);

  const resetConfigFilters=()=>{setConfigSearch("");setConfigReportType("");setConfigFormat("");setConfigLink("any");setConfigEnabled("");setConfigPage(1);};
  const changeConfigView=(value:ReportConfigView)=>{setConfigView(value);if(value==="definitions"&&!canManage)return;if(value==="schedules"&&!canSchedule)return;setConfigPage(1);setConfigSearch("");setConfigReportType("");setConfigFormat("");setConfigLink("any");setConfigEnabled("");};
  const closeEditorFor=(kind:"definition"|"schedule",id:string)=>{const key=`${kind}:${id}` as ReportEditorKey;setEditorTabs(current=>current.filter(tab=>tab.key!==key));if(activeView===key)setActiveView("reports");};

  const run=async()=>{try{setBusy(true);await apiFetch<ReportJob>("/reports/run",{method:"POST",body:JSON.stringify({report_type:reportType,format,filters:currentFilters(),include_sensitive:sensitive})},token);feedback.success("Report queued. Large reports execute asynchronously.");await load();}catch(error){feedback.error(friendlyError(error,"Unable to queue report."));}finally{setBusy(false);}};
  const saveDef=async()=>{if(!definitionName.trim())return;try{setBusy(true);await apiFetch("/reports/definitions",{method:"POST",body:JSON.stringify({name:definitionName.trim(),report_type:reportType,format,filters:currentFilters(),include_sensitive:sensitive,description:null})},token);setDefinitionName("");setConfigView("definitions");setConfigPage(1);feedback.success("Report definition saved.");await load();}catch(error){feedback.error(friendlyError(error,"Unable to save report definition."));}finally{setBusy(false);}};
  const useDefinition=(row:ReportDefinition)=>{setReportType(row.report_type);setFormat(row.format);setReportFilters(reportFiltersToForm(row.filters));setSensitive(row.include_sensitive);};
  const runDefinition=async(row:ReportDefinition)=>{try{setBusy(true);await apiFetch<ReportJob>("/reports/run",{method:"POST",body:JSON.stringify({definition_id:row.id})},token);feedback.success(`${row.name} queued.`);await load();}catch(error){feedback.error(friendlyError(error,"Unable to run saved definition."));}finally{setBusy(false);}};

  const openDefinitionEditor=(row:ReportDefinition)=>{const key=`definition:${row.id}` as ReportEditorKey;setEditorTabs(current=>current.some(tab=>tab.key===key)?current:[...current,{key,kind:"definition",label:`Edit Saved Definition · ${row.name}`,draft:{id:row.id,name:row.name,report_type:row.report_type,format:row.format,filters:reportFiltersToForm(row.filters),include_sensitive:row.include_sensitive,description:row.description||""}}]);setActiveView(key);};
  const openScheduleEditor=(row:ReportSchedule)=>{const key=`schedule:${row.id}` as ReportEditorKey;setEditorTabs(current=>current.some(tab=>tab.key===key)?current:[...current,{key,kind:"schedule",label:`Edit Scheduled Report · ${row.name}`,draft:{id:row.id,definition_id:row.definition_id||"",definition_name:row.definition_name||"",name:row.name,report_type:row.report_type,format:row.format,filters:reportFiltersToForm(row.filters||{}),include_sensitive:row.include_sensitive,interval_minutes:row.interval_minutes,enabled:row.enabled,next_run_at:toLocalDateTime(row.next_run_at),channel_type:row.channel_type||"",destination:row.destination||"",max_attempts:row.max_attempts||3,retry_base_seconds:row.retry_base_seconds||60}}]);setActiveView(key);};
  const updateEditor=(key:ReportEditorKey,updater:(tab:ReportEditorTab)=>ReportEditorTab)=>setEditorTabs(current=>current.map(tab=>tab.key===key?updater(tab):tab));

  const loadDefinitionOptions=useCallback(async(query:string,page:number,pageSize:number):Promise<ComboboxPage<ReportDefinition>>=>{const params=new URLSearchParams({state:"active",page:String(page),page_size:String(pageSize),sort_by:"name",sort_direction:"asc"});if(query.trim())params.set("search",query.trim());const result=await apiFetch<PageResult<ReportDefinition>>(`/reports/definitions?${params}`,{},token);return {items:result.items.map(row=>({id:row.id,label:row.name,description:`${row.report_type.replace(/_/g," ")} · ${row.format}`,data:row})),total:result.total,page:result.page,page_size:result.page_size};},[token]);

  const saveDefinitionEdit=async(tab:Extract<ReportEditorTab,{kind:"definition"}>)=>{const draft=tab.draft;if(!draft.name.trim())return;const item=catalog.find(row=>row.code===draft.report_type);const filters=reportFiltersToRequest([...(item?.filters||[]),...(draft.report_type==="audit"?[]:REPORT_SCOPE_KEYS)],draft.filters);try{setBusy(true);await apiFetch(`/reports/definitions/${draft.id}`,{method:"PATCH",body:JSON.stringify({name:draft.name.trim(),report_type:draft.report_type,format:draft.format,filters,include_sensitive:draft.include_sensitive,description:draft.description.trim()||null})},token);updateEditor(tab.key,current=>current.kind==="definition"?{...current,label:`Edit Saved Definition · ${draft.name.trim()}`,draft:{...current.draft,name:draft.name.trim()}}:current);feedback.success("Report definition updated.");await load();}catch(error){feedback.error(friendlyError(error,"Unable to update report definition."));}finally{setBusy(false);}};
  const deleteDefinition=async(row:ReportDefinition)=>{if(!await dialog.confirm({title:"Move saved definition to Deleted configurations",message:`Move “${row.name}” to the report configuration trash? It can be restored until its purge date. Active schedules using it must be removed or detached first.`,confirmLabel:"Move to Deleted",tone:"danger"}))return;try{setBusy(true);await apiFetch(`/reports/definitions/${row.id}`,{method:"DELETE"},token);closeEditorFor("definition",row.id);feedback.success("Report definition moved to Deleted configurations.");await load();}catch(error){feedback.error(friendlyError(error,"Unable to delete report definition."));}finally{setBusy(false);}};
  const restoreDefinition=async(row:ReportDefinition)=>{try{setBusy(true);await apiFetch(`/reports/definitions/${row.id}/restore`,{method:"POST"},token);feedback.success("Report definition restored.");await load();}catch(error){feedback.error(friendlyError(error,"Unable to restore report definition."));}finally{setBusy(false);}};
  const purgeDefinition=async(row:ReportDefinition)=>{if(!await dialog.confirm({title:"Permanently delete saved definition",message:`Permanently delete “${row.name}”? This cannot be undone. Deleted schedules that still reference it must be handled first.`,confirmLabel:"Delete permanently",tone:"danger"}))return;try{setBusy(true);await apiFetch(`/reports/definitions/${row.id}/permanent`,{method:"DELETE"},token);closeEditorFor("definition",row.id);feedback.success("Report definition permanently deleted.");await load();}catch(error){feedback.error(friendlyError(error,"Unable to permanently delete report definition."));}finally{setBusy(false);}};

  const createSchedule=async()=>{if(!scheduleName.trim())return;try{setBusy(true);await apiFetch("/reports/schedules",{method:"POST",body:JSON.stringify({name:scheduleName.trim(),report_type:reportType,format,filters:currentFilters(),include_sensitive:sensitive,interval_minutes:interval,enabled:true,next_run_at:new Date(Date.now()+Math.max(interval,60)*60000).toISOString(),channel_type:channel||null,destination:channel?destination.trim():null,max_attempts:3,retry_base_seconds:60})},token);setScheduleName("");setConfigView("schedules");setConfigPage(1);feedback.success("Scheduled report created.");await load();}catch(error){feedback.error(friendlyError(error,"Unable to create report schedule."));}finally{setBusy(false);}};
  const toggleSchedule=async(row:ReportSchedule)=>{try{setBusy(true);await apiFetch(`/reports/schedules/${row.id}`,{method:"PATCH",body:JSON.stringify({enabled:!row.enabled})},token);feedback.success(row.enabled?"Scheduled report disabled.":"Scheduled report enabled.");await load();}catch(error){feedback.error(friendlyError(error,"Unable to update schedule."));}finally{setBusy(false);}};
  const runScheduleNow=async(row:ReportSchedule)=>{try{setBusy(true);await apiFetch<ReportJob>("/reports/run",{method:"POST",body:JSON.stringify({schedule_id:row.id})},token);feedback.success(`${row.name} queued now. Its next planned run was not changed.`);await load();}catch(error){feedback.error(friendlyError(error,"Unable to run scheduled report now."));}finally{setBusy(false);}};
  const saveScheduleEdit=async(tab:Extract<ReportEditorTab,{kind:"schedule"}>)=>{const draft=tab.draft;if(!draft.name.trim())return;const item=catalog.find(row=>row.code===draft.report_type);const filters=reportFiltersToRequest([...(item?.filters||[]),...(draft.report_type==="audit"?[]:REPORT_SCOPE_KEYS)],draft.filters);const nextRun=new Date(draft.next_run_at);if(Number.isNaN(nextRun.getTime())){feedback.error("Enter a valid next-run date and time.");return;}const payload:Record<string,unknown>={definition_id:draft.definition_id||null,name:draft.name.trim(),interval_minutes:draft.interval_minutes,enabled:draft.enabled,next_run_at:nextRun.toISOString(),channel_type:draft.channel_type||null,destination:draft.channel_type?draft.destination.trim():null,max_attempts:draft.max_attempts,retry_base_seconds:draft.retry_base_seconds};if(!draft.definition_id)Object.assign(payload,{report_type:draft.report_type,format:draft.format,filters,include_sensitive:draft.include_sensitive});try{setBusy(true);await apiFetch(`/reports/schedules/${draft.id}`,{method:"PATCH",body:JSON.stringify(payload)},token);updateEditor(tab.key,current=>current.kind==="schedule"?{...current,label:`Edit Scheduled Report · ${draft.name.trim()}`,draft:{...current.draft,name:draft.name.trim()}}:current);feedback.success("Scheduled report updated.");await load();}catch(error){feedback.error(friendlyError(error,"Unable to update scheduled report."));}finally{setBusy(false);}};
  const deleteSchedule=async(row:ReportSchedule)=>{if(!await dialog.confirm({title:"Move scheduled report to Deleted configurations",message:`Move “${row.name}” to the report configuration trash? Future automatic runs stop immediately. It can be restored until its purge date.`,confirmLabel:"Move to Deleted",tone:"danger"}))return;try{setBusy(true);await apiFetch(`/reports/schedules/${row.id}`,{method:"DELETE"},token);closeEditorFor("schedule",row.id);feedback.success("Scheduled report moved to Deleted configurations.");await load();}catch(error){feedback.error(friendlyError(error,"Unable to delete scheduled report."));}finally{setBusy(false);}};
  const restoreSchedule=async(row:ReportSchedule)=>{try{setBusy(true);await apiFetch(`/reports/schedules/${row.id}/restore`,{method:"POST"},token);feedback.success("Scheduled report restored in disabled state. Review it before enabling automatic runs.");await load();}catch(error){feedback.error(friendlyError(error,"Unable to restore scheduled report."));}finally{setBusy(false);}};
  const purgeSchedule=async(row:ReportSchedule)=>{if(!await dialog.confirm({title:"Permanently delete scheduled report",message:`Permanently delete “${row.name}”? Historical generated reports are preserved, but this schedule cannot be restored.`,confirmLabel:"Delete permanently",tone:"danger"}))return;try{setBusy(true);await apiFetch(`/reports/schedules/${row.id}/permanent`,{method:"DELETE"},token);closeEditorFor("schedule",row.id);feedback.success("Scheduled report permanently deleted.");await load();}catch(error){feedback.error(friendlyError(error,"Unable to permanently delete scheduled report."));}finally{setBusy(false);}};

  const download=async(job:ReportJob)=>{try{setBusy(true);const result=await apiDownload(`/reports/jobs/${job.id}/download`,{},token);saveDownloadedBlob(result.blob,safeFilename(result.filename,job.artifact_name||`report.${job.format.toLowerCase()}`));}catch(error){feedback.error(friendlyError(error,"Unable to download report."));}finally{setBusy(false);}};
  const toggleJobSelection=(jobId:string,checked:boolean)=>setSelectedJobs(current=>{const next=new Set(current);if(checked)next.add(jobId);else next.delete(jobId);return next;});
  const toggleAllDeletable=(checked:boolean)=>setSelectedJobs(current=>{const next=new Set(current);deletableJobs.forEach(row=>checked?next.add(row.id):next.delete(row.id));return next;});
  const deleteGeneratedJobs=async(ids:string[])=>{if(!ids.length)return;const label=ids.length===1?"this generated report":`${ids.length} generated reports`;if(!await dialog.confirm({title:"Delete generated report",message:`Delete ${label} and its retained downloadable artifact? Generated reports are not moved to Deleted configurations.`,confirmLabel:ids.length===1?"Delete report":"Delete selected",tone:"danger"}))return;try{setBusy(true);await apiFetch<{deleted:number;deleted_ids:string[]}>("/reports/jobs",{method:"DELETE",body:JSON.stringify({job_ids:ids})},token);setSelectedJobs(new Set());feedback.success(ids.length===1?"Generated report deleted.":`${ids.length} generated reports deleted.`);if(ids.length>=jobs.length&&jobPage>1)setJobPage(page=>Math.max(1,page-1));else await load();}catch(error){feedback.error(friendlyError(error,"Unable to delete generated report."));}finally{setBusy(false);}};

  const editorToolbar=(saveLabel:string,disabled:boolean,onSave:()=>void)=><div className="phase-d-editor-toolbar"><Button unstyled className="secondary phase-d-back-button" aria-label="Back to Reports" onClick={()=>setActiveView("reports")}><span aria-hidden="true">←</span> Back to Reports</Button><Button unstyled disabled={disabled} onClick={onSave}>{saveLabel}</Button></div>;

  const renderDefinitionEditor=(tab:Extract<ReportEditorTab,{kind:"definition"}>)=>{const draft=tab.draft;const item=catalog.find(row=>row.code===draft.report_type);return <section className="panel phase-d-report-editor-page">
    <WorkspaceSectionHeader className="phase-d-panel-header" title="Edit saved report definition" help="Edit the reusable report configuration in a full workspace instead of a dialog." />
    {editorToolbar("Save changes",busy||!draft.name.trim(),()=>void saveDefinitionEdit(tab))}
    <div className="phase-d-editor-surface">
      <div className="phase-d-editor-section"><h4>Definition</h4><div className="phase-d-editor-grid"><label>Name<Input value={draft.name} onChange={e=>updateEditor(tab.key,current=>current.kind==="definition"?{...current,draft:{...current.draft,name:e.target.value}}:current)}/></label><label>Report<Select value={draft.report_type} onChange={e=>updateEditor(tab.key,current=>current.kind==="definition"?{...current,draft:{...current.draft,report_type:e.target.value,format:catalog.find(row=>row.code===e.target.value)?.supported_formats[0]||"CSV",filters:{}}}:current)}>{catalog.map(row=><option key={row.code} value={row.code}>{row.name}</option>)}</Select></label><label>Format<Select value={draft.format} onChange={e=>updateEditor(tab.key,current=>current.kind==="definition"?{...current,draft:{...current.draft,format:e.target.value}}:current)}>{(item?.supported_formats||["CSV"]).map(value=><option key={value}>{value}</option>)}</Select></label></div></div>
      {draft.report_type!=="audit"&&<div className="phase-d-editor-section"><h4>Scope</h4><ScopeSelector token={token} value={scopeFromFilters(draft.filters)} onChange={value=>updateEditor(tab.key,current=>current.kind==="definition"?{...current,draft:{...current.draft,filters:{...current.draft.filters,...value}}}:current)} canGeo={canGeoFilter} canGroup={canGroupFilter}/></div>}
      <div className="phase-d-editor-section"><h4>Report filters</h4><div className="phase-d-editor-grid">{(item?.filters||[]).map(filter=><ReportFilterField key={filter} filter={filter} value={draft.filters[filter]||""} onChange={value=>updateEditor(tab.key,current=>current.kind==="definition"?{...current,draft:{...current.draft,filters:{...current.draft.filters,[filter]:value}}}:current)}/>)}{item&&item.filters.length===0&&<div className="empty-state">No additional filters are needed for this report.</div>}</div></div>
      <div className="phase-d-editor-section phase-d-editor-options"><h4>Options</h4>{canSensitive&&<Checkbox label="Include sensitive fields" checked={draft.include_sensitive} onChange={e=>updateEditor(tab.key,current=>current.kind==="definition"?{...current,draft:{...current.draft,include_sensitive:e.target.checked}}:current)}/>}<label>Description<Textarea rows={4} value={draft.description} onChange={e=>updateEditor(tab.key,current=>current.kind==="definition"?{...current,draft:{...current.draft,description:e.target.value}}:current)} placeholder="Optional description"/></label></div>
    </div>
    <div className="phase-d-editor-footer"><Button unstyled disabled={busy||!draft.name.trim()} onClick={()=>void saveDefinitionEdit(tab)}>Save changes</Button></div>
  </section>;};

  const renderScheduleEditor=(tab:Extract<ReportEditorTab,{kind:"schedule"}>)=>{const draft=tab.draft;const item=catalog.find(row=>row.code===draft.report_type);const selectedDefinition:ComboboxOption<ReportDefinition>|null=draft.definition_id?{id:draft.definition_id,label:draft.definition_name||"Linked saved definition",description:`${draft.report_type.replace(/_/g," ")} · ${draft.format}`}:null;const selectDefinition=(option:ComboboxOption<ReportDefinition>|null)=>{updateEditor(tab.key,current=>{if(current.kind!=="schedule")return current;const definition=option?.data;if(!definition)return {...current,draft:{...current.draft,definition_id:"",definition_name:""}};return {...current,draft:{...current.draft,definition_id:definition.id,definition_name:definition.name,report_type:definition.report_type,format:definition.format,filters:reportFiltersToForm(definition.filters),include_sensitive:definition.include_sensitive}};});};return <section className="panel phase-d-report-editor-page">
    <WorkspaceSectionHeader className="phase-d-panel-header" title="Edit scheduled report" help="Review schedule timing, delivery, and report configuration in a full workspace." />
    {editorToolbar("Save schedule",busy||!draft.name.trim(),()=>void saveScheduleEdit(tab))}
    <div className="phase-d-editor-surface">
      <div className="phase-d-editor-section"><h4>Schedule</h4><div className="phase-d-editor-grid"><label>Name<Input value={draft.name} onChange={e=>updateEditor(tab.key,current=>current.kind==="schedule"?{...current,draft:{...current.draft,name:e.target.value}}:current)}/></label><label>Saved definition<SearchableCombobox<ReportDefinition> value={draft.definition_id} selectedOption={selectedDefinition} onChange={selectDefinition} loadPage={loadDefinitionOptions} placeholder="Search saved definitions…" emptyText="No active saved definitions found." ariaLabel="Saved definition" /></label><div className="phase-d-editor-check"><Checkbox label="Enabled" checked={draft.enabled} onChange={e=>updateEditor(tab.key,current=>current.kind==="schedule"?{...current,draft:{...current.draft,enabled:e.target.checked}}:current)}/></div><label>Interval minutes<Input type="number" min={60} max={525600} value={draft.interval_minutes} onChange={e=>updateEditor(tab.key,current=>current.kind==="schedule"?{...current,draft:{...current.draft,interval_minutes:Number(e.target.value)}}:current)}/></label><label>Next run<Input type="datetime-local" value={draft.next_run_at} onChange={e=>updateEditor(tab.key,current=>current.kind==="schedule"?{...current,draft:{...current.draft,next_run_at:e.target.value}}:current)}/></label><label>Delivery<Select value={draft.channel_type} onChange={e=>updateEditor(tab.key,current=>current.kind==="schedule"?{...current,draft:{...current.draft,channel_type:e.target.value,destination:e.target.value?current.draft.destination:""}}:current)}><option value="">No delivery</option><option value="EMAIL">Email</option><option value="WEBHOOK">Webhook</option></Select></label>{draft.channel_type&&<label>Destination<Input value={draft.destination} onChange={e=>updateEditor(tab.key,current=>current.kind==="schedule"?{...current,draft:{...current.draft,destination:e.target.value}}:current)} placeholder={draft.channel_type==="EMAIL"?"recipient@example.com":"https://..."}/></label>}<label>Max attempts<Input type="number" min={1} max={10} value={draft.max_attempts} onChange={e=>updateEditor(tab.key,current=>current.kind==="schedule"?{...current,draft:{...current.draft,max_attempts:Number(e.target.value)}}:current)}/></label><label>Retry base seconds<Input type="number" min={5} max={3600} value={draft.retry_base_seconds} onChange={e=>updateEditor(tab.key,current=>current.kind==="schedule"?{...current,draft:{...current.draft,retry_base_seconds:Number(e.target.value)}}:current)}/></label></div></div>
      <div className="phase-d-editor-section"><h4>Report configuration</h4>{draft.definition_id?<div className="phase-d-relationship-note"><strong>Definition: {draft.definition_name||"Linked saved definition"}</strong><span>Report type, filters, format, and sensitive-field setting are inherited from this definition.</span></div>:<><div className="phase-d-editor-grid"><label>Report<Select value={draft.report_type} onChange={e=>updateEditor(tab.key,current=>current.kind==="schedule"?{...current,draft:{...current.draft,report_type:e.target.value,format:catalog.find(row=>row.code===e.target.value)?.supported_formats[0]||"CSV",filters:{}}}:current)}>{catalog.map(row=><option key={row.code} value={row.code}>{row.name}</option>)}</Select></label><label>Format<Select value={draft.format} onChange={e=>updateEditor(tab.key,current=>current.kind==="schedule"?{...current,draft:{...current.draft,format:e.target.value}}:current)}>{(item?.supported_formats||["CSV"]).map(value=><option key={value}>{value}</option>)}</Select></label></div>{draft.report_type!=="audit"&&<ScopeSelector token={token} value={scopeFromFilters(draft.filters)} onChange={value=>updateEditor(tab.key,current=>current.kind==="schedule"?{...current,draft:{...current.draft,filters:{...current.draft.filters,...value}}}:current)} canGeo={canGeoFilter} canGroup={canGroupFilter}/>}<div className="phase-d-editor-grid">{(item?.filters||[]).map(filter=><ReportFilterField key={filter} filter={filter} value={draft.filters[filter]||""} onChange={value=>updateEditor(tab.key,current=>current.kind==="schedule"?{...current,draft:{...current.draft,filters:{...current.draft.filters,[filter]:value}}}:current)}/>)}</div>{canSensitive&&<div className="phase-d-editor-check"><Checkbox label="Include sensitive fields" checked={draft.include_sensitive} onChange={e=>updateEditor(tab.key,current=>current.kind==="schedule"?{...current,draft:{...current.draft,include_sensitive:e.target.checked}}:current)}/></div>}</>}</div>
    </div>
    <div className="phase-d-editor-footer"><Button unstyled disabled={busy||!draft.name.trim()} onClick={()=>void saveScheduleEdit(tab)}>Save schedule</Button></div>
  </section>;};

  const jobColSpan=canManage?10:8;
  const definitionExportFilters={state:configState,search:configSearchDebounced,report_type:configReportType,format:configFormat,link_state:configLink,sort_by:definitionSort.key,sort_direction:definitionSort.direction};
  const scheduleExportFilters={state:configState,search:configSearchDebounced,report_type:configReportType,format:configFormat,link_state:configLink,enabled:configEnabled,sort_by:scheduleSort.key,sort_direction:scheduleSort.direction};
  return <div className="phase-d-stack phase-d-reports-workspace">
    {activeView==="reports"?<>
      <section className="panel"><WorkspaceSectionHeader className="phase-d-panel-header" title="Report catalog" help="Choose and run a report." /><div className="form-grid three phase-d-report-builder"><label>Report<Select unstyled value={reportType} onChange={e=>changeReportType(e.target.value)}>{catalog.map(item=><option key={item.code} value={item.code}>{item.name}</option>)}</Select></label><label>Format<Select unstyled value={format} onChange={e=>setFormat(e.target.value)}>{(selected?.supported_formats||["CSV"]).map(v=><option key={v}>{v}</option>)}</Select></label>{canSensitive&&<div className="phase-d-builder-check"><Checkbox label="Include sensitive fields" checked={sensitive} onChange={e=>setSensitive(e.target.checked)}/></div>}</div>{reportType!=="audit"&&<ScopeSelector token={token} value={scopeFromFilters(reportFilters)} onChange={value=>setReportFilters(current=>({...current,...value}))} canGeo={canGeoFilter} canGroup={canGroupFilter}/>}<div className="form-grid three phase-d-report-filter-grid" aria-label="Report filters">{(selected?.filters||[]).map(filter=><ReportFilterField key={filter} filter={filter} value={reportFilters[filter]||""} onChange={value=>setFilter(filter,value)}/>)}{selected&&selected.filters.length===0&&<div className="empty-state">No additional filters are needed for this report.</div>}</div><div className="button-row phase-d-builder-actions">{canExport&&<Button unstyled disabled={busy} onClick={()=>void run()}>Run report</Button>}{canManage&&<><Input unstyled value={definitionName} onChange={e=>setDefinitionName(e.target.value)} placeholder="Saved definition name"/><Button unstyled className="secondary" disabled={!definitionName.trim()||busy} onClick={()=>void saveDef()}>Save definition</Button></>}</div></section>

      <section className="panel"><WorkspaceSectionHeader className="phase-d-panel-header" title="Report jobs" help="Track generated reports, download completed files, and remove retained report history." actions={<div className="button-row">{canManage&&selectedJobs.size>0&&<Button unstyled className="danger" disabled={busy} onClick={()=>void deleteGeneratedJobs([...selectedJobs])}>Delete Selected ({selectedJobs.size})</Button>}<TableExportButton token={token} tableId="report_jobs" filters={{sort_by:jobSort.key,sort_direction:jobSort.direction}}/><Button unstyled className="secondary" onClick={()=>void load()}>Refresh</Button></div>} /><DataTable viewportClassName="table-wrap"><thead><tr>{canManage&&<th className="phase-d-select-column"><Checkbox aria-label="Select all deletable report jobs" checked={allDeletableSelected} disabled={!deletableJobs.length} onChange={e=>toggleAllDeletable(e.target.checked)}/></th>}<SortHeader label="Requested" sortKey="requested_at" sort={jobSort} onSort={key=>{setJobSort(current=>nextSort(current,key));setJobPage(1);}}/><SortHeader label="Name" sortKey="display_name" sort={jobSort} onSort={key=>{setJobSort(current=>nextSort(current,key));setJobPage(1);}}/><SortHeader label="Type" sortKey="report_type" sort={jobSort} onSort={key=>{setJobSort(current=>nextSort(current,key));setJobPage(1);}}/><SortHeader label="Format" sortKey="format" sort={jobSort} onSort={key=>{setJobSort(current=>nextSort(current,key));setJobPage(1);}}/><SortHeader label="Status" sortKey="status" sort={jobSort} onSort={key=>{setJobSort(current=>nextSort(current,key));setJobPage(1);}}/><SortHeader label="Rows" sortKey="row_count" sort={jobSort} onSort={key=>{setJobSort(current=>nextSort(current,key));setJobPage(1);}}/><SortHeader label="Artifact" sortKey="artifact_name" sort={jobSort} onSort={key=>{setJobSort(current=>nextSort(current,key));setJobPage(1);}}/><SortHeader label="Error" sortKey="error_code" sort={jobSort} onSort={key=>{setJobSort(current=>nextSort(current,key));setJobPage(1);}}/>{canManage&&<th>Actions</th>}</tr></thead><tbody>{jobs.map(row=>{const deletable=!["QUEUED","RUNNING"].includes(row.status);return <tr key={row.id}>{canManage&&<td className="phase-d-select-column"><Checkbox aria-label={`Select report ${row.display_name}`} checked={selectedJobs.has(row.id)} disabled={!deletable||busy} onChange={e=>toggleJobSelection(row.id,e.target.checked)}/></td>}<td>{when(row.requested_at)}</td><td><strong>{row.display_name}</strong></td><td>{row.report_type}</td><td>{row.format}</td><td><Badge value={row.status}/></td><td>{row.row_count}</td><td>{row.status==="COMPLETED"&&row.artifact_name?<Button unstyled className="link-button" title={row.artifact_name} disabled={busy} onClick={()=>void download(row)}>Download · {bytes(row.artifact_size)}</Button>:"—"}</td><td>{row.error_code||row.error_message||"—"}</td>{canManage&&<td><Button unstyled className="danger" disabled={!deletable||busy} title={deletable?"Delete generated report":"Active reports cannot be deleted"} onClick={()=>void deleteGeneratedJobs([row.id])}>Delete</Button></td>}</tr>})}{!jobs.length&&<tr><td colSpan={jobColSpan}>No report jobs.</td></tr>}</tbody></DataTable><ServerPagination page={jobPage} pageSize={jobPageSize} total={jobTotal} onPage={setJobPage} onPageSize={v=>{setJobPageSize(v);setJobPage(1);}} itemLabel="report jobs"/></section>

      {(canManage||canSchedule)&&<section className="panel phase-d-config-panel"><WorkspaceSectionHeader className="phase-d-panel-header" title="Configuration management" help="Manage active and deleted report configurations without loading the entire configuration inventory at once." /><WorkspaceTabs<ReportConfigView> className="phase-d-config-tabs" value={configView} onChange={changeConfigView} tabs={[{id:"definitions",label:"Saved Definitions",visible:canManage},{id:"schedules",label:"Scheduled Reports",visible:canSchedule},{id:"deleted",label:"Deleted Configurations",visible:canManage||canSchedule}]}/>
        {configView==="deleted"&&<div className="phase-d-config-kind"><label>Deleted object type<Select unstyled value={deletedKind} onChange={e=>{setDeletedKind(e.target.value as DeletedConfigKind);setConfigPage(1);setConfigLink("any");setConfigEnabled("");}}>{canManage&&<option value="definitions">Saved Definitions</option>}{canSchedule&&<option value="schedules">Scheduled Reports</option>}</Select></label><small>Deleted configurations are automatically purged after their retention date.</small></div>}
        <div className="phase-d-config-filters"><label>Search<Input unstyled value={configSearch} onChange={e=>{setConfigSearch(e.target.value);setConfigPage(1);}} placeholder="Search configuration name…"/></label><label>Report type<Select unstyled value={configReportType} onChange={e=>{setConfigReportType(e.target.value);setConfigPage(1);}}><option value="">All report types</option>{catalog.map(item=><option key={item.code} value={item.code}>{item.name}</option>)}</Select></label><label>Format<Select unstyled value={configFormat} onChange={e=>{setConfigFormat(e.target.value);setConfigPage(1);}}><option value="">All formats</option>{formats.map(value=><option key={value}>{value}</option>)}</Select></label><label>Relationship<Select unstyled value={configLink} onChange={e=>{setConfigLink(e.target.value);setConfigPage(1);}}><option value="any">All relationships</option>{configIsDefinitions?<><option value="linked">Used by schedules</option><option value="unlinked">Not used by schedules</option></>:<><option value="linked">Linked definition</option><option value="standalone">Standalone</option></>}</Select></label>{!configIsDefinitions&&configView!=="deleted"&&<label>Status<Select unstyled value={configEnabled} onChange={e=>{setConfigEnabled(e.target.value);setConfigPage(1);}}><option value="">Enabled + Disabled</option><option value="true">Enabled</option><option value="false">Disabled</option></Select></label>}<div className="phase-d-config-clear"><ClearFiltersButton disabled={!configFiltersActive} onClick={resetConfigFilters}/></div></div>

        {configView==="definitions"&&canManage&&<><div className="phase-d-config-toolbar"><strong>{configTotal} saved definition{configTotal===1?"":"s"}</strong>{canExport&&<TableExportButton token={token} tableId="report_definitions" filters={definitionExportFilters}/>}</div><div className="phase-d-card-list">{definitions.map(row=><article className="phase-d-definition-card" key={row.id}><div className="phase-d-definition-card-head"><div><strong>{row.name}</strong><span>{row.report_type.replace(/_/g," ")} · {row.format}</span></div><Badge value="ACTIVE"/></div><p>{row.description||"Reusable report configuration"}</p><small>{row.include_sensitive?"Sensitive fields requested":"Standard fields"}</small><div className="phase-d-relationship"><strong>{row.linked_schedules?.length?`Used by ${row.linked_schedules.length} scheduled report${row.linked_schedules.length===1?"":"s"}`:"Not linked to a scheduled report"}</strong>{row.linked_schedules?.length>0&&<span>{row.linked_schedules.map(item=>`${item.name}${item.deleted_at?" (Deleted)":""}`).join(" · ")}</span>}</div><div className="phase-d-card-actions">{canExport&&<Button unstyled disabled={busy} onClick={()=>void runDefinition(row)}>Run</Button>}<Button unstyled className="secondary" disabled={busy} onClick={()=>useDefinition(row)}>Load</Button><Button unstyled className="secondary" disabled={busy} onClick={()=>openDefinitionEditor(row)}>Edit</Button><Button unstyled className="danger" disabled={busy} onClick={()=>void deleteDefinition(row)}>Delete</Button></div></article>)}{!definitions.length&&<div className="empty-state">No saved report definitions match the current filters.</div>}</div><ServerPagination page={configPage} pageSize={configPageSize} total={configTotal} onPage={setConfigPage} onPageSize={value=>{setConfigPageSize(value);setConfigPage(1);}} itemLabel="saved definitions"/></>}

        {configView==="schedules"&&canSchedule&&<><div className="inline-form phase-d-schedule-form"><Input unstyled value={scheduleName} onChange={e=>setScheduleName(e.target.value)} placeholder="Schedule name"/><label>Interval minutes<Input unstyled type="number" min={60} max={525600} value={interval} onChange={e=>setInterval(Number(e.target.value))}/></label><label>Delivery<Select unstyled value={channel} onChange={e=>setChannel(e.target.value)}><option value="">No delivery</option><option value="EMAIL">Email</option><option value="WEBHOOK">Webhook</option></Select></label>{channel&&<Input unstyled value={destination} onChange={e=>setDestination(e.target.value)} placeholder={channel==="EMAIL"?"recipient@example.com":"https://..."}/>}<Button unstyled disabled={!scheduleName.trim()||busy||(Boolean(channel)&&!destination.trim())} onClick={()=>void createSchedule()}>Create schedule</Button></div><div className="phase-d-config-toolbar"><strong>{configTotal} scheduled report{configTotal===1?"":"s"}</strong>{canExport&&<TableExportButton token={token} tableId="report_schedules" filters={scheduleExportFilters}/>}</div><DataTable viewportClassName="table-wrap"><thead><tr><SortHeader label="Name" sortKey="name" sort={scheduleSort} onSort={key=>{setScheduleSort(current=>nextSort(current,key));setConfigPage(1);}}/><SortHeader label="Report" sortKey="report_type" sort={scheduleSort} onSort={key=>{setScheduleSort(current=>nextSort(current,key));setConfigPage(1);}}/><th>Definition</th><SortHeader label="Interval" sortKey="interval_minutes" sort={scheduleSort} onSort={key=>{setScheduleSort(current=>nextSort(current,key));setConfigPage(1);}}/><SortHeader label="Next run" sortKey="next_run_at" sort={scheduleSort} onSort={key=>{setScheduleSort(current=>nextSort(current,key));setConfigPage(1);}}/><th>Delivery</th><SortHeader label="Enabled" sortKey="enabled" sort={scheduleSort} onSort={key=>{setScheduleSort(current=>nextSort(current,key));setConfigPage(1);}}/><th>Actions</th></tr></thead><tbody>{schedules.map(row=><tr key={row.id}><td><strong>{row.name}</strong></td><td>{row.report_type} · {row.format}</td><td>{row.definition_id?<><strong>{row.definition_name||"Linked definition"}</strong><small className="table-subtext">{row.definition_deleted_at?"Deleted definition":"Active definition"}</small></>:<span>Standalone</span>}</td><td>{row.interval_minutes} min</td><td>{when(row.next_run_at)}</td><td>{row.channel_type?`${row.channel_type} · ${row.destination}`:"None"}</td><td><Badge value={row.enabled?"ENABLED":"DISABLED"}/></td><td><div className="button-row phase-d-table-actions">{canExport&&<Button unstyled disabled={busy} onClick={()=>void runScheduleNow(row)}>Run Now</Button>}<Button unstyled className="secondary" disabled={busy} onClick={()=>openScheduleEditor(row)}>Edit</Button><Button unstyled className="secondary" disabled={busy} onClick={()=>void toggleSchedule(row)}>{row.enabled?"Disable":"Enable"}</Button><Button unstyled className="danger" disabled={busy} onClick={()=>void deleteSchedule(row)}>Delete</Button></div></td></tr>)}{!schedules.length&&<tr><td colSpan={8}>No scheduled reports match the current filters.</td></tr>}</tbody></DataTable><ServerPagination page={configPage} pageSize={configPageSize} total={configTotal} onPage={setConfigPage} onPageSize={value=>{setConfigPageSize(value);setConfigPage(1);}} itemLabel="scheduled reports"/><div className="panel-header phase-d-delivery-heading"><h4>Recent deliveries</h4><TableExportButton token={token} tableId="report_deliveries" filters={{sort_by:deliverySort.key,sort_direction:deliverySort.direction}}/></div><DataTable viewportClassName="table-wrap"><thead><tr><SortHeader label="Status" sortKey="status" sort={deliverySort} onSort={key=>{setDeliverySort(current=>nextSort(current,key));setDeliveryPage(1);}}/><SortHeader label="Channel" sortKey="channel_type" sort={deliverySort} onSort={key=>{setDeliverySort(current=>nextSort(current,key));setDeliveryPage(1);}}/><SortHeader label="Destination" sortKey="destination" sort={deliverySort} onSort={key=>{setDeliverySort(current=>nextSort(current,key));setDeliveryPage(1);}}/><SortHeader label="Attempts" sortKey="attempt_count" sort={deliverySort} onSort={key=>{setDeliverySort(current=>nextSort(current,key));setDeliveryPage(1);}}/><SortHeader label="Next attempt" sortKey="next_attempt_at" sort={deliverySort} onSort={key=>{setDeliverySort(current=>nextSort(current,key));setDeliveryPage(1);}}/><SortHeader label="Error" sortKey="last_error_code" sort={deliverySort} onSort={key=>{setDeliverySort(current=>nextSort(current,key));setDeliveryPage(1);}}/></tr></thead><tbody>{deliveries.map(row=><tr key={row.id}><td><Badge value={row.status}/></td><td>{row.channel_type}</td><td>{row.destination}</td><td>{row.attempt_count}</td><td>{when(row.next_attempt_at)}</td><td>{row.last_error_code||"—"}</td></tr>)}{!deliveries.length&&<tr><td colSpan={6}>No report deliveries.</td></tr>}</tbody></DataTable><ServerPagination page={deliveryPage} pageSize={deliveryPageSize} total={deliveryTotal} onPage={setDeliveryPage} onPageSize={value=>{setDeliveryPageSize(value);setDeliveryPage(1);}} itemLabel="report deliveries"/></>}

        {configView==="deleted"&&configIsDefinitions&&canManage&&<><div className="phase-d-config-toolbar"><strong>{configTotal} deleted saved definition{configTotal===1?"":"s"}</strong></div><div className="phase-d-trash-list">{definitions.map(row=><article className="phase-d-trash-card" key={row.id}><div><strong>{row.name}</strong><span>{row.report_type} · {row.format}</span></div><Badge value="DELETED"/><small>Deleted {when(row.deleted_at)}</small><small>Purge after {when(row.purge_after)}</small><div className="phase-d-relationship"><strong>{row.linked_schedules?.length?`Linked schedules: ${row.linked_schedules.length}`:"No linked schedules"}</strong>{row.linked_schedules?.length>0&&<span>{row.linked_schedules.map(item=>`${item.name}${item.deleted_at?" (Deleted)":" (Active)"}`).join(" · ")}</span>}</div><div className="phase-d-trash-actions"><Button unstyled className="secondary" disabled={busy} onClick={()=>void restoreDefinition(row)}>Restore</Button><Button unstyled className="danger" disabled={busy} onClick={()=>void purgeDefinition(row)}>Delete permanently</Button></div></article>)}{!definitions.length&&<div className="empty-state">No deleted saved definitions match the current filters.</div>}</div><ServerPagination page={configPage} pageSize={configPageSize} total={configTotal} onPage={setConfigPage} onPageSize={value=>{setConfigPageSize(value);setConfigPage(1);}} itemLabel="deleted saved definitions"/></>}
        {configView==="deleted"&&!configIsDefinitions&&canSchedule&&<><div className="phase-d-config-toolbar"><strong>{configTotal} deleted scheduled report{configTotal===1?"":"s"}</strong></div><div className="phase-d-trash-list">{schedules.map(row=><article className="phase-d-trash-card" key={row.id}><div><strong>{row.name}</strong><span>{row.report_type} · {row.format}</span></div><Badge value="DELETED"/><small>Deleted {when(row.deleted_at)}</small><small>Purge after {when(row.purge_after)}</small><div className="phase-d-relationship"><strong>{row.definition_id?`Definition: ${row.definition_name||"Linked definition"}`:"Standalone schedule"}</strong>{row.definition_id&&<span>{row.definition_deleted_at?"Definition is also deleted":"Definition is active"}</span>}</div><div className="phase-d-trash-actions"><Button unstyled className="secondary" disabled={busy} onClick={()=>void restoreSchedule(row)}>Restore</Button><Button unstyled className="danger" disabled={busy} onClick={()=>void purgeSchedule(row)}>Delete permanently</Button></div></article>)}{!schedules.length&&<div className="empty-state">No deleted scheduled reports match the current filters.</div>}</div><ServerPagination page={configPage} pageSize={configPageSize} total={configTotal} onPage={setConfigPage} onPageSize={value=>{setConfigPageSize(value);setConfigPage(1);}} itemLabel="deleted scheduled reports"/></>}
      </section>}
    </>:activeEditor?.kind==="definition"?renderDefinitionEditor(activeEditor):activeEditor?.kind==="schedule"?renderScheduleEditor(activeEditor):null}
  </div>;
}
