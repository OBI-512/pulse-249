import { PageLayout } from "../design-system/layouts";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiFetch } from "../api/client";
import type { PageResult, SortState } from "../types";
import { friendlyError } from "../utils/feedback";
import { useFeedback } from "../components/common/FeedbackSystem";
import { SearchableCombobox, type ComboboxPage, type ComboboxOption } from "../design-system/composites/SearchableSelect";

import { useDebouncedValue } from "../hooks/useDebouncedValue";
import { nextSort } from "../utils/sorting";
import { Tabs } from "../design-system/composites/Tabs";

import { Button, Input, Select } from "../design-system/primitives";
import { DataTable } from "../design-system/data/DataTable";
import { ServerPaginationRow } from "../design-system/data/Pagination";
import { SortHeader } from "../design-system/data/SortHeader";
import { TableExportButton } from "../design-system/data/TableExport";
import { ClearFiltersButton } from "../design-system/composites/FilterBar";
type AuditPage={items:any[];total:number;page:number;page_size:number};
type OpLog={timestamp:string;level:string;service:string;logger:string;message:string;request_id?:string|null;user_id?:string|null;exception_class?:string|null;context:Record<string,unknown>};
type OpPage={items:OpLog[];total:number;page:number;page_size:number};
type LogFilterOption={id:string;label:string;description?:string|null};
type TimePreset="ALL"|"LAST_HOUR"|"LAST_24_HOURS"|"LAST_2_DAYS"|"LAST_7_DAYS"|"LAST_30_DAYS"|"CUSTOM";

function toLocalInput(date:Date){const offset=date.getTimezoneOffset()*60000;return new Date(date.getTime()-offset).toISOString().slice(0,16)}
function timeBounds(preset:TimePreset,from:string,to:string){
  if(preset==="ALL")return {since:"",until:""};
  if(preset==="CUSTOM")return {since:from?new Date(from).toISOString():"",until:to?new Date(to).toISOString():""};
  const durations:Record<Exclude<TimePreset,"ALL"|"CUSTOM">,number>={LAST_HOUR:3600e3,LAST_24_HOURS:86400e3,LAST_2_DAYS:2*86400e3,LAST_7_DAYS:7*86400e3,LAST_30_DAYS:30*86400e3};
  const now=new Date();return {since:new Date(now.getTime()-durations[preset]).toISOString(),until:now.toISOString()};
}

function FilterCombobox({value,onChange,loadPage,placeholder}:{value:string;onChange:(value:string)=>void;loadPage:(query:string,page:number,pageSize:number)=>Promise<ComboboxPage<LogFilterOption>>;placeholder:string}){
  const [selected,setSelected]=useState<ComboboxOption<LogFilterOption>|null>(null);
  const fallback=useMemo<ComboboxOption<LogFilterOption>|null>(()=>value?{id:value,label:value.includes("|")?"Current entity":value}:null,[value]);
  const load=useCallback(async(query:string,page:number,pageSize:number)=>{
    const result=await loadPage(query,page,pageSize);
    const current=result.items.find(item=>item.id===value);if(current)setSelected(current);
    return result;
  },[loadPage,value]);
  return <SearchableCombobox<LogFilterOption> value={value} selectedOption={selected?.id===value?selected:fallback} onChange={option=>{setSelected(option);onChange(option?.id||"")}} loadPage={load} placeholder={placeholder} emptyText="No matching log values."/>;
}

function entityLabel(row:any){
  const snapshot=row.entity_display_snapshot;
  if(snapshot&&typeof snapshot==="object")for(const key of ["display_name","name","label","service_code","customer_code","ip_address","code"]){if(snapshot[key])return String(snapshot[key])}
  if(row.entity_type&&row.entity_id)return `${row.entity_type} · ${String(row.entity_id).slice(0,8)}…`;
  return row.entity_type||"—";
}
function shortRequest(value?:string|null){return value&&value.length>16?`${value.slice(0,12)}…`:value||"—"}

export function LogsPage({token,permissions,refreshKey=0}:{token:string;permissions:string[];refreshKey?:number}){
 const feedback=useFeedback();
 const [tab,setTab]=useState<"audit"|"operational">(permissions.includes("audit.read")?"audit":"operational");
 const [audit,setAudit]=useState<any[]>([]),[auditTotal,setAuditTotal]=useState(0),[auditPage,setAuditPage]=useState(1),[auditPageSize,setAuditPageSize]=useState(50);
 const [ops,setOps]=useState<OpLog[]>([]),[opsTotal,setOpsTotal]=useState(0),[opsPage,setOpsPage]=useState(1),[opsPageSize,setOpsPageSize]=useState(50);
 const [auditSort,setAuditSort]=useState<SortState>({key:"occurred_at",direction:"desc"});
 const [opsSort,setOpsSort]=useState<SortState>({key:"timestamp",direction:"desc"});
 const [service,setService]=useState("all"),[level,setLevel]=useState("");
 const [search,setSearch]=useState(""),[error,setError]=useState("");
 const [actor,setActor]=useState(""),[action,setAction]=useState(""),[entity,setEntity]=useState(""),[result,setResult]=useState(""),[auditRequestId,setAuditRequestId]=useState("");
 const [logger,setLogger]=useState(""),[opUser,setOpUser]=useState(""),[opRequestId,setOpRequestId]=useState("");
 const [timePreset,setTimePreset]=useState<TimePreset>("LAST_24_HOURS");
 const [customFrom,setCustomFrom]=useState(()=>toLocalInput(new Date(Date.now()-86400e3)));
 const [customTo,setCustomTo]=useState(()=>toLocalInput(new Date()));
 const debouncedSearch=useDebouncedValue(search,300);
 const auditRequestRef=useRef(0),opsRequestRef=useRef(0);
 const canAudit=permissions.includes("audit.read"),canOps=permissions.includes("logs.read");
 const bounds=useMemo(()=>timeBounds(timePreset,customFrom,customTo),[timePreset,customFrom,customTo]);

 const auditOptionLoader=useCallback((kind:string)=>async(query:string,page:number,pageSize:number):Promise<ComboboxPage<LogFilterOption>>=>{
   const p=new URLSearchParams({page:String(page),page_size:String(pageSize)});if(query)p.set("search",query);
   const d=await apiFetch<PageResult<LogFilterOption>>(`/audit/filter-options/${kind}?${p.toString()}`,{},token);
   return {...d,items:d.items.map(row=>({id:row.id,label:row.label,description:row.description||undefined,data:row}))};
 },[token]);
 const opOptionLoader=useCallback((kind:string)=>async(query:string,page:number,pageSize:number):Promise<ComboboxPage<LogFilterOption>>=>{
   const p=new URLSearchParams({service,page:String(page),page_size:String(pageSize)});if(query)p.set("search",query);
   const d=await apiFetch<PageResult<LogFilterOption>>(`/operational-logs/filter-options/${kind}?${p.toString()}`,{},token);
   return {...d,items:d.items.map(row=>({id:row.id,label:row.label,description:row.description||undefined,data:row}))};
 },[token,service]);

 const loadAudit=async()=>{if(!canAudit)return;const requestId=++auditRequestRef.current;try{const p=new URLSearchParams({page:String(auditPage),page_size:String(auditPageSize),sort_by:auditSort.key,sort_direction:auditSort.direction});if(debouncedSearch.trim())p.set("search",debouncedSearch.trim());if(actor)p.set("actor",actor);if(action)p.set("action",action);if(entity)p.set("entity_key",entity);if(result)p.set("result",result);if(auditRequestId)p.set("request_id",auditRequestId);if(bounds.since)p.set("occurred_after",bounds.since);if(bounds.until)p.set("occurred_before",bounds.until);const d=await apiFetch<AuditPage>(`/audit?${p.toString()}`,{},token);if(auditRequestRef.current!==requestId)return;setAudit(d.items);setAuditTotal(d.total);setError("")}catch(e){if(auditRequestRef.current===requestId)setError(friendlyError(e,"Unable to load audit log"))}};
 const loadOps=async()=>{if(!canOps)return;const requestId=++opsRequestRef.current;try{const p=new URLSearchParams({service,page:String(opsPage),page_size:String(opsPageSize),sort_by:opsSort.key,sort_direction:opsSort.direction});if(level)p.set("level",level);if(logger)p.set("logger",logger);if(opUser)p.set("user_id",opUser);if(opRequestId)p.set("request_id",opRequestId);if(debouncedSearch.trim())p.set("search",debouncedSearch.trim());if(bounds.since)p.set("since",bounds.since);if(bounds.until)p.set("until",bounds.until);const d=await apiFetch<OpPage>(`/operational-logs/page?${p.toString()}`,{},token);if(opsRequestRef.current!==requestId)return;setOps(d.items);setOpsTotal(d.total);setError("")}catch(e){if(opsRequestRef.current===requestId)setError(friendlyError(e,"Unable to load operational logs"))}};
 useEffect(()=>{setAuditPage(1);setOpsPage(1)},[debouncedSearch,service,level,actor,action,entity,result,auditRequestId,logger,opUser,opRequestId,timePreset,customFrom,customTo,tab]);
 useEffect(()=>{if(tab==="audit")void loadAudit();else void loadOps()},[tab,auditPage,auditPageSize,auditSort,opsPage,opsPageSize,opsSort,debouncedSearch,service,level,actor,action,entity,result,auditRequestId,logger,opUser,opRequestId,bounds.since,bounds.until,refreshKey]);
 useEffect(()=>{if(!error)return;feedback.error(error);setError("")},[error,feedback]);

 const clearFilters=()=>{setSearch("");setActor("");setAction("");setEntity("");setResult("");setAuditRequestId("");setLogger("");setOpUser("");setOpRequestId("");setService("all");setLevel("");setTimePreset("LAST_24_HOURS")};
 return <PageLayout className="page"><div className="page-heading"><div><h2 className="hover-help-title" data-help="Search, filter, correlate, and sort audit and operational events.">Logs</h2></div></div>
 <section className="panel log-control-panel"><Tabs<"audit" | "operational"> ariaLabel="Log views" value={tab} onChange={setTab} tabs={[{ id: "audit", label: "Audit log", visible: canAudit }, { id: "operational", label: "Operational logs", visible: canOps }]} />
   <div className="log-time-row"><label>Time range<Select unstyled value={timePreset} onChange={e=>setTimePreset(e.target.value as TimePreset)}><option value="LAST_HOUR">Last hour</option><option value="LAST_24_HOURS">Last 24 hours</option><option value="LAST_2_DAYS">Last 2 days</option><option value="LAST_7_DAYS">Last 7 days</option><option value="LAST_30_DAYS">Last 30 days</option><option value="CUSTOM">Custom range</option><option value="ALL">All available</option></Select></label>{timePreset==="CUSTOM"&&<><label>From<Input unstyled type="datetime-local" value={customFrom} onChange={e=>setCustomFrom(e.target.value)}/></label><label>To<Input unstyled type="datetime-local" value={customTo} onChange={e=>setCustomTo(e.target.value)}/></label></>}</div>
   <div className="log-filter-grid"><label className="log-keyword">Keyword<Input unstyled value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search messages, descriptions, entity details..."/></label>
   {tab==="audit"?<>
     <label>Actor<FilterCombobox value={actor} onChange={setActor} loadPage={auditOptionLoader("actor")} placeholder="Search actor..."/></label>
     <label>Action<FilterCombobox value={action} onChange={setAction} loadPage={auditOptionLoader("action")} placeholder="Search action..."/></label>
     <label>Entity<FilterCombobox value={entity} onChange={setEntity} loadPage={auditOptionLoader("entity")} placeholder="Search entity..."/></label>
     <label>Result<Select unstyled value={result} onChange={e=>setResult(e.target.value)}><option value="">All results</option><option>SUCCESS</option><option>FAILURE</option><option>ATTEMPT</option></Select></label>
     <label>Request ID<FilterCombobox value={auditRequestId} onChange={setAuditRequestId} loadPage={auditOptionLoader("request-id")} placeholder="Search request ID..."/></label>
   </>:<>
     <label>Service<Select unstyled value={service} onChange={e=>{setService(e.target.value);setLogger("");setOpUser("");setOpRequestId("")}}><option value="all">All services</option><option value="backend">Backend</option><option value="worker">Worker</option><option value="scheduler">Scheduler</option><option value="maintenance">Restore control</option></Select></label>
     <label>Level<Select unstyled value={level} onChange={e=>setLevel(e.target.value)}><option value="">All levels</option><option>DEBUG</option><option>INFO</option><option>WARNING</option><option>ERROR</option><option>CRITICAL</option></Select></label>
     <label>Logger<FilterCombobox value={logger} onChange={setLogger} loadPage={opOptionLoader("logger")} placeholder="Search logger..."/></label>
     <label>User ID<FilterCombobox value={opUser} onChange={setOpUser} loadPage={opOptionLoader("user")} placeholder="Search user ID..."/></label>
     <label>Request ID<FilterCombobox value={opRequestId} onChange={setOpRequestId} loadPage={opOptionLoader("request-id")} placeholder="Search request ID..."/></label>
   </>}</div><div className="filter-clear-row"><TableExportButton token={token} tableId={tab==="audit"?"audit_logs":"operational_logs"} filters={tab==="audit"?{search:debouncedSearch,actor,action,entity_key:entity,result,request_id:auditRequestId,occurred_after:bounds.since,occurred_before:bounds.until,sort_by:auditSort.key,sort_direction:auditSort.direction}:{service,level,logger,user_id:opUser,request_id:opRequestId,search:debouncedSearch,since:bounds.since,until:bounds.until,sort_by:opsSort.key,sort_direction:opsSort.direction}}/><ClearFiltersButton onClick={clearFilters}/></div></section>
 {tab==="audit"?<section className="panel"><DataTable viewportClassName="table-wrap"><thead><tr><SortHeader label="Time" sortKey="occurred_at" sort={auditSort} onSort={key=>setAuditSort(c=>nextSort(c,key))}/><SortHeader label="Actor" sortKey="actor" sort={auditSort} onSort={key=>setAuditSort(c=>nextSort(c,key))}/><SortHeader label="Action" sortKey="action" sort={auditSort} onSort={key=>setAuditSort(c=>nextSort(c,key))}/><SortHeader label="Entity" sortKey="entity" sort={auditSort} onSort={key=>setAuditSort(c=>nextSort(c,key))}/><SortHeader label="Result" sortKey="result" sort={auditSort} onSort={key=>setAuditSort(c=>nextSort(c,key))}/><SortHeader label="Description" sortKey="description" sort={auditSort} onSort={key=>setAuditSort(c=>nextSort(c,key))}/><SortHeader label="Request ID" sortKey="request_id" sort={auditSort} onSort={key=>setAuditSort(c=>nextSort(c,key))}/></tr></thead><tbody>{audit.map((x:any)=><tr key={x.id}><td>{new Date(x.occurred_at).toLocaleString()}</td><td>{x.actor_display_name_snapshot||x.actor_username_snapshot||"SYSTEM"}</td><td>{x.action}</td><td><strong>{entityLabel(x)}</strong>{x.entity_type&&<span className="table-secondary">{x.entity_type}</span>}</td><td>{x.result}</td><td>{x.description||"—"}</td><td>{x.request_id?<Button unstyled className="request-id-link mono" title={x.request_id} onClick={()=>setAuditRequestId(x.request_id)}>{shortRequest(x.request_id)}</Button>:"—"}</td></tr>)}{!audit.length&&<tr><td colSpan={7}>No audit events found.</td></tr>}<ServerPaginationRow colSpan={7} page={auditPage} pageSize={auditPageSize} total={auditTotal} onPage={setAuditPage} onPageSize={size=>{setAuditPageSize(size);setAuditPage(1)}} itemLabel="audit events"/></tbody></DataTable></section>:
 <section className="panel"><DataTable viewportClassName="table-wrap"><thead><tr><SortHeader label="Time" sortKey="timestamp" sort={opsSort} onSort={key=>setOpsSort(c=>nextSort(c,key))}/><SortHeader label="Level" sortKey="level" sort={opsSort} onSort={key=>setOpsSort(c=>nextSort(c,key))}/><SortHeader label="Service" sortKey="service" sort={opsSort} onSort={key=>setOpsSort(c=>nextSort(c,key))}/><SortHeader label="Logger" sortKey="logger" sort={opsSort} onSort={key=>setOpsSort(c=>nextSort(c,key))}/><SortHeader label="User" sortKey="user_id" sort={opsSort} onSort={key=>setOpsSort(c=>nextSort(c,key))}/><SortHeader label="Message" sortKey="message" sort={opsSort} onSort={key=>setOpsSort(c=>nextSort(c,key))}/><SortHeader label="Request ID" sortKey="request_id" sort={opsSort} onSort={key=>setOpsSort(c=>nextSort(c,key))}/></tr></thead><tbody>{ops.map((x:OpLog,i)=><tr key={`${x.timestamp}-${i}`}><td>{x.timestamp?new Date(x.timestamp).toLocaleString():"—"}</td><td>{x.level}</td><td>{x.service}</td><td>{x.logger||"—"}</td><td className="mono">{x.user_id||"—"}</td><td>{x.message}</td><td>{x.request_id?<Button unstyled className="request-id-link mono" title={x.request_id} onClick={()=>setOpRequestId(x.request_id||"")}>{shortRequest(x.request_id)}</Button>:"—"}</td></tr>)}{!ops.length&&<tr><td colSpan={7}>No operational events found.</td></tr>}<ServerPaginationRow colSpan={7} page={opsPage} pageSize={opsPageSize} total={opsTotal} onPage={setOpsPage} onPageSize={size=>{setOpsPageSize(size);setOpsPage(1)}} itemLabel="operational events"/></tbody></DataTable></section>}
 </PageLayout>;
}
