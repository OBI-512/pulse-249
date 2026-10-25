import { PageLayout } from "../design-system/layouts";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Button, Input, Select } from "../design-system/primitives";
import { apiFetch } from "../api/client";
import type { MaintenanceTargetOption, MaintenanceWindow, NotificationDelivery, PageResult, SortState } from "../types";
import { useDialog } from "../components/common/DialogSystem";
import { useFeedback } from "../components/common/FeedbackSystem";
import { friendlyError } from "../utils/feedback";
import { SearchableCombobox, type ComboboxOption, type ComboboxPage } from "../design-system/composites/SearchableSelect";

import { nextSort, sortRows } from "../utils/sorting";
import { DataTable } from "../design-system/data/DataTable";
import { ServerPagination } from "../design-system/data/Pagination";
import { SortHeader } from "../design-system/data/SortHeader";
import { TableExportButton } from "../design-system/data/TableExport";
import { ClearFiltersButton } from "../design-system/composites/FilterBar";


type Props = { token:string; permissions:string[]; refreshKey:number };
type WindowState = "ACTIVE"|"UPCOMING"|"PAST"|"CANCELLED"|"ALL";
type TargetType = "DEVICE"|"LOCATION"|"CITY"|"GROUP"|"NETWORK";

function localInput(date:Date):string {
  const offset = date.getTimezoneOffset() * 60000;
  return new Date(date.getTime() - offset).toISOString().slice(0,16);
}

function when(value:string|null|undefined):string {
  return value ? new Date(value).toLocaleString() : "—";
}

function deliverySummary(row:NotificationDelivery):string {
  const value = row.metadata?.summary;
  return typeof value === "string" ? value : "—";
}

function MaintenanceMetricIcon({kind}:{kind:"active"|"windows"|"measurement"}) {
  return <span className="maintenance-metric-icon"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    {kind==="active"
      ? <><circle cx="12" cy="12" r="8"/><path d="m8.5 12 2.2 2.2 4.8-5"/></>
      : kind==="windows"
        ? <><rect x="4" y="5" width="16" height="15" rx="2"/><path d="M8 3v4M16 3v4M4 9h16"/></>
        : <><path d="M4 13h3l2-5 4 10 2-5h5"/><path d="M4 5v14h16"/></>}
  </svg></span>;
}

export function MaintenancePage({ token, permissions, refreshKey }:Props) {
  const dialog = useDialog();
  const feedback = useFeedback();
  const canManage = permissions.includes("maintenance.manage");
  const canReadNotifications = permissions.includes("notification.read");
  const [state,setState] = useState<WindowState>("ALL");
  const [search,setSearch] = useState("");
  const [page,setPage] = useState(1);
  const [pageSize,setPageSize] = useState(25);
  const [sort,setSort] = useState<SortState>({key:"starts_at",direction:"desc"});
  const [deliverySort,setDeliverySort] = useState<SortState>({key:"created_at",direction:"desc"});
  const [rows,setRows] = useState<MaintenanceWindow[]>([]);
  const [total,setTotal] = useState(0);
  const [busy,setBusy] = useState(false);
  const [editingId,setEditingId] = useState<string|null>(null);
  const [targetType,setTargetType] = useState<TargetType>("DEVICE");
  const [targetId,setTargetId] = useState("");
  const [selectedTarget,setSelectedTarget] = useState<ComboboxOption<MaintenanceTargetOption>|null>(null);
  const [name,setName] = useState("");
  const [reason,setReason] = useState("");
  const [startsAt,setStartsAt] = useState(() => localInput(new Date(Date.now()+5*60000)));
  const [endsAt,setEndsAt] = useState(() => localInput(new Date(Date.now()+65*60000)));
  const [deliveries,setDeliveries] = useState<NotificationDelivery[]>([]);

  const loadWindows = useCallback(async () => {
    const query = new URLSearchParams({state,page:String(page),page_size:String(pageSize),sort_by:sort.key,sort_direction:sort.direction});
    if (search.trim()) query.set("search",search.trim());
    const result = await apiFetch<PageResult<MaintenanceWindow>>(`/maintenance-windows?${query}`,{},token);
    setRows(result.items); setTotal(result.total);
  },[token,state,page,pageSize,search,sort]);

  const loadTargetPage = useCallback(async (queryText:string,targetPage:number,targetPageSize:number):Promise<ComboboxPage<MaintenanceTargetOption>> => {
    const query = new URLSearchParams({
      target_type:targetType,
      page:String(targetPage),
      page_size:String(targetPageSize),
    });
    if (queryText.trim()) query.set("search",queryText.trim());
    const result = await apiFetch<PageResult<MaintenanceTargetOption>>(`/maintenance-windows/targets?${query}`,{},token);
    return {
      ...result,
      items:result.items.map(item=>({
        id:item.id,
        label:item.label,
        description:item.context || undefined,
        data:item,
      })),
    };
  },[token,targetType]);

  const loadDeliveries = useCallback(async () => {
    if (!canReadNotifications) return;
    const result = await apiFetch<PageResult<NotificationDelivery>>(`/notifications/deliveries?page=1&page_size=20`,{},token);
    setDeliveries(result.items);
  },[token,canReadNotifications]);

  const refresh = useCallback(async () => {
    try { await Promise.all([loadWindows(),loadDeliveries()]); }
    catch(error){ feedback.error(friendlyError(error,"Unable to load maintenance workspace.")); }
  },[loadWindows,loadDeliveries,feedback]);

  useEffect(()=>{ setPage(1); },[state,search]);
  useEffect(()=>{ void refresh(); },[refresh,refreshKey]);
  useEffect(()=>{ const timer=window.setInterval(()=>void loadWindows().catch(()=>undefined),15000); return()=>window.clearInterval(timer); },[loadWindows]);

  const resetEditor = useCallback(() => {
    setEditingId(null);
    setTargetType("DEVICE");
    setTargetId("");
    setSelectedTarget(null);
    setName("");
    setReason("");
    setStartsAt(localInput(new Date(Date.now()+5*60000)));
    setEndsAt(localInput(new Date(Date.now()+65*60000)));
  },[]);

  const beginEdit = (row:MaintenanceWindow) => {
    if (row.state !== "UPCOMING") return;
    setEditingId(row.id);
    setTargetType(row.target_type);
    setTargetId(row.target_id);
    setSelectedTarget({
      id:row.target_id,
      label:row.target_display_name,
      data:{id:row.target_id,target_type:row.target_type,label:row.target_display_name,context:null},
    });
    setName(row.name);
    setReason(row.reason||"");
    setStartsAt(localInput(new Date(row.starts_at)));
    setEndsAt(localInput(new Date(row.ends_at)));
  };

  const submitWindow = async () => {
    if (!targetId || !name.trim()) return;
    const start = new Date(startsAt);
    const end = new Date(endsAt);
    if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || end <= start) {
      feedback.error("Maintenance end time must be later than start time."); return;
    }
    if (editingId && start <= new Date()) {
      feedback.error("An edited maintenance window must remain upcoming and start in the future."); return;
    }
    setBusy(true);
    try {
      const body=JSON.stringify({
        name:name.trim(), reason:reason.trim()||null, target_type:targetType, target_id:targetId,
        starts_at:start.toISOString(), ends_at:end.toISOString(),
      });
      if (editingId) {
        await apiFetch<MaintenanceWindow>(`/maintenance-windows/${editingId}`,{method:"PUT",body},token);
        feedback.success("Maintenance window updated.");
      } else {
        await apiFetch<MaintenanceWindow>("/maintenance-windows",{method:"POST",body},token);
        feedback.success("Maintenance window created.");
      }
      setState("ALL"); resetEditor(); await refresh();
    } catch(error){ feedback.error(friendlyError(error,editingId?"Unable to update maintenance window.":"Unable to create maintenance window.")); }
    finally { setBusy(false); }
  };

  const cancel = async (row:MaintenanceWindow) => {
    if (!await dialog.confirm({ title:"Cancel maintenance window", message:`Cancel maintenance window “${row.name}”? Cancellation preserves its historical record.`, confirmLabel:"Cancel window", tone:"danger" })) return;
    setBusy(true);
    try {
      await apiFetch<MaintenanceWindow>(`/maintenance-windows/${row.id}/cancel`,{method:"POST",body:JSON.stringify({reason:null})},token);
      feedback.success("Maintenance window cancelled."); await refresh();
    } catch(error){ feedback.error(friendlyError(error,"Unable to cancel maintenance window.")); }
    finally { setBusy(false); }
  };

  const activeCount = useMemo(()=>rows.filter(row=>row.state==="ACTIVE").length,[rows]);
  const visibleDeliveries = useMemo(()=>sortRows(deliveries,deliverySort,(row,key)=>{
    if(key==="summary") return deliverySummary(row);
    return row[key as keyof NotificationDelivery];
  }),[deliveries,deliverySort]);

  return <PageLayout className="page maintenance-page">
    <div className="page-heading"><div><h2 className="hover-help-title" data-help="Schedule maintenance for devices, groups, or geographic areas and review notification activity. Availability checks continue during maintenance.">Maintenance</h2></div><Button unstyled className="secondary" onClick={()=>void refresh()}>Refresh</Button></div>

    <section className="maintenance-summary-grid">
      <article className="maintenance-metric maintenance-metric-active"><MaintenanceMetricIcon kind="active"/><div><span>Active in current view</span><strong>{activeCount}</strong><small>Currently effective windows</small></div></article>
      <article className="maintenance-metric maintenance-metric-windows"><MaintenanceMetricIcon kind="windows"/><div><span>Matching windows</span><strong>{total}</strong><small>Current filter result</small></div></article>
      <article className="maintenance-metric maintenance-metric-measurement"><MaintenanceMetricIcon kind="measurement"/><div><span className="hover-help-title" data-help="Availability checks continue during maintenance.">Availability measurement</span><strong>CONTINUES</strong></div></article>
    </section>

    {canManage && <section className="panel maintenance-create-panel"><div className="panel-heading"><div><h3 className="hover-help-title" data-help={editingId?"Only upcoming maintenance windows can be edited. Once maintenance starts, its operational record becomes immutable.":"Maintenance can delay notifications while availability checks and alarms continue."}>{editingId?"Edit upcoming maintenance":"Schedule maintenance"}</h3></div></div>
      <div className="maintenance-form-grid">
        <label>Target type<Select unstyled value={targetType} onChange={e=>{setTargetType(e.target.value as TargetType);setTargetId("");setSelectedTarget(null)}}><option>DEVICE</option><option>LOCATION</option><option>CITY</option><option>GROUP</option><option>NETWORK</option></Select></label>
        <label className="maintenance-target-select">Target<SearchableCombobox<MaintenanceTargetOption>
          required
          value={targetId}
          selectedOption={selectedTarget}
          onChange={option=>{setSelectedTarget(option);setTargetId(option?.id||"")}}
          loadPage={loadTargetPage}
          placeholder={`Search ${targetType.toLowerCase()} targets…`}
          emptyText={`No matching ${targetType.toLowerCase()} targets.`}
          ariaLabel="Maintenance target"
        /></label>
        <label>Name<Input unstyled value={name} onChange={e=>setName(e.target.value)} maxLength={160} placeholder="Planned maintenance" /></label>
        <label>Starts<Input unstyled type="datetime-local" value={startsAt} onChange={e=>setStartsAt(e.target.value)} /></label>
        <label>Ends<Input unstyled type="datetime-local" value={endsAt} onChange={e=>setEndsAt(e.target.value)} /></label>
        <label className="maintenance-reason">Reason<Input unstyled value={reason} onChange={e=>setReason(e.target.value)} maxLength={4000} placeholder="Optional operational reason" /></label>
      </div>
      <div className="actions"><Button unstyled disabled={busy||!targetId||!name.trim()} onClick={()=>void submitWindow()}>{editingId?"Save changes":"Create window"}</Button>{editingId&&<Button unstyled className="secondary" disabled={busy} onClick={resetEditor}>Discard edit</Button>}</div>
    </section>}

    <section className="panel"><div className="panel-heading"><div><h3 className="hover-help-title" data-help="Cancellation preserves historical records.">Maintenance windows</h3></div></div>
      <div className="filter-row compact"><Select unstyled value={state} onChange={e=>setState(e.target.value as WindowState)}><option value="ALL">All</option><option value="ACTIVE">Active</option><option value="UPCOMING">Upcoming</option><option value="PAST">Past</option><option value="CANCELLED">Cancelled</option></Select><Input unstyled value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search name or reason…" /><TableExportButton token={token} tableId="maintenance" filters={{ state, search, sort_by: sort.key, sort_direction: sort.direction }}/><ClearFiltersButton disabled={state==="ALL"&&!search} onClick={()=>{setState("ALL");setSearch("");setPage(1)}}/></div>
      <DataTable viewportClassName="table-wrap"><thead><tr><SortHeader label="State" sortKey="state" sort={sort} onSort={key=>{setSort(current=>nextSort(current,key));setPage(1)}}/><SortHeader label="Name" sortKey="name" sort={sort} onSort={key=>{setSort(current=>nextSort(current,key));setPage(1)}}/><SortHeader label="Target" sortKey="target" sort={sort} onSort={key=>{setSort(current=>nextSort(current,key));setPage(1)}}/><SortHeader label="Starts" sortKey="starts_at" sort={sort} onSort={key=>{setSort(current=>nextSort(current,key));setPage(1)}}/><SortHeader label="Ends" sortKey="ends_at" sort={sort} onSort={key=>{setSort(current=>nextSort(current,key));setPage(1)}}/><SortHeader label="Reason" sortKey="reason" sort={sort} onSort={key=>{setSort(current=>nextSort(current,key));setPage(1)}}/>{canManage&&<th>Action</th>}</tr></thead><tbody>
        {rows.map(row=><tr key={row.id}><td><span className={`badge maintenance-state-${row.state.toLowerCase()}`}>{row.state}</span></td><td><strong>{row.name}</strong></td><td>{row.target_type}<br/><small>{row.target_display_name}</small></td><td>{when(row.starts_at)}</td><td>{when(row.ends_at)}</td><td>{row.reason||"—"}</td>{canManage&&<td>{(row.state==="ACTIVE"||row.state==="UPCOMING")?<div className="actions">{row.state==="UPCOMING"&&<Button unstyled className="small secondary" disabled={busy} onClick={()=>beginEdit(row)}>Edit</Button>}<Button unstyled className="small danger" disabled={busy} onClick={()=>void cancel(row)}>Cancel</Button></div>:"—"}</td>}</tr>)}
        {!rows.length&&<tr><td colSpan={canManage?7:6}>No maintenance windows match the current filters.</td></tr>}
      </tbody></DataTable>
      <ServerPagination page={page} pageSize={pageSize} total={total} onPage={setPage} onPageSize={size=>{setPageSize(size);setPage(1)}} itemLabel="maintenance windows" />
    </section>

    {canReadNotifications && <section className="panel"><div className="panel-heading"><div><h3 className="hover-help-title" data-help="Recent scoped delivery, suppression, retry, failure, and cancellation records.">Notification delivery log</h3></div><TableExportButton token={token} tableId="notification_deliveries" filters={{ sort_by: deliverySort.key, sort_direction: deliverySort.direction }}/></div><DataTable viewportClassName="table-wrap"><thead><tr>
      <SortHeader label="Status" sortKey="status" sort={deliverySort} onSort={key=>setDeliverySort(current=>nextSort(current,key))}/>
      <SortHeader label="Channel" sortKey="channel_type" sort={deliverySort} onSort={key=>setDeliverySort(current=>nextSort(current,key))}/>
      <SortHeader label="Summary" sortKey="summary" sort={deliverySort} onSort={key=>setDeliverySort(current=>nextSort(current,key))}/>
      <SortHeader label="Attempts" sortKey="attempt_count" sort={deliverySort} onSort={key=>setDeliverySort(current=>nextSort(current,key))}/>
      <SortHeader label="Next attempt" sortKey="next_attempt_at" sort={deliverySort} onSort={key=>setDeliverySort(current=>nextSort(current,key))}/>
      <SortHeader label="Error" sortKey="last_error_code" sort={deliverySort} onSort={key=>setDeliverySort(current=>nextSort(current,key))}/>
    </tr></thead><tbody>
      {visibleDeliveries.map(row=><tr key={row.id}><td><span className={`badge notification-${row.status.toLowerCase()}`}>{row.status}</span></td><td>{row.channel_type}</td><td>{deliverySummary(row)}</td><td>{row.attempt_count}</td><td>{when(row.next_attempt_at)}</td><td>{row.last_error_code||"—"}</td></tr>)}
      {!deliveries.length&&<tr><td colSpan={6}>No notification delivery records.</td></tr>}
    </tbody></DataTable></section>}
  </PageLayout>;
}
