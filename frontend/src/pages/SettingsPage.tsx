import { PageLayout } from "../design-system/layouts";
import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "../api/client";
import { friendlyError } from "../utils/feedback";
import { useFeedback } from "../components/common/FeedbackSystem";

import type { AuthUser, OperationsDashboard, SortState } from "../types";
import { nextSort, sortRows } from "../utils/sorting";
import { Tabs, type TabOption } from "../design-system/composites/Tabs";
import { AccessTemplatesPanel } from "../features/access-templates/AccessTemplatesPanel";
import { WebTemplateWizard } from "../features/access-templates/WebTemplateWizard";

import { Button, Checkbox, Input, Select, Textarea } from "../design-system/primitives";
import { DataTable } from "../design-system/data/DataTable";
import { PaginatedTableRows } from "../design-system/data/Pagination";
import { SortHeader } from "../design-system/data/SortHeader";
import { TableExportButton } from "../design-system/data/TableExport";
import { ClearFiltersButton } from "../design-system/composites/FilterBar";
import { StatCard } from "../design-system/composites/Metric";
type Setting = { key:string; value:Record<string,unknown>; description:string|null; is_secret:boolean; category:string|null; is_configured:boolean };
type SystemInfo = { application_version:string; database_status:string; postgresql_version:string|null; alembic_revision:string|null; redis_status:string; worker_status:string|null; maintenance_mode:boolean; last_automatic_restore_point_at:string|null; restore_point_schedule:Record<string,unknown>; last_recycle_purge_at:string|null; log_storage:Record<string,unknown> };
type SettingsTab = "general" | "polling" | "access";

const SECURITY_SETTING_KEYS = [
  "auth.password.min_length",
  "auth.password.require_complexity",
  "auth.password.history_count",
  "auth.password.min_edit_distance",
  "auth.password.max_age_days",
  "auth.password.expiry_warning_days",
  "auth.session_online_window_minutes",
] as const;

const numberFormatter = new Intl.NumberFormat("en-US");
function count(value: number | null | undefined) { return numberFormatter.format(value ?? 0); }
function when(value: string | null | undefined) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function PollingPipelineSettings({ dashboard }: { dashboard: OperationsDashboard | null }) {
  const poll = dashboard?.polling;
  const tone = poll?.status === "HEALTHY" || poll?.status === "IDLE" ? "good" : poll?.status === "STARTING" ? "warn" : "bad";
  return <section className="panel settings-polling-panel">
    <div className="settings-polling-hero">
      <div>
        <span className="settings-polling-eyebrow">MONITORING ENGINE</span>
        <h3 className="hover-help-title" data-help="Shows scheduler activity, queue load, worker status, and recent polling activity.">Polling pipeline</h3>
        <p>Diagnostics for availability polling and worker health.</p>
      </div>
      <span className={`noc-health-pill ${tone}`}>{poll?.status || "INITIALIZING"}</span>
    </div>

    <div className="settings-polling-kpis">
      <article><span>Due now</span><strong>{count(poll?.due_now)}</strong><small>dispatcher backlog</small></article>
      <article><span>Outstanding</span><strong>{count(poll?.active_leases)}</strong><small>active leases</small></article>
      <article><span>Overdue</span><strong>{count(poll?.overdue)}</strong><small>late schedule slots</small></article>
      <article><span>Checked / interval</span><strong>{count(poll?.checked_last_interval)}</strong><small>{poll?.interval_seconds ?? 300}s measurement window</small></article>
    </div>

    <div className="settings-polling-runtime">
      <div><span>Worker heartbeat</span><strong>{poll?.worker_heartbeat_age_seconds == null ? "Waiting" : `${Math.round(poll.worker_heartbeat_age_seconds)}s ago`}</strong></div>
      <div><span>Last device check</span><strong>{when(poll?.latest_check_at)}</strong></div>
      <div><span>Last dispatch</span><strong>{when(poll?.latest_dispatch_at)}</strong></div>
      <div><span>Redis</span><strong>{poll?.redis_status || "UNKNOWN"}</strong></div>
      <div><span>Worker concurrency</span><strong>{poll?.worker_concurrency ?? "—"}</strong></div>
      <div><span>Max outstanding</span><strong>{poll?.max_outstanding_devices == null ? "—" : count(poll.max_outstanding_devices)}</strong></div>
      <div><span>Monitored devices</span><strong>{count(poll?.monitored_devices)}</strong></div>
      <div><span>Polling enabled</span><strong>{poll?.enabled ? "YES" : "NO"}</strong></div>
    </div>

    {!poll && <div className="empty-cell settings-polling-empty">Polling telemetry is not available yet. Refresh after the worker heartbeat is established.</div>}
  </section>;
}

export function SettingsPage({token,canManage=true,refreshKey=0}:{token:string;canManage?:boolean;refreshKey?:number}) {
  const feedback = useFeedback();
  const [tab,setTab]=useState<SettingsTab>("general");
  const [settings,setSettings]=useState<Setting[]>([]);
  const [system,setSystem]=useState<SystemInfo|null>(null);
  const [dashboard,setDashboard]=useState<OperationsDashboard|null>(null);
  const [sessionUser,setSessionUser]=useState<AuthUser|null>(null);
  const [drafts,setDrafts]=useState<Record<string,string>>({});
  const [error,setError]=useState("");
  const [message,setMessage]=useState("");
  const [busy,setBusy]=useState(false);
  const [search,setSearch]=useState("");
  const [category,setCategory]=useState("");
  const [sort,setSort]=useState<SortState>({key:"key",direction:"asc"});
  const [accessRevision,setAccessRevision]=useState(0);

  const load=async()=>{
    try {
      const [rows,info,user]=await Promise.all([
        apiFetch<Setting[]>("/admin/settings",{},token),
        apiFetch<SystemInfo>("/system-information",{},token),
        apiFetch<AuthUser>("/auth/me",{},token),
      ]);
      setSettings(rows);
      setSystem(info);
      setSessionUser(user);
      setDrafts(Object.fromEntries(rows.map(row=>[row.key,JSON.stringify(row.value)])));
      setError("");
      try { setDashboard(await apiFetch<OperationsDashboard>("/operations-dashboard",{},token)); }
      catch { setDashboard(null); }
    } catch(e) {
      setError(friendlyError(e,"Unable to load settings"));
    }
  };

  useEffect(()=>{void load()},[token,refreshKey]);
  useEffect(()=>{if(tab==="access"&&!sessionUser?.permissions.includes("access_template.read"))setTab("general")},[tab,sessionUser]);

  const save=async(setting:Setting)=>{
    setBusy(true); setError(""); setMessage("");
    try {
      const value=JSON.parse(drafts[setting.key]??"{}");
      await apiFetch(`/admin/settings/${encodeURIComponent(setting.key)}`,{method:"PUT",body:JSON.stringify({value})},token);
      setMessage(`${setting.key} updated.`);
      await load();
    } catch(e) {
      setError(friendlyError(e,"Unable to update setting"));
    } finally {
      setBusy(false);
    }
  };

  const setScalarDraft=(key:string,value:number|boolean)=>setDrafts(current=>({...current,[key]:JSON.stringify({value})}));
  const scalar=(key:string,fallback:number|boolean)=>{
    try {
      const parsed=JSON.parse(drafts[key]??"{}");
      return typeof parsed?.value === typeof fallback ? parsed.value : fallback;
    } catch { return fallback; }
  };

  const saveSecurityPolicy=async()=>{
    setBusy(true); setError(""); setMessage("");
    try {
      const available = new Set(settings.map(setting=>setting.key));
      for (const key of SECURITY_SETTING_KEYS) {
        if (!available.has(key)) continue;
        const value=JSON.parse(drafts[key]??"{}");
        await apiFetch(`/admin/settings/${encodeURIComponent(key)}`,{method:"PUT",body:JSON.stringify({value})},token);
      }
      setMessage("Security policy updated.");
      await load();
    } catch(e) {
      setError(friendlyError(e,"Unable to update security policy"));
    } finally {
      setBusy(false);
    }
  };

  useEffect(()=>{if(error){feedback.error(error);setError("")}},[error,feedback]);
  useEffect(()=>{if(message){feedback.success(message);setMessage("")}},[message,feedback]);

  const categories=useMemo(()=>[...new Set(settings.map(item=>item.category).filter(Boolean) as string[])].sort(),[settings]);
  const rows=useMemo(()=>{
    const query=search.trim().toLowerCase();
    const filtered=settings.filter(item=>(!query||`${item.key} ${item.category||""} ${item.description||""}`.toLowerCase().includes(query))&&(!category||item.category===category));
    return sortRows(filtered,sort,(item,key)=>item[key as keyof Setting] as any);
  },[settings,search,category,sort]);

  const hasSecurityPolicy = SECURITY_SETTING_KEYS.some(key=>settings.some(setting=>setting.key===key));
  const settingsTabs = useMemo<TabOption<SettingsTab>[]>(()=>[
    { id: "general", label: "General settings" },
    { id: "polling", label: "Polling pipeline" },
    ...(sessionUser?.permissions.includes("access_template.read") ? [{ id: "access" as const, label: "Access Templates" }] : []),
  ],[sessionUser]);

  return <PageLayout className="page settings-page">
    <div className="page-heading"><div><h2 className="hover-help-title" data-help="Manage system settings and review current administrative status.">Settings</h2></div><Button unstyled className="secondary" onClick={()=>void load()} disabled={busy}>Refresh</Button></div>

    <Tabs<SettingsTab>
      ariaLabel="Settings views"
      value={tab}
      onChange={setTab}
      tabs={settingsTabs}
    />

    {tab === "access" && sessionUser ? <>
      <WebTemplateWizard token={token} permissions={sessionUser.permissions} onCompleted={()=>setAccessRevision(value=>value+1)} />
      <AccessTemplatesPanel token={token} permissions={sessionUser.permissions} currentUserId={sessionUser.id} refreshKey={refreshKey+accessRevision} />
    </> : tab === "polling" ? <PollingPipelineSettings dashboard={dashboard}/> : <>
      {system&&<section className="panel"><h3>System information</h3><div className="stats-grid"><StatCard label="Application" value={system.application_version}/><StatCard label="Database" value={system.database_status}/><StatCard label="Alembic" value={system.alembic_revision||"-"}/><StatCard label="Redis" value={system.redis_status}/><StatCard label="Maintenance" value={system.maintenance_mode?"ACTIVE":"OFF"}/><StatCard label="Last automatic restore point" value={system.last_automatic_restore_point_at?new Date(system.last_automatic_restore_point_at).toLocaleString():"None"}/></div></section>}

      {hasSecurityPolicy && <section className="panel">
        <div className="panel-header"><div><h3 className="hover-help-title" data-help="Controls password requirements and how active sessions are classified.">Security policy</h3><span>Authentication and session controls</span></div>{canManage&&<Button unstyled onClick={()=>void saveSecurityPolicy()} disabled={busy}>Save security policy</Button>}</div>
        <div className="form-grid three security-policy-grid">
          <label>Minimum password length<Input unstyled type="number" min={8} max={200} disabled={!canManage} value={Number(scalar("auth.password.min_length",8))} onChange={event=>setScalarDraft("auth.password.min_length",Number(event.target.value))}/></label>
          <label>Password history<Input unstyled type="number" min={0} max={20} disabled={!canManage} value={Number(scalar("auth.password.history_count",5))} onChange={event=>setScalarDraft("auth.password.history_count",Number(event.target.value))}/><span className="muted">Number of previous passwords that cannot be reused; 0 disables history.</span></label>
          <label>Minimum password difference<Input unstyled type="number" min={0} max={20} disabled={!canManage} value={Number(scalar("auth.password.min_edit_distance",3))} onChange={event=>setScalarDraft("auth.password.min_edit_distance",Number(event.target.value))}/><span className="muted">Minimum number of character changes required when choosing a new password.</span></label>
          <label>Maximum password age (days)<Input unstyled type="number" min={0} max={3650} disabled={!canManage} value={Number(scalar("auth.password.max_age_days",0))} onChange={event=>setScalarDraft("auth.password.max_age_days",Number(event.target.value))}/><span className="muted">Number of days before a password expires; 0 disables expiration.</span></label>
          <label>Expiration warning (days)<Input unstyled type="number" min={0} max={365} disabled={!canManage} value={Number(scalar("auth.password.expiry_warning_days",14))} onChange={event=>setScalarDraft("auth.password.expiry_warning_days",Number(event.target.value))}/></label>
          <label>Online activity window (minutes)<Input unstyled type="number" min={1} max={1440} disabled={!canManage} value={Number(scalar("auth.session_online_window_minutes",5))} onChange={event=>setScalarDraft("auth.session_online_window_minutes",Number(event.target.value))}/><span className="muted">Valid sessions with no recent activity are shown as IDLE after this period.</span></label>
        </div>
        <label className="security-policy-toggle"><Checkbox unstyled disabled={!canManage} checked={Boolean(scalar("auth.password.require_complexity",true))} onChange={event=>setScalarDraft("auth.password.require_complexity",event.target.checked)}/><span><strong>Require password complexity</strong><small>Uppercase, lowercase, number, and symbol.</small></span></label>
        <p className="muted">New users and administrator password resets require a password change at the next login.</p>
      </section>}

      <section className="panel"><div className="panel-header"><div><h3>Operational settings</h3><span>{rows.length} shown</span></div></div><div className="filter-row compact management-filter-row"><Input unstyled value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search settings..."/><Select unstyled value={category} onChange={e=>setCategory(e.target.value)}><option value="">All Categories</option>{categories.map(value=><option key={value}>{value}</option>)}</Select><TableExportButton token={token} tableId="settings" filters={{ search, category, sort_by: sort.key, sort_direction: sort.direction }}/><ClearFiltersButton disabled={!search&&!category} onClick={()=>{setSearch("");setCategory("")}}/></div><DataTable viewportClassName="table-wrap"><thead><tr><SortHeader label="Key" sortKey="key" sort={sort} onSort={key=>setSort(current=>nextSort(current,key))}/><SortHeader label="Category" sortKey="category" sort={sort} onSort={key=>setSort(current=>nextSort(current,key))}/><SortHeader label="Description" sortKey="description" sort={sort} onSort={key=>setSort(current=>nextSort(current,key))}/><th>Value</th><th>Action</th></tr></thead><tbody><PaginatedTableRows items={rows} colSpan={5} itemLabel="settings" renderRow={(s)=><tr key={s.key}><td><strong>{s.key}</strong>{s.is_secret&&<div className="muted">Secret / masked</div>}</td><td>{s.category||"-"}</td><td>{s.description||"-"}</td><td><Textarea unstyled rows={2} value={drafts[s.key]??JSON.stringify(s.value)} disabled={!canManage||s.is_secret} onChange={e=>setDrafts({...drafts,[s.key]:e.target.value})}/></td><td>{canManage&&!s.is_secret&&<Button unstyled className="small" onClick={()=>void save(s)} disabled={busy}>Save</Button>}</td></tr>} /></tbody></DataTable></section>
    </>}
  </PageLayout>;
}
