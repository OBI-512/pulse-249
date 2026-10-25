import { PageLayout } from "../design-system/layouts";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiFetch } from "../api/client";
import { useDialog } from "../components/common/DialogSystem";
import { useFeedback } from "../components/common/FeedbackSystem";

import { useDebouncedValue } from "../hooks/useDebouncedValue";
import type { AlarmHistoryEntry, AlarmRow, AlarmSummary, OperationalEventEntry, PageResult, SortState } from "../types";
import { friendlyError } from "../utils/feedback";
import { nextSort } from "../utils/sorting";
import { Button, Input, Select } from "../design-system/primitives";
import { DataTable } from "../design-system/data/DataTable";
import { ServerPagination } from "../design-system/data/Pagination";
import { SortHeader } from "../design-system/data/SortHeader";
import { TableExportButton } from "../design-system/data/TableExport";
import { ClearFiltersButton } from "../design-system/composites/FilterBar";

type StateFilter = "ACTIVE" | "CLEARED" | "ALL";
type AckFilter = "ALL" | "ACKNOWLEDGED" | "UNACKNOWLEDGED";
type OwnerFilter = "ALL" | "OWNED" | "UNOWNED";

const EMPTY_SUMMARY: AlarmSummary = { active_total:0, unacknowledged:0, info:0, warning:0, minor:0, major:0, critical:0 };

function when(value: string | null | undefined) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function label(value: string) {
  return value.replaceAll("_", " ").toLowerCase().replace(/\b\w/g, char => char.toUpperCase());
}

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`alarm-severity severity-${severity.toLowerCase()}`}>{severity}</span>;
}

function StateBadge({ state }: { state: string }) {
  return <span className={`alarm-state state-${state.toLowerCase()}`}>{state}</span>;
}

export function AlarmPage({
  token,
  currentUserId,
  permissions,
  refreshKey = 0,
}: {
  token: string;
  currentUserId: string;
  permissions: string[];
  refreshKey?: number;
}) {
  const dialog = useDialog();
  const feedback = useFeedback();
  const [summary, setSummary] = useState<AlarmSummary>(EMPTY_SUMMARY);
  const [rows, setRows] = useState<AlarmRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [sort, setSort] = useState<SortState>({ key:"last_raised_at", direction:"desc" });
  const [state, setState] = useState<StateFilter>("ALL");
  const [severity, setSeverity] = useState("");
  const [ack, setAck] = useState<AckFilter>("ALL");
  const [owner, setOwner] = useState<OwnerFilter>("ALL");
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebouncedValue(search, 300);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<AlarmRow | null>(null);
  const [history, setHistory] = useState<AlarmHistoryEntry[]>([]);
  const [events, setEvents] = useState<OperationalEventEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(false);
  const requestRef = useRef(0);

  const canAck = permissions.includes("alarm.acknowledge");
  const canAssign = permissions.includes("alarm.assign");
  const canClear = permissions.includes("alarm.clear");

  const query = useMemo(() => {
    const params = new URLSearchParams({ state, page:String(page), page_size:String(pageSize), sort_by:sort.key, sort_direction:sort.direction });
    if (severity) params.set("severity", severity);
    if (ack === "ACKNOWLEDGED") params.set("acknowledged", "true");
    if (ack === "UNACKNOWLEDGED") params.set("acknowledged", "false");
    if (owner !== "ALL") params.set("owner", owner);
    if (debouncedSearch.trim()) params.set("search", debouncedSearch.trim());
    return params.toString();
  }, [state, severity, ack, owner, page, pageSize, debouncedSearch, sort]);

  const loadList = useCallback(async () => {
    const requestId = ++requestRef.current;
    setLoading(true);
    try {
      const [summaryData, pageData] = await Promise.all([
        apiFetch<AlarmSummary>("/alarms/summary", {}, token),
        apiFetch<PageResult<AlarmRow>>(`/alarms/page?${query}`, {}, token),
      ]);
      if (requestRef.current !== requestId) return;
      setSummary(summaryData);
      setRows(pageData.items);
      setTotal(pageData.total);
      if (selectedId && !pageData.items.some(row => row.id === selectedId) && state === "ACTIVE") {
        setSelectedId(null);
        setSelected(null);
        setHistory([]);
        setEvents([]);
      }
    } catch (error) {
      if (requestRef.current === requestId) feedback.error(friendlyError(error, "Unable to load alarms"));
    } finally {
      if (requestRef.current === requestId) setLoading(false);
    }
  }, [token, query, selectedId, state, feedback]);

  const loadDetail = useCallback(async (alarmId: string) => {
    try {
      const [alarm, historyRows, eventRows] = await Promise.all([
        apiFetch<AlarmRow>(`/alarms/${alarmId}`, {}, token),
        apiFetch<AlarmHistoryEntry[]>(`/alarms/${alarmId}/history?limit=100`, {}, token),
        apiFetch<OperationalEventEntry[]>(`/alarms/${alarmId}/events?limit=100`, {}, token),
      ]);
      setSelected(alarm);
      setHistory(historyRows);
      setEvents(eventRows);
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to load alarm details"));
    }
  }, [token, feedback]);

  useEffect(() => { setPage(1); }, [state, severity, ack, owner, debouncedSearch]);
  useEffect(() => { void loadList(); }, [loadList, refreshKey]);
  useEffect(() => {
    const timer = window.setInterval(() => void loadList(), 10000);
    return () => window.clearInterval(timer);
  }, [loadList]);
  useEffect(() => { if (selectedId) void loadDetail(selectedId); }, [selectedId, loadDetail]);

  const refresh = async (alarmId?: string) => {
    await loadList();
    if (alarmId) await loadDetail(alarmId);
  };

  const mutate = async (path: string, method: "POST" | "PATCH", body: object, success: string) => {
    if (!selected) return;
    setBusy(true);
    try {
      await apiFetch<AlarmRow>(path, { method, body:JSON.stringify(body) }, token);
      feedback.success(success);
      await refresh(selected.id);
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to update alarm"));
    } finally {
      setBusy(false);
    }
  };

  const acknowledge = () => mutate(`/alarms/${selected!.id}/acknowledge`, "POST", { note:null }, "Alarm acknowledged.");
  const assignToMe = () => mutate(`/alarms/${selected!.id}/owner`, "PATCH", { owner_user_id:currentUserId, note:null }, "Alarm assigned to you.");
  const unassign = () => mutate(`/alarms/${selected!.id}/owner`, "PATCH", { owner_user_id:null, note:null }, "Alarm unassigned.");
  const clear = async () => {
    if (!selected) return;
    if (!await dialog.confirm({ title:"Clear alarm", message:"Clear this alarm? If the device remains offline, the alarm will reopen on a later availability observation.", confirmLabel:"Clear alarm", tone:"danger" })) return;
    await mutate(`/alarms/${selected.id}/clear`, "POST", { note:null }, "Alarm cleared.");
  };

  return <PageLayout className="page alarm-page">
    <div className="page-heading alarm-heading">
      <div><h2 className="hover-help-title" data-help="Availability alarms, acknowledgement, ownership, and lifecycle history.">Alarms</h2></div>
      <Button unstyled className="secondary" disabled={loading} onClick={() => void loadList()}>{loading ? "Refreshing…" : "Refresh"}</Button>
    </div>

    <section className="alarm-summary-grid" aria-label="Alarm summary">
      <Button unstyled className="alarm-summary-card summary-active" onClick={() => { setState("ACTIVE"); setSeverity(""); }}><span>Active</span><strong>{summary.active_total}</strong><small>{summary.unacknowledged} unacknowledged</small></Button>
      <Button unstyled className="alarm-summary-card severity-critical" onClick={() => { setState("ACTIVE"); setSeverity("CRITICAL"); }}><span>Critical</span><strong>{summary.critical}</strong></Button>
      <Button unstyled className="alarm-summary-card severity-major" onClick={() => { setState("ACTIVE"); setSeverity("MAJOR"); }}><span>Major</span><strong>{summary.major}</strong></Button>
      <Button unstyled className="alarm-summary-card severity-minor" onClick={() => { setState("ACTIVE"); setSeverity("MINOR"); }}><span>Minor</span><strong>{summary.minor}</strong></Button>
      <Button unstyled className="alarm-summary-card severity-warning" onClick={() => { setState("ACTIVE"); setSeverity("WARNING"); }}><span>Warning</span><strong>{summary.warning}</strong></Button>
    </section>

    <section className="panel alarm-filter-panel">
      <div className="alarm-filter-grid">
        <label>State<Select unstyled value={state} onChange={event => setState(event.target.value as StateFilter)}><option value="ALL">All</option><option value="ACTIVE">Active</option><option value="CLEARED">Cleared</option></Select></label>
        <label>Severity<Select unstyled value={severity} onChange={event => setSeverity(event.target.value)}><option value="">All severities</option><option>CRITICAL</option><option>MAJOR</option><option>MINOR</option><option>WARNING</option><option>INFO</option></Select></label>
        <label>Acknowledgement<Select unstyled value={ack} onChange={event => setAck(event.target.value as AckFilter)}><option value="ALL">All</option><option value="UNACKNOWLEDGED">Unacknowledged</option><option value="ACKNOWLEDGED">Acknowledged</option></Select></label>
        <label>Ownership<Select unstyled value={owner} onChange={event => setOwner(event.target.value as OwnerFilter)}><option value="ALL">All</option><option value="UNOWNED">Unowned</option><option value="OWNED">Owned</option></Select></label>
        <label className="alarm-search">Search<Input unstyled value={search} onChange={event => setSearch(event.target.value)} placeholder="Device, alarm, correlation key…" /></label>
      </div>
      <div className="filter-clear-actions"><TableExportButton token={token} tableId="alarms" filters={{ state, severity, acknowledged: ack === "ACKNOWLEDGED" ? "true" : ack === "UNACKNOWLEDGED" ? "false" : "", owner: owner === "ALL" ? "" : owner, search: debouncedSearch, sort_by: sort.key, sort_direction: sort.direction }}/><ClearFiltersButton disabled={state==="ALL"&&!severity&&ack==="ALL"&&owner==="ALL"&&!search} onClick={()=>{setState("ALL");setSeverity("");setAck("ALL");setOwner("ALL");setSearch("");setPage(1)}}/></div>
    </section>

    <div className="alarm-workspace-grid">
      <section className="panel alarm-list-panel">
        <div className="panel-heading"><div><h3>Alarm queue</h3><p>{total.toLocaleString()} matching alarms</p></div></div>
        <DataTable viewportClassName="table-wrap alarm-table-wrap" className="alarm-table"><thead><tr><SortHeader label="Severity" sortKey="severity" sort={sort} onSort={key=>{setSort(current=>nextSort(current,key));setPage(1)}}/><SortHeader label="Device" sortKey="device" sort={sort} onSort={key=>{setSort(current=>nextSort(current,key));setPage(1)}}/><SortHeader label="State" sortKey="state" sort={sort} onSort={key=>{setSort(current=>nextSort(current,key));setPage(1)}}/><SortHeader label="Ack" sortKey="acknowledged" sort={sort} onSort={key=>{setSort(current=>nextSort(current,key));setPage(1)}}/><SortHeader label="Owner" sortKey="owner" sort={sort} onSort={key=>{setSort(current=>nextSort(current,key));setPage(1)}}/><SortHeader label="Occurrences" sortKey="occurrence_count" sort={sort} onSort={key=>{setSort(current=>nextSort(current,key));setPage(1)}}/><SortHeader label="Last raised" sortKey="last_raised_at" sort={sort} onSort={key=>{setSort(current=>nextSort(current,key));setPage(1)}}/></tr></thead><tbody>
          {rows.map(row => <tr key={row.id} className={selectedId === row.id ? "selected-row" : ""} onClick={() => setSelectedId(row.id)} tabIndex={0} onKeyDown={event => { if (event.key === "Enter") setSelectedId(row.id); }}>
            <td><SeverityBadge severity={row.severity} /></td><td><strong>{row.device_display_name}</strong><small>{row.management_ip || "No management IP"}</small></td><td><StateBadge state={row.state} /></td><td>{row.acknowledged_at ? <span className="alarm-ack yes">Acknowledged</span> : <span className="alarm-ack no">Unacknowledged</span>}</td><td>{row.owner_display_name || "Unowned"}</td><td>{row.occurrence_count}</td><td>{when(row.last_raised_at)}</td>
          </tr>)}
          {!rows.length && <tr><td colSpan={7} className="empty-cell">No alarms match the current filters.</td></tr>}
        </tbody></DataTable>
        <ServerPagination page={page} pageSize={pageSize} total={total} onPage={setPage} onPageSize={size => { setPageSize(size); setPage(1); }} itemLabel="alarms" />
      </section>

      <section className="panel alarm-detail-panel">
        {!selected ? <div className="alarm-empty-detail"><strong>Select an alarm</strong><span>Choose an alarm from the queue to inspect workflow and operational events.</span></div> : <>
          <div className="alarm-detail-head"><div><div className="actions"><SeverityBadge severity={selected.severity} /><StateBadge state={selected.state} /></div><h3>{selected.device_display_name}</h3><p>{selected.summary}</p></div></div>
          <dl className="alarm-detail-grid"><div><dt>Availability</dt><dd>{selected.availability_status || "—"}</dd></div><div><dt>Management IP</dt><dd>{selected.management_ip || "—"}</dd></div><div><dt>Owner</dt><dd>{selected.owner_display_name || "Unowned"}</dd></div><div><dt>Acknowledged by</dt><dd>{selected.acknowledged_by_display_name || "—"}</dd></div><div><dt>Occurrences</dt><dd>{selected.occurrence_count}</dd></div><div><dt>First raised</dt><dd>{when(selected.first_raised_at)}</dd></div><div><dt>Last raised</dt><dd>{when(selected.last_raised_at)}</dd></div><div><dt>Last cleared</dt><dd>{when(selected.last_cleared_at)}</dd></div></dl>
          {selected.state === "ACTIVE" && (canAck || canAssign || canClear) && <div className="actions alarm-actions">
            {canAck && !selected.acknowledged_at && <Button unstyled disabled={busy} onClick={() => void acknowledge()}>Acknowledge</Button>}
            {canAssign && selected.owner_user_id !== currentUserId && <Button unstyled className="secondary" disabled={busy} onClick={() => void assignToMe()}>Assign to me</Button>}
            {canAssign && selected.owner_user_id === currentUserId && <Button unstyled className="secondary" disabled={busy} onClick={() => void unassign()}>Unassign</Button>}
            {canClear && <Button unstyled className="danger" disabled={busy} onClick={() => void clear()}>Clear alarm</Button>}
          </div>}

          <div className="alarm-timeline-section"><h4>Workflow history</h4><div className="alarm-timeline">
            {history.map(item => <div className="alarm-timeline-item" key={item.id}><span className="timeline-dot" /><div><strong>{label(item.action)}</strong><span>{when(item.occurred_at)}{item.actor_display_name ? ` · ${item.actor_display_name}` : " · System"}</span>{item.note && <p>{item.note}</p>}</div></div>)}
            {!history.length && <div className="empty-cell">No workflow history.</div>}
          </div></div>

          <div className="alarm-timeline-section"><h4>Operational events</h4><div className="alarm-timeline">
            {events.map(item => <div className="alarm-timeline-item" key={item.id}><span className={`timeline-dot event-${item.severity.toLowerCase()}`} /><div><strong>{label(item.event_type)}</strong><span>{when(item.occurred_at)} · {item.severity}</span><p>{item.summary}</p></div></div>)}
            {!events.length && <div className="empty-cell">No correlated operational events.</div>}
          </div></div>
        </>}
      </section>
    </div>
  </PageLayout>;
}
