import { PageLayout } from "../design-system/layouts";
import { useEffect, useMemo, useState } from "react";
import { Button, Input, Select } from "../design-system/primitives";
import { apiFetch } from "../api/client";
import { friendlyError } from "../utils/feedback";
import { useFeedback } from "../components/common/FeedbackSystem";

import type { AuthUser, SortState } from "../types";
import { nextSort, sortRows } from "../utils/sorting";

import { DataTable } from "../design-system/data/DataTable";
import { PaginatedTableRows } from "../design-system/data/Pagination";
import { SortHeader } from "../design-system/data/SortHeader";
import { TableExportButton } from "../design-system/data/TableExport";
import { ClearFiltersButton } from "../design-system/composites/FilterBar";
type Session = {
  id: string;
  user_id: string;
  created_at: string;
  last_seen_at: string | null;
  last_user_activity_at: string | null;
  expires_at: string;
  revoked_at: string | null;
  revoked_reason: string | null;
  is_current: boolean;
  status: string;
  login_ip: string | null;
  last_ip: string | null;
  browser_name: string | null;
  browser_version: string | null;
  os_name: string | null;
  os_version: string | null;
  device_type: string | null;
  user_agent: string | null;
};

function clientText(session:Session) {
  const browser = [session.browser_name, session.browser_version].filter(Boolean).join(" ") || "Unknown browser";
  const os = [session.os_name, session.os_version].filter(Boolean).join(" ") || "Unknown OS";
  return `${browser} / ${os}`;
}

export function AccountPage({ token, user, onSignedOut, refreshKey = 0 }: { token: string; user: AuthUser; onSignedOut: () => void; refreshKey?: number }) {
  const feedback = useFeedback();
  const [sessions, setSessions] = useState<Session[]>([]);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [sessionSearch,setSessionSearch]=useState("");
  const [sessionFilter,setSessionFilter]=useState("");
  const [sessionSort,setSessionSort]=useState<SortState>({key:"created_at",direction:"desc"});

  useEffect(() => { if (error) { feedback.error(error); setError(""); } }, [error, feedback]);
  useEffect(() => { if (message) { feedback.success(message); setMessage(""); } }, [message, feedback]);

  const loadSessions = async () => {
    try { setSessions(await apiFetch<Session[]>("/auth/sessions", {}, token)); setError(""); }
    catch (err) { setError(friendlyError(err, "Unable to load sessions.")); }
  };
  useEffect(() => { void loadSessions(); }, [token, refreshKey]);

  const changePassword = async () => {
    setError(""); setMessage("");
    if (!newPassword || newPassword !== confirmPassword) { setError("New password and confirmation must match."); return; }
    setBusy(true);
    try {
      await apiFetch("/auth/password/change", { method:"POST", body:JSON.stringify({ current_password:currentPassword, new_password:newPassword }) }, token);
      setMessage("Password changed. All sessions were revoked; sign in again with the new password.");
      localStorage.removeItem("fttw_session_token"); sessionStorage.removeItem("fttw_session_token");
      setTimeout(onSignedOut, 600);
    } catch (err) { setError(friendlyError(err, "Unable to change password.")); }
    finally { setBusy(false); }
  };

  const revoke = async (sessionId:string, current:boolean) => {
    setBusy(true); setError(""); setMessage("");
    try {
      await apiFetch(`/auth/sessions/${sessionId}`, { method:"DELETE" }, token);
      if (current) { localStorage.removeItem("fttw_session_token"); sessionStorage.removeItem("fttw_session_token"); onSignedOut(); return; }
      setMessage("Session revoked."); await loadSessions();
    } catch (err) { setError(friendlyError(err, "Unable to revoke session.")); }
    finally { setBusy(false); }
  };

  const visibleSessions=useMemo(()=>{const query=sessionSearch.trim().toLowerCase();const filtered=sessions.filter(session=>(!query||`${session.id} ${session.created_at} ${session.expires_at} ${session.login_ip||""} ${session.last_ip||""} ${session.browser_name||""} ${session.os_name||""}`.toLowerCase().includes(query))&&(!sessionFilter||(sessionFilter==="CURRENT"?session.is_current:!session.is_current)));return sortRows(filtered,sessionSort,(session,key)=>session[key as keyof Session] as any)},[sessions,sessionSearch,sessionFilter,sessionSort]);

  const revokeOthers = async () => {
    setBusy(true); setError(""); setMessage("");
    try { const result=await apiFetch<{revoked_count:number}>("/auth/sessions/revoke-others",{method:"POST"},token); setMessage(`${result.revoked_count} other session(s) revoked.`); await loadSessions(); }
    catch (err) { setError(friendlyError(err,"Unable to revoke sessions.")); }
    finally { setBusy(false); }
  };

  return <PageLayout className="page">
    <div className="page-heading"><div><h2 className="hover-help-title" data-help="Change your password and manage active sessions.">My Account</h2></div></div>
    {user.password_expiry_warning && user.password_expires_in_days !== null && <div className="inline-notice">Your password expires in {user.password_expires_in_days} day(s). Change it before expiration to avoid a mandatory password-change gate.</div>}
    <section className="panel"><h3>Account</h3><div className="form-grid two"><label>Username<Input unstyled value={user.username} disabled /></label><label>Display name<Input unstyled value={user.display_name || ""} disabled /></label></div><p className="muted">Roles: {user.roles.join(", ") || "None"}</p></section>
    <section className="panel"><h3>Change password</h3><p className="muted">Your new password must meet the current security requirements.</p><div className="form-grid three"><label>Current password<Input unstyled type="password" autoComplete="current-password" value={currentPassword} onChange={e=>setCurrentPassword(e.target.value)} /></label><label>New password<Input unstyled type="password" autoComplete="new-password" value={newPassword} onChange={e=>setNewPassword(e.target.value)} /></label><label>Confirm new password<Input unstyled type="password" autoComplete="new-password" value={confirmPassword} onChange={e=>setConfirmPassword(e.target.value)} /></label></div><Button unstyled onClick={()=>void changePassword()} disabled={busy||!currentPassword||!newPassword||!confirmPassword}>Change password</Button></section>
    <section className="panel"><div className="page-heading"><div><h3 className="hover-help-title" data-help="Revoking the current session signs you out immediately.">Active sessions</h3></div><Button unstyled className="secondary" onClick={()=>void revokeOthers()} disabled={busy}>Revoke other sessions</Button></div><div className="filter-row compact management-filter-row"><Input unstyled value={sessionSearch} onChange={e=>setSessionSearch(e.target.value)} placeholder="Search session, IP, browser, OS..."/><Select unstyled value={sessionFilter} onChange={e=>setSessionFilter(e.target.value)}><option value="">All Sessions</option><option value="CURRENT">Current Session</option><option value="OTHER">Other Sessions</option></Select><TableExportButton token={token} tableId="account_sessions" filters={{ search: sessionSearch, current: sessionFilter === "CURRENT" ? "true" : sessionFilter === "OTHER" ? "false" : "", sort_by: sessionSort.key, sort_direction: sessionSort.direction }}/><ClearFiltersButton disabled={!sessionSearch&&!sessionFilter} onClick={()=>{setSessionSearch("");setSessionFilter("")}}/></div><DataTable viewportClassName="table-wrap"><thead><tr><SortHeader label="Login" sortKey="created_at" sort={sessionSort} onSort={key=>setSessionSort(current=>nextSort(current,key))}/><SortHeader label="Last activity" sortKey="last_user_activity_at" sort={sessionSort} onSort={key=>setSessionSort(current=>nextSort(current,key))}/><th>Status</th><th>IP</th><th>Client</th><th>Device</th><SortHeader label="Expires" sortKey="expires_at" sort={sessionSort} onSort={key=>setSessionSort(current=>nextSort(current,key))}/><SortHeader label="Current" sortKey="is_current" sort={sessionSort} onSort={key=>setSessionSort(current=>nextSort(current,key))}/><th>Action</th></tr></thead><tbody><PaginatedTableRows items={visibleSessions} colSpan={9} resetKey={`${sessionSearch}|${sessionFilter}`} itemLabel="sessions" renderRow={(session)=><tr key={session.id}><td>{new Date(session.created_at).toLocaleString()}</td><td>{session.last_user_activity_at?new Date(session.last_user_activity_at).toLocaleString():"-"}</td><td><span className={`badge ${session.status==="ACTIVE"?"badge-online":session.status==="IDLE"?"badge-maintenance":"badge-unknown"}`}>{session.status}</span></td><td>{session.last_ip||session.login_ip||"-"}</td><td>{clientText(session)}</td><td>{session.device_type||"-"}</td><td>{new Date(session.expires_at).toLocaleString()}</td><td>{session.is_current?"YES":""}</td><td><Button unstyled className="small danger" disabled={busy} onClick={()=>void revoke(session.id,session.is_current)}>Revoke</Button></td></tr>} />{!visibleSessions.length&&<tr><td colSpan={9}>No sessions match the current filters.</td></tr>}</tbody></DataTable></section>
  </PageLayout>;
}
