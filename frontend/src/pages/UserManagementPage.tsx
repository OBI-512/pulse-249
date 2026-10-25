import { PageLayout } from "../design-system/layouts";
import { Fragment, useCallback, useEffect, useMemo, useRef, useState, type UIEvent } from "react";
import { apiFetch } from "../api/client";
import { friendlyError } from "../utils/feedback";
import { useFeedback } from "../components/common/FeedbackSystem";
import { ModalShell, useDialog } from "../components/common/DialogSystem";

import { SearchableCombobox, type ComboboxPage, type ComboboxOption } from "../design-system/composites/SearchableSelect";
import type { SortState } from "../types";
import { nextSort, sortRows } from "../utils/sorting";
import { Tabs } from "../design-system/composites/Tabs";

import { DataTable } from "../design-system/data/DataTable";
import { PaginatedTableRows, ServerPaginationRow } from "../design-system/data/Pagination";
import { SortHeader } from "../design-system/data/SortHeader";
import { TableExportButton } from "../design-system/data/TableExport";
import { ClearFiltersButton } from "../design-system/composites/FilterBar";
import { MultiSelectDropdown, type SelectOption } from "../design-system/composites/MultiSelect";
import { Button, Checkbox, Input, Select } from "../design-system/primitives";
type UserRow = {
  id: string;
  username: string;
  display_name: string | null;
  is_active: boolean;
  must_change_password: boolean;
  password_change_reason: string | null;
  password_changed_at: string | null;
  roles: string[];
  permissions: string[];
  direct_permissions: string[];
};

type SessionRow = {
  id:string;
  user_id:string;
  created_at:string;
  last_seen_at:string|null;
  last_user_activity_at:string|null;
  expires_at:string;
  revoked_at:string|null;
  revoked_reason:string|null;
  status:string;
  login_ip:string|null;
  last_ip:string|null;
  browser_name:string|null;
  browser_version:string|null;
  os_name:string|null;
  os_version:string|null;
  device_type:string|null;
  user_agent:string|null;
};

type OnlineSessionRow = SessionRow & {
  username:string;
  display_name:string|null;
  roles:string[];
  duration_seconds:number;
  idle_seconds:number;
  time_remaining_seconds:number;
};

type SecurityOption = { code:string; name:string; description:string|null; requires?:string[] };
type SecurityOptions = { roles:SecurityOption[]; permissions:SecurityOption[] };
type ResourceScopeType = "GLOBAL"|"NETWORK"|"CITY"|"LOCATION"|"SECTOR"|"GROUP";
type ResourceScopeRow = { id:string; scope_type:ResourceScopeType; resource_id:string|null; label:string; context:string|null; assigned_by_user_id:string|null; created_at:string };
type UserResourceScopes = { user_id:string; username:string; direct_scopes:ResourceScopeRow[]; effective_summary:Record<string,number|boolean> };
type ResourceScopeOption = { scope_type:ResourceScopeType; resource_id:string|null; label:string; context:string|null };
type ScopeDraft = { scope_type:ResourceScopeType; resource_id:string|null; label:string; context?:string|null };
type UserPage = { items:UserRow[]; total:number; page:number; page_size:number };
type OnlineSessionPage = { items:OnlineSessionRow[]; total:number; page:number; page_size:number };
type Editor = { kind:"display"|"role"|"password"; user:UserRow } | null;
type Tab = "users" | "online" | "permissions";

function formatDuration(totalSeconds:number) {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days) return `${days}d ${hours}h ${minutes}m`;
  if (hours) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function sessionBadge(status:string) {
  const normalized = status.toLowerCase();
  const tone = normalized === "active" ? "badge-online" : normalized === "idle" ? "badge-maintenance" : normalized === "revoked" ? "badge-offline" : "badge-unknown";
  return <span className={`badge ${tone}`}>{status}</span>;
}

function clientLabel(session:SessionRow) {
  const browser = [session.browser_name, session.browser_version].filter(Boolean).join(" ") || "Unknown browser";
  const os = [session.os_name, session.os_version].filter(Boolean).join(" ") || "Unknown OS";
  return { browser, os };
}

type FilterOption = { value:string; label:string; description?:string };

function SearchableFilterDropdown({
  value,
  options,
  onChange,
  placeholder,
  searchPlaceholder,
}: {
  value:string;
  options:FilterOption[];
  onChange:(value:string)=>void;
  placeholder:string;
  searchPlaceholder:string;
}) {
  const [open,setOpen]=useState(false);
  const [search,setSearch]=useState("");
  const [visibleLimit,setVisibleLimit]=useState(20);
  const root=useRef<HTMLDivElement|null>(null);
  const selected=options.find((option)=>option.value===value);
  const filtered=useMemo(()=>{
    const query=search.trim().toLowerCase();
    if (!query) return options;
    return options.filter((option)=>`${option.label} ${option.value} ${option.description || ""}`.toLowerCase().includes(query));
  },[options,search]);
  const visible=filtered.slice(0,visibleLimit);

  useEffect(()=>{
    if (!open) return;
    const close=(event:MouseEvent)=>{ if (!root.current?.contains(event.target as Node)) setOpen(false); };
    document.addEventListener("mousedown",close);
    return ()=>document.removeEventListener("mousedown",close);
  },[open]);
  useEffect(()=>{ setVisibleLimit(20); },[search,open]);

  const handleOptionsScroll=(event:UIEvent<HTMLDivElement>)=>{
    const target=event.currentTarget;
    if (target.scrollTop + target.clientHeight >= target.scrollHeight - 24) {
      setVisibleLimit((current)=>Math.min(current + 20,filtered.length));
    }
  };

  return <div className="permission-filter-dropdown" ref={root}>
    <Button unstyled type="button" className="permission-filter-trigger" aria-expanded={open} onClick={()=>setOpen((current)=>!current)}>
      <span>{selected?.label || placeholder}</span><span aria-hidden="true">▾</span>
    </Button>
    {open && <div className="permission-filter-menu">
      <Input unstyled value={search} onChange={(event)=>setSearch(event.target.value)} placeholder={searchPlaceholder} autoFocus />
      <div className="permission-filter-options" onScroll={handleOptionsScroll}>
        {visible.map((option)=><Button unstyled type="button" key={`${option.value || "all"}-${option.label}`} className={value===option.value ? "selected" : ""} onClick={()=>{onChange(option.value);setOpen(false);setSearch("");}}>
          <span>{option.label}</span>{option.description && <small>{option.description}</small>}
        </Button>)}
        {!visible.length && <div className="permission-filter-empty">No matching options.</div>}
        {visible.length < filtered.length && <div className="permission-filter-more">Scroll to load more…</div>}
      </div>
    </div>}
  </div>;
}

export function UserManagementPage({ token, busy = false, permissions, refreshKey = 0 }: { token:string; busy?:boolean; permissions:string[]; refreshKey?:number }) {
  const feedback = useFeedback();
  const dialog = useDialog();
  const [tab,setTab]=useState<Tab>("users");
  const [permissionUser,setPermissionUser]=useState<UserRow|null>(null);
  const [permissionSearch,setPermissionSearch]=useState("");
  const [permissionCategory,setPermissionCategory]=useState("");
  const [permissionGrantFilter,setPermissionGrantFilter]=useState("");
  const [resourceScopes,setResourceScopes]=useState<UserResourceScopes|null>(null);
  const [editScopes,setEditScopes]=useState<ScopeDraft[]>([]);
  const [scopeType,setScopeType]=useState<ResourceScopeType>("NETWORK");
  const [scopeOption,setScopeOption]=useState<ResourceScopeOption|null>(null);
  const [users, setUsers] = useState<UserRow[]>([]);
  const [options, setOptions] = useState<SecurityOptions>({ roles:[], permissions:[] });
  const [form, setForm] = useState({ username:"", display_name:"", password:"", role_code:"restricted", permission_codes:[] as string[] });
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [sessions, setSessions] = useState<Record<string,SessionRow[]>>({});
  const [editor, setEditor] = useState<Editor>(null);
  const [editValue, setEditValue] = useState("");
  const [editPermissions, setEditPermissions] = useState<string[]>([]);
  const [passwordPair, setPasswordPair] = useState({ first:"", second:"" });
  const [saving, setSaving] = useState(false);
  const [userSearch,setUserSearch]=useState("");
  const [userStatus,setUserStatus]=useState("");
  const [userRole,setUserRole]=useState("");
  const [userSort,setUserSort]=useState<SortState>({key:"username",direction:"asc"});
  const [userPage,setUserPage]=useState(1);
  const [userPageSize,setUserPageSize]=useState(50);
  const [userTotal,setUserTotal]=useState(0);
  const [sessionStatus,setSessionStatus]=useState("");
  const [sessionSort,setSessionSort]=useState<SortState>({key:"created_at",direction:"desc"});

  const [onlineSessions,setOnlineSessions]=useState<OnlineSessionRow[]>([]);
  const [onlineTotal,setOnlineTotal]=useState(0);
  const [onlinePage,setOnlinePage]=useState(1);
  const [onlinePageSize,setOnlinePageSize]=useState(50);
  const [onlineSearch,setOnlineSearch]=useState("");
  const [onlineStatus,setOnlineStatus]=useState("");
  const [onlineBrowser,setOnlineBrowser]=useState("");
  const [onlineOs,setOnlineOs]=useState("");
  const [onlineDevice,setOnlineDevice]=useState("");
  const [onlineSort,setOnlineSort]=useState<SortState>({key:"last_user_activity_at",direction:"desc"});

  useEffect(() => { if (error) { feedback.error(error); setError(""); } }, [error, feedback]);
  useEffect(() => { if (message) { feedback.success(message); setMessage(""); } }, [message, feedback]);

  const can = (permission:string) => permissions.includes(permission);
  const canReadScopes = can("user.scopes.read") || can("user.scopes.manage");
  const canManageScopes = can("user.scopes.manage");
  const canOpenAccessWorkspace = can("user.permissions.manage") || canReadScopes;
  const canReadSessions = can("user.sessions.read") || can("user.sessions.manage");
  const canManageSessions = can("user.sessions.manage");
  const permissionOptions = useMemo<SelectOption[]>(() => options.permissions.map((item) => ({
    value:item.code,
    label:item.name,
    description:[item.description, item.requires?.length ? `Requires: ${item.requires.join(", ")} (added automatically when not supplied by the role)` : ""].filter(Boolean).join(" · "),
  })), [options.permissions]);

  const permissionByCode = useMemo(() => new Map(options.permissions.map((item) => [item.code, item])), [options.permissions]);
  const roleDerivedPermissions = useMemo(() => {
    if (!permissionUser) return new Set<string>();
    const direct = new Set(permissionUser.direct_permissions);
    return new Set(permissionUser.permissions.filter((code) => !direct.has(code)));
  }, [permissionUser]);
  const requiredBySelection = useMemo(() => {
    const required = new Map<string,Set<string>>();
    const visit = (code:string, dependent:string, seen:Set<string>) => {
      if (seen.has(code)) return;
      seen.add(code);
      const option = permissionByCode.get(code);
      for (const prerequisite of option?.requires || []) {
        if (!roleDerivedPermissions.has(prerequisite)) {
          const dependents = required.get(prerequisite) || new Set<string>();
          dependents.add(dependent);
          required.set(prerequisite, dependents);
        }
        visit(prerequisite, dependent, seen);
      }
    };
    for (const code of editPermissions) visit(code, code, new Set<string>());
    return required;
  }, [editPermissions, permissionByCode, roleDerivedPermissions]);
  const permissionCategories = useMemo(() => Array.from(new Set(options.permissions.map((item) => item.code.split(".")[0]))).sort(), [options.permissions]);
  const permissionCategoryOptions = useMemo<FilterOption[]>(() => [
    { value:"", label:"All permission groups" },
    ...permissionCategories.map((category) => ({ value:category, label:category.replaceAll("_", " ") })),
  ], [permissionCategories]);
  const permissionGrantOptions = useMemo<FilterOption[]>(() => [
    { value:"", label:"All permissions" },
    { value:"granted", label:"Show granted only", description:"Role, direct, or automatically required" },
    { value:"direct", label:"Direct grants only" },
    { value:"role", label:"Role-derived only" },
    { value:"required", label:"Required prerequisites only" },
    { value:"not_granted", label:"Not granted" },
  ], []);
  const visiblePermissionOptions = useMemo(() => options.permissions.filter((item) => {
    const category = item.code.split(".")[0];
    if (permissionCategory && category !== permissionCategory) return false;
    const roleDerived = roleDerivedPermissions.has(item.code);
    const direct = editPermissions.includes(item.code);
    const required = Boolean(requiredBySelection.get(item.code)?.size);
    const granted = roleDerived || direct || required;
    if (permissionGrantFilter === "granted" && !granted) return false;
    if (permissionGrantFilter === "direct" && !direct) return false;
    if (permissionGrantFilter === "role" && !roleDerived) return false;
    if (permissionGrantFilter === "required" && !required) return false;
    if (permissionGrantFilter === "not_granted" && granted) return false;
    const query = permissionSearch.trim().toLowerCase();
    if (!query) return true;
    return [item.code,item.name,item.description || "",...(item.requires || [])].some((value) => value.toLowerCase().includes(query));
  }), [options.permissions,permissionCategory,permissionGrantFilter,permissionSearch,roleDerivedPermissions,editPermissions,requiredBySelection]);
  const groupedPermissionOptions = useMemo(() => {
    const groups = new Map<string,SecurityOption[]>();
    for (const item of visiblePermissionOptions) {
      const category = item.code.split(".")[0];
      const rows = groups.get(category) || [];
      rows.push(item);
      groups.set(category, rows);
    }
    return Array.from(groups.entries()).sort(([a],[b]) => a.localeCompare(b));
  }, [visiblePermissionOptions]);

  const loadUsers = async () => {
    try {
      const params = new URLSearchParams({ page:String(userPage), page_size:String(userPageSize), sort_by:userSort.key === "role" ? "role" : userSort.key, sort_dir:userSort.direction });
      if (userSearch.trim()) params.set("search", userSearch.trim());
      if (userStatus) params.set("status", userStatus);
      if (userRole) params.set("role", userRole);
      const result = await apiFetch<UserPage>(`/admin/users/page?${params.toString()}`, {}, token);
      setUsers(result.items); setUserTotal(result.total); setError("");
    } catch (e) { setError(friendlyError(e, "Unable to load users")); }
  };

  const loadOptions = async () => {
    try {
      const securityOptions = await apiFetch<SecurityOptions>("/admin/security-options", {}, token);
      setOptions(securityOptions);
      setForm((current) => ({
        ...current,
        role_code: securityOptions.roles.some((role) => role.code === current.role_code)
          ? current.role_code
          : (securityOptions.roles.find((role) => role.code === "restricted")?.code || securityOptions.roles[0]?.code || ""),
      }));
    } catch (e) { setError(friendlyError(e, "Unable to load security options")); }
  };

  const loadOnlineSessions = async () => {
    if (!canReadSessions) return;
    try {
      const params = new URLSearchParams({ page:String(onlinePage), page_size:String(onlinePageSize), sort_by:onlineSort.key, sort_dir:onlineSort.direction });
      if (onlineSearch.trim()) params.set("search", onlineSearch.trim());
      if (onlineStatus) params.set("status", onlineStatus);
      if (onlineBrowser.trim()) params.set("browser", onlineBrowser.trim());
      if (onlineOs.trim()) params.set("operating_system", onlineOs.trim());
      if (onlineDevice) params.set("device_type", onlineDevice);
      const result = await apiFetch<OnlineSessionPage>(`/admin/sessions/online?${params.toString()}`, {}, token);
      setOnlineSessions(result.items); setOnlineTotal(result.total); setError("");
    } catch (e) { setError(friendlyError(e, "Unable to load online sessions")); }
  };

  const load = async () => {
    if (tab === "online") await loadOnlineSessions();
    else await Promise.all([loadUsers(), loadOptions()]);
  };

  useEffect(() => { void loadOptions(); }, [token,refreshKey]);
  useEffect(() => {
    if (tab !== "users") return;
    const handle = window.setTimeout(() => { void loadUsers(); }, 280);
    return () => window.clearTimeout(handle);
  }, [tab,userSearch,userStatus,userRole,userSort.key,userSort.direction,userPage,userPageSize,token,refreshKey]);
  useEffect(() => {
    if (tab !== "online" || !canReadSessions) return;
    const handle = window.setTimeout(() => { void loadOnlineSessions(); }, 280);
    return () => window.clearTimeout(handle);
  }, [tab,onlineSearch,onlineStatus,onlineBrowser,onlineOs,onlineDevice,onlineSort.key,onlineSort.direction,onlinePage,onlinePageSize,token,canReadSessions,refreshKey]);

  const create = async () => {
    if (!form.role_code) { setError("Select one role for the new user."); return; }
    setSaving(true); setError(""); setMessage("");
    try {
      await apiFetch("/admin/users", { method:"POST", body:JSON.stringify({ username:form.username, display_name:form.display_name || null, password:form.password, role_codes:[form.role_code], permission_codes:form.permission_codes }) }, token);
      setForm({ username:"", display_name:"", password:"", role_code:options.roles.find((role) => role.code === "restricted")?.code || options.roles[0]?.code || "", permission_codes:[] });
      setMessage("User created. The temporary password must be changed at first login.");
      await loadUsers();
    } catch (e) { setError(friendlyError(e, "Unable to create user")); }
    finally { setSaving(false); }
  };

  const patch = async (id:string, payload:Record<string,unknown>, success = "User updated.") => {
    setSaving(true); setError(""); setMessage("");
    try { await apiFetch(`/admin/users/${id}`, { method:"PATCH", body:JSON.stringify(payload) }, token); setMessage(success); await loadUsers(); setEditor(null); }
    catch (e) { setError(friendlyError(e, "Unable to update user")); }
    finally { setSaving(false); }
  };

  const openEditor = (kind:NonNullable<Editor>["kind"], user:UserRow) => {
    setEditor({ kind, user });
    setEditValue(kind === "display" ? (user.display_name || "") : kind === "role" ? (user.roles[0] || options.roles.find((role) => role.code === "restricted")?.code || options.roles[0]?.code || "") : "");
    setPasswordPair({ first:"", second:"" });
  };

  const loadResourceScopes = async (user:UserRow) => {
    if (!canReadScopes) { setResourceScopes(null); setEditScopes([]); return; }
    try {
      const result = await apiFetch<UserResourceScopes>(`/admin/users/${user.id}/resource-scopes`, {}, token);
      setResourceScopes(result);
      setEditScopes(result.direct_scopes.map((row)=>({ scope_type:row.scope_type, resource_id:row.resource_id, label:row.label, context:row.context })));
    } catch (e) { setError(friendlyError(e, "Unable to load resource scopes")); }
  };

  const loadScopeOptionPage = useCallback(async (query:string, page:number, pageSize:number):Promise<ComboboxPage<ResourceScopeOption>> => {
    if (!canReadScopes || tab !== "permissions" || !permissionUser || scopeType === "GLOBAL") {
      return { items:[], total:0, page, page_size:pageSize };
    }
    if (page > 1) return { items:[], total:0, page, page_size:pageSize };
    const params = new URLSearchParams({ scope_type:scopeType, limit:String(Math.min(500, Math.max(100, pageSize))) });
    if (query.trim()) params.set("search",query.trim());
    const rows = await apiFetch<ResourceScopeOption[]>(`/admin/resource-scope-options?${params.toString()}`, {}, token);
    return {
      items:rows.map((row)=>({
        id:String(row.resource_id || "GLOBAL"),
        label:row.label,
        description:row.context || undefined,
        data:row,
      })),
      total:rows.length,
      page:1,
      page_size:pageSize,
    };
  },[canReadScopes,tab,permissionUser?.id,scopeType,token]);

  const addScopeDraft = () => {
    const option:ResourceScopeOption|undefined = scopeType === "GLOBAL"
      ? { scope_type:"GLOBAL", resource_id:null, label:"Global", context:"All resources" }
      : scopeOption || undefined;
    if (!option) { setError("Choose an area to add."); return; }
    const key = `${option.scope_type}:${option.resource_id || "GLOBAL"}`;
    if (editScopes.some((row)=>`${row.scope_type}:${row.resource_id || "GLOBAL"}`===key)) return;
    setEditScopes((current)=>[...current,{ scope_type:option.scope_type, resource_id:option.resource_id, label:option.label, context:option.context }]);
    setScopeOption(null);
  };

  const saveResourceScopes = async () => {
    if (!permissionUser || !canManageScopes) return;
    setSaving(true); setError(""); setMessage("");
    try {
      const result = await apiFetch<UserResourceScopes>(`/admin/users/${permissionUser.id}/resource-scopes`, { method:"PUT", body:JSON.stringify({ scopes:editScopes.map((row)=>({ scope_type:row.scope_type, resource_id:row.resource_id })) }) }, token);
      setResourceScopes(result);
      setEditScopes(result.direct_scopes.map((row)=>({ scope_type:row.scope_type, resource_id:row.resource_id, label:row.label, context:row.context })));
      setMessage("Resource scopes updated; active sessions were revoked.");
    } catch (e) { setError(friendlyError(e, "Unable to update resource scopes")); }
    finally { setSaving(false); }
  };

  const selectPermissionUser = (user:UserRow) => {
    setPermissionUser(user);
    setEditPermissions([...user.direct_permissions]);
    setPermissionSearch("");
    setPermissionCategory("");
    setPermissionGrantFilter("");
    setResourceScopes(null); setEditScopes([]); setScopeOption(null);
  };

  const openPermissionsWorkspace = (user:UserRow) => {
    selectPermissionUser(user);
    setTab("permissions");
    void loadResourceScopes(user);
  };

  const openSelectedPermissionsWorkspace = () => {
    if (!permissionUser) return;
    setTab("permissions");
    void loadResourceScopes(permissionUser);
  };

  const closePermissionsWorkspace = () => {
    setTab("users");
  };

  const savePermissionWorkspace = async () => {
    if (!permissionUser) return;
    setSaving(true); setError(""); setMessage("");
    try {
      const updated = await apiFetch<UserRow>(`/admin/users/${permissionUser.id}`, { method:"PATCH", body:JSON.stringify({ permission_codes:editPermissions }) }, token);
      setPermissionUser(updated);
      setEditPermissions([...updated.direct_permissions]);
      setUsers((current) => current.map((user) => user.id === updated.id ? updated : user));
      setMessage("Direct permissions updated; prerequisites were normalized and active sessions were revoked.");
    } catch (e) { setError(friendlyError(e, "Unable to update permissions")); }
    finally { setSaving(false); }
  };

  const saveEditor = async () => {
    if (!editor) return;
    if (editor.kind === "display") await patch(editor.user.id, { display_name:editValue });
    if (editor.kind === "role") { if (!editValue) { setError("Select one role."); return; } await patch(editor.user.id, { role_codes:[editValue] }, "User role updated; active sessions were revoked."); }
    if (editor.kind === "password") {
      if (!passwordPair.first) { setError("Enter a new temporary password."); return; }
      if (passwordPair.first !== passwordPair.second) { setError("Password confirmation did not match."); return; }
      setSaving(true); setError(""); setMessage("");
      try {
        await apiFetch(`/admin/users/${editor.user.id}/password-reset`, { method:"POST", body:JSON.stringify({ new_password:passwordPair.first }) }, token);
        setMessage(`Temporary password reset for ${editor.user.username}; sessions were revoked and password change is required at next login.`);
        setEditor(null); await loadUsers();
      } catch (e) { setError(friendlyError(e, "Password reset failed")); }
      finally { setSaving(false); }
    }
  };

  const loadSessions = async (user:UserRow) => {
    try { const rows = await apiFetch<SessionRow[]>(`/admin/users/${user.id}/sessions`, {}, token); setSessions((current) => ({ ...current, [user.id]:rows })); setError(""); }
    catch (e) { setError(friendlyError(e, "Unable to load sessions")); }
  };

  const toggleSessions = async (user:UserRow) => {
    if (Object.prototype.hasOwnProperty.call(sessions, user.id)) {
      setSessions((current) => { const next = { ...current }; delete next[user.id]; return next; });
      return;
    }
    await loadSessions(user);
  };

  const revokeSession = async (user:UserRow, sessionId:string) => {
    const confirmed = await dialog.confirm({ title:"Revoke session", message:`Revoke this active session for ${user.username}?`, confirmLabel:"Revoke session", tone:"danger" });
    if (!confirmed) return;
    try { await apiFetch(`/admin/users/${user.id}/sessions/${sessionId}`, { method:"DELETE" }, token); setMessage("Session revoked."); await loadSessions(user); if (tab === "online") await loadOnlineSessions(); }
    catch (e) { setError(friendlyError(e, "Unable to revoke session")); }
  };

  const revokeOnlineSession = async (session:OnlineSessionRow) => {
    const user:UserRow = { id:session.user_id, username:session.username, display_name:session.display_name, is_active:true, must_change_password:false, password_change_reason:null, password_changed_at:null, roles:session.roles, permissions:[], direct_permissions:[] };
    await revokeSession(user, session.id);
  };

  const revokeAll = async (user:UserRow) => {
    const confirmed = await dialog.confirm({ title:"Revoke all sessions", message:`Revoke all active sessions for ${user.username}?`, confirmLabel:"Revoke all", tone:"danger" });
    if (!confirmed) return;
    try { const result = await apiFetch<{revoked_count:number}>(`/admin/users/${user.id}/sessions/revoke-all`, { method:"POST" }, token); setMessage(`${result.revoked_count} session(s) revoked.`); await loadSessions(user); }
    catch (e) { setError(friendlyError(e, "Unable to revoke sessions")); }
  };

  const toggleActive = async (user:UserRow) => {
    const verb = user.is_active ? "Disable" : "Reactivate";
    const confirmed = await dialog.confirm({ title:`${verb} user`, message:user.is_active ? `Disable ${user.username}? Active sessions will be revoked.` : `Reactivate ${user.username}?`, confirmLabel:verb, tone:user.is_active ? "danger" : "default" });
    if (confirmed) await patch(user.id, { is_active:!user.is_active }, `User ${user.is_active ? "disabled" : "reactivated"}.`);
  };

  const visibleSessions=(rows:SessionRow[])=>{const filtered=rows.filter(session=>!sessionStatus||session.status===sessionStatus);return sortRows(filtered,sessionSort,(session,key)=>session[key as keyof SessionRow] as any)};
  const editorTitle = editor ? ({ display:"Edit display name", role:"Assign role", password:"Reset temporary password" } as const)[editor.kind] : "Edit user";

  return <PageLayout className="page user-management-page">
    <div className="page-heading"><div><h2 className="hover-help-title" data-help="Manage accounts, access, password lifecycle, and authentication sessions.">User Management</h2></div><Button unstyled className="secondary" onClick={() => void load()}>Refresh</Button></div>
    <Tabs<Tab>
      ariaLabel="User management views"
      value={tab}
      onChange={(nextTab) => {
        if (nextTab === "permissions") openSelectedPermissionsWorkspace();
        else setTab(nextTab);
      }}
      tabs={[
        { id: "users", label: "Users" },
        { id: "online", label: "Online Users", visible: canReadSessions },
        {
          id: "permissions",
          label: "Permissions",
          visible: canOpenAccessWorkspace,
          disabled: !permissionUser,
          title: permissionUser ? `Open permissions for ${permissionUser.username}` : "Select a user to enable Permissions",
        },
      ]}
    />

    {tab === "users" && <>
      {can("user.create") && <section className="panel"><div className="panel-header"><div><h3 className="hover-help-title" data-help="The initial password is temporary and must be replaced by the user at first login.">Create user</h3></div></div>
        <div className="form-grid four">
          <label>Username<Input unstyled value={form.username} onChange={(e) => setForm({ ...form, username:e.target.value })} /></label>
          <label>Display name<Input unstyled value={form.display_name} onChange={(e) => setForm({ ...form, display_name:e.target.value })} /></label>
          <label>Temporary password<Input unstyled type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password:e.target.value })} /><span className="field-help">Minimum 8 characters; uppercase, lowercase, number and symbol by default.</span></label>
          <label>Role<Select unstyled value={form.role_code} onChange={(e) => setForm({ ...form, role_code:e.target.value })}><option value="">Select role</option>{options.roles.map((role) => <option key={role.code} value={role.code}>{role.name} ({role.code})</option>)}</Select><span className="field-help">Restricted starts with no operational permissions.</span></label>
        </div>
        <div className="field-block"><span className="field-label">Direct permissions</span><MultiSelectDropdown options={permissionOptions} value={form.permission_codes} onChange={(permission_codes) => setForm({ ...form, permission_codes })} placeholder="Add direct permissions" /><span className="field-help">Direct permissions are added to role permissions. Required supporting permissions are included automatically.</span></div>
        <Button unstyled onClick={() => void create()} disabled={busy || saving || !form.username || !form.password || !form.role_code}>Create user</Button>
      </section>}

      <section className="panel"><div className="panel-header"><div><h3>Users</h3><span>{userTotal} total</span></div></div>
        <div className="filter-row compact management-filter-row"><Input unstyled value={userSearch} onChange={e=>{setUserSearch(e.target.value);setUserPage(1)}} placeholder="Search users..."/><Select unstyled value={userStatus} onChange={e=>{setUserStatus(e.target.value);setUserPage(1)}}><option value="">All Statuses</option><option value="ACTIVE">ACTIVE</option><option value="DISABLED">DISABLED</option></Select><Select unstyled value={userRole} onChange={e=>{setUserRole(e.target.value);setUserPage(1)}}><option value="">All Roles</option>{options.roles.map(role=><option key={role.code} value={role.code}>{role.name}</option>)}</Select><TableExportButton token={token} tableId="users" filters={{ search:userSearch,status:userStatus,role:userRole,sort_by:userSort.key,sort_dir:userSort.direction }}/><ClearFiltersButton disabled={!userSearch&&!userStatus&&!userRole} onClick={()=>{setUserSearch("");setUserStatus("");setUserRole("");setUserPage(1)}}/></div>
        <DataTable viewportClassName="table-wrap"><thead><tr><SortHeader label="Username" sortKey="username" sort={userSort} onSort={key=>{setUserSort(current=>nextSort(current,key));setUserPage(1)}}/><SortHeader label="Display name" sortKey="display_name" sort={userSort} onSort={key=>{setUserSort(current=>nextSort(current,key));setUserPage(1)}}/><SortHeader label="Status" sortKey="is_active" sort={userSort} onSort={key=>{setUserSort(current=>nextSort(current,key));setUserPage(1)}}/><SortHeader label="Role" sortKey="role" sort={userSort} onSort={key=>{setUserSort(current=>nextSort(current,key));setUserPage(1)}}/><th>Password state</th><th>Effective permissions</th><th>Actions</th></tr></thead><tbody>{users.map((user) => <Fragment key={user.id}>
          <tr className={permissionUser?.id === user.id ? "selected-row" : ""} onClick={() => selectPermissionUser(user)} onDoubleClick={() => openPermissionsWorkspace(user)}><td>{user.username}</td><td>{user.display_name || "-"}</td><td>{user.is_active ? "ACTIVE" : "DISABLED"}</td><td>{user.roles[0] || "-"}{user.roles.length > 1 && <span className="legacy-warning"> +{user.roles.length - 1} legacy</span>}</td><td>{user.must_change_password ? <span className="badge badge-maintenance">CHANGE REQUIRED</span> : <span className="badge badge-active">CURRENT</span>}</td><td>{user.permissions.length}</td><td onClick={(event) => event.stopPropagation()} onDoubleClick={(event) => event.stopPropagation()}><div className="actions">
            {can("user.update") && <Button unstyled className="small" onClick={() => openEditor("display", user)}>Display name</Button>}
            {can("user.roles.manage") && <Button unstyled className="small" onClick={() => openEditor("role", user)}>Role</Button>}
            {canOpenAccessWorkspace && <Button unstyled className="small" onClick={() => openPermissionsWorkspace(user)}>Permissions</Button>}
            {can("user.password.reset") && <Button unstyled className="small" onClick={() => openEditor("password", user)}>Reset password</Button>}
            {can("user.deactivate") && <Button unstyled className={`small ${user.is_active ? "danger" : ""}`} onClick={() => void toggleActive(user)}>{user.is_active ? "Disable" : "Reactivate"}</Button>}
            {canReadSessions && <Button unstyled className="small secondary" aria-expanded={Object.prototype.hasOwnProperty.call(sessions, user.id)} onClick={() => void toggleSessions(user)}>Sessions</Button>}
          </div></td></tr>
          {Object.prototype.hasOwnProperty.call(sessions, user.id) && <tr><td colSpan={7}><div className="subpanel"><div className="page-heading"><div><strong>Sessions for {user.username}</strong></div>{canManageSessions && <Button unstyled className="small danger" onClick={() => void revokeAll(user)}>Revoke all</Button>}</div><div className="filter-row compact management-filter-row"><Select unstyled value={sessionStatus} onChange={e=>setSessionStatus(e.target.value)}><option value="">All Sessions</option><option value="ACTIVE">Active</option><option value="IDLE">Idle</option><option value="EXPIRED">Expired</option><option value="REVOKED">Revoked</option></Select><TableExportButton token={token} tableId="user_sessions" filters={{ user_id:user.id,status:sessionStatus,sort_by:sessionSort.key,sort_direction:sessionSort.direction }}/><ClearFiltersButton disabled={!sessionStatus} onClick={()=>setSessionStatus("")}/></div><DataTable viewportClassName="table-wrap"><thead><tr><SortHeader label="Login" sortKey="created_at" sort={sessionSort} onSort={key=>setSessionSort(current=>nextSort(current,key))}/><SortHeader label="Last activity" sortKey="last_user_activity_at" sort={sessionSort} onSort={key=>setSessionSort(current=>nextSort(current,key))}/><th>Status</th><th>IP</th><th>Browser</th><th>Operating system</th><th>Device</th><SortHeader label="Expires" sortKey="expires_at" sort={sessionSort} onSort={key=>setSessionSort(current=>nextSort(current,key))}/><th>Action</th></tr></thead><tbody><PaginatedTableRows items={visibleSessions(sessions[user.id])} colSpan={9} resetKey={sessionStatus} itemLabel="sessions" renderRow={(session) => { const client=clientLabel(session); return <tr key={session.id}><td>{new Date(session.created_at).toLocaleString()}</td><td>{session.last_user_activity_at ? new Date(session.last_user_activity_at).toLocaleString() : "-"}</td><td>{sessionBadge(session.status)}</td><td>{session.last_ip || session.login_ip || "-"}</td><td>{client.browser}</td><td>{client.os}</td><td>{session.device_type || "-"}</td><td>{new Date(session.expires_at).toLocaleString()}</td><td>{canManageSessions && !session.revoked_at && session.status !== "EXPIRED" && <Button unstyled className="small danger" onClick={() => void revokeSession(user, session.id)}>Revoke</Button>}</td></tr>; }} /></tbody></DataTable></div></td></tr>}
        </Fragment>)}{!users.length && <tr><td colSpan={7}>No users match the current filters.</td></tr>}<ServerPaginationRow colSpan={7} page={userPage} pageSize={userPageSize} total={userTotal} onPage={setUserPage} onPageSize={(size)=>{setUserPageSize(size);setUserPage(1)}} itemLabel="users" /></tbody></DataTable>
      </section>
    </>}

    {tab === "permissions" && permissionUser && canOpenAccessWorkspace && <section className="panel permission-workspace">
      <div className="permission-workspace-header">
        <div>
          <Button unstyled type="button" className="permission-back-link" onClick={closePermissionsWorkspace}>← Back to users</Button>
          <h3>Permissions</h3>
          <p className="muted">Permissions control what the user can do. Resource scopes control where they can do it.</p>
        </div>
        <div className="actions">
          <Button unstyled type="button" className="secondary" onClick={() => { setEditPermissions([...permissionUser.direct_permissions]); setPermissionSearch(""); setPermissionCategory(""); setPermissionGrantFilter(""); }}>Reset changes</Button>
          {can("user.permissions.manage") && <Button unstyled type="button" onClick={() => void savePermissionWorkspace()} disabled={saving}>Save permissions</Button>}
        </div>
      </div>

      <div className="permission-summary-grid">
        <div className="permission-summary-card"><span>User</span><strong>{permissionUser.display_name || permissionUser.username}</strong><small>{permissionUser.is_active ? "ACTIVE" : "DISABLED"}</small></div>
        <div className="permission-summary-card"><span>Role</span><strong>{permissionUser.roles.join(", ") || "No role"}</strong><small>{roleDerivedPermissions.size} role-derived permission(s)</small></div>
        <div className="permission-summary-card"><span>Direct</span><strong>{editPermissions.length}</strong><small>Explicit user grants</small></div>
        <div className="permission-summary-card"><span>Effective</span><strong>{new Set([...roleDerivedPermissions,...editPermissions,...requiredBySelection.keys()]).size}</strong><small>After prerequisites</small></div>
      </div>

      <div className="permission-access-note">
        <strong>Access model</strong>
        <span><b>WHAT</b> controls which actions the user can perform. <b>WHERE</b> controls which resources those actions can apply to. Geographic access includes the selected area and its child areas, and multiple assignments are combined.</span>
      </div>

      {canReadScopes && <section className="resource-scope-panel">
        <div className="resource-scope-header">
          <div><strong>Resource scopes · WHERE</strong><small>Direct assignments can be edited here. Child geographic areas are included automatically.</small></div>
          <div className="resource-scope-stats">
            <span>Direct <b>{editScopes.length}</b></span>
            <span>Global <b>{resourceScopes?.effective_summary?.global ? "YES" : "NO"}</b></span>
            <span>Groups <b>{Number(resourceScopes?.effective_summary?.effective_groups || 0)}</b></span>
          </div>
        </div>
        {canManageScopes && <div className="resource-scope-add">
          <Select unstyled value={scopeType} onChange={(event)=>{setScopeType(event.target.value as ResourceScopeType);setScopeOption(null);}}>
            <option value="GLOBAL">GLOBAL</option><option value="NETWORK">NETWORK</option><option value="CITY">CITY</option><option value="LOCATION">LOCATION</option><option value="SECTOR">SECTOR</option><option value="GROUP">GROUP</option>
          </Select>
          {scopeType === "GLOBAL" ? <div className="resource-scope-global-choice"><strong>Global</strong><small>All resources</small></div> : <SearchableCombobox<ResourceScopeOption>
            value={scopeOption ? String(scopeOption.resource_id || "") : ""}
            selectedOption={scopeOption ? { id:String(scopeOption.resource_id || ""), label:scopeOption.label, description:scopeOption.context || undefined, data:scopeOption } : null}
            onChange={(option:ComboboxOption<ResourceScopeOption>|null)=>setScopeOption(option?.data || null)}
            loadPage={loadScopeOptionPage}
            placeholder={`Search or select ${scopeType.toLowerCase()}...`}
            emptyText={`No ${scopeType.toLowerCase()} matches your search.`}
            errorText="Unable to load available areas."
            pageSize={100}
          />}
          <Button unstyled type="button" className="secondary" onClick={addScopeDraft} disabled={scopeType!=="GLOBAL" && !scopeOption}>Add scope</Button>
        </div>}
        <div className="resource-scope-list">
          {editScopes.map((row)=><div className="resource-scope-row" key={`${row.scope_type}:${row.resource_id || "GLOBAL"}`}>
            <b>{row.scope_type}</b><span>{row.label}</span>{row.context && <small>{row.context}</small>}
            {canManageScopes && <Button unstyled type="button" className="small danger" onClick={()=>setEditScopes((current)=>current.filter((item)=>!(item.scope_type===row.scope_type && item.resource_id===row.resource_id)))}>Remove</Button>}
          </div>)}
          {!editScopes.length && <div className="permission-empty">No direct resource scopes. The user will fail closed for scoped resources.</div>}
        </div>
        {canManageScopes && <div className="resource-scope-footer"><span className="muted">Saving replaces the user's direct resource scopes and signs them out of active sessions.</span><Button unstyled type="button" onClick={()=>void saveResourceScopes()} disabled={saving}>Save resource scopes</Button></div>}
      </section>}

      <div className="permission-toolbar">
        <Input unstyled value={permissionSearch} onChange={(event) => setPermissionSearch(event.target.value)} placeholder="Search permission, code, description, prerequisite..." />
        <SearchableFilterDropdown value={permissionCategory} options={permissionCategoryOptions} onChange={setPermissionCategory} placeholder="All permission groups" searchPlaceholder="Search permission groups" />
        <SearchableFilterDropdown value={permissionGrantFilter} options={permissionGrantOptions} onChange={setPermissionGrantFilter} placeholder="All permissions" searchPlaceholder="Search permission states" />
        <ClearFiltersButton disabled={!permissionSearch&&!permissionCategory&&!permissionGrantFilter} onClick={()=>{setPermissionSearch("");setPermissionCategory("");setPermissionGrantFilter("")}}/>
        <span className="permission-result-count">{visiblePermissionOptions.length} permission(s)</span>
      </div>

      <div className="permission-legend" aria-label="Permission legend">
        <span><b className="permission-chip role">ROLE</b> supplied by role</span>
        <span><b className="permission-chip direct">DIRECT</b> explicit grant</span>
        <span><b className="permission-chip required">REQUIRED</b> prerequisite</span>
      </div>

      <div className="permission-groups">
        {groupedPermissionOptions.map(([category,items]) => <section key={category} className="permission-group">
          <div className="permission-group-title"><strong>{category.replaceAll("_", " ")}</strong><span>{items.length}</span></div>
          <div className="permission-card-grid">
            {items.map((item) => {
              const roleDerived = roleDerivedPermissions.has(item.code);
              const direct = editPermissions.includes(item.code);
              const requiredBy = requiredBySelection.get(item.code);
              const required = Boolean(requiredBy?.size);
              const checked = roleDerived || direct || required;
              const locked = roleDerived || required;
              return <label key={item.code} className={`permission-card ${checked ? "selected" : ""} ${locked ? "locked" : ""}`}>
                <Checkbox unstyled checked={checked} disabled={locked} onChange={(event) => setEditPermissions((current) => event.target.checked ? Array.from(new Set([...current,item.code])) : current.filter((code) => code !== item.code))} />
                <span className="permission-card-body">
                  <span className="permission-card-heading"><strong>{item.name}</strong><code>{item.code}</code></span>
                  {item.description && <small>{item.description}</small>}
                  <span className="permission-card-chips">
                    {roleDerived && <b className="permission-chip role">ROLE</b>}
                    {direct && <b className="permission-chip direct">DIRECT</b>}
                    {required && !roleDerived && <b className="permission-chip required">REQUIRED</b>}
                  </span>
                  {item.requires?.length ? <span className="permission-dependency">Requires: {item.requires.join(", ")}</span> : null}
                  {requiredBy?.size ? <span className="permission-dependency">Required by: {Array.from(requiredBy).join(", ")}</span> : null}
                </span>
              </label>;
            })}
          </div>
        </section>)}
        {!visiblePermissionOptions.length && <div className="permission-empty">No permissions match the current search/filter.</div>}
      </div>

      {can("user.permissions.manage") && <div className="permission-workspace-footer">
        <span className="muted">Saving updates the user's permissions and signs them out of active sessions.</span>
        <Button unstyled type="button" onClick={() => void savePermissionWorkspace()} disabled={saving}>Save permissions</Button>
      </div>}
    </section>}

    {tab === "online" && canReadSessions && <section className="panel">
      <div className="panel-header"><div><h3 className="hover-help-title" data-help="Each row is one valid authentication session. A user can appear more than once when signed in from multiple clients. Some device details may not be available from the browser.">Online Users</h3><span>{onlineTotal} valid session(s)</span></div></div>
      <div className="filter-row compact management-filter-row">
        <Input unstyled value={onlineSearch} onChange={e=>{setOnlineSearch(e.target.value);setOnlinePage(1)}} placeholder="Search user, IP, browser, OS..." />
        <Select unstyled value={onlineStatus} onChange={e=>{setOnlineStatus(e.target.value);setOnlinePage(1)}}><option value="">Active + Idle</option><option value="ACTIVE">ACTIVE</option><option value="IDLE">IDLE</option></Select>
        <Input unstyled value={onlineBrowser} onChange={e=>{setOnlineBrowser(e.target.value);setOnlinePage(1)}} placeholder="Browser filter..." />
        <Input unstyled value={onlineOs} onChange={e=>{setOnlineOs(e.target.value);setOnlinePage(1)}} placeholder="OS filter..." />
        <Select unstyled value={onlineDevice} onChange={e=>{setOnlineDevice(e.target.value);setOnlinePage(1)}}><option value="">All Devices</option><option value="DESKTOP">Desktop</option><option value="MOBILE">Mobile</option><option value="TABLET">Tablet</option><option value="UNKNOWN">Unknown</option></Select>
        <TableExportButton token={token} tableId="online_sessions" filters={{ search:onlineSearch,status:onlineStatus,browser:onlineBrowser,operating_system:onlineOs,device_type:onlineDevice,sort_by:onlineSort.key,sort_dir:onlineSort.direction }}/><ClearFiltersButton disabled={!onlineSearch&&!onlineStatus&&!onlineBrowser&&!onlineOs&&!onlineDevice} onClick={()=>{setOnlineSearch("");setOnlineStatus("");setOnlineBrowser("");setOnlineOs("");setOnlineDevice("");setOnlinePage(1)}}/>
      </div>
      <DataTable viewportClassName="table-wrap management-table-wrap"><thead><tr><SortHeader label="Username" sortKey="username" sort={onlineSort} onSort={key=>{setOnlineSort(current=>nextSort(current,key));setOnlinePage(1)}}/><SortHeader label="Display name" sortKey="display_name" sort={onlineSort} onSort={key=>{setOnlineSort(current=>nextSort(current,key));setOnlinePage(1)}}/><th>Status</th><SortHeader label="Login time" sortKey="created_at" sort={onlineSort} onSort={key=>{setOnlineSort(current=>nextSort(current,key));setOnlinePage(1)}}/><SortHeader label="Last activity" sortKey="last_user_activity_at" sort={onlineSort} onSort={key=>{setOnlineSort(current=>nextSort(current,key));setOnlinePage(1)}}/><SortHeader label="Duration" sortKey="duration" sort={onlineSort} onSort={key=>{setOnlineSort(current=>nextSort(current,key));setOnlinePage(1)}}/><th>Idle</th><SortHeader label="IP" sortKey="login_ip" sort={onlineSort} onSort={key=>{setOnlineSort(current=>nextSort(current,key));setOnlinePage(1)}}/><SortHeader label="Browser" sortKey="browser" sort={onlineSort} onSort={key=>{setOnlineSort(current=>nextSort(current,key));setOnlinePage(1)}}/><SortHeader label="OS" sortKey="operating_system" sort={onlineSort} onSort={key=>{setOnlineSort(current=>nextSort(current,key));setOnlinePage(1)}}/><SortHeader label="Device" sortKey="device_type" sort={onlineSort} onSort={key=>{setOnlineSort(current=>nextSort(current,key));setOnlinePage(1)}}/><th>Role</th><th>Expires in</th><th>Action</th></tr></thead><tbody>{onlineSessions.map(session=>{const client=clientLabel(session);return <tr key={session.id}><td><strong>{session.username}</strong></td><td>{session.display_name || "-"}</td><td>{sessionBadge(session.status)}</td><td>{new Date(session.created_at).toLocaleString()}</td><td>{session.last_user_activity_at ? new Date(session.last_user_activity_at).toLocaleString() : "-"}</td><td>{formatDuration(session.duration_seconds)}</td><td>{formatDuration(session.idle_seconds)}</td><td>{session.last_ip || session.login_ip || "-"}</td><td>{client.browser}</td><td>{client.os}</td><td>{session.device_type || "-"}</td><td>{session.roles.join(", ") || "-"}</td><td>{formatDuration(session.time_remaining_seconds)}</td><td>{canManageSessions && <Button unstyled className="small danger" onClick={()=>void revokeOnlineSession(session)}>Revoke</Button>}</td></tr>})}{!onlineSessions.length && <tr><td colSpan={14}>No sessions match the current filters.</td></tr>}<ServerPaginationRow colSpan={14} page={onlinePage} pageSize={onlinePageSize} total={onlineTotal} onPage={setOnlinePage} onPageSize={(size)=>{setOnlinePageSize(size);setOnlinePage(1)}} itemLabel="sessions" /></tbody></DataTable>
      
    </section>}

    <ModalShell open={Boolean(editor)} title={editorTitle} eyebrow="USER MANAGEMENT" onClose={() => setEditor(null)} footer={<><Button unstyled type="button" className="secondary" onClick={() => setEditor(null)}>Cancel</Button><Button unstyled type="button" onClick={() => void saveEditor()} disabled={saving}>Save changes</Button></>}>
      {editor?.kind === "display" && <label>Display name<Input unstyled value={editValue} onChange={(event) => setEditValue(event.target.value)} autoFocus /></label>}
      {editor?.kind === "role" && <><label>Role<Select unstyled value={editValue} onChange={(event) => setEditValue(event.target.value)} autoFocus><option value="">Select role</option>{options.roles.map((role) => <option key={role.code} value={role.code}>{role.name} ({role.code})</option>)}</Select></label><p className="muted">Saving replaces the user's role assignment with this single role.</p></>}
      {editor?.kind === "password" && <><div className="form-grid two"><label>Temporary password<Input unstyled type="password" autoComplete="new-password" value={passwordPair.first} onChange={(event) => setPasswordPair({ ...passwordPair, first:event.target.value })} autoFocus /></label><label>Confirm temporary password<Input unstyled type="password" autoComplete="new-password" value={passwordPair.second} onChange={(event) => setPasswordPair({ ...passwordPair, second:event.target.value })} /></label></div><p className="muted">Resetting the password revokes active sessions and forces the user to choose a new password at the next login.</p></>}
    </ModalShell>
  </PageLayout>;
}
