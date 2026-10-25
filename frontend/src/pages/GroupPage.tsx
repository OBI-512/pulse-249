import { PageLayout } from "../design-system/layouts";
import { useEffect, useMemo, useRef, useState } from "react";
import { ApiError, apiFetch } from "../api/client";
import { useDialog } from "../components/common/DialogSystem";
import { useFeedback } from "../components/common/FeedbackSystem";
import { GroupDeviceSearchSelect } from "../components/common/GroupDeviceSearchSelect";
import { LocalSearchableCombobox } from "../design-system/composites/SearchableSelect";
import { ChildGroupSelector, EditableChildGroupSelector } from "../features/groups/components";
import { EmptyState } from "../design-system/composites/AsyncState";
import { StatusBadge as Badge } from "../design-system/composites/Status";
import { useDebouncedValue } from "../hooks/useDebouncedValue";
import type { City, Device, Group, GroupDeviceItem, GroupItemsPage, Location, Network, PageResult, Sector, SortState } from "../types";
import { friendlyError } from "../utils/feedback";
import { nextSort } from "../utils/sorting";
import { Tabs } from "../design-system/composites/Tabs";

import { DataTable } from "../design-system/data/DataTable";
import { ServerPaginationRow } from "../design-system/data/Pagination";
import { SortHeader } from "../design-system/data/SortHeader";
import { TableExportButton } from "../design-system/data/TableExport";
import { ClearFiltersButton } from "../design-system/composites/FilterBar";
import { Button, Input, Select, Textarea } from "../design-system/primitives";
type Tab = "groups" | "items";
type ReferenceData = { networks: Network[]; cities: City[]; locations: Location[]; sectors: Sector[] };

const DEVICE_SCOPES = ["ANY", "ACCESS_POINT", "CPE", "SECTOR", "SWITCH", "ROUTER", "FIREWALL", "SERVER", "WIRELESS_BRIDGE", "NETWORK_DEVICE", "OTHER"];
const SCOPE_TYPES = ["GLOBAL", "NETWORK", "CITY", "LOCATION", "SECTOR"];
const blankForm = { name: "", code: "", description: "", membership_mode: "MANUAL", scope_type: "GLOBAL", network_id: "", city_id: "", location_id: "", sector_id: "", device_scope: "ANY", sector_role: "" };

export function GroupPage({ token, permissions = [], onGroupsRefresh }: any) {
  const dialog = useDialog();
  const feedback = useFeedback();
  const [tab, setTab] = useState<Tab>("groups");
  const [groups, setGroups] = useState<Group[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [sort, setSort] = useState<SortState>({ key: "name", direction: "asc" });
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebouncedValue(search, 300);
  const [kindFilter, setKindFilter] = useState("");
  const [modeFilter, setModeFilter] = useState("");
  const [scopeFilter, setScopeFilter] = useState("");
  const [deviceFilter, setDeviceFilter] = useState("");
  const [roleFilter, setRoleFilter] = useState("");
  const [selected, setSelected] = useState<Group | null>(null);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ ...blankForm });
  const [refs, setRefs] = useState<ReferenceData>({ networks: [], cities: [], locations: [], sectors: [] });
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [validationAttempted, setValidationAttempted] = useState(false);
  const requestRef = useRef(0);
  const eligibleChildRequestRef = useRef(0);
  const [editChildOptions, setEditChildOptions] = useState<Group[]>([]);
  const [editChildTotal, setEditChildTotal] = useState(0);
  const [editChildBaseTotal, setEditChildBaseTotal] = useState(0);
  const [editChildIds, setEditChildIds] = useState<string[]>([]);
  const [editChildSearch, setEditChildSearch] = useState("");
  const debouncedEditChildSearch = useDebouncedValue(editChildSearch, 300);
  const [editChildLoading, setEditChildLoading] = useState(false);

  const [manualDeviceId, setManualDeviceId] = useState("");
  const [memberRows, setMemberRows] = useState<Device[]>([]);
  const [memberTotal, setMemberTotal] = useState(0);
  const [memberPage, setMemberPage] = useState(1);
  const [memberPageSize, setMemberPageSize] = useState(50);
  const [memberSearch, setMemberSearch] = useState("");
  const debouncedMemberSearch = useDebouncedValue(memberSearch, 300);
  const [memberSort, setMemberSort] = useState<SortState>({ key: "display_name", direction: "asc" });
  const [memberRevision, setMemberRevision] = useState(0);

  const [itemsGroup, setItemsGroup] = useState<Group | null>(null);
  const [itemsRows, setItemsRows] = useState<GroupDeviceItem[]>([]);
  const [itemsChildren, setItemsChildren] = useState<Group[]>([]);
  const [itemsTotal, setItemsTotal] = useState(0);
  const [itemsPage, setItemsPage] = useState(1);
  const [itemsPageSize, setItemsPageSize] = useState(50);
  const [itemsSearch, setItemsSearch] = useState("");
  const debouncedItemsSearch = useDebouncedValue(itemsSearch, 300);
  const [itemsItemType, setItemsItemType] = useState("");
  const [itemsDeviceType, setItemsDeviceType] = useState("");
  const [itemsLifecycle, setItemsLifecycle] = useState("");
  const [itemsOperational, setItemsOperational] = useState("");
  const [itemsSort, setItemsSort] = useState<SortState>({ key: "display_name", direction: "asc" });
  const [includeAllChildren, setIncludeAllChildren] = useState(true);
  const [selectedChildren, setSelectedChildren] = useState<string[]>([]);
  const [breadcrumb, setBreadcrumb] = useState<Group[]>([]);

  const canGeoRead = permissions.includes("geo.read");
  const canCreate = permissions.includes("group.create");
  const canUpdate = permissions.includes("group.update");
  const canDelete = permissions.includes("group.delete");
  const canMembership = permissions.includes("group.membership.manage");

  const networkById = useMemo(() => new Map(refs.networks.map((item) => [item.id, item])), [refs.networks]);
  const cityById = useMemo(() => new Map(refs.cities.map((item) => [item.id, item])), [refs.cities]);
  const locationById = useMemo(() => new Map(refs.locations.map((item) => [item.id, item])), [refs.locations]);
  const sectorById = useMemo(() => new Map(refs.sectors.map((item) => [item.id, item])), [refs.sectors]);

  const loadReferences = async () => {
    const geo = canGeoRead ? await apiFetch<ReferenceData>("/geography/scope-options", {}, token) : { networks: [], cities: [], locations: [], sectors: [] } as ReferenceData;
    setRefs(geo);
  };

  const loadGroups = async () => {
    const requestId = ++requestRef.current;
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize), sort_by: sort.key, sort_direction: sort.direction });
    if (debouncedSearch.trim()) params.set("search", debouncedSearch.trim());
    if (kindFilter) params.set("group_kind", kindFilter);
    if (modeFilter) params.set("membership_mode", modeFilter);
    if (scopeFilter) params.set("scope_type", scopeFilter);
    if (deviceFilter) params.set("device_scope", deviceFilter);
    if (roleFilter) params.set("sector_role", roleFilter);
    try {
      const result = await apiFetch<PageResult<Group>>(`/device-groups/page?${params}`, {}, token);
      if (requestRef.current !== requestId) return;
      setGroups(result.items); setTotal(result.total); setSelectedIds([]);
      const maxPage = Math.max(1, Math.ceil(result.total / pageSize)); if (page > maxPage) setPage(maxPage);
      if (selected) {
        const refreshed = result.items.find((group) => group.id === selected.id); if (refreshed) selectGroup(refreshed);
      }
    } catch (error) { if (requestRef.current === requestId) feedback.error(friendlyError(error, "Unable to load groups.")); }
  };

  useEffect(() => { void loadReferences().catch((error) => feedback.error(friendlyError(error, "Unable to load group reference data."))); }, [token, canGeoRead]);
  useEffect(() => { setPage(1); }, [debouncedSearch, kindFilter, modeFilter, scopeFilter, deviceFilter, roleFilter, pageSize]);
  useEffect(() => { if (tab === "groups") void loadGroups(); }, [tab, page, pageSize, sort.key, sort.direction, debouncedSearch, kindFilter, modeFilter, scopeFilter, deviceFilter, roleFilter]);

  const selectGroup = (group: Group) => {
    setSelected(group); setCreating(false); setManualDeviceId(""); setMemberPage(1); setEditChildIds([]); setEditChildSearch("");
    setForm({
      name: group.name, code: group.code, description: group.description || "", membership_mode: group.membership_mode || "MANUAL",
      scope_type: group.scope_type, network_id: group.network_id || "", city_id: group.city_id || "", location_id: group.location_id || "", sector_id: group.sector_id || "",
      device_scope: group.device_scope || "ANY", sector_role: group.sector_role || "",
    });
  };

  const startCreate = () => { setValidationAttempted(false); setSelected(null); setCreating(true); setForm({ ...blankForm }); setManualDeviceId(""); setEditChildIds([]); setEditChildSearch(""); setEditChildOptions([]); setEditChildTotal(0); setEditChildBaseTotal(0); };

  const loadMembers = async () => {
    if (!selected || (selected.membership_mode || "MANUAL") !== "MANUAL") { setMemberRows([]); setMemberTotal(0); return; }
    const params = new URLSearchParams({ page: String(memberPage), page_size: String(memberPageSize), sort_by: memberSort.key, sort_direction: memberSort.direction });
    if (debouncedMemberSearch.trim()) params.set("search", debouncedMemberSearch.trim());
    try {
      const result = await apiFetch<PageResult<Device>>(`/device-groups/${selected.id}/devices/page?${params}`, {}, token);
      setMemberRows(result.items); setMemberTotal(result.total);
    } catch (error) { feedback.error(friendlyError(error, "Unable to load direct group members.")); }
  };
  useEffect(() => { setMemberPage(1); }, [selected?.id, debouncedMemberSearch, memberPageSize, memberSort.key, memberSort.direction]);
  useEffect(() => { if (tab === "groups") void loadMembers(); }, [tab, selected?.id, memberPage, memberPageSize, debouncedMemberSearch, memberSort.key, memberSort.direction, memberRevision]);

  useEffect(() => {
    if (creating || !selected || selected.group_kind === "SYSTEM" || !canMembership) {
      if (!creating) setEditChildIds([]);
      return;
    }
    let active = true;
    void apiFetch<Group[]>(`/device-groups/${selected.id}/children`, {}, token)
      .then((rows) => { if (active) setEditChildIds(rows.map((group) => group.id)); })
      .catch((error) => { if (active) feedback.error(friendlyError(error, "Unable to load current child groups.")); });
    return () => { active = false; };
  }, [selected?.id, creating, canMembership, token]);

  useEffect(() => {
    const system = !creating && selected?.group_kind === "SYSTEM";
    const contextId = form.scope_type === "NETWORK" ? form.network_id : form.scope_type === "CITY" ? form.city_id : form.scope_type === "LOCATION" ? form.location_id : form.scope_type === "SECTOR" ? form.sector_id : "";
    if (!canMembership || system || (!creating && !selected) || (form.scope_type !== "GLOBAL" && !contextId)) {
      setEditChildOptions([]); setEditChildTotal(0); setEditChildBaseTotal(0); return;
    }
    const requestId = ++eligibleChildRequestRef.current;
    const params = new URLSearchParams({ page: "1", page_size: "50", scope_type: form.scope_type, device_scope: form.device_scope });
    if (!creating && selected) params.set("parent_group_id", selected.id);
    if (form.scope_type === "NETWORK" && form.network_id) params.set("network_id", form.network_id);
    if (form.scope_type === "CITY" && form.city_id) params.set("city_id", form.city_id);
    if (form.scope_type === "LOCATION" && form.location_id) params.set("location_id", form.location_id);
    if (form.scope_type === "SECTOR" && form.sector_id) params.set("sector_id", form.sector_id);
    if (form.device_scope === "SECTOR" && form.sector_role) params.set("sector_role", form.sector_role);
    if (debouncedEditChildSearch.trim()) params.set("search", debouncedEditChildSearch.trim());
    setEditChildLoading(true);
    void apiFetch<PageResult<Group>>(`/device-groups/eligible-children/page?${params}`, {}, token)
      .then((result) => {
        if (eligibleChildRequestRef.current !== requestId) return;
        setEditChildOptions(result.items); setEditChildTotal(result.total);
        if (!debouncedEditChildSearch.trim()) setEditChildBaseTotal(result.total);
      })
      .catch((error) => { if (eligibleChildRequestRef.current === requestId) feedback.error(friendlyError(error, "Unable to load eligible child groups.")); })
      .finally(() => { if (eligibleChildRequestRef.current === requestId) setEditChildLoading(false); });
  }, [creating, selected?.id, selected?.group_kind, canMembership, token, form.scope_type, form.network_id, form.city_id, form.location_id, form.sector_id, form.device_scope, form.sector_role, debouncedEditChildSearch]);

  const save = async (forceReconcile = false) => {
    if (!creating && !selected) return;
    if (!form.name.trim() || (creating && !form.code.trim())) { feedback.error("Group name and code are required."); return; }
    if (creating && form.scope_type !== "GLOBAL" && !contextValue()) { feedback.error(`Select the ${form.scope_type.toLowerCase()} context.`); return; }
    setBusy(true);
    try {
      let saved: Group;
      if (creating) {
        const payload = {
          name: form.name.trim(), code: form.code.trim(), description: form.description || null, membership_mode: form.membership_mode,
          scope_type: form.scope_type, network_id: form.scope_type === "NETWORK" ? form.network_id || null : null,
          city_id: form.scope_type === "CITY" ? form.city_id || null : null, location_id: form.scope_type === "LOCATION" ? form.location_id || null : null,
          sector_id: form.scope_type === "SECTOR" ? form.sector_id || null : null, device_scope: form.device_scope,
          sector_role: form.device_scope === "SECTOR" ? form.sector_role || null : null, metadata: {}, child_group_ids: canMembership ? editChildIds : [],
        };
        saved = await apiFetch<Group>("/device-groups", { method: "POST", body: JSON.stringify(payload) }, token);
        feedback.success("Group created.");
      } else {
        if (selected!.group_kind === "SYSTEM") return;
        saved = selected!;
        if (canUpdate) {
          const payload = { name: form.name.trim(), description: form.description || null, membership_mode: form.membership_mode, device_scope: form.device_scope, sector_role: form.device_scope === "SECTOR" ? form.sector_role || null : null, reconcile_memberships: forceReconcile, ...(canMembership ? { child_group_ids: editChildIds } : {}) };
          try {
            saved = await apiFetch<Group>(`/device-groups/${selected!.id}`, { method: "PATCH", body: JSON.stringify(payload) }, token);
          } catch (error) {
            if (error instanceof ApiError && ["GROUP_DYNAMIC_REQUIRES_RECONCILIATION", "GROUP_CRITERIA_HAS_INCOMPATIBLE_MEMBERS"].includes(error.code || "") && !forceReconcile) {
              setBusy(false);
              const confirmed = await dialog.confirm({ title: "Reconcile group memberships", message: "This update changes the group's membership rules and requires incompatible stored memberships to be removed. Continue with explicit reconciliation?", confirmLabel: "Reconcile and update" });
              if (confirmed) await save(true);
              return;
            }
            throw error;
          }
        }
        if (!canUpdate && canMembership) {
          await apiFetch(`/device-groups/${selected!.id}/children`, { method: "PUT", body: JSON.stringify({ child_group_ids: editChildIds }) }, token);
        }
        feedback.success(canUpdate ? "Group updated." : "Child groups updated.");
      }
      setCreating(false);
      await Promise.all([loadReferences(), loadGroups()]);
      if (onGroupsRefresh) await onGroupsRefresh();
      const fresh = await apiFetch<Group>(`/device-groups/${saved.id}`, {}, token); selectGroup(fresh);
    } catch (error) { feedback.error(friendlyError(error, `Unable to ${creating ? "create" : "update"} group.`)); }
    finally { setBusy(false); }
  };

  const contextValue = () => form.scope_type === "NETWORK" ? form.network_id : form.scope_type === "CITY" ? form.city_id : form.scope_type === "LOCATION" ? form.location_id : form.scope_type === "SECTOR" ? form.sector_id : "";
  const setContextValue = (value: string) => setForm({ ...form, network_id: form.scope_type === "NETWORK" ? value : "", city_id: form.scope_type === "CITY" ? value : "", location_id: form.scope_type === "LOCATION" ? value : "", sector_id: form.scope_type === "SECTOR" ? value : "" });

  const addMember = async () => {
    if (!selected || !manualDeviceId) return;
    setBusy(true);
    try { await apiFetch(`/device-groups/${selected.id}/devices/${manualDeviceId}`, { method: "POST" }, token); setManualDeviceId(""); setMemberRevision((v) => v + 1); feedback.success("Device added to the group."); }
    catch (error) { feedback.error(friendlyError(error, "Unable to add device to group.")); }
    finally { setBusy(false); }
  };
  const removeMember = async (device: Device) => {
    if (!selected || !await dialog.confirm({ message: `Remove ${device.display_name} from ${selected.name}?`, confirmLabel: "Remove" })) return;
    try { await apiFetch(`/device-groups/${selected.id}/devices/${device.id}`, { method: "DELETE" }, token); setMemberRevision((v) => v + 1); feedback.success("Device removed from the group."); }
    catch (error) { feedback.error(friendlyError(error, "Unable to remove device from group.")); }
  };

  const deleteGroups = async (idsOverride?: string[]) => {
    const ids = (idsOverride ?? selectedIds).filter((id) => { const group = groups.find((row) => row.id === id) || (selected?.id === id ? selected : null); return group?.group_kind !== "SYSTEM"; });
    if (!ids.length) return;
    if (!await dialog.confirm({ title: "Move selected groups to Recycle Bin", message: `Move ${ids.length} selected custom group(s) to the Recycle Bin? Their direct memberships and parent/child nesting links will be detached with the deleted group. Devices and the other groups themselves will remain active.`, confirmLabel: "Move selected", tone: "danger" })) return;
    setBusy(true); let done = 0; let failed = 0;
    for (const id of ids) {
      try {
        await apiFetch(`/device-groups/${id}?confirmed=true`, { method: "DELETE" }, token); done += 1;
      } catch { failed += 1; }
    }
    if (done) feedback.success(`${done} group(s) moved to the Recycle Bin.`);
    if (failed) feedback.warning(`${failed} group(s) could not be recycled because of dependencies or validation rules.`);
    setSelected(null); setSelectedIds([]); await Promise.all([loadGroups(), loadReferences()]); if (onGroupsRefresh) await onGroupsRefresh(); setBusy(false);
  };

  const openItems = (group: Group, fromChild = false) => {
    if (!fromChild) setBreadcrumb([group]); else setBreadcrumb((current) => [...current, group]);
    setItemsGroup(group); setItemsPage(1); setItemsSearch(""); setItemsItemType(""); setItemsDeviceType(""); setItemsLifecycle(""); setItemsOperational(""); setIncludeAllChildren(true); setSelectedChildren([]); setTab("items");
  };

  const openBreadcrumb = (index: number) => {
    const group = breadcrumb[index]; setBreadcrumb((current) => current.slice(0, index + 1)); setItemsGroup(group); setItemsPage(1); setIncludeAllChildren(true); setSelectedChildren([]);
  };

  const openChildItem = (id: string) => {
    const child = itemsChildren.find((group) => group.id === id);
    if (child) openItems(child, true);
  };

  const loadItems = async () => {
    if (!itemsGroup) { setItemsRows([]); setItemsChildren([]); setItemsTotal(0); return; }
    const params = new URLSearchParams({ page: String(itemsPage), page_size: String(itemsPageSize), sort_by: itemsSort.key, sort_direction: itemsSort.direction, include_all_children: String(includeAllChildren) });
    if (debouncedItemsSearch.trim()) params.set("search", debouncedItemsSearch.trim());
    if (itemsItemType) params.set("item_type", itemsItemType);
    if (itemsDeviceType) params.set("device_type", itemsDeviceType);
    if (itemsLifecycle) params.set("lifecycle_state", itemsLifecycle);
    if (itemsOperational) params.set("operational_state", itemsOperational);
    if (!includeAllChildren && selectedChildren.length) params.set("child_group_ids", selectedChildren.join(","));
    try { const result = await apiFetch<GroupItemsPage>(`/device-groups/${itemsGroup.id}/items/page?${params}`, {}, token); setItemsRows(result.items); setItemsChildren(result.child_groups); setItemsTotal(result.total); }
    catch (error) { feedback.error(friendlyError(error, "Unable to load Group Items.")); }
  };
  useEffect(() => { setItemsPage(1); }, [debouncedItemsSearch, itemsItemType, itemsDeviceType, itemsLifecycle, itemsOperational, itemsPageSize, itemsSort.key, itemsSort.direction, includeAllChildren, selectedChildren.join(",")]);
  useEffect(() => { if (tab === "items") void loadItems(); }, [tab, itemsGroup?.id, itemsPage, itemsPageSize, debouncedItemsSearch, itemsItemType, itemsDeviceType, itemsLifecycle, itemsOperational, itemsSort.key, itemsSort.direction, includeAllChildren, selectedChildren.join(",")]);

  const toggleGroup = (group: Group, checked: boolean) => {
    if (group.group_kind === "SYSTEM") return;
    setSelectedIds((current) => checked ? [...new Set([...current, group.id])] : current.filter((id) => id !== group.id));
  };
  const selectableGroups = groups.filter((group) => group.group_kind !== "SYSTEM");
  const allSelected = selectableGroups.length > 0 && selectableGroups.every((group) => selectedIds.includes(group.id));

  const groupEditor = () => {
    if (!creating && !selected) return <EmptyState text="Select a group to view or edit it, or create a new custom group."/>;
    const system = selected?.group_kind === "SYSTEM";
    const editable = creating ? canCreate : canUpdate && !system;
    const childEditable = !system && canMembership && (creating ? canCreate : true);
    const canSaveEditor = !system && (creating ? canCreate : canUpdate || canMembership);
    const contextOptions = form.scope_type === "NETWORK" ? refs.networks.map((row) => ({ id: row.id, label: row.name, description: row.code })) : form.scope_type === "CITY" ? refs.cities.map((row) => ({ id: row.id, label: row.name, description: networkById.get(row.network_id)?.name })) : form.scope_type === "LOCATION" ? refs.locations.map((row) => ({ id: row.id, label: row.name, description: cityById.get(row.city_id)?.name })) : form.scope_type === "SECTOR" ? refs.sectors.map((row) => ({ id: row.id, label: row.name, description: locationById.get(row.location_id)?.name })) : [];
    return <>
      {system && <div className="inline-notice">System groups are managed automatically and cannot be edited.</div>}
      <div className="form-grid two"><label><span className="required-field-label">Name</span><Input unstyled required value={form.name} disabled={!editable} onChange={(e) => setForm({ ...form, name: e.target.value })}/></label><label><span className="required-field-label">Code</span><Input unstyled required value={form.code} disabled={!creating || !canCreate} onChange={(e) => setForm({ ...form, code: e.target.value })}/></label></div>
      <label>Description<Textarea unstyled rows={3} value={form.description} disabled={!editable} onChange={(e) => setForm({ ...form, description: e.target.value })}/></label>
      <div className="form-grid two"><label>Category<Input unstyled value={system ? "SYSTEM" : "CUSTOM"} disabled /></label><label>Membership Mode<Select unstyled value={form.membership_mode} disabled={!editable || system} onChange={(e) => setForm({ ...form, membership_mode: e.target.value })}><option value="MANUAL">MANUAL</option><option value="DYNAMIC">DYNAMIC</option></Select></label></div>
      <div className="form-grid two"><label>Device Scope<Select unstyled value={form.device_scope} disabled={!editable || system} onChange={(e) => setForm({ ...form, device_scope: e.target.value, sector_role: e.target.value === "SECTOR" ? form.sector_role : "" })}>{DEVICE_SCOPES.map((value) => <option key={value}>{value}</option>)}</Select></label>{form.device_scope === "SECTOR" && <label>Sector Role<Select unstyled value={form.sector_role} disabled={!editable || system} onChange={(e) => setForm({ ...form, sector_role: e.target.value })}><option value="">Any Sector Role</option><option value="CUSTOMER_ACCESS">CUSTOMER_ACCESS</option><option value="BACKHAUL">BACKHAUL</option></Select></label>}</div>
      <div className="form-grid two"><label>Organizational Scope<Select unstyled value={form.scope_type} disabled={!creating || !canCreate} onChange={(e) => setForm({ ...form, scope_type: e.target.value, network_id: "", city_id: "", location_id: "", sector_id: "" })}>{SCOPE_TYPES.filter((value) => value === "GLOBAL" || canGeoRead).map((value) => <option key={value}>{value}</option>)}</Select></label>{form.scope_type !== "GLOBAL" && <label><span className="required-field-label">{form.scope_type[0] + form.scope_type.slice(1).toLowerCase()} Context</span>{creating ? <LocalSearchableCombobox required value={contextValue()} options={contextOptions} onChange={(option) => setContextValue(option?.id || "")} placeholder={`Search ${form.scope_type.toLowerCase()}...`} /> : <Input unstyled value={(selected?.context_name || (form.scope_type === "NETWORK" ? networkById.get(form.network_id)?.name : form.scope_type === "CITY" ? cityById.get(form.city_id)?.name : form.scope_type === "LOCATION" ? locationById.get(form.location_id)?.name : sectorById.get(form.sector_id)?.name) || "—")} disabled />}</label>}</div>
      {!system && canMembership && <label>Child Groups<EditableChildGroupSelector options={editChildOptions} total={editChildTotal} baseTotal={editChildBaseTotal} selected={editChildIds} search={editChildSearch} onSearch={setEditChildSearch} onSelected={setEditChildIds} loading={editChildLoading} disabled={!childEditable || busy} /></label>}
      {canSaveEditor && <div className="button-row editor-actions"><Button unstyled disabled={busy} onClick={() => { if (creating) setValidationAttempted(true); void save(); }}>{creating ? "Create" : canUpdate ? "Update" : "Update Children"}</Button>{creating && <Button unstyled className="secondary" onClick={() => setCreating(false)}>Cancel</Button>}</div>}
      {!creating && selected && canDelete && <div className="panel-subsection"><Button unstyled className="small danger" disabled={system || busy} title={system ? "Built-in system groups cannot be deleted." : "Move this group to the Recycle Bin."} onClick={() => { if (!system) void deleteGroups([selected.id]); }}>Move Group to Recycle Bin</Button></div>}
      {!creating && selected && !system && (selected.membership_mode || "MANUAL") === "MANUAL" && <div className="panel-subsection"><div className="panel-header"><div><h3 className="hover-help-title" data-help="Select the devices you want to include in this group.">Manual Membership</h3></div></div>{canMembership && <div className="group-member-add"><GroupDeviceSearchSelect token={token} groupId={selected.id} value={manualDeviceId} onChange={setManualDeviceId} disabled={busy}/><Button unstyled className="small" disabled={!manualDeviceId || busy} onClick={() => void addMember()}>Add Device</Button></div>}<div className="filter-row compact"><Input unstyled value={memberSearch} onChange={(e) => setMemberSearch(e.target.value)} placeholder="Search direct members..." /><TableExportButton token={token} tableId="group_members" filters={{ group_id: selected.id, search: debouncedMemberSearch, sort_by: memberSort.key, sort_direction: memberSort.direction }}/><ClearFiltersButton disabled={!memberSearch} onClick={()=>{setMemberSearch("");setMemberPage(1)}}/></div><DataTable viewportClassName="table-wrap" className="compact-table"><thead><tr><SortHeader label="Device" sortKey="display_name" sort={memberSort} onSort={(key) => setMemberSort((current) => nextSort(current, key))}/><SortHeader label="Lifecycle" sortKey="lifecycle_state" sort={memberSort} onSort={(key) => setMemberSort((current) => nextSort(current, key))}/><SortHeader label="Operational" sortKey="operational_state" sort={memberSort} onSort={(key) => setMemberSort((current) => nextSort(current, key))}/>{canMembership && <th>Membership</th>}</tr></thead><tbody>{memberRows.map((device) => <tr key={device.id}><td>{device.display_name}</td><td><Badge value={device.lifecycle_state}/></td><td><Badge value={device.operational_state}/></td>{canMembership && <td><Button unstyled className="small danger" onClick={() => void removeMember(device)}>Remove</Button></td>}</tr>)}{!memberRows.length && <tr><td colSpan={canMembership ? 4 : 3}><EmptyState text="No direct manual members match this search."/></td></tr>}<ServerPaginationRow colSpan={canMembership ? 4 : 3} page={memberPage} pageSize={memberPageSize} total={memberTotal} onPage={setMemberPage} onPageSize={setMemberPageSize} itemLabel="direct members" /></tbody></DataTable></div>}
    </>;
  };

  if (tab === "items") return <PageLayout className="group-page management-page">
    <div className="page-heading"><div><h2 className="hover-help-title" data-help="Review devices included in this group and manage contributing child groups.">Group Items</h2></div></div>
    <Tabs<Tab>
      ariaLabel="Device group views"
      value={tab}
      onChange={(nextTab) => { if (nextTab === "groups") setTab("groups"); else if (selected) openItems(selected); }}
      tabs={[{ id: "groups", label: "Groups" }, { id: "items", label: "Group Items", disabled: !selected && tab !== "items" }]}
    />
    <section className="panel"><div className="group-breadcrumb">{breadcrumb.map((group, index) => <span key={group.id}><Button unstyled className="table-link" onClick={() => openBreadcrumb(index)}>{group.name}</Button>{index < breadcrumb.length - 1 && <b>›</b>}</span>)}</div><div className="panel-header"><div><h3 className="hover-help-title" data-help="Selected child groups also contribute their members.">{itemsGroup?.name || "Group Items"}</h3></div></div>
      <div className="filter-row compact management-filter-row"><Input unstyled value={itemsSearch} onChange={(e) => setItemsSearch(e.target.value)} placeholder="Search group items..."/><Select unstyled value={itemsItemType} onChange={(e) => setItemsItemType(e.target.value)}><option value="">All Item Types</option><option value="GROUP">Groups</option><option value="DEVICE">Devices</option></Select><Select unstyled value={itemsDeviceType} onChange={(e) => setItemsDeviceType(e.target.value)}><option value="">All Classifications</option>{DEVICE_SCOPES.map((v) => <option key={v}>{v}</option>)}</Select><Select unstyled value={itemsLifecycle} onChange={(e) => setItemsLifecycle(e.target.value)}><option value="">All Lifecycle States</option><option>REGISTERED</option><option>ACTIVE</option><option>MAINTENANCE</option><option>DECOMMISSIONED</option></Select><Select unstyled value={itemsOperational} onChange={(e) => setItemsOperational(e.target.value)}><option value="">All Operational States</option><option>UP</option><option>DOWN</option><option>DEGRADED</option><option>UNKNOWN</option></Select>{itemsChildren.length > 0 && <ChildGroupSelector children={itemsChildren} all={includeAllChildren} selected={selectedChildren} onAll={setIncludeAllChildren} onSelected={setSelectedChildren}/>}<TableExportButton token={token} tableId="group_items" filters={{ group_id: itemsGroup?.id || "", search: debouncedItemsSearch, item_type: itemsItemType, device_type: itemsDeviceType, lifecycle_state: itemsLifecycle, operational_state: itemsOperational, include_all_children: includeAllChildren, child_group_ids: selectedChildren, sort_by: itemsSort.key, sort_direction: itemsSort.direction }} disabled={!itemsGroup}/><ClearFiltersButton disabled={!itemsSearch&&!itemsItemType&&!itemsDeviceType&&!itemsLifecycle&&!itemsOperational&&includeAllChildren&&selectedChildren.length===0} onClick={()=>{setItemsSearch("");setItemsItemType("");setItemsDeviceType("");setItemsLifecycle("");setItemsOperational("");setIncludeAllChildren(true);setSelectedChildren([]);setItemsPage(1)}}/></div>
      <DataTable viewportClassName="table-wrap management-table-wrap" className="compact-table clickable-table"><thead><tr><SortHeader label="Name" sortKey="display_name" sort={itemsSort} onSort={(key) => setItemsSort((current) => nextSort(current, key))}/><SortHeader label="Type" sortKey="item_type" sort={itemsSort} onSort={(key) => setItemsSort((current) => nextSort(current, key))}/><SortHeader label="Classification" sortKey="device_type" sort={itemsSort} onSort={(key) => setItemsSort((current) => nextSort(current, key))}/><th>Management IP</th><th>Source Group</th><SortHeader label="Lifecycle" sortKey="lifecycle_state" sort={itemsSort} onSort={(key) => setItemsSort((current) => nextSort(current, key))}/><SortHeader label="Operational" sortKey="operational_state" sort={itemsSort} onSort={(key) => setItemsSort((current) => nextSort(current, key))}/><th>Items</th></tr></thead><tbody>{itemsRows.map((item) => item.item_type === "GROUP" ? <tr key={`group-${item.id}`} className="group-item-row" onDoubleClick={() => openChildItem(item.id)}><td><Button unstyled className="table-link" onClick={() => openChildItem(item.id)}>{item.display_name}</Button>{item.code && <span className="cell-subtext">{item.code}</span>}</td><td><Badge value="GROUP"/></td><td>{item.device_type_code || "ANY"}</td><td>—</td><td>{item.source_groups[0] || itemsGroup?.name || "—"}</td><td>—</td><td>—</td><td>{item.item_count ?? 0}</td></tr> : <tr key={`device-${item.id}`}><td><strong>{item.display_name}</strong>{item.hostname && <span className="cell-subtext">{item.hostname}</span>}</td><td><Badge value="DEVICE"/></td><td>{item.device_type_code}</td><td>{item.management_ip || "—"}</td><td title={item.source_groups.join(", ")}>{item.source_groups.length > 1 ? `${item.source_groups[0]} +${item.source_groups.length - 1}` : item.source_groups[0] || "—"}</td><td>{item.lifecycle_state ? <Badge value={item.lifecycle_state}/> : "—"}</td><td>{item.operational_state ? <Badge value={item.operational_state}/> : "—"}</td><td>—</td></tr>)}{!itemsRows.length && <tr><td colSpan={8}><EmptyState text="This group currently has no matching items."/></td></tr>}<ServerPaginationRow colSpan={8} page={itemsPage} pageSize={itemsPageSize} total={itemsTotal} onPage={setItemsPage} onPageSize={setItemsPageSize} itemLabel="group items" /></tbody></DataTable>
    </section>
  </PageLayout>;

  return <PageLayout className="group-page management-page">
    <div className="page-heading"><div><h2 className="hover-help-title" data-help="Manage system and custom device groups.">Device Groups</h2></div></div>
    <Tabs<Tab>
      ariaLabel="Device group views"
      value={tab}
      onChange={(nextTab) => { if (nextTab === "items") { if (selected) openItems(selected); } else setTab("groups"); }}
      tabs={[{ id: "groups", label: "Groups" }, { id: "items", label: "Group Items", disabled: !selected }]}
    />
    <div className="management-split"><section className="panel management-list-panel"><div className="panel-header"><div><h3>Groups</h3><span>{total} configured</span></div><div className="button-row"><TableExportButton token={token} tableId="groups" filters={{ search: debouncedSearch, group_kind: kindFilter, membership_mode: modeFilter, scope_type: scopeFilter, device_scope: deviceFilter, sector_role: roleFilter, sort_by: sort.key, sort_direction: sort.direction }}/>{canDelete && selectedIds.length > 0 && <Button unstyled className="small danger" disabled={busy} onClick={() => void deleteGroups()}>Recycle selected ({selectedIds.length})</Button>}{canCreate && <Button unstyled className="small" onClick={startCreate}>Create Group</Button>}</div></div>
      <div className="filter-row compact management-filter-row"><Input unstyled value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search groups..."/><Select unstyled value={kindFilter} onChange={(e) => setKindFilter(e.target.value)}><option value="">All Categories</option><option value="SYSTEM">System</option><option value="CUSTOM">Custom</option></Select><Select unstyled value={modeFilter} onChange={(e) => setModeFilter(e.target.value)}><option value="">All Membership Modes</option><option value="DYNAMIC">Dynamic</option><option value="MANUAL">Manual</option></Select><Select unstyled value={scopeFilter} onChange={(e) => setScopeFilter(e.target.value)}><option value="">All Organizational Scopes</option>{SCOPE_TYPES.map((v) => <option key={v}>{v}</option>)}</Select><Select unstyled value={deviceFilter} onChange={(e) => setDeviceFilter(e.target.value)}><option value="">All Device Scopes</option>{DEVICE_SCOPES.map((v) => <option key={v}>{v}</option>)}</Select><Select unstyled value={roleFilter} onChange={(e) => setRoleFilter(e.target.value)}><option value="">All Sector Roles</option><option value="CUSTOMER_ACCESS">CUSTOMER_ACCESS</option><option value="BACKHAUL">BACKHAUL</option></Select><ClearFiltersButton disabled={!search&&!kindFilter&&!modeFilter&&!scopeFilter&&!deviceFilter&&!roleFilter} onClick={()=>{setSearch("");setKindFilter("");setModeFilter("");setScopeFilter("");setDeviceFilter("");setRoleFilter("");setPage(1)}}/></div>
      <DataTable viewportClassName="table-wrap management-table-wrap" className="clickable-table compact-table"><thead><tr>{canDelete && <th className="select-col"><Input unstyled type="checkbox" checked={allSelected} onChange={(e) => setSelectedIds(e.target.checked ? selectableGroups.map((group) => group.id) : [])}/></th>}<SortHeader label="Name" sortKey="name" sort={sort} onSort={(key) => setSort((current) => nextSort(current, key))}/><SortHeader label="Category" sortKey="group_kind" sort={sort} onSort={(key) => setSort((current) => nextSort(current, key))}/><SortHeader label="Mode" sortKey="membership_mode" sort={sort} onSort={(key) => setSort((current) => nextSort(current, key))}/><SortHeader label="Device Scope" sortKey="device_scope" sort={sort} onSort={(key) => setSort((current) => nextSort(current, key))}/><SortHeader label="Org Scope" sortKey="scope_type" sort={sort} onSort={(key) => setSort((current) => nextSort(current, key))}/><SortHeader label="Context" sortKey="context_name" sort={sort} onSort={(key) => setSort((current) => nextSort(current, key))}/><SortHeader label="Sector Role" sortKey="sector_role" sort={sort} onSort={(key) => setSort((current) => nextSort(current, key))}/><SortHeader label="Parent" sortKey="parent_group_name" sort={sort} onSort={(key) => setSort((current) => nextSort(current, key))}/><SortHeader label="Devices" sortKey="device_count" sort={sort} onSort={(key) => setSort((current) => nextSort(current, key))}/><SortHeader label="Children" sortKey="child_count" sort={sort} onSort={(key) => setSort((current) => nextSort(current, key))}/></tr></thead><tbody>{groups.map((group) => <tr key={group.id} className={selected?.id === group.id ? "selected-row" : ""} onClick={() => selectGroup(group)} onDoubleClick={() => openItems(group)}>{canDelete && <td onClick={(e) => e.stopPropagation()}><Input unstyled type="checkbox" disabled={group.group_kind === "SYSTEM"} title={group.group_kind === "SYSTEM" ? "Built-in system groups cannot be deleted." : undefined} checked={selectedIds.includes(group.id)} onChange={(e) => toggleGroup(group, e.target.checked)}/></td>}<td><Button unstyled className="table-link" onClick={(e) => { e.stopPropagation(); selectGroup(group); }} onDoubleClick={(e) => { e.stopPropagation(); openItems(group); }}>{group.name}</Button><span className="cell-subtext">{group.code}</span></td><td><Badge value={group.group_kind || "CUSTOM"}/></td><td><Badge value={group.membership_mode || "MANUAL"}/></td><td>{group.device_scope || "ANY"}</td><td>{group.scope_type}</td><td>{group.context_name || "—"}</td><td>{group.sector_role || "—"}</td><td>{group.parent_group_name || "—"}</td><td>{group.device_count ?? 0}</td><td>{group.child_count ?? 0}</td></tr>)}{!groups.length && <tr><td colSpan={10 + (canDelete ? 1 : 0)}><EmptyState text="No groups match the current filters."/></td></tr>}<ServerPaginationRow colSpan={10 + (canDelete ? 1 : 0)} page={page} pageSize={pageSize} total={total} onPage={setPage} onPageSize={setPageSize} itemLabel="groups" /></tbody></DataTable>
    </section><section className={`panel management-editor-panel${creating && validationAttempted ? " validation-attempted" : ""}`}><div className="panel-header"><div><h3>{creating ? "Create Group" : selected ? selected.name : "Group Details"}</h3>{selected?.group_kind === "SYSTEM" && <span>Managed automatically by the system.</span>}</div></div>{groupEditor()}</section></div>
  </PageLayout>;
}
