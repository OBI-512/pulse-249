import { PageLayout } from "../design-system/layouts";
import { useEffect, useMemo, useRef, useState } from "react";
import { apiFetch } from "../api/client";
import { useDialog } from "../components/common/DialogSystem";
import { useFeedback } from "../components/common/FeedbackSystem";
import { LocalSearchableCombobox } from "../design-system/composites/SearchableSelect";
import { EmptyState } from "../design-system/composites/AsyncState";
import { StatusBadge as Badge } from "../design-system/composites/Status";
import { useDebouncedValue } from "../hooks/useDebouncedValue";
import type { City, Location, Network, PageResult, Sector, SortState } from "../types";
import { friendlyError } from "../utils/feedback";
import { nextSort } from "../utils/sorting";
import { Tabs } from "../design-system/composites/Tabs";

import { DataTable } from "../design-system/data/DataTable";
import { ServerPaginationRow } from "../design-system/data/Pagination";
import { SortHeader } from "../design-system/data/SortHeader";
import { TableExportButton } from "../design-system/data/TableExport";
import { ClearFiltersButton } from "../design-system/composites/FilterBar";
import { Button, Checkbox, Input, Select, Textarea } from "../design-system/primitives";
type Tab = "networks" | "cities" | "locations" | "sectors";
type Entity = Network | City | Location | Sector;

function initialNetworkWorkspaceTab(): Tab {
  if (typeof window === "undefined") return "networks";
  try {
    const requested = window.sessionStorage.getItem("fttw.network-workspace-tab");
    window.sessionStorage.removeItem("fttw.network-workspace-tab");
    if (requested === "networks" || requested === "cities" || requested === "locations" || requested === "sectors") return requested;
  } catch { /* storage can be unavailable in hardened browsers */ }
  return "networks";
}
type ReferenceData = { networks: Network[]; cities: City[]; locations: Location[]; sectors: Sector[] };

const blankNetwork = { name: "", code: "", description: "", status: "ACTIVE" };
const blankCity = { name: "", code: "", description: "", status: "ACTIVE", service_vlan_id: "", network_id: "" };
const blankLocation = { name: "", code: "", address: "", latitude: "", longitude: "", description: "", status: "ACTIVE", city_id: "" };
const blankSector = { name: "", code: "", sequence_number: "", description: "", status: "ACTIVE", role: "CUSTOMER_ACCESS", customer_vlan_start: "", customer_vlan_end: "", location_id: "" };

export function NetworkPage({ token, permissions = [], onReferenceRefresh }: any) {
  const dialog = useDialog();
  const feedback = useFeedback();
  const [tab, setTab] = useState<Tab>(() => initialNetworkWorkspaceTab());
  const [items, setItems] = useState<Entity[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [sort, setSort] = useState<SortState>({ key: "name", direction: "asc" });
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebouncedValue(search, 300);
  const [statusFilter, setStatusFilter] = useState("");
  const [networkFilter, setNetworkFilter] = useState("");
  const [cityFilter, setCityFilter] = useState("");
  const [locationFilter, setLocationFilter] = useState("");
  const [roleFilter, setRoleFilter] = useState("");
  const [boundFilter, setBoundFilter] = useState("");
  const [serviceVlanFilter, setServiceVlanFilter] = useState("");
  const [customerVlanFilter, setCustomerVlanFilter] = useState("");
  const [selected, setSelected] = useState<Entity | null>(null);
  const [creating, setCreating] = useState(false);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [validationAttempted, setValidationAttempted] = useState(false);
  const entityLabel = tab === "networks" ? "Network" : tab === "cities" ? "City" : tab === "locations" ? "Location" : "Sector";
  const [refs, setRefs] = useState<ReferenceData>({ networks: [], cities: [], locations: [], sectors: [] });
  const [networkForm, setNetworkForm] = useState({ ...blankNetwork });
  const [cityForm, setCityForm] = useState({ ...blankCity });
  const [locationForm, setLocationForm] = useState({ ...blankLocation });
  const [sectorForm, setSectorForm] = useState({ ...blankSector });
  const requestRef = useRef(0);

  const canReadNetwork = permissions.includes("network.read");
  const canReadGeo = permissions.includes("geo.read");
  const canCreateNetwork = permissions.includes("network.create");
  const canUpdateNetwork = permissions.includes("network.update");
  const canDeleteNetwork = permissions.includes("network.delete");
  const canCreateGeo = permissions.includes("geo.create");
  const canUpdateGeo = permissions.includes("geo.update");
  const canDeleteGeo = permissions.includes("geo.delete");
  const canCreate = tab === "networks" ? canCreateNetwork : canCreateGeo;
  const canUpdate = tab === "networks" ? canUpdateNetwork : canUpdateGeo;
  const canDelete = tab === "networks" ? canDeleteNetwork : canDeleteGeo;

  const networkById = useMemo(() => new Map(refs.networks.map((item) => [item.id, item])), [refs.networks]);
  const cityById = useMemo(() => new Map(refs.cities.map((item) => [item.id, item])), [refs.cities]);
  const locationById = useMemo(() => new Map(refs.locations.map((item) => [item.id, item])), [refs.locations]);
  const eligibleCities = useMemo(() => refs.cities.filter((city) => (!networkFilter || city.network_id === networkFilter) && (!cityFilter || city.id === cityFilter)), [refs.cities, networkFilter, cityFilter]);
  const serviceVlanOptions = useMemo(() => Array.from(new Set(eligibleCities.map((city) => city.service_vlan_id).filter((value): value is number => value != null))).sort((a,b)=>a-b).map((value)=>({id:String(value),label:String(value),description:"Service VLAN"})), [eligibleCities]);
  const customerVlanOptions = useMemo(() => {
    const cityIds=new Set(eligibleCities.filter(city=>!serviceVlanFilter||String(city.service_vlan_id)===serviceVlanFilter).map(city=>city.id));
    const locationIds=new Set(refs.locations.filter(location=>cityIds.has(location.city_id)&&(!locationFilter||location.id===locationFilter)).map(location=>location.id));
    const values=new Set<number>();
    for(const sector of refs.sectors){
      if(!locationIds.has(sector.location_id)||sector.customer_vlan_start==null||sector.customer_vlan_end==null)continue;
      for(let vlan=sector.customer_vlan_start;vlan<=sector.customer_vlan_end;vlan++)values.add(vlan);
    }
    return Array.from(values).sort((a,b)=>a-b).map(value=>({id:String(value),label:String(value),description:"Customer VLAN"}));
  },[eligibleCities,refs.locations,refs.sectors,serviceVlanFilter,locationFilter]);

  const loadReferences = async () => {
    if (!canReadGeo) { setRefs({ networks: [], cities: [], locations: [], sectors: [] }); return; }
    const data = await apiFetch<ReferenceData>("/geography/scope-options", {}, token);
    setRefs(data);
  };

  const load = async () => {
    if ((tab === "networks" && !canReadNetwork) || (tab !== "networks" && !canReadGeo)) { setItems([]); setTotal(0); return; }
    const requestId = ++requestRef.current;
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize), sort_by: sort.key, sort_direction: sort.direction });
    if (debouncedSearch.trim()) params.set("search", debouncedSearch.trim());
    if (statusFilter) params.set("status", statusFilter);
    let path = "/networks/page";
    if (tab === "cities") {
      path = "/cities/page";
      if (networkFilter) params.set("network_id", networkFilter);
      if (serviceVlanFilter) params.set("service_vlan_id", serviceVlanFilter);
    } else if (tab === "locations") {
      path = "/locations/page";
      if (networkFilter) params.set("network_id", networkFilter);
      if (cityFilter) params.set("city_id", cityFilter);
      if (serviceVlanFilter) params.set("service_vlan_id", serviceVlanFilter);
      if (customerVlanFilter) params.set("customer_vlan_id", customerVlanFilter);
    } else if (tab === "sectors") {
      path = "/sectors/page";
      if (networkFilter) params.set("network_id", networkFilter);
      if (cityFilter) params.set("city_id", cityFilter);
      if (locationFilter) params.set("location_id", locationFilter);
      if (roleFilter) params.set("role", roleFilter);
      if (boundFilter) params.set("bound", boundFilter);
      if (serviceVlanFilter) params.set("service_vlan_id", serviceVlanFilter);
      if (customerVlanFilter) params.set("customer_vlan_id", customerVlanFilter);
    }
    try {
      const result = await apiFetch<PageResult<any>>(`${path}?${params}`, {}, token);
      if (requestRef.current !== requestId) return;
      setItems(result.items);
      setTotal(result.total);
      setSelectedIds([]);
      const maxPage = Math.max(1, Math.ceil(result.total / pageSize));
      if (page > maxPage) setPage(maxPage);
    } catch (error) {
      if (requestRef.current === requestId) feedback.error(friendlyError(error, `Unable to load ${tab}.`));
    }
  };

  useEffect(() => { void loadReferences().catch((error) => feedback.error(friendlyError(error, "Unable to load geography reference data."))); }, [token, canReadGeo]);
  useEffect(() => {
    const allowed: Tab[] = [...(canReadNetwork ? ["networks" as Tab] : []), ...(canReadGeo ? ["cities" as Tab, "locations" as Tab, "sectors" as Tab] : [])];
    if (allowed.length && !allowed.includes(tab)) setTab(allowed[0]);
  }, [canReadNetwork, canReadGeo, tab]);
  useEffect(() => { setPage(1); setSelected(null); setCreating(false); setSelectedIds([]); setSort({ key: "name", direction: "asc" }); if(tab==="networks"){setServiceVlanFilter("");setCustomerVlanFilter("")} if(tab==="cities")setCustomerVlanFilter(""); }, [tab]);
  useEffect(() => { setPage(1); }, [debouncedSearch, statusFilter, networkFilter, cityFilter, locationFilter, roleFilter, boundFilter, serviceVlanFilter, customerVlanFilter, pageSize]);
  useEffect(() => { void load(); }, [tab, page, pageSize, sort.key, sort.direction, debouncedSearch, statusFilter, networkFilter, cityFilter, locationFilter, roleFilter, boundFilter, serviceVlanFilter, customerVlanFilter]);

  const resetDependentFilters = (level: "network" | "city") => {
    if (level === "network") { setCityFilter(""); setLocationFilter(""); setServiceVlanFilter(""); setCustomerVlanFilter(""); }
    if (level === "city") { setLocationFilter(""); setServiceVlanFilter(""); setCustomerVlanFilter(""); }
  };

  const selectItem = (item: Entity) => {
    setSelected(item); setCreating(false);
    if (tab === "networks") {
      const row = item as Network; setNetworkForm({ name: row.name, code: row.code, description: row.description || "", status: row.status });
    } else if (tab === "cities") {
      const row = item as City; setCityForm({ name: row.name, code: row.code, description: row.description || "", status: row.status, service_vlan_id: row.service_vlan_id == null ? "" : String(row.service_vlan_id), network_id: row.network_id });
    } else if (tab === "locations") {
      const row = item as Location; setLocationForm({ name: row.name, code: row.code, address: row.address || "", latitude: row.latitude == null ? "" : String(row.latitude), longitude: row.longitude == null ? "" : String(row.longitude), description: row.description || "", status: row.status, city_id: row.city_id });
    } else {
      const row = item as Sector; setSectorForm({ name: row.name, code: row.code, sequence_number: row.sequence_number == null ? "" : String(row.sequence_number), description: row.description || "", status: row.status, role: row.role || "CUSTOMER_ACCESS", customer_vlan_start: row.customer_vlan_start == null ? "" : String(row.customer_vlan_start), customer_vlan_end: row.customer_vlan_end == null ? "" : String(row.customer_vlan_end), location_id: row.location_id });
    }
  };

  const startCreate = () => {
    setValidationAttempted(false); setSelected(null); setCreating(true);
    if (tab === "networks") setNetworkForm({ ...blankNetwork });
    else if (tab === "cities") setCityForm({ ...blankCity, network_id: networkFilter });
    else if (tab === "locations") setLocationForm({ ...blankLocation, city_id: cityFilter });
    else setSectorForm({ ...blankSector, location_id: locationFilter });
  };

  const refreshAll = async () => {
    await Promise.all([load(), loadReferences()]);
    if (onReferenceRefresh) await onReferenceRefresh();
  };

  const save = async () => {
    if (!creating && !selected) return;
    setBusy(true);
    try {
      if (tab === "networks") {
        if (!networkForm.name.trim() || (creating && !networkForm.code.trim())) throw new Error("Name and code are required.");
        const path = creating ? "/networks" : `/networks/${selected!.id}`;
        const body = creating ? networkForm : { name: networkForm.name.trim(), description: networkForm.description || null, status: networkForm.status };
        const row = await apiFetch<Network>(path, { method: creating ? "POST" : "PATCH", body: JSON.stringify(body) }, token);
        feedback.success(creating ? "Network created." : "Network updated."); selectItem(row);
      } else if (tab === "cities") {
        if (!cityForm.name.trim() || !cityForm.service_vlan_id || (creating && (!cityForm.code.trim() || !cityForm.network_id))) throw new Error("Name, code, Network and Service VLAN are required.");
        const path = creating ? `/networks/${cityForm.network_id}/cities` : `/cities/${selected!.id}`;
        const body = creating ? { name: cityForm.name.trim(), code: cityForm.code.trim(), description: cityForm.description || null, status: cityForm.status, service_vlan_id: Number(cityForm.service_vlan_id) } : { name: cityForm.name.trim(), description: cityForm.description || null, status: cityForm.status, service_vlan_id: Number(cityForm.service_vlan_id) };
        const row = await apiFetch<City>(path, { method: creating ? "POST" : "PATCH", body: JSON.stringify(body) }, token);
        feedback.success(creating ? "City created." : "City updated."); selectItem(row);
      } else if (tab === "locations") {
        if (!locationForm.name.trim() || (creating && (!locationForm.code.trim() || !locationForm.city_id))) throw new Error("Name, code and City are required.");
        const path = creating ? `/cities/${locationForm.city_id}/locations` : `/locations/${selected!.id}`;
        const common = { name: locationForm.name.trim(), address: locationForm.address || null, latitude: locationForm.latitude ? Number(locationForm.latitude) : null, longitude: locationForm.longitude ? Number(locationForm.longitude) : null, description: locationForm.description || null, status: locationForm.status, metadata: {} };
        const body = creating ? { ...common, code: locationForm.code.trim() } : common;
        const row = await apiFetch<Location>(path, { method: creating ? "POST" : "PATCH", body: JSON.stringify(body) }, token);
        feedback.success(creating ? "Location created." : "Location updated."); selectItem(row);
      } else {
        if (!sectorForm.name.trim() || (creating && (!sectorForm.code.trim() || !sectorForm.location_id))) throw new Error("Name, code and Location are required.");
        const path = creating ? `/locations/${sectorForm.location_id}/sectors` : `/sectors/${selected!.id}`;
        const vlanStart = sectorForm.customer_vlan_start ? Number(sectorForm.customer_vlan_start) : null;
        const vlanEnd = sectorForm.customer_vlan_end ? Number(sectorForm.customer_vlan_end) : null;
        if ((vlanStart == null) !== (vlanEnd == null)) throw new Error("Customer VLAN start and end must be set together.");
        const common = { name: sectorForm.name.trim(), sequence_number: sectorForm.sequence_number ? Number(sectorForm.sequence_number) : null, description: sectorForm.description || null, status: sectorForm.status, role: sectorForm.role, customer_vlan_start: vlanStart, customer_vlan_end: vlanEnd, metadata: {} };
        const body = creating ? { ...common, code: sectorForm.code.trim() } : common;
        const row = await apiFetch<Sector>(path, { method: creating ? "POST" : "PATCH", body: JSON.stringify(body) }, token);
        feedback.success(creating ? "Sector created." : "Sector updated."); selectItem(row);
      }
      setCreating(false); await refreshAll();
    } catch (error) {
      feedback.error(error instanceof Error && !("status" in error) ? error.message : friendlyError(error, `Unable to ${creating ? "create" : "update"} ${entityLabel.toLowerCase()}.`));
    } finally { setBusy(false); }
  };

  const deleteSelected = async () => {
    if (!selectedIds.length) return;
    if (!await dialog.confirm({ title: "Move selected items to Recycle Bin", message: `Move ${selectedIds.length} selected ${tab} item(s) to the Recycle Bin? Existing dependency protections will still be enforced for every item.`, confirmLabel: "Move selected", tone: "danger" })) return;
    setBusy(true);
    const base = tab === "networks" ? "/networks" : tab === "cities" ? "/cities" : tab === "locations" ? "/locations" : "/sectors";
    let done = 0; const failures: string[] = [];
    for (const id of selectedIds) {
      try {
        await apiFetch(`${base}/${id}?confirmed=true`, { method: "DELETE" }, token); done += 1;
      } catch { failures.push(id); }
    }
    if (done) feedback.success(`${done} item(s) moved to the Recycle Bin.`);
    if (failures.length) feedback.warning(`${failures.length} selected item(s) were not deleted because of dependencies or another validation rule.`, "Batch action partially completed");
    setSelected(null); setSelectedIds([]); await refreshAll(); setBusy(false);
  };

  const openChildren = (item: Entity) => {
    if (tab === "networks") { if (!canReadGeo) return; setNetworkFilter(item.id); resetDependentFilters("network"); setTab("cities"); }
    else if (tab === "cities") { const row = item as City; setNetworkFilter(row.network_id); setCityFilter(row.id); resetDependentFilters("city"); setTab("locations"); }
    else if (tab === "locations") { const row = item as Location; const city = cityById.get(row.city_id); setNetworkFilter(city?.network_id || row.network_id || ""); setCityFilter(row.city_id); setLocationFilter(row.id); setTab("sectors"); }
  };

  const toggleAll = (checked: boolean) => setSelectedIds(checked ? items.map((item) => item.id) : []);
  const toggleOne = (id: string, checked: boolean) => setSelectedIds((current) => checked ? [...new Set([...current, id])] : current.filter((value) => value !== id));
  const selectedAll = items.length > 0 && items.every((item) => selectedIds.includes(item.id));
  const sortBy = (key: string) => setSort((current) => nextSort(current, key));

  const table = () => {
    const deleteColumn = canDelete ? 1 : 0;
    if (tab === "networks") return <DataTable viewportClassName="table-wrap management-table-wrap" className="clickable-table compact-table"><thead><tr>{canDelete && <th className="select-col"><Checkbox unstyled checked={selectedAll} onChange={(e) => toggleAll(e.target.checked)} /></th>}<SortHeader label="Name" sortKey="name" sort={sort} onSort={sortBy}/><SortHeader label="Code" sortKey="code" sort={sort} onSort={sortBy}/><SortHeader label="Status" sortKey="status" sort={sort} onSort={sortBy}/><SortHeader label="Cities" sortKey="city_count" sort={sort} onSort={sortBy}/><th>Description</th></tr></thead><tbody>{(items as Network[]).map((row) => <tr key={row.id} className={selected?.id === row.id ? "selected-row" : ""} onClick={() => selectItem(row)} onDoubleClick={() => openChildren(row)}>{canDelete && <td onClick={(e) => e.stopPropagation()}><Checkbox unstyled checked={selectedIds.includes(row.id)} onChange={(e) => toggleOne(row.id, e.target.checked)} /></td>}<td><Button unstyled className="table-link" onClick={(e) => { e.stopPropagation(); selectItem(row); }}>{row.name}</Button></td><td>{row.code}</td><td><Badge value={row.status}/></td><td>{row.city_count ?? 0}</td><td className="truncate-cell">{row.description || "—"}</td></tr>)}{!items.length && <tr><td colSpan={5 + deleteColumn}><EmptyState text="No networks match the current filters."/></td></tr>}<ServerPaginationRow colSpan={5 + deleteColumn} page={page} pageSize={pageSize} total={total} onPage={setPage} onPageSize={setPageSize} itemLabel="networks" /></tbody></DataTable>;
    if (tab === "cities") return <DataTable viewportClassName="table-wrap management-table-wrap" className="clickable-table compact-table"><thead><tr>{canDelete && <th className="select-col"><Checkbox unstyled checked={selectedAll} onChange={(e) => toggleAll(e.target.checked)} /></th>}<SortHeader label="Name" sortKey="name" sort={sort} onSort={sortBy}/><SortHeader label="Code" sortKey="code" sort={sort} onSort={sortBy}/><SortHeader label="Network" sortKey="network_name" sort={sort} onSort={sortBy}/><th>S-VLAN</th><SortHeader label="Status" sortKey="status" sort={sort} onSort={sortBy}/><SortHeader label="Locations" sortKey="location_count" sort={sort} onSort={sortBy}/><th>Description</th></tr></thead><tbody>{(items as City[]).map((row) => <tr key={row.id} className={selected?.id === row.id ? "selected-row" : ""} onClick={() => selectItem(row)} onDoubleClick={() => openChildren(row)}>{canDelete && <td onClick={(e) => e.stopPropagation()}><Checkbox unstyled checked={selectedIds.includes(row.id)} onChange={(e) => toggleOne(row.id, e.target.checked)} /></td>}<td><Button unstyled className="table-link" onClick={(e) => { e.stopPropagation(); selectItem(row); }}>{row.name}</Button></td><td>{row.code}</td><td>{row.network_name || networkById.get(row.network_id)?.name || "—"}</td><td>{row.service_vlan_id ?? "—"}</td><td><Badge value={row.status}/></td><td>{row.location_count ?? 0}</td><td className="truncate-cell">{row.description || "—"}</td></tr>)}{!items.length && <tr><td colSpan={7 + deleteColumn}><EmptyState text="No cities match the current filters."/></td></tr>}<ServerPaginationRow colSpan={7 + deleteColumn} page={page} pageSize={pageSize} total={total} onPage={setPage} onPageSize={setPageSize} itemLabel="cities" /></tbody></DataTable>;
    if (tab === "locations") return <DataTable viewportClassName="table-wrap management-table-wrap" className="clickable-table compact-table"><thead><tr>{canDelete && <th className="select-col"><Checkbox unstyled checked={selectedAll} onChange={(e) => toggleAll(e.target.checked)} /></th>}<SortHeader label="Name" sortKey="name" sort={sort} onSort={sortBy}/><SortHeader label="Code" sortKey="code" sort={sort} onSort={sortBy}/><SortHeader label="Network" sortKey="network_name" sort={sort} onSort={sortBy}/><SortHeader label="City" sortKey="city_name" sort={sort} onSort={sortBy}/><th>S-VLAN</th><th>Address</th><th>Latitude</th><th>Longitude</th><SortHeader label="Status" sortKey="status" sort={sort} onSort={sortBy}/><SortHeader label="Sectors" sortKey="sector_count" sort={sort} onSort={sortBy}/></tr></thead><tbody>{(items as Location[]).map((row) => <tr key={row.id} className={selected?.id === row.id ? "selected-row" : ""} onClick={() => selectItem(row)} onDoubleClick={() => openChildren(row)}>{canDelete && <td onClick={(e) => e.stopPropagation()}><Checkbox unstyled checked={selectedIds.includes(row.id)} onChange={(e) => toggleOne(row.id, e.target.checked)} /></td>}<td><Button unstyled className="table-link" onClick={(e) => { e.stopPropagation(); selectItem(row); }}>{row.name}</Button></td><td>{row.code}</td><td>{row.network_name || "—"}</td><td>{row.city_name || cityById.get(row.city_id)?.name || "—"}</td><td>{row.service_vlan_id ?? cityById.get(row.city_id)?.service_vlan_id ?? "—"}</td><td className="truncate-cell">{row.address || "\u2014"}</td><td>{row.latitude ?? "\u2014"}</td><td>{row.longitude ?? "\u2014"}</td><td><Badge value={row.status}/></td><td>{row.sector_count ?? 0}</td></tr>)}{!items.length && <tr><td colSpan={10 + deleteColumn}><EmptyState text="No locations match the current filters."/></td></tr>}<ServerPaginationRow colSpan={10 + deleteColumn} page={page} pageSize={pageSize} total={total} onPage={setPage} onPageSize={setPageSize} itemLabel="locations" /></tbody></DataTable>;
    return <DataTable viewportClassName="table-wrap management-table-wrap" className="clickable-table compact-table"><thead><tr>{canDelete && <th className="select-col"><Checkbox unstyled checked={selectedAll} onChange={(e) => toggleAll(e.target.checked)} /></th>}<SortHeader label="Name" sortKey="name" sort={sort} onSort={sortBy}/><SortHeader label="Code" sortKey="code" sort={sort} onSort={sortBy}/><SortHeader label="Role" sortKey="role" sort={sort} onSort={sortBy}/><SortHeader label="Network" sortKey="network_name" sort={sort} onSort={sortBy}/><SortHeader label="City" sortKey="city_name" sort={sort} onSort={sortBy}/><th>S-VLAN</th><th>C-VLAN Range</th><SortHeader label="Location" sortKey="location_name" sort={sort} onSort={sortBy}/><SortHeader label="Physical Sector" sortKey="physical_sector_device_name" sort={sort} onSort={sortBy}/><SortHeader label="Sequence" sortKey="sequence_number" sort={sort} onSort={sortBy}/><SortHeader label="Status" sortKey="status" sort={sort} onSort={sortBy}/></tr></thead><tbody>{(items as Sector[]).map((row) => <tr key={row.id} className={selected?.id === row.id ? "selected-row" : ""} onClick={() => selectItem(row)}>{canDelete && <td onClick={(e) => e.stopPropagation()}><Checkbox unstyled checked={selectedIds.includes(row.id)} onChange={(e) => toggleOne(row.id, e.target.checked)} /></td>}<td><Button unstyled className="table-link" onClick={(e) => { e.stopPropagation(); selectItem(row); }}>{row.name}</Button></td><td>{row.code}</td><td><Badge value={row.role || "CUSTOMER_ACCESS"}/></td><td>{row.network_name || "—"}</td><td>{row.city_name || "—"}</td><td>{row.service_vlan_id ?? (row.city_id ? (cityById.get(row.city_id)?.service_vlan_id ?? "—") : "—")}</td><td>{row.customer_vlan_start != null && row.customer_vlan_end != null ? `${row.customer_vlan_start}-${row.customer_vlan_end}` : "—"}</td><td>{row.location_name || locationById.get(row.location_id)?.name || "—"}</td><td>{row.physical_sector_device_name || "—"}</td><td>{row.sequence_number ?? "—"}</td><td><Badge value={row.status}/></td></tr>)}{!items.length && <tr><td colSpan={11 + deleteColumn}><EmptyState text="No sectors match the current filters."/></td></tr>}<ServerPaginationRow colSpan={11 + deleteColumn} page={page} pageSize={pageSize} total={total} onPage={setPage} onPageSize={setPageSize} itemLabel="sectors" /></tbody></DataTable>;
  };

  const editor = () => {
    if (!creating && !selected) return <EmptyState text={`Select a ${entityLabel.toLowerCase()} to view or edit it, or create a new one.`}/>;
    const readonlyCode = !creating;
    if (tab === "networks") return <><div className="form-grid two"><label><span className="required-field-label">Name</span><Input unstyled required value={networkForm.name} disabled={!canUpdate && !creating} onChange={(e) => setNetworkForm({ ...networkForm, name: e.target.value })}/></label><label><span className="required-field-label">Code</span><Input unstyled required value={networkForm.code} disabled={readonlyCode || !canCreate} onChange={(e) => setNetworkForm({ ...networkForm, code: e.target.value })}/></label></div><label>Status<Select unstyled value={networkForm.status} disabled={!canUpdate && !creating} onChange={(e) => setNetworkForm({ ...networkForm, status: e.target.value })}><option>ACTIVE</option><option>INACTIVE</option></Select></label><label>Description<Textarea unstyled rows={5} value={networkForm.description} disabled={!canUpdate && !creating} onChange={(e) => setNetworkForm({ ...networkForm, description: e.target.value })}/></label></>;
    if (tab === "cities") return <><label><span className="required-field-label">Network</span>{creating ? <Select unstyled required value={cityForm.network_id} onChange={(e) => setCityForm({ ...cityForm, network_id: e.target.value })}><option value="">Select Network</option>{refs.networks.map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}</Select> : <Input unstyled value={networkById.get(cityForm.network_id)?.name || "—"} disabled />}</label><div className="form-grid two"><label><span className="required-field-label">Name</span><Input unstyled required value={cityForm.name} disabled={!canUpdate && !creating} onChange={(e) => setCityForm({ ...cityForm, name: e.target.value })}/></label><label><span className="required-field-label">Code</span><Input unstyled required value={cityForm.code} disabled={readonlyCode || !canCreate} onChange={(e) => setCityForm({ ...cityForm, code: e.target.value })}/></label></div><label><span className="required-field-label">Service VLAN (S-VLAN)</span><Input unstyled required type="number" min={2} max={4094} value={cityForm.service_vlan_id} disabled={!canUpdate && !creating} onChange={(e) => setCityForm({ ...cityForm, service_vlan_id: e.target.value })}/></label><label>Status<Select unstyled value={cityForm.status} disabled={!canUpdate && !creating} onChange={(e) => setCityForm({ ...cityForm, status: e.target.value })}><option>ACTIVE</option><option>INACTIVE</option></Select></label><label>Description<Textarea unstyled rows={4} value={cityForm.description} disabled={!canUpdate && !creating} onChange={(e) => setCityForm({ ...cityForm, description: e.target.value })}/></label></>;
    if (tab === "locations") return <><label><span className="required-field-label">City</span>{creating ? <LocalSearchableCombobox required value={locationForm.city_id} options={refs.cities.map((c) => ({ id: c.id, label: c.name, description: networkById.get(c.network_id)?.name }))} onChange={(option) => setLocationForm({ ...locationForm, city_id: option?.id || "" })} placeholder="Search City" /> : <Input unstyled value={cityById.get(locationForm.city_id)?.name || "—"} disabled />}</label><label>Inherited Service VLAN<Input unstyled value={locationForm.city_id ? (cityById.get(locationForm.city_id)?.service_vlan_id ?? "—") : "—"} disabled /></label><div className="form-grid two"><label><span className="required-field-label">Name</span><Input unstyled required value={locationForm.name} disabled={!canUpdate && !creating} onChange={(e) => setLocationForm({ ...locationForm, name: e.target.value })}/></label><label><span className="required-field-label">Code</span><Input unstyled required value={locationForm.code} disabled={readonlyCode || !canCreate} onChange={(e) => setLocationForm({ ...locationForm, code: e.target.value })}/></label></div><label>Address<Input unstyled value={locationForm.address} disabled={!canUpdate && !creating} onChange={(e) => setLocationForm({ ...locationForm, address: e.target.value })}/></label><div className="form-grid two"><label>Latitude<Input unstyled inputMode="decimal" value={locationForm.latitude} disabled={!canUpdate && !creating} onChange={(e) => setLocationForm({ ...locationForm, latitude: e.target.value })}/></label><label>Longitude<Input unstyled inputMode="decimal" value={locationForm.longitude} disabled={!canUpdate && !creating} onChange={(e) => setLocationForm({ ...locationForm, longitude: e.target.value })}/></label></div><label>Status<Select unstyled value={locationForm.status} disabled={!canUpdate && !creating} onChange={(e) => setLocationForm({ ...locationForm, status: e.target.value })}><option>ACTIVE</option><option>INACTIVE</option></Select></label><label>Description<Textarea unstyled rows={3} value={locationForm.description} disabled={!canUpdate && !creating} onChange={(e) => setLocationForm({ ...locationForm, description: e.target.value })}/></label></>;
    return <><label><span className="required-field-label">Location</span>{creating ? <LocalSearchableCombobox required value={sectorForm.location_id} options={refs.locations.map((l) => ({ id: l.id, label: l.name, description: cityById.get(l.city_id)?.name }))} onChange={(option) => setSectorForm({ ...sectorForm, location_id: option?.id || "" })} placeholder="Search Location" /> : <Input unstyled value={locationById.get(sectorForm.location_id)?.name || "—"} disabled />}</label><label>Inherited Service VLAN<Input unstyled value={sectorForm.location_id ? (cityById.get(locationById.get(sectorForm.location_id)?.city_id || "")?.service_vlan_id ?? "—") : "—"} disabled /></label><div className="form-grid two"><label><span className="required-field-label">Name</span><Input unstyled required value={sectorForm.name} disabled={!canUpdate && !creating} onChange={(e) => setSectorForm({ ...sectorForm, name: e.target.value })}/></label><label><span className="required-field-label">Code</span><Input unstyled required value={sectorForm.code} disabled={readonlyCode || !canCreate} onChange={(e) => setSectorForm({ ...sectorForm, code: e.target.value })}/></label></div><div className="form-grid two"><label>Role<Select unstyled value={sectorForm.role} disabled={!canUpdate && !creating} onChange={(e) => setSectorForm({ ...sectorForm, role: e.target.value })}><option value="CUSTOMER_ACCESS">CUSTOMER_ACCESS</option><option value="BACKHAUL">BACKHAUL</option></Select></label><label>Sequence Number<Input unstyled type="number" value={sectorForm.sequence_number} disabled={!canUpdate && !creating} onChange={(e) => setSectorForm({ ...sectorForm, sequence_number: e.target.value })}/></label></div><div className="form-grid two"><label>Customer VLAN start<Input unstyled type="number" min={2} max={4094} value={sectorForm.customer_vlan_start} disabled={!canUpdate && !creating} onChange={(e) => setSectorForm({ ...sectorForm, customer_vlan_start: e.target.value })}/></label><label>Customer VLAN end<Input unstyled type="number" min={2} max={4094} value={sectorForm.customer_vlan_end} disabled={!canUpdate && !creating} onChange={(e) => setSectorForm({ ...sectorForm, customer_vlan_end: e.target.value })}/></label></div><label>Status<Select unstyled value={sectorForm.status} disabled={!canUpdate && !creating} onChange={(e) => setSectorForm({ ...sectorForm, status: e.target.value })}><option>ACTIVE</option><option>INACTIVE</option></Select></label><label>Description<Textarea unstyled rows={3} value={sectorForm.description} disabled={!canUpdate && !creating} onChange={(e) => setSectorForm({ ...sectorForm, description: e.target.value })}/></label></>;
  };

  return <PageLayout className="network-page management-page">
    <div className="page-heading"><div><h2 className="hover-help-title" data-help="Manage Networks, Cities, Locations and logical Sectors.">Networks and Geography</h2></div></div>
    <Tabs<Tab>
      ariaLabel="Network geography views"
      value={tab}
      onChange={setTab}
      tabs={(["networks", "cities", "locations", "sectors"] as Tab[]).map((value) => ({
        id: value,
        label: value[0].toUpperCase() + value.slice(1),
        visible: value === "networks" ? canReadNetwork : canReadGeo,
      }))}
    />
    <div className="management-split">
      <section className="panel management-list-panel">
        <div className="panel-header"><div><h3>{tab[0].toUpperCase() + tab.slice(1)}</h3><span>{total} configured</span></div><div className="button-row"><TableExportButton token={token} tableId={tab} filters={{search:debouncedSearch,status:statusFilter,network_id:networkFilter,city_id:cityFilter,location_id:locationFilter,service_vlan_id:serviceVlanFilter,customer_vlan_id:customerVlanFilter,role:roleFilter,bound:boundFilter,sort_by:sort.key,sort_direction:sort.direction}} />{canDelete && selectedIds.length > 0 && <Button unstyled className="small danger" disabled={busy} onClick={() => void deleteSelected()}>Recycle selected ({selectedIds.length})</Button>}{canCreate && <Button unstyled className="small" disabled={busy} onClick={startCreate}>Create {tab === "networks" ? "Network" : tab === "cities" ? "City" : tab === "locations" ? "Location" : "Sector"}</Button>}</div></div>
        <div className="filter-row compact management-filter-row"><Input unstyled value={search} onChange={(e) => setSearch(e.target.value)} placeholder={`Search ${tab}...`} />{tab !== "networks" && <Select unstyled value={networkFilter} onChange={(e) => { setNetworkFilter(e.target.value); resetDependentFilters("network"); }}><option value="">All Networks</option>{refs.networks.map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}</Select>}{(tab === "locations" || tab === "sectors") && <Select unstyled value={cityFilter} onChange={(e) => { setCityFilter(e.target.value); resetDependentFilters("city"); }}><option value="">All Cities</option>{refs.cities.filter((c) => !networkFilter || c.network_id === networkFilter).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</Select>}{tab === "sectors" && <Select unstyled value={locationFilter} onChange={(e) => {setLocationFilter(e.target.value);setCustomerVlanFilter("")}}><option value="">All Locations</option>{refs.locations.filter((l) => !cityFilter || l.city_id === cityFilter).map((l) => <option key={l.id} value={l.id}>{l.name}</option>)}</Select>}{tab !== "networks" && <LocalSearchableCombobox value={serviceVlanFilter} options={serviceVlanOptions} onChange={(option)=>{setServiceVlanFilter(option?.id||"");setCustomerVlanFilter("")}} placeholder="All S-VLANs / search..." emptyText="No eligible S-VLANs." />}{(tab === "locations" || tab === "sectors") && <LocalSearchableCombobox value={customerVlanFilter} options={customerVlanOptions} onChange={(option)=>setCustomerVlanFilter(option?.id||"")} placeholder="All C-VLANs / search..." emptyText="No eligible C-VLANs." />}<Select unstyled value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}><option value="">All Statuses</option><option>ACTIVE</option><option>INACTIVE</option></Select>{tab === "sectors" && <><Select unstyled value={roleFilter} onChange={(e) => setRoleFilter(e.target.value)}><option value="">All Roles</option><option value="CUSTOMER_ACCESS">Customer Access</option><option value="BACKHAUL">Backhaul</option></Select><Select unstyled value={boundFilter} onChange={(e) => setBoundFilter(e.target.value)}><option value="">Bound or Unbound</option><option value="true">Bound</option><option value="false">Unbound</option></Select></>}<ClearFiltersButton disabled={!search&&!networkFilter&&!cityFilter&&!locationFilter&&!serviceVlanFilter&&!customerVlanFilter&&!statusFilter&&!roleFilter&&!boundFilter} onClick={()=>{setSearch("");setNetworkFilter("");setCityFilter("");setLocationFilter("");setServiceVlanFilter("");setCustomerVlanFilter("");setStatusFilter("");setRoleFilter("");setBoundFilter("");setPage(1)}}/></div>
        {table()}
      </section>
      <section className={`panel management-editor-panel${creating && validationAttempted ? " validation-attempted" : ""}`}><div className="panel-header"><div><h3 className={selected && !creating ? "hover-help-title" : undefined} data-help={selected && !creating ? "Some fields cannot be changed after creation." : undefined}>{creating ? `Create ${entityLabel}` : selected ? `Edit ${(selected as any).name}` : "Details"}</h3>{!creating && !selected && <span>Select an item from the table.</span>}</div></div>{editor()}{(creating || selected) && ((creating && canCreate) || (!creating && canUpdate)) && <div className="button-row editor-actions"><Button unstyled disabled={busy} onClick={() => { if (creating) setValidationAttempted(true); void save(); }}>{creating ? "Create" : "Update"}</Button>{creating && <Button unstyled className="secondary" disabled={busy} onClick={() => setCreating(false)}>Cancel</Button>}</div>}</section>
    </div>
  </PageLayout>;
}
