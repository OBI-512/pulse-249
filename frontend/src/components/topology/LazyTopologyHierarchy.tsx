import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiFetch } from "../../api/client";
import type { City, Group, Location, Network, Sector } from "../../types";
import { useDebouncedValue } from "../../hooks/useDebouncedValue";
import { friendlyError } from "../../utils/feedback";
import { useFeedback } from "../common/FeedbackSystem";
import { copyToClipboard } from "../../utils/management";
import { useDeviceAccessActions } from "../../hooks/useDeviceAccessActions";
import { EmptyState } from "../../design-system/composites/AsyncState";
import { ContextMenu } from "../../design-system/composites/Menu";
import { LocalSearchableCombobox } from "../../design-system/composites/SearchableSelect";
import { SearchableMultiSelect } from "../../design-system/composites/SearchableSelect";
import type { ComboboxOption, ComboboxPage } from "../../design-system/composites/SearchableSelect";
import "../../topology-phase24.css";
import { ClearFiltersButton } from "../../design-system/composites/FilterBar";
import { Button, Input, Select } from "../../design-system/primitives";

type SourceType = "network" | "group";
type FilterKind = "network" | "service_vlan" | "city" | "location" | "sector" | "customer_vlan" | "cpe" | "access_point";
type NodeKind = "network" | "city" | "location" | "sector" | "sector_device" | "cpe" | "access_point" | "device";
type ExpandableNodeKind = "root" | "network" | "city" | "location" | "sector" | "sector_device" | "cpe";

type FilterOption = ComboboxOption;
type HierarchyNode = {
  id: string;
  kind: NodeKind;
  name: string;
  code?: string | null;
  detail?: string | null;
  has_children: boolean;
  context_only?: boolean;
  device_type_code?: string | null;
  hostname?: string | null;
  management_ip?: string | null;
  management_protocol?: string | null;
  lifecycle_state?: string | null;
  operational_state?: string | null;
  remote_ssh_ready?: boolean;
};
type ChildrenResponse = { items: HierarchyNode[] };
type OptionResponse = { items: Array<{ id:string; label:string; description?:string|null }>; total:number; page:number; page_size:number };
type LoadedSource = { type: SourceType; id:string; name:string; code:string };

type FilterState = {
  network: FilterOption[];
  service_vlan: FilterOption[];
  city: FilterOption[];
  location: FilterOption[];
  sector: FilterOption[];
  customer_vlan: FilterOption[];
  cpe: FilterOption[];
  access_point: FilterOption[];
};

const EMPTY_FILTERS: FilterState = { network:[], service_vlan:[], city:[], location:[], sector:[], customer_vlan:[], cpe:[], access_point:[] };
const DEVICE_KINDS = new Set<NodeKind>(["sector_device", "cpe", "access_point", "device"]);

function ids(rows: FilterOption[]) { return rows.map((row) => row.id); }
function nodeKey(node: Pick<HierarchyNode, "kind" | "id">) { return `${node.kind}:${node.id}`; }

export function LazyTopologyHierarchy({
  token,
  refreshKey = 0,
  permissions,
  networks,
  sourceNetworks,
  cities,
  locations,
  sectors,
  groups,
  onTestAccessibility,
  onDeleteDevice,
}: {
  token: string;
  refreshKey?: number;
  permissions: string[];
  networks: Network[];
  sourceNetworks: Network[];
  cities: City[];
  locations: Location[];
  sectors: Sector[];
  groups: Group[];
  onTestAccessibility: (deviceId: string) => void | Promise<void>;
  onDeleteDevice: (deviceId: string, displayName: string) => Promise<boolean>;
}) {
  const canDelete = permissions.includes("device.delete");
  const feedback = useFeedback();
  const deviceAccess = useDeviceAccessActions({ token, permissions });
  const accessTarget = (node: HierarchyNode) => ({
    id: node.id,
    display_name: node.name,
    management_ip: node.management_ip,
    lifecycle_state: node.lifecycle_state,
  });
  const [sourceType, setSourceType] = useState<SourceType>("network");
  const [sourceId, setSourceId] = useState("");
  const [loadedSource, setLoadedSource] = useState<LoadedSource | null>(null);
  const [filters, setFilters] = useState<FilterState>(EMPTY_FILTERS);
  const [keyword, setKeyword] = useState("");
  const debouncedKeyword = useDebouncedValue(keyword, 300);
  const [sourceExpanded, setSourceExpanded] = useState(false);
  const [childrenByKey, setChildrenByKey] = useState<Record<string, HierarchyNode[]>>({});
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState<Set<string>>(new Set());
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [refreshNonce, setRefreshNonce] = useState(0);
  const generationRef = useRef(0);
  const autoVisitedRef = useRef<Set<string>>(new Set());

  const directSourceNetworkIds = useMemo(() => new Set(sourceNetworks.map((item) => item.id)), [sourceNetworks]);

  const contextFiltersForNetwork = useCallback((networkId: string): FilterState => {
    const networkCities = cities.filter((item) => item.network_id === networkId);
    const citySelection = networkCities.length === 1
      ? [{ id: networkCities[0].id, label: networkCities[0].name, description: networkCities[0].code }]
      : [];
    const allowedCityIds = new Set(citySelection.map((item) => item.id));
    const networkLocations = locations.filter((item) => allowedCityIds.size === 1 && allowedCityIds.has(item.city_id));
    const locationSelection = networkLocations.length === 1
      ? [{ id: networkLocations[0].id, label: networkLocations[0].name, description: networkLocations[0].code }]
      : [];
    const allowedLocationIds = new Set(locationSelection.map((item) => item.id));
    const networkSectors = sectors.filter((item) => allowedLocationIds.size === 1 && allowedLocationIds.has(item.location_id));
    const sectorSelection = networkSectors.length === 1
      ? [{ id: networkSectors[0].id, label: networkSectors[0].physical_sector_device_name || networkSectors[0].name, description: networkSectors[0].code }]
      : [];
    return { ...EMPTY_FILTERS, city:citySelection, location:locationSelection, sector:sectorSelection };
  }, [cities, locations, sectors]);

  const sourceOptions = useMemo(() => (sourceType === "network" ? networks : groups).map((item) => ({
    id:item.id,
    label:item.name,
    description:sourceType === "network" && !directSourceNetworkIds.has(item.id)
      ? `${item.code} · assigned-area context`
      : item.code,
    data:item,
  })), [sourceType, networks, groups, directSourceNetworkIds]);

  const selectedSource = sourceType === "network"
    ? networks.find((item) => item.id === sourceId)
    : groups.find((item) => item.id === sourceId);

  const hasFilters = Boolean(keyword.trim()) || Object.values(filters).some((rows) => rows.length > 0);
  const exactDeviceFilter = filters.access_point.length === 1 || (filters.access_point.length === 0 && filters.cpe.length === 1);

  const appendFilters = useCallback((params: URLSearchParams, state = filters) => {
    const entries: Array<[keyof FilterState, string]> = [
      ["network", "network_ids"], ["service_vlan", "service_vlan_ids"], ["city", "city_ids"], ["location", "location_ids"],
      ["sector", "sector_ids"], ["customer_vlan", "customer_vlan_ids"], ["cpe", "cpe_ids"], ["access_point", "access_point_ids"],
    ];
    for (const [key, param] of entries) for (const option of state[key]) params.append(param, option.id);
  }, [filters]);

  const buildBaseParams = useCallback((state = filters) => {
    const params = new URLSearchParams();
    if (!loadedSource) return params;
    params.set("source_type", loadedSource.type);
    params.set("source_id", loadedSource.id);
    appendFilters(params, state);
    return params;
  }, [loadedSource, appendFilters, filters]);

  const loadOptionPage = useCallback((kind: FilterKind) => async (query: string, page: number, pageSize: number): Promise<ComboboxPage> => {
    if (!loadedSource) return { items:[], total:0, page, page_size:pageSize };
    const params = buildBaseParams();
    params.set("kind", kind);
    params.set("page", String(page));
    params.set("page_size", String(pageSize));
    if (query) params.set("search", query);
    const result = await apiFetch<OptionResponse>(`/topology/hierarchy/options?${params.toString()}`, {}, token);
    return {
      items: result.items.map((item) => ({ id:item.id, label:item.label, description:item.description || undefined })),
      total: result.total,
      page: result.page,
      page_size: result.page_size,
    };
  }, [loadedSource, buildBaseParams, token]);

  const setFilter = (kind: FilterKind, value: FilterOption[]) => {
    const order: FilterKind[] = ["network", "service_vlan", "city", "location", "sector", "customer_vlan", "cpe", "access_point"];
    const index = order.indexOf(kind);
    setFilters((current) => {
      const next = { ...current, [kind]:value };
      for (let i=index + 1;i<order.length;i++) next[order[i]] = [];
      return next;
    });
  };

  const optionContextKey = (kind: FilterKind) => {
    const order: FilterKind[] = ["network", "service_vlan", "city", "location", "sector", "customer_vlan", "cpe", "access_point"];
    const index = order.indexOf(kind);
    const upstream = order.slice(0, index).map((item) => `${item}:${ids(filters[item]).join(",")}`);
    return `${loadedSource?.type || "none"}:${loadedSource?.id || "none"}|${upstream.join("|")}`;
  };

  const treeContextKey = useMemo(() => JSON.stringify({
    source: loadedSource ? `${loadedSource.type}:${loadedSource.id}` : "",
    keyword: debouncedKeyword.trim(),
    network:ids(filters.network), serviceVlan:ids(filters.service_vlan), city:ids(filters.city), location:ids(filters.location),
    sector:ids(filters.sector), customerVlan:ids(filters.customer_vlan), cpe:ids(filters.cpe), ap:ids(filters.access_point), refreshNonce,
  }), [loadedSource, debouncedKeyword, filters, refreshNonce]);

  const setBusy = (key:string, active:boolean) => setLoading((current) => {
    const next = new Set(current);
    active ? next.add(key) : next.delete(key);
    return next;
  });

  const loadChildren = useCallback(async (
    requestKind: ExpandableNodeKind,
    requestId: string | null,
    storageKey: string,
    generation: number,
    autoWalk = false,
  ): Promise<HierarchyNode[]> => {
    if (!loadedSource) return [];
    setBusy(storageKey, true);
    setErrors((current) => { const next={...current}; delete next[storageKey]; return next; });
    try {
      const params = buildBaseParams();
      params.set("node_kind", requestKind);
      if (requestId) params.set("node_id", requestId);
      if (debouncedKeyword.trim()) params.set("keyword", debouncedKeyword.trim());
      const response = await apiFetch<ChildrenResponse>(`/topology/hierarchy/children?${params.toString()}`, {}, token);
      if (generationRef.current !== generation) return [];
      setChildrenByKey((current) => ({ ...current, [storageKey]:response.items }));

      if (autoWalk && response.items.length === 1) {
        const child = response.items[0];
        const childKey = nodeKey(child);
        const expandable = child.has_children && ["network", "city", "location", "sector", "sector_device", "cpe"].includes(child.kind);
        if (expandable && !autoVisitedRef.current.has(childKey)) {
          autoVisitedRef.current.add(childKey);
          setExpanded((current) => new Set(current).add(childKey));
          window.setTimeout(() => {
            if (generationRef.current === generation) void loadChildren(child.kind as ExpandableNodeKind, child.id, childKey, generation, true);
          }, 0);
        }
      }
      return response.items;
    } catch (error) {
      if (generationRef.current === generation) setErrors((current) => ({ ...current, [storageKey]:friendlyError(error, "Unable to load this topology branch.") }));
      return [];
    } finally {
      if (generationRef.current === generation) setBusy(storageKey, false);
    }
  }, [loadedSource, buildBaseParams, debouncedKeyword, token]);

  useEffect(() => {
    const generation = ++generationRef.current;
    setChildrenByKey({});
    setExpanded(new Set());
    setLoading(new Set());
    setErrors({});
    autoVisitedRef.current = new Set();
    if (!loadedSource) {
      setSourceExpanded(false);
      return;
    }
    if (exactDeviceFilter) {
      setSourceExpanded(true);
      autoVisitedRef.current.add("source-root");
      void loadChildren("root", null, "source-root", generation, true);
    } else if (sourceExpanded) {
      void loadChildren("root", null, "source-root", generation, false);
    }
  }, [treeContextKey]);

  useEffect(() => {
    if (refreshKey <= 0 || !loadedSource) return;
    const generation = ++generationRef.current;
    setErrors({});
    autoVisitedRef.current = new Set();
    if (sourceExpanded) void loadChildren("root", null, "source-root", generation, exactDeviceFilter);
    for (const key of expanded) {
      const separator = key.indexOf(":");
      if (separator <= 0) continue;
      const kind = key.slice(0, separator) as ExpandableNodeKind;
      const nodeId = key.slice(separator + 1);
      if (!["network", "city", "location", "sector", "sector_device", "cpe"].includes(kind)) continue;
      void loadChildren(kind, nodeId, key, generation, false);
    }
  }, [refreshKey]);

  const loadSource = () => {
    if (!selectedSource) return;
    setLoadedSource({ type:sourceType, id:selectedSource.id, name:selectedSource.name, code:selectedSource.code });
    const contextOnlyNetwork = sourceType === "network" && !directSourceNetworkIds.has(selectedSource.id);
    setFilters(contextOnlyNetwork ? contextFiltersForNetwork(selectedSource.id) : EMPTY_FILTERS);
    setKeyword("");
    setSourceExpanded(contextOnlyNetwork);
    setChildrenByKey({});
    setExpanded(new Set());
  };

  useEffect(() => {
    if (sourceType !== "network" || loadedSource || networks.length !== 1) return;
    const only = networks[0];
    if (directSourceNetworkIds.has(only.id)) {
      if (!sourceId) setSourceId(only.id);
      return;
    }
    setSourceId(only.id);
    setLoadedSource({ type:"network", id:only.id, name:only.name, code:only.code });
    setFilters(contextFiltersForNetwork(only.id));
    setKeyword("");
    setSourceExpanded(true);
    setChildrenByKey({});
    setExpanded(new Set());
  }, [sourceType, sourceId, loadedSource, networks, directSourceNetworkIds, contextFiltersForNetwork]);

  const toggleSource = () => {
    if (!loadedSource) return;
    const opening = !sourceExpanded;
    setSourceExpanded(opening);
    if (opening && !childrenByKey["source-root"] && !loading.has("source-root")) void loadChildren("root", null, "source-root", generationRef.current, exactDeviceFilter);
  };

  const toggleNode = (node:HierarchyNode) => {
    if (!node.has_children || !["network", "city", "location", "sector", "sector_device", "cpe"].includes(node.kind)) return;
    const key = nodeKey(node);
    const opening = !expanded.has(key);
    setExpanded((current) => {
      const next = new Set(current);
      opening ? next.add(key) : next.delete(key);
      return next;
    });
    if (opening && !childrenByKey[key] && !loading.has(key)) void loadChildren(node.kind as ExpandableNodeKind, node.id, key, generationRef.current, false);
  };

  const deviceMenuItems = (node:HierarchyNode) => [
    ...deviceAccess.menuItems(accessTarget(node)),
    { label:"Copy management IP", disabled:!node.management_ip, onClick:() => void copyToClipboard(node.management_ip || "") },
    { label:"Test accessibility", disabled:!node.management_ip, onClick:() => void onTestAccessibility(node.id) },
    ...(canDelete ? [{ label:"Move to Recycle Bin", danger:true, onClick:() => void (async () => {
      if (await onDeleteDevice(node.id, node.name)) setRefreshNonce((value) => value + 1);
    })() }] : []),
  ];

  const renderNode = (node:HierarchyNode, depth = 0) => {
    const key = nodeKey(node);
    const open = expanded.has(key);
    const isDevice = DEVICE_KINDS.has(node.kind);
    const childRows = childrenByKey[key];
    const error = errors[key];
    const busy = loading.has(key);

    if (isDevice) {
      const body = <Button unstyled
        type="button"
        className={`tree-leaf topology-device topology-lazy-device${node.has_children ? " expandable" : ""}${node.context_only ? " context-only" : ""}`}
        onClick={() => node.has_children && toggleNode(node)}
        onPointerEnter={() => void deviceAccess.prefetch(node.id)}
        onPointerDown={() => void deviceAccess.prefetch(node.id)}
        onContextMenu={() => void deviceAccess.prefetch(node.id)}
        onDoubleClick={() => deviceAccess.openSecureWebIfAvailable(accessTarget(node))}
        aria-expanded={node.has_children ? open : undefined}
      >
        <div><strong>{node.has_children && <span className="topology-chevron" aria-hidden="true">{open ? "▼" : "▶"}</span>}{node.name}</strong>{node.context_only && <span className="topology-context-badge">Path context</span>}</div>
        <span>{busy ? "Loading…" : node.detail || node.device_type_code || "Device"}</span>
      </Button>;
      return <div className="tree-node topology-lazy-device-node" key={key} style={{ marginLeft:depth > 0 ? 10 : 0 }}>
        <ContextMenu items={deviceMenuItems(node)}>{body}</ContextMenu>
        {open && <div className="topology-lazy-children">
          {error && <div className="topology-lazy-error"><span>{error}</span><Button unstyled type="button" className="secondary small" onClick={() => void loadChildren(node.kind as ExpandableNodeKind, node.id, key, generationRef.current, false)}>Retry</Button></div>}
          {!error && childRows?.length === 0 && !busy && <div className="topology-lazy-empty">No matching child nodes.</div>}
          {!error && childRows?.map((child) => renderNode(child, depth + 1))}
        </div>}
      </div>;
    }

    const cardKind = node.kind === "network" ? "network" : node.kind === "city" ? "city" : node.kind === "location" ? "location" : "sector";
    return <div className={`tree-node topology-level-${cardKind}`} key={key}>
      <Button unstyled className={`tree-card topology-node topology-toggle topology-card-${cardKind}`} type="button" onClick={() => toggleNode(node)} aria-expanded={open}>
        <strong><span className="topology-chevron" aria-hidden="true">{open ? "▼" : "▶"}</span>{node.name}</strong>
        <span>{busy ? "Loading…" : node.detail || node.code || ""}</span>
      </Button>
      {open && <div className="topology-lazy-children">
        {error && <div className="topology-lazy-error"><span>{error}</span><Button unstyled type="button" className="secondary small" onClick={() => void loadChildren(node.kind as ExpandableNodeKind, node.id, key, generationRef.current, false)}>Retry</Button></div>}
        {!error && childRows?.length === 0 && !busy && <div className="topology-lazy-empty">No matching child nodes.</div>}
        {!error && childRows?.map((child) => renderNode(child, depth + 1))}
      </div>}
    </div>;
  };

  const filterControl = (kind:FilterKind, label:string) => <label className="topology-filter-field" key={kind}>
    <span>{label}</span>
    <SearchableMultiSelect
      key={`${kind}:${optionContextKey(kind)}`}
      value={filters[kind]}
      onChange={(rows) => setFilter(kind, rows)}
      loadPage={loadOptionPage(kind)}
      disabled={!loadedSource}
      placeholder={`All ${label}`}
      emptyText={`No eligible ${label.toLowerCase()} match.`}
    />
  </label>;

  const rootRows = childrenByKey["source-root"] || [];
  const sourceError = errors["source-root"];
  const sourceBusy = loading.has("source-root");

  return <>
    <section className="panel topology-toolbar topology-lazy-toolbar">
      <div className="inline-form topology-source-controls">
        <Select unstyled value={sourceType} onChange={(event) => {
          setSourceType(event.target.value as SourceType);
          setSourceId("");
          setLoadedSource(null);
          setFilters(EMPTY_FILTERS);
          setKeyword("");
        }}><option value="network">Network</option><option value="group">Group</option></Select>
        <div className="topology-target-combobox"><LocalSearchableCombobox value={sourceId} options={sourceOptions} disabled={sourceType === "network" && networks.length === 1} onChange={(option) => setSourceId(option?.id || "")} placeholder={`Search ${sourceType}...`} emptyText={`No ${sourceType}s match this search.`} /></div>
        <Button unstyled onClick={loadSource} disabled={!sourceId}>Load Topology</Button>
      </div>
    </section>

    {loadedSource && <section className="panel topology-filter-panel">
      <div className="topology-filter-heading">
        <div><h3 className={loadedSource.type === "network" && !directSourceNetworkIds.has(loadedSource.id) ? "hover-help-title" : undefined} data-help={loadedSource.type === "network" && !directSourceNetworkIds.has(loadedSource.id) ? "Location information is shown for reference and cannot be edited here." : undefined}>Hierarchy Filters</h3></div>
        <ClearFiltersButton disabled={!hasFilters} onClick={() => { setFilters(EMPTY_FILTERS); setKeyword(""); }}/>
      </div>
      <div className="topology-keyword-row"><label><span>Keyword</span><Input unstyled value={keyword} onChange={(event) => setKeyword(event.target.value)} placeholder="Search name, code, hostname, management IP..." /></label></div>
      <div className="topology-filter-grid">
        {loadedSource.type === "group" && filterControl("network", "Networks")}
        {filterControl("service_vlan", "S-VLANs")}
        {filterControl("city", "Cities")}
        {filterControl("location", "Locations")}
        {filterControl("sector", "Sectors")}
        {filterControl("customer_vlan", "C-VLANs")}
        {filterControl("cpe", "CPEs")}
        {filterControl("access_point", "Access Points")}
      </div>
      <div className="topology-filter-summary">{hasFilters ? "The tree contains only matching hierarchy paths. Device payloads still load only when branches are expanded." : "No filters applied. Expand only the branches you need; child data is requested on demand."}</div>
    </section>}

    {!loadedSource ? <EmptyState text="Select a network or group, then load its hierarchy. No topology branch data is requested until you expand the source." /> : <section className="topology-tree topology-lazy-tree">
      <Button unstyled type="button" className="tree-root topology-source-root" onClick={toggleSource} aria-expanded={sourceExpanded}>
        <strong><span className="topology-chevron" aria-hidden="true">{sourceExpanded ? "▼" : "▶"}</span>{loadedSource.name}</strong>
        <span>{sourceBusy ? "Loading…" : `${loadedSource.code} · ${loadedSource.type === "group" ? "Group" : "Network"}`}</span>
      </Button>
      {sourceExpanded && <div className="topology-lazy-root-children">
        {sourceError && <div className="topology-lazy-error"><span>{sourceError}</span><Button unstyled type="button" className="secondary small" onClick={() => void loadChildren("root", null, "source-root", generationRef.current, exactDeviceFilter)}>Retry</Button></div>}
        {!sourceError && rootRows.length === 0 && !sourceBusy && <div className="topology-lazy-empty">No topology paths match the current source and filters.</div>}
        {!sourceError && rootRows.map((node) => renderNode(node))}
      </div>}
    </section>}
  </>;
}
