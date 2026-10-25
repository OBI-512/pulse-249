import { PageLayout } from "../design-system/layouts";
import { type PointerEvent as ReactPointerEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { City, Group, Location, Network, NetworkTopology, Sector, SectorLiveTopology, TopologyDevice } from "../types";
import { apiFetch } from "../api/client";
import { EmptyState } from "../design-system/composites/AsyncState";
import { ContextMenu } from "../design-system/composites/Menu";
import { useFeedback } from "../components/common/FeedbackSystem";
import { friendlyError } from "../utils/feedback";
import { copyToClipboard } from "../utils/management";
import { useDeviceAccessActions } from "../hooks/useDeviceAccessActions";
import { LocalSearchableCombobox } from "../design-system/composites/SearchableSelect";
import { LazyTopologyHierarchy } from "../components/topology/LazyTopologyHierarchy";
import { Tabs } from "../design-system/composites/Tabs";
import { Button } from "../design-system/primitives";
import { LiveDeviceNode, topologyLiveState } from "../features/topology/LiveDeviceNode";
import { LocationPhysicalTopology } from "../features/topology/LocationPhysicalTopology";

type TopologyPageProps = {
  token: string;
  refreshKey?: number;
  permissions: string[];
  sourceNetworks: Network[];
  networks: Network[];
  cities: City[];
  locations: Location[];
  sectors: Sector[];
  groups: Group[];
  topology: NetworkTopology | null;
  onLoad: (network: Network) => void | Promise<void>;
  onLoadGroup: (group: Group) => void | Promise<void>;
  onTestAccessibility: (deviceId: string) => void | Promise<void>;
  onDeleteDevice: (deviceId: string, displayName: string) => Promise<boolean>;
};

type TopologyCity = NetworkTopology["cities"][number];
type TopologyLocation = TopologyCity["locations"][number];
type TopologySector = TopologyLocation["sectors"][number];
type NodeKind = "network" | "city" | "location" | "sector";
type ViewMode = "hierarchy" | "live-sector" | "location";

const LIVE_STANDARD_ZOOM = 1;
const LIVE_MIN_ZOOM = 0.05;
const LIVE_MIN_FIT_ZOOM = 0.02;
const LIVE_MAX_ZOOM = 1.8;
const LIVE_CPE_MIN_BRANCH_WIDTH = 270;
const LIVE_AP_GAP = 170;
const LIVE_BRANCH_SIDE_PADDING = 90;
const LIVE_CANVAS_SIDE_PADDING = 150;
const LIVE_CANVAS_HEIGHT = 680;

export function TopologyPage({ token, refreshKey = 0, permissions, sourceNetworks, networks, cities: allCities, locations: allLocations, sectors: allSectors, groups, topology, onLoad, onLoadGroup, onTestAccessibility, onDeleteDevice }: TopologyPageProps) {
  const [view, setView] = useState<ViewMode>("hierarchy");
  const [source, setSource] = useState("network");
  const [id, setId] = useState("");
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [lazyNetworkId, setLazyNetworkId] = useState("");
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set());
  const [lazyLocationDevices, setLazyLocationDevices] = useState<Record<string, TopologyDevice[]>>({});
  const [lazySectorTrees, setLazySectorTrees] = useState<Record<string, TopologySector>>({});
  const [lazySectorLabels, setLazySectorLabels] = useState<Record<string, string>>({});
  const [lazyLoading, setLazyLoading] = useState<Set<string>>(new Set());
  const [liveNetworkId, setLiveNetworkId] = useState("");
  const [liveServiceVlanId, setLiveServiceVlanId] = useState("");
  const [liveCustomerVlanId, setLiveCustomerVlanId] = useState("");
  const [liveCityId, setLiveCityId] = useState("");
  const [liveLocationId, setLiveLocationId] = useState("");
  const [liveSectorId, setLiveSectorId] = useState("");
  const [liveTopology, setLiveTopology] = useState<SectorLiveTopology | null>(null);
  const [liveLoading, setLiveLoading] = useState(false);
  const feedback = useFeedback();
  const [liveAutoRefresh, setLiveAutoRefresh] = useState(true);
  const [liveZoom, setLiveZoom] = useState(LIVE_STANDARD_ZOOM);
  const [liveFitMode, setLiveFitMode] = useState(false);
  const [livePanning, setLivePanning] = useState(false);
  const liveLoadInFlight = useRef(false);
  const liveScrollRef = useRef<HTMLDivElement | null>(null);
  const liveCenteredSectorRef = useRef<string | null>(null);
  const livePanRef = useRef<{ pointerId:number; startX:number; startY:number; scrollLeft:number; scrollTop:number } | null>(null);

  const selectedGroup = groups.find((group) => group.id === id);
  const cityById = useMemo(() => new Map(allCities.map((city) => [city.id, city])), [allCities]);
  const locationById = useMemo(() => new Map(allLocations.map((location) => [location.id, location])), [allLocations]);
  const liveCities = useMemo(() => allCities.filter((city) => (!liveNetworkId || city.network_id === liveNetworkId) && (!liveServiceVlanId || String(city.service_vlan_id) === liveServiceVlanId)), [allCities, liveNetworkId, liveServiceVlanId]);
  const liveLocations = useMemo(() => allLocations.filter((location) => {
    const city = cityById.get(location.city_id);
    if (liveCityId && location.city_id !== liveCityId) return false;
    if (liveNetworkId && city?.network_id !== liveNetworkId) return false;
    if (liveServiceVlanId && String(city?.service_vlan_id ?? "") !== liveServiceVlanId) return false;
    return true;
  }), [allLocations, cityById, liveCityId, liveNetworkId, liveServiceVlanId]);
  const liveSectors = useMemo(() => allSectors.filter((sector) => {
    const location = locationById.get(sector.location_id);
    const city = location ? cityById.get(location.city_id) : undefined;
    if (liveLocationId && sector.location_id !== liveLocationId) return false;
    if (liveCityId && location?.city_id !== liveCityId) return false;
    if (liveNetworkId && city?.network_id !== liveNetworkId) return false;
    if (liveServiceVlanId && String(city?.service_vlan_id ?? "") !== liveServiceVlanId) return false;
    if (liveCustomerVlanId) {
      const vlan = Number(liveCustomerVlanId);
      if (
        !Number.isInteger(vlan) ||
        sector.customer_vlan_start == null ||
        sector.customer_vlan_end == null ||
        vlan < sector.customer_vlan_start ||
        vlan > sector.customer_vlan_end
      ) return false;
    }
    return true;
  }), [allSectors, cityById, locationById, liveCityId, liveLocationId, liveNetworkId, liveServiceVlanId, liveCustomerVlanId]);
  const topologyTargetOptions = useMemo(() => (source === "network" ? networks : groups).map((item) => ({ id:item.id, label:item.name, description:item.code, data:item })), [source, networks, groups]);
  const liveNetworkOptions = useMemo(() => networks.map((item) => ({ id:item.id, label:item.name, description:item.code, data:item })), [networks]);
  const liveServiceVlanOptions = useMemo(() => Array.from(new Set(allCities.filter(city=>!liveNetworkId||city.network_id===liveNetworkId).map(city=>city.service_vlan_id).filter((value):value is number=>value!=null))).sort((a,b)=>a-b).map(value=>({id:String(value),label:String(value),description:"Service VLAN"})), [allCities, liveNetworkId]);
  const liveCustomerVlanOptions = useMemo(() => {
    const values = new Set<number>();
    for (const sector of allSectors) {
      const location = locationById.get(sector.location_id);
      const city = location ? cityById.get(location.city_id) : undefined;
      if (liveNetworkId && city?.network_id !== liveNetworkId) continue;
      if (liveServiceVlanId && String(city?.service_vlan_id ?? "") !== liveServiceVlanId) continue;
      if (liveCityId && location?.city_id !== liveCityId) continue;
      if (liveLocationId && sector.location_id !== liveLocationId) continue;
      if (sector.customer_vlan_start == null || sector.customer_vlan_end == null) continue;
      for (let vlan = sector.customer_vlan_start; vlan <= sector.customer_vlan_end; vlan += 1) values.add(vlan);
    }
    return Array.from(values)
      .sort((a, b) => a - b)
      .map((value) => ({ id:String(value), label:String(value), description:"Customer VLAN" }));
  }, [allSectors, cityById, locationById, liveNetworkId, liveServiceVlanId, liveCityId, liveLocationId]);
  const liveCityOptions = useMemo(() => liveCities.map((item) => ({ id:item.id, label:item.name, description:item.code, data:item })), [liveCities]);
  const liveLocationOptions = useMemo(() => liveLocations.map((item) => ({ id:item.id, label:item.name, description:item.code, data:item })), [liveLocations]);
  const liveSectorOptions = useMemo(() => liveSectors.map((item) => ({
    id:item.id,
    label:item.physical_sector_device_name || item.name,
    description:[item.location_name, item.city_name, item.network_name].filter(Boolean).join(" / "),
    data:item,
  })), [liveSectors]);
  const canDelete = permissions.includes("device.delete");
  const deviceAccess = useDeviceAccessActions({ token, permissions });

  useEffect(() => {
    if (view !== "live-sector") return;

    const validNetwork = networks.some((item) => item.id === liveNetworkId);
    const validCity = allCities.some((item) => item.id === liveCityId);
    const validLocation = allLocations.some((item) => item.id === liveLocationId);
    const validSector = allSectors.some((item) => item.id === liveSectorId);

    let nextNetwork = validNetwork ? liveNetworkId : "";
    let nextCity = validCity ? liveCityId : "";
    let nextLocation = validLocation ? liveLocationId : "";
    let nextSector = validSector ? liveSectorId : "";

    if (!nextNetwork && networks.length === 1) nextNetwork = networks[0].id;
    if (!nextCity && allCities.length === 1) nextCity = allCities[0].id;
    if (!nextLocation && allLocations.length === 1) nextLocation = allLocations[0].id;
    if (!nextSector && allSectors.length === 1) nextSector = allSectors[0].id;

    const selectedSector = allSectors.find((item) => item.id === nextSector);
    if (selectedSector) nextLocation = selectedSector.location_id;
    const selectedLocation = allLocations.find((item) => item.id === nextLocation);
    if (selectedLocation) nextCity = selectedLocation.city_id;
    const selectedCity = allCities.find((item) => item.id === nextCity);
    if (selectedCity) { nextNetwork = selectedCity.network_id; if(selectedCity.service_vlan_id!=null && String(selectedCity.service_vlan_id)!==liveServiceVlanId) setLiveServiceVlanId(String(selectedCity.service_vlan_id)); }

    if (nextNetwork !== liveNetworkId) setLiveNetworkId(nextNetwork);
    if (nextCity !== liveCityId) setLiveCityId(nextCity);
    if (nextLocation !== liveLocationId) setLiveLocationId(nextLocation);
    if (nextSector !== liveSectorId) { setLiveSectorId(nextSector); setLiveTopology(null); }
  }, [view, networks, allCities, allLocations, allSectors, liveNetworkId, liveServiceVlanId, liveCityId, liveLocationId, liveSectorId]);

  const cityKeys = (cities: TopologyCity[]) => cities.flatMap((city) => [
    `city:${city.id}`,
    ...city.locations.flatMap((location) => [
      `location:${location.id}`,
      ...location.sectors.map((sector) => `sector:${sector.id}`),
    ]),
  ]);

  const allKeys = useMemo(
    () => topology
      ? [
          ...(topology.networks || []).flatMap((network) => [`network:${network.id}`, ...cityKeys(network.cities)]),
          ...cityKeys(topology.cities || []),
        ]
      : [],
    [topology],
  );

  const toggle = (key:string) => setCollapsed((current) => {
    const next = new Set(current);
    next.has(key) ? next.delete(key) : next.add(key);
    return next;
  });

  const header = (key:string, title:string, detail:string, kind:NodeKind) => (
    <Button unstyled className={`tree-card topology-node topology-toggle topology-card-${kind}`} type="button" onClick={() => toggle(key)} aria-expanded={!collapsed.has(key)}>
      <strong><span className="topology-chevron" aria-hidden="true">{collapsed.has(key) ? "▶" : "▼"}</span>{title}</strong><span>{detail}</span>
    </Button>
  );

  const deviceMenuItems = (item:TopologyDevice, afterDelete?:() => void) => [
    ...deviceAccess.menuItems(item),
    { label:"Copy management IP", disabled:!item.management_ip, onClick:() => void copyToClipboard(item.management_ip || "") },
    { label:"Test accessibility", disabled:!item.management_ip, onClick:() => void onTestAccessibility(item.id) },
    ...(canDelete ? [{ label:"Move to Recycle Bin", danger:true, onClick:() => void (async () => { if (await onDeleteDevice(item.id, item.display_name)) afterDelete?.(); })() }] : []),
  ];

  const device = (item:TopologyDevice, level = 0, afterDelete?:() => void) => (
    <div className="context-target-holder" key={item.id}>
      <ContextMenu items={deviceMenuItems(item, afterDelete)}>
        <div className="tree-leaf topology-device" style={{ marginLeft:level * 18 }} onPointerEnter={() => void deviceAccess.prefetch(item.id)} onPointerDown={() => void deviceAccess.prefetch(item.id)} onDoubleClick={() => deviceAccess.openSecureWebIfAvailable(item)}>
          <div><strong>{item.display_name}</strong></div><span>{item.management_ip || "No management IP"} · {item.device_type_code} · {item.lifecycle_state} · {item.operational_state}</span>
        </div>
      </ContextMenu>
      {item.children?.map((child) => device(child, level + 1, afterDelete))}
    </div>
  );

  const renderCities = (items:TopologyCity[]) => items.map((city) => (
    <div className="tree-node topology-level-city" key={city.id}>{header(`city:${city.id}`, city.name, city.code, "city")}{!collapsed.has(`city:${city.id}`) && city.locations.map((location) => (
      <div className="tree-node topology-level-location" key={location.id}>{header(`location:${location.id}`, location.name, location.code, "location")}{!collapsed.has(`location:${location.id}`) && <>{location.devices.map((item) => device(item))}{location.sectors.map((sector:TopologySector) => (
        <div className="tree-node topology-level-sector" key={sector.id}>{header(`sector:${sector.id}`, sector.name, `${sector.code} · ${sector.role}`, "sector")}{!collapsed.has(`sector:${sector.id}`) && sector.devices.map((item) => device(item))}</div>
      ))}</>}</div>
    ))}</div>
  ));

  const lazyCities = useMemo(() => allCities.filter((city) => city.network_id === lazyNetworkId), [allCities, lazyNetworkId]);

  const setLazyBusy = (key:string, active:boolean) => setLazyLoading((current) => {
    const next = new Set(current);
    active ? next.add(key) : next.delete(key);
    return next;
  });

  const reloadLazyLocation = useCallback(async (locationId:string) => {
    const key=`location:${locationId}`; setLazyBusy(key,true);
    try {
      const [rows, sectorOptions]=await Promise.all([
        apiFetch<TopologyDevice[]>(`/topology/locations/${locationId}/devices`,{},token),
        apiFetch<{items:Array<{id:string;label:string}>}>(`/assignment-options/sectors?location_id=${locationId}&page=1&page_size=100`,{},token),
      ]);
      setLazyLocationDevices((current)=>({...current,[locationId]:rows}));
      setLazySectorLabels((current)=>({...current,...Object.fromEntries(sectorOptions.items.map((item)=>[item.id,item.label]))}));
    } catch(error) { feedback.error(friendlyError(error,"Unable to load location topology.")); }
    finally { setLazyBusy(key,false); }
  },[token,feedback]);

  const reloadLazySector = useCallback(async (sectorId:string) => {
    const key=`sector:${sectorId}`; setLazyBusy(key,true);
    try {
      const row=await apiFetch<TopologySector>(`/topology/sectors/${sectorId}/tree`,{},token);
      setLazySectorTrees((current)=>({...current,[sectorId]:row}));
    } catch(error) { feedback.error(friendlyError(error,"Unable to load sector topology.")); }
    finally { setLazyBusy(key,false); }
  },[token,feedback]);

  const toggleLazyNode = (key:string, loader?:()=>Promise<void>) => {
    const opening=!expandedNodes.has(key);
    setExpandedNodes((current)=>{const next=new Set(current); opening?next.add(key):next.delete(key); return next;});
    if(opening && loader) void loader();
  };

  const lazyHeader = (key:string,title:string,detail:string,kind:NodeKind,loader?:()=>Promise<void>) => {
    const open=expandedNodes.has(key);
    const loading=lazyLoading.has(key);
    return <Button unstyled className={`tree-card topology-node topology-toggle topology-card-${kind}`} type="button" onClick={()=>toggleLazyNode(key,loader)} aria-expanded={open}>
      <strong><span className="topology-chevron" aria-hidden="true">{open?"▼":"▶"}</span>{title}</strong><span>{loading?"Loading…":detail}</span>
    </Button>;
  };

  const renderLazyNetwork = () => {
    const network=networks.find((item)=>item.id===lazyNetworkId);
    if(!network)return <EmptyState text="Select a network and load its hierarchy."/>;
    return <section className="topology-tree"><div className="tree-root"><strong>{network.name}</strong><span>{network.code}</span></div>{lazyCities.map((city)=>{
      const cityKey=`lazy-city:${city.id}`; const cityOpen=expandedNodes.has(cityKey);
      const cityLocations=allLocations.filter((location)=>location.city_id===city.id);
      return <div className="tree-node topology-level-city" key={city.id}>{lazyHeader(cityKey,city.name,`${city.code} · ${cityLocations.length} location(s)`,"city")}{cityOpen&&cityLocations.map((location)=>{
        const locationKey=`location:${location.id}`; const locationOpen=expandedNodes.has(locationKey);
        const locationSectors=allSectors.filter((sector)=>sector.location_id===location.id);
        const locationRows=lazyLocationDevices[location.id]||[];
        return <div className="tree-node topology-level-location" key={location.id}>{lazyHeader(locationKey,location.name,`${location.code} · ${locationSectors.length} sector(s)`,"location",()=>reloadLazyLocation(location.id))}{locationOpen&&<>
          {locationRows.map((item)=>device(item,0,()=>void reloadLazyLocation(location.id)))}
          {locationSectors.map((sector)=>{const sectorKey=`sector:${sector.id}`;const sectorOpen=expandedNodes.has(sectorKey);const tree=lazySectorTrees[sector.id];return <div className="tree-node topology-level-sector" key={sector.id}>{lazyHeader(sectorKey,lazySectorLabels[sector.id] || tree?.name || sector.name,`${sector.code} · ${sector.role||"CUSTOMER_ACCESS"}`,"sector",()=>reloadLazySector(sector.id))}{sectorOpen&&tree?.devices.map((item)=>device(item,0,()=>void reloadLazySector(sector.id)))}</div>})}
        </>}</div>;
      })}</div>;
    })}</section>;
  };

  const loadLiveSector = useCallback(async ({ silent = false }: { silent?: boolean } = {}) => {
    if (!liveSectorId || liveLoadInFlight.current) return;
    liveLoadInFlight.current = true;
    if (!silent) setLiveLoading(true);
    try {
      setLiveTopology(await apiFetch<SectorLiveTopology>(`/topology/sectors/${liveSectorId}`, {}, token));
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to load live sector topology."));
    } finally {
      liveLoadInFlight.current = false;
      if (!silent) setLiveLoading(false);
    }
  }, [liveSectorId, token]);

  useEffect(() => {
    if (view !== "live-sector" || !liveSectorId || !liveTopology || !liveAutoRefresh) return;
    const timer = window.setInterval(() => void loadLiveSector({ silent: true }), 5000);
    return () => window.clearInterval(timer);
  }, [view, liveSectorId, liveTopology, liveAutoRefresh, loadLiveSector]);

  useEffect(() => {
    if (refreshKey <= 0 || view !== "live-sector" || !liveSectorId) return;
    void loadLiveSector({ silent: true });
  }, [refreshKey]);

  useEffect(() => {
    liveCenteredSectorRef.current = null;
    setLiveZoom(LIVE_STANDARD_ZOOM);
    setLiveFitMode(false);
  }, [liveSectorId]);

  const liveRoot = liveTopology?.sector.devices.find((item) => item.device_type_code === "SECTOR") || liveTopology?.sector.devices[0] || null;
  const liveCpes = liveRoot?.children?.filter((item) => item.device_type_code === "CPE") || [];
  const liveBranchWidths = liveCpes.map((cpe) => {
    const apCount = Math.max(cpe.children?.length || 0, 1);
    return Math.max(LIVE_CPE_MIN_BRANCH_WIDTH, apCount * LIVE_AP_GAP + LIVE_BRANCH_SIDE_PADDING);
  });
  const totalBranchWidth = liveBranchWidths.reduce((sum, width) => sum + width, 0);
  const canvasWidth = Math.max(1000, totalBranchWidth + LIVE_CANVAS_SIDE_PADDING * 2);
  const canvasHeight = LIVE_CANVAS_HEIGHT;
  const rootX = canvasWidth / 2;
  const rootY = 110;
  const cpeY = 335;
  const apY = 575;
  let branchCursor = (canvasWidth - totalBranchWidth) / 2;
  const cpeXs = liveBranchWidths.map((width) => {
    const x = branchCursor + width / 2;
    branchCursor += width;
    return x;
  });
  const xFor = (index:number) => cpeXs[index] ?? rootX;
  const apXFor = (cpeIndex:number, apIndex:number, apCount:number) => xFor(cpeIndex) + (apIndex - (apCount - 1) / 2) * LIVE_AP_GAP;
  const liveState = topologyLiveState;
  const liveCheckedAt = liveRoot?.live_checked_at ? new Date(liveRoot.live_checked_at).toLocaleTimeString() : null;
  const zoomPercent = Math.round(liveZoom * 100);

  const setZoomKeepingViewportCenter = (nextZoom:number) => {
    const viewport = liveScrollRef.current;
    const bounded = Math.max(LIVE_MIN_ZOOM, Math.min(LIVE_MAX_ZOOM, Math.round(nextZoom * 1000) / 1000));
    const logicalCenterX = viewport ? (viewport.scrollLeft + viewport.clientWidth / 2) / Math.max(liveZoom, 0.001) : rootX;
    const logicalCenterY = viewport ? (viewport.scrollTop + viewport.clientHeight / 2) / Math.max(liveZoom, 0.001) : canvasHeight / 2;
    setLiveFitMode(false);
    setLiveZoom(bounded);
    window.requestAnimationFrame(() => {
      if (!viewport) return;
      viewport.scrollLeft = Math.max(0, logicalCenterX * bounded - viewport.clientWidth / 2);
      viewport.scrollTop = Math.max(0, logicalCenterY * bounded - viewport.clientHeight / 2);
    });
  };

  const adjustZoom = (direction:number) => {
    const step = liveZoom < 0.25 ? 0.025 : liveZoom < 0.6 ? 0.05 : 0.1;
    setZoomKeepingViewportCenter(liveZoom + direction * step);
  };

  const beginLivePan = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (event.button !== 0) return;
    const target = event.target as HTMLElement;
    if (target.closest(".live-device-node, .context-menu, button, a, input, select, textarea")) return;
    const viewport = liveScrollRef.current;
    if (!viewport) return;
    livePanRef.current = {
      pointerId: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      scrollLeft: viewport.scrollLeft,
      scrollTop: viewport.scrollTop,
    };
    setLivePanning(true);
    viewport.setPointerCapture(event.pointerId);
    event.preventDefault();
  };

  const moveLivePan = (event: ReactPointerEvent<HTMLDivElement>) => {
    const pan = livePanRef.current;
    const viewport = liveScrollRef.current;
    if (!pan || !viewport || pan.pointerId !== event.pointerId) return;
    viewport.scrollLeft = pan.scrollLeft - (event.clientX - pan.startX);
    viewport.scrollTop = pan.scrollTop - (event.clientY - pan.startY);
    event.preventDefault();
  };

  const endLivePan = (event: ReactPointerEvent<HTMLDivElement>) => {
    const pan = livePanRef.current;
    const viewport = liveScrollRef.current;
    if (!pan || pan.pointerId !== event.pointerId) return;
    livePanRef.current = null;
    setLivePanning(false);
    if (viewport?.hasPointerCapture(event.pointerId)) viewport.releasePointerCapture(event.pointerId);
  };

  const fitLiveTopology = () => {
    const viewport = liveScrollRef.current;
    if (!viewport) return;
    const availableWidth = Math.max(220, viewport.clientWidth - 28);
    const availableHeight = Math.max(220, viewport.clientHeight - 28);
    const rawFit = Math.min(1, availableWidth / canvasWidth, availableHeight / canvasHeight) * 0.97;
    const fitted = Math.max(LIVE_MIN_FIT_ZOOM, Math.min(1, Math.floor(rawFit * 1000) / 1000));
    setLiveFitMode(true);
    setLiveZoom(fitted);
    window.requestAnimationFrame(() => {
      viewport.scrollLeft = 0;
      viewport.scrollTop = 0;
    });
  };

  useEffect(() => {
    const sectorId = liveTopology?.sector.id;
    if (!sectorId || !liveRoot || liveCenteredSectorRef.current === sectorId) return;
    liveCenteredSectorRef.current = sectorId;
    window.requestAnimationFrame(() => {
      const viewport = liveScrollRef.current;
      if (!viewport) return;
      const scaledRootX = rootX * liveZoom;
      const maxLeft = Math.max(0, canvasWidth * liveZoom - viewport.clientWidth);
      viewport.scrollLeft = Math.min(maxLeft, Math.max(0, scaledRootX - viewport.clientWidth / 2));
      viewport.scrollTop = 0;
    });
  }, [liveTopology?.sector.id, liveRoot, rootX, canvasWidth, liveZoom]);

  const liveNode = (item:TopologyDevice, x:number, y:number) => (
    <LiveDeviceNode
      key={item.id}
      item={item}
      x={x}
      y={y}
      canDelete={canDelete}
      onTestAccessibility={onTestAccessibility}
      onDeleteDevice={onDeleteDevice}
      onAfterDelete={() => void loadLiveSector({ silent: true })}
      remoteAccessItems={deviceAccess.menuItems(item)}
      onPrefetchAccess={() => void deviceAccess.prefetch(item.id)}
      onOpenSecureWebIfAvailable={() => deviceAccess.openSecureWebIfAvailable(item)}
    />
  );

  return <PageLayout className="topology-page">
    <div className="page-heading"><div><h2 className="hover-help-title" data-help="Navigate the hierarchy, inspect a Sector hierarchy, or view the physical infrastructure directly installed at a Location.">Network Topology</h2></div></div>
    <Tabs<ViewMode> ariaLabel="Topology views" value={view} onChange={setView} tabs={[{ id: "hierarchy", label: "Hierarchy Tree" }, { id: "live-sector", label: "Sector View" }, { id: "location", label: "Location View" }]} />

    {view === "hierarchy" ? <LazyTopologyHierarchy
      token={token}
      refreshKey={refreshKey}
      permissions={permissions}
      networks={networks}
      sourceNetworks={sourceNetworks}
      cities={allCities}
      locations={allLocations}
      sectors={allSectors}
      groups={groups}
      onTestAccessibility={onTestAccessibility}
      onDeleteDevice={onDeleteDevice}
    /> : view === "live-sector" ? <>
      <section className="panel live-sector-controls"><div className="panel-header"><div><h3 className="hover-help-title" data-help="Select a logical Sector to view its live SECTOR → CPE → ACCESS_POINT hierarchy.">Live Sector View</h3></div></div><div className="form-grid six">
        <label>Network<LocalSearchableCombobox value={liveNetworkId} options={liveNetworkOptions} disabled={networks.length === 1} onChange={(option) => { setLiveNetworkId(option?.id||""); setLiveServiceVlanId(""); setLiveCustomerVlanId(""); setLiveCityId(""); setLiveLocationId(""); setLiveSectorId(""); setLiveTopology(null); }} placeholder="Search network..." emptyText="No networks are available in your assigned area." /></label>
        <label>S-VLAN<LocalSearchableCombobox value={liveServiceVlanId} options={liveServiceVlanOptions} onChange={(option)=>{setLiveServiceVlanId(option?.id||"");setLiveCityId("");setLiveLocationId("");setLiveSectorId("");setLiveTopology(null)}} placeholder="All S-VLANs / search..." emptyText="No S-VLANs are available in the selected network." /></label>
        <label>C-VLAN<LocalSearchableCombobox value={liveCustomerVlanId} options={liveCustomerVlanOptions} onChange={(option)=>{setLiveCustomerVlanId(option?.id||"");setLiveSectorId("");setLiveTopology(null)}} placeholder="All C-VLANs / search..." emptyText="No C-VLANs are available in the selected area." /></label>
        <label>City<LocalSearchableCombobox value={liveCityId} options={liveCityOptions} disabled={allCities.length === 1} onChange={(option) => { const city=option?.data; setLiveCityId(option?.id||""); if (city?.network_id) setLiveNetworkId(city.network_id); if(city?.service_vlan_id!=null)setLiveServiceVlanId(String(city.service_vlan_id)); setLiveLocationId(""); setLiveSectorId(""); setLiveTopology(null); }} placeholder="Search city..." emptyText="No cities are available in the selected area." /></label>
        <label>Location<LocalSearchableCombobox value={liveLocationId} options={liveLocationOptions} disabled={allLocations.length === 1} onChange={(option) => { const location=option?.data; const city=location ? cityById.get(location.city_id) : undefined; setLiveLocationId(option?.id||""); if (location) setLiveCityId(location.city_id); if (city?.network_id) setLiveNetworkId(city.network_id); if(city?.service_vlan_id!=null)setLiveServiceVlanId(String(city.service_vlan_id)); setLiveSectorId(""); setLiveTopology(null); }} placeholder="Search location..." emptyText="No locations are available in the selected area." /></label>
        <label>Sector<LocalSearchableCombobox value={liveSectorId} options={liveSectorOptions} disabled={allSectors.length === 1} onChange={(option) => { const sector=option?.data; const location=sector ? locationById.get(sector.location_id) : undefined; const city=location ? cityById.get(location.city_id) : undefined; setLiveSectorId(option?.id||""); if (sector) setLiveLocationId(sector.location_id); if (location) setLiveCityId(location.city_id); if (city?.network_id) setLiveNetworkId(city.network_id); if(city?.service_vlan_id!=null)setLiveServiceVlanId(String(city.service_vlan_id)); setLiveTopology(null); }} placeholder="Search sector by physical or logical name..." emptyText="No sectors are available in the selected area." /></label>
      </div><Button unstyled onClick={() => void loadLiveSector()} disabled={!liveSectorId || liveLoading}>{liveLoading ? "Loading…" : "Show Live Topology"}</Button></section>
      {!liveTopology ? <EmptyState text="Select a logical sector to render its live device hierarchy." /> : <section className="panel live-sector-panel"><div className="live-sector-heading"><div><div className="eyebrow">{liveTopology.network.name} / {liveTopology.city.name} / {liveTopology.location.name}</div><h3>{liveTopology.sector.name}</h3><span>{liveTopology.sector.code} · {liveTopology.sector.role} · {liveCpes.length} CPE branch(es){liveCheckedAt ? ` · checked ${liveCheckedAt}` : ""}</span></div><div className="live-sector-actions"><div className="live-status-legend"><span><i className="legend-dot up"/>UP</span><span><i className="legend-dot down"/>DOWN</span><span><i className="legend-dot degraded"/>DEGRADED</span><span><i className="legend-dot unknown"/>UNKNOWN</span></div><div className="live-toolbar"><Button unstyled type="button" className="secondary small" onClick={() => adjustZoom(-1)} disabled={liveZoom <= LIVE_MIN_ZOOM}>−</Button><Button unstyled type="button" className="secondary small zoom-readout" onClick={() => setZoomKeepingViewportCenter(LIVE_STANDARD_ZOOM)} title="Reset to 100%">{zoomPercent}%</Button><Button unstyled type="button" className="secondary small" onClick={() => adjustZoom(1)} disabled={liveZoom >= LIVE_MAX_ZOOM}>+</Button><Button unstyled type="button" className={`secondary small${liveFitMode ? " active-fit" : ""}`} onClick={fitLiveTopology}>Fit</Button><Button unstyled type="button" className="secondary small" onClick={() => setLiveAutoRefresh((current) => !current)}>{liveAutoRefresh ? "Pause live refresh" : "Resume live refresh"}</Button><Button unstyled type="button" className="secondary small" onClick={() => void loadLiveSector({ silent: true })}>Refresh now</Button></div></div></div>
        {!liveRoot ? <EmptyState text="This logical sector has no bound SECTOR equipment to render." /> : <div ref={liveScrollRef} className={`live-topology-scroll${livePanning ? " is-panning" : ""}`} onPointerDown={beginLivePan} onPointerMove={moveLivePan} onPointerUp={endLivePan} onPointerCancel={endLivePan} onWheel={(event) => { if (event.ctrlKey) { event.preventDefault(); adjustZoom(event.deltaY < 0 ? 1 : -1); } }}><div className="live-topology-stage" style={{ width:canvasWidth * liveZoom, height:canvasHeight * liveZoom }}><div className="live-topology-canvas" style={{ width:canvasWidth, height:canvasHeight, transform:`scale(${liveZoom})` }}>
          <svg className="live-connectors" width={canvasWidth} height={canvasHeight} viewBox={`0 0 ${canvasWidth} ${canvasHeight}`} aria-hidden="true">
            {liveCpes.map((cpe, index) => { const x=xFor(index); return <g key={cpe.id}><path d={`M ${rootX} ${rootY + 62} C ${rootX} ${rootY + 145}, ${x} ${cpeY - 135}, ${x} ${cpeY - 62}`} />{(cpe.children || []).map((ap, apIndex) => { const apX=apXFor(index, apIndex, cpe.children?.length || 1); return <path key={ap.id} d={`M ${x} ${cpeY + 62} C ${x} ${cpeY + 132}, ${apX} ${apY - 112}, ${apX} ${apY - 62}`} />; })}</g>; })}
          </svg>
          {liveNode(liveRoot, rootX, rootY)}
          {liveCpes.map((cpe, index) => { const x=xFor(index); return <div key={cpe.id}>{liveNode(cpe, x, cpeY)}{(cpe.children || []).map((ap, apIndex) => liveNode(ap, apXFor(index, apIndex, cpe.children?.length || 1), apY))}</div>; })}
        </div></div></div>}
      </section>}
    </> : <LocationPhysicalTopology
      token={token}
      refreshKey={refreshKey}
      permissions={permissions}
      networks={networks}
      cities={allCities}
      locations={allLocations}
      onTestAccessibility={onTestAccessibility}
      onDeleteDevice={onDeleteDevice}
    />}
  </PageLayout>;
}
