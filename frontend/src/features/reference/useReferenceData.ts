import { useCallback, useEffect, useRef, useState } from "react";
import { apiFetch } from "../../api/client";
import type { City, DeviceType, Group, Location, Network, Page, Sector } from "../../types";

async function fetchAllOffsetPages<T>(path: string, token: string, pageSize = 500, concurrency = 4): Promise<T[]> {
  const items: T[] = [];
  let offset = 0;
  const separator = path.includes("?") ? (path.endsWith("?") || path.endsWith("&") ? "" : "&") : "?";
  while (true) {
    const offsets = Array.from({ length: concurrency }, (_, index) => offset + index * pageSize);
    const pages = await Promise.all(
      offsets.map((pageOffset) => apiFetch<T[]>(`${path}${separator}limit=${pageSize}&offset=${pageOffset}`, {}, token)),
    );
    for (const page of pages) {
      items.push(...page);
      if (page.length < pageSize) return items;
    }
    offset += pageSize * concurrency;
  }
}

type ReferenceDataOptions = {
  token: string;
  permissions: string[];
  page: Page;
  onError: (error: unknown, fallback: string) => void;
};

type CoreReferenceData = { types: DeviceType[]; networks: Network[] };

export function useReferenceData({ token, permissions, page, onError }: ReferenceDataOptions) {
  const onErrorRef = useRef(onError);
  onErrorRef.current = onError;
  const [types, setTypes] = useState<DeviceType[]>([]);
  const [networks, setNetworks] = useState<Network[]>([]);
  const [cities, setCities] = useState<City[]>([]);
  const [locations, setLocations] = useState<Location[]>([]);
  const [sectors, setSectors] = useState<Sector[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [scopeNetworks, setScopeNetworks] = useState<Network[]>([]);
  const [topologySourceNetworks, setTopologySourceNetworks] = useState<Network[]>([]);
  const [scopeCities, setScopeCities] = useState<City[]>([]);
  const [scopeLocations, setScopeLocations] = useState<Location[]>([]);
  const [scopeSectors, setScopeSectors] = useState<Sector[]>([]);

  const fetchCore = useCallback(async (sessionToken: string, sessionPermissions: string[]): Promise<CoreReferenceData> => {
    const can = (permission: string) => sessionPermissions.includes(permission);
    const [typeData, networkData] = await Promise.all([
      can("device.read") ? apiFetch<DeviceType[]>("/devices/types", {}, sessionToken) : Promise.resolve([] as DeviceType[]),
      can("network.read") ? fetchAllOffsetPages<Network>("/networks", sessionToken) : Promise.resolve([] as Network[]),
    ]);
    return { types: typeData, networks: networkData };
  }, []);

  const applyCore = useCallback((data: CoreReferenceData) => {
    setTypes(data.types);
    setNetworks(data.networks);
  }, []);

  const loadNetworks = useCallback(async () => {
    if (!permissions.includes("network.read")) {
      setNetworks([]);
      return;
    }
    setNetworks(await fetchAllOffsetPages<Network>("/networks", token));
  }, [permissions, token]);

  const loadGroups = useCallback(async () => {
    setGroups(await apiFetch<Group[]>("/device-groups", {}, token));
  }, [token]);

  const loadCities = useCallback(async (networkId: string) => {
    if (!networkId) { setCities([]); return; }
    setCities(await apiFetch<City[]>(`/networks/${networkId}/cities`, {}, token));
  }, [token]);

  const loadLocations = useCallback(async (cityId: string) => {
    if (!cityId) { setLocations([]); return; }
    setLocations(await apiFetch<Location[]>(`/cities/${cityId}/locations`, {}, token));
  }, [token]);

  const loadSectors = useCallback(async (locationId: string) => {
    if (!locationId) { setSectors([]); return; }
    setSectors(await apiFetch<Sector[]>(`/locations/${locationId}/sectors`, {}, token));
  }, [token]);

  const loadCrossNetworkGeography = useCallback(async () => {
    const data = await apiFetch<{ networks: Network[]; cities: City[]; locations: Location[]; sectors: Sector[] }>(
      "/geography/scope-options", {}, token,
    );
    setTopologySourceNetworks(data.networks || []);
    setScopeNetworks(data.networks || []);
    setScopeCities(data.cities || []);
    setScopeLocations(data.locations || []);
    setScopeSectors(data.sectors || []);
  }, [token]);

  const loadTopologyScopeGeography = useCallback(async () => {
    const data = await apiFetch<{ source_networks:Network[]; networks:Network[]; cities:City[]; locations:Location[]; sectors:Sector[] }>(
      "/topology/scope-options", {}, token,
    );
    setTopologySourceNetworks(data.source_networks || []);
    setScopeNetworks(data.networks || []);
    setScopeCities(data.cities || []);
    setScopeLocations(data.locations || []);
    setScopeSectors(data.sectors || []);
  }, [token]);

  useEffect(() => {
    if (!permissions.length || !["groups", "devices", "topology", "candidates", "customers"].includes(page)) return;
    if (page === "topology" && permissions.includes("topology.read")) {
      void loadTopologyScopeGeography().catch((error) => onErrorRef.current(error, "Unable to load the topology area available to this account."));
      return;
    }
    if (!permissions.includes("geo.read")) {
      setTopologySourceNetworks([]); setScopeNetworks([]); setScopeCities([]); setScopeLocations([]); setScopeSectors([]);
      return;
    }
    void loadCrossNetworkGeography().catch((error) => onErrorRef.current(error, "Unable to load available geography."));
  }, [page, permissions, loadCrossNetworkGeography, loadTopologyScopeGeography]);

  return {
    types, networks, cities, locations, sectors, groups,
    scopeNetworks, scopeCities, scopeLocations, scopeSectors, topologySourceNetworks,
    fetchCore, applyCore, loadNetworks, loadGroups,
    loadCities, loadLocations, loadSectors, loadCrossNetworkGeography, loadTopologyScopeGeography,
  };
}
