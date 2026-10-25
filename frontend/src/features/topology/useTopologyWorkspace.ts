import { useCallback, useRef, useState } from "react";
import { apiFetch } from "../../api/client";
import type { Group, Network, NetworkTopology } from "../../types";

type Options = {
  token: string;
  recycleEntity: (entityType: string, id: string, label: string, deletePath: string) => Promise<boolean>;
  onDevicesChanged: () => Promise<void>;
  setMessage: (value: string) => void;
  onError: (error: unknown, fallback: string) => void;
};

export function useTopologyWorkspace(options: Options) {
  const optionsRef = useRef(options); optionsRef.current = options;
  const [topology, setTopology] = useState<NetworkTopology | null>(null);

  const loadGroup = useCallback(async (group: Group) => {
    const current = optionsRef.current;
    try { setTopology(await apiFetch<NetworkTopology>(`/topology/groups/${group.id}`, {}, current.token)); }
    catch (error) { current.onError(error, "Unable to load group topology."); }
  }, []);

  const loadNetwork = useCallback(async (network: Network) => {
    const current = optionsRef.current;
    try { setTopology(await apiFetch<NetworkTopology>(`/topology/networks/${network.id}`, {}, current.token)); }
    catch (error) { current.onError(error, "Unable to load topology."); }
  }, []);

  const deleteDevice = useCallback(async (deviceId: string, displayName: string) => {
    const current = optionsRef.current;
    try {
      if (!await current.recycleEntity("DEVICE", deviceId, displayName, `/devices/${deviceId}`)) return false;
      await current.onDevicesChanged(); current.setMessage(`${displayName} moved to the Recycle Bin.`); return true;
    } catch (error) { current.onError(error, "Unable to move topology device to the Recycle Bin."); return false; }
  }, []);

  return { topology, loadGroup, loadNetwork, deleteDevice };
}
