import { ContextMenu } from "../../design-system/composites/Menu";
import { Button } from "../../design-system/primitives";
import type { TopologyDevice } from "../../types";
import { copyToClipboard } from "../../utils/management";
import type { DeviceAccessMenuItem } from "../../utils/deviceAccess";

function statusClass(state: string) {
  const normalized = state.toUpperCase();
  if (normalized === "UP") return "live-status-up";
  if (normalized === "DOWN") return "live-status-down";
  if (normalized === "DEGRADED") return "live-status-degraded";
  return "live-status-unknown";
}

function DeviceVectorIcon({ type }: { type: string }) {
  const normalized = type.toUpperCase();
  if (normalized === "SECTOR") return <svg viewBox="0 0 48 48" aria-hidden="true"><path d="M24 8v30M17 38h14M18 14a9 9 0 0 1 12 0M13 9a16 16 0 0 1 22 0"/><circle cx="24" cy="19" r="3"/></svg>;
  if (normalized === "CPE") return <svg viewBox="0 0 48 48" aria-hidden="true"><rect x="10" y="15" width="28" height="20" rx="5"/><path d="M18 15v-4M30 15v-4M17 26h14"/><circle cx="17" cy="30" r="1.5"/><circle cx="22" cy="30" r="1.5"/></svg>;
  if (normalized === "ACCESS_POINT") return <svg viewBox="0 0 48 48" aria-hidden="true"><rect x="11" y="26" width="26" height="10" rx="4"/><circle cx="24" cy="31" r="2"/><path d="M18 21a9 9 0 0 1 12 0M14 16a15 15 0 0 1 20 0"/></svg>;
  if (["ROUTER", "SWITCH", "FIREWALL"].includes(normalized)) return <svg viewBox="0 0 48 48" aria-hidden="true"><rect x="8" y="14" width="32" height="20" rx="4"/><path d="M14 20h20M14 27h4M22 27h4M30 27h4"/></svg>;
  if (normalized === "WIRELESS_BRIDGE") return <svg viewBox="0 0 48 48" aria-hidden="true"><path d="M11 33h26M16 33V22m16 11V22M13 19a15 15 0 0 1 22 0M18 24a8 8 0 0 1 12 0"/><circle cx="16" cy="20" r="2"/><circle cx="32" cy="20" r="2"/></svg>;
  return <svg viewBox="0 0 48 48" aria-hidden="true"><rect x="9" y="11" width="30" height="26" rx="5"/><path d="M15 18h18M15 24h18M15 30h12"/></svg>;
}

export function topologyLiveState(item: TopologyDevice) {
  return item.live_state || item.operational_state || "UNKNOWN";
}

export function LiveDeviceNode({
  item,
  x,
  y,
  canDelete,
  onTestAccessibility,
  onDeleteDevice,
  onAfterDelete,
  remoteAccessItems,
  onPrefetchAccess,
  onOpenSecureWebIfAvailable,
}: {
  item: TopologyDevice;
  x: number;
  y: number;
  canDelete: boolean;
  onTestAccessibility: (deviceId: string) => void | Promise<void>;
  onDeleteDevice: (deviceId: string, displayName: string) => Promise<boolean>;
  onAfterDelete?: () => void;
  remoteAccessItems: DeviceAccessMenuItem[];
  onPrefetchAccess: () => void;
  onOpenSecureWebIfAvailable: () => void;
}) {
  const state = topologyLiveState(item);
  const menuItems = [
    ...remoteAccessItems,
    { label: "Copy management IP", disabled: !item.management_ip, onClick: () => void copyToClipboard(item.management_ip || "") },
    { label: "Test accessibility", disabled: !item.management_ip, onClick: () => void onTestAccessibility(item.id) },
    ...(canDelete ? [{ label: "Move to Recycle Bin", danger: true, onClick: () => void (async () => { if (await onDeleteDevice(item.id, item.display_name)) onAfterDelete?.(); })() }] : []),
  ];

  return <div className="live-node-position" style={{ left: x, top: y }}>
    <ContextMenu items={menuItems}>
      <Button
        unstyled
        type="button"
        className={`live-device-node ${statusClass(state)}`}
        onPointerEnter={onPrefetchAccess}
        onPointerDown={onPrefetchAccess}
        onContextMenu={onPrefetchAccess}
        onDoubleClick={onOpenSecureWebIfAvailable}
        title={`${item.device_type_code} · ${state}${item.live_response_time_ms != null ? ` · ${item.live_response_time_ms} ms` : ""}. Double-click opens Secure GUI when available. Right-click for actions.`}
      >
        <span className="live-device-icon"><DeviceVectorIcon type={item.device_type_code} /></span>
        <span className="live-device-copy"><strong>{item.display_name}</strong><span>{item.management_ip || "No management IP"}</span></span>
        <span className="live-state-dot" aria-label={state} title={state} />
      </Button>
    </ContextMenu>
  </div>;
}