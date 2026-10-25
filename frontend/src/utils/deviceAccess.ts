import { apiFetch } from "../api/client";

export type DeviceAccessCapability = {
  available: boolean;
  ready: boolean;
  reason_code: string | null;
};

export type DeviceAccessCapabilities = {
  device_id: string;
  secure_web: DeviceAccessCapability;
  ssh: DeviceAccessCapability;
  telnet: DeviceAccessCapability;
};

export type DeviceAccessTarget = {
  id: string;
  display_name: string;
  management_ip?: string | null;
  lifecycle_state?: string | null;
};

export type DeviceAccessMenuItem = {
  label: string;
  disabled?: boolean;
  onClick: () => void;
};

export const DEVICE_ACCESS_CHANGED_EVENT = "fttw-device-access-changed";

export async function fetchDeviceAccessCapabilities(
  token: string,
  deviceId: string,
): Promise<DeviceAccessCapabilities> {
  return apiFetch<DeviceAccessCapabilities>(
    `/devices/${deviceId}/access-capabilities`,
    {},
    token,
  );
}

export function notifyDeviceAccessChanged(deviceId: string): void {
  window.dispatchEvent(new CustomEvent(DEVICE_ACCESS_CHANGED_EVENT, { detail: { deviceId } }));
}

export function buildDeviceAccessMenuItems({
  capabilities,
  loading,
  onSecureWeb,
  onSsh,
  onTelnet,
}: {
  capabilities: DeviceAccessCapabilities | undefined;
  loading: boolean;
  onSecureWeb: () => void;
  onSsh: () => void;
  onTelnet: () => void;
}): DeviceAccessMenuItem[] {
  if (!capabilities) {
    return loading
      ? [{ label: "Checking remote access…", disabled: true, onClick: () => undefined }]
      : [];
  }

  const items: DeviceAccessMenuItem[] = [];
  if (capabilities.secure_web.available) {
    items.push({ label: "Secure GUI", onClick: onSecureWeb });
  }
  if (capabilities.ssh.available) {
    const hostTrustRequired = capabilities.ssh.reason_code === "SSH_HOST_KEY_TRUST_REQUIRED";
    items.push({
      label: capabilities.ssh.ready || hostTrustRequired ? "SSH Terminal" : "SSH Terminal (not ready)",
      disabled: !capabilities.ssh.ready && !hostTrustRequired,
      onClick: onSsh,
    });
  }
  if (capabilities.telnet.available) {
    items.push({ label: "Telnet Terminal", onClick: onTelnet });
  }
  return items;
}