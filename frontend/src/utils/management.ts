import { apiFetch } from "../api/client";

type ManagementDevice = {
  id?: string;
  management_ip?: string | null;
  management_protocol?: string | null;
  web_scheme?: string | null;
  web_port?: number | null;
};

type AccessibilityResult = {
  reachable: boolean;
  url: string;
  status_code: number | null;
  response_time_ms: number | null;
  message: string;
};

export function managementUrl(device: ManagementDevice) {
  if (!device.management_ip) return "";
  const normalized = (device.web_scheme || device.management_protocol || "").trim().toUpperCase();
  // Management protocols such as SNMP/SSH do not describe the web GUI.
  // Prefer HTTPS when the GUI scheme is not explicitly known.
  const protocol = normalized.includes("HTTP") && !normalized.includes("HTTPS") ? "http" : "https";
  const ip = device.management_ip.includes(":") && !device.management_ip.startsWith("[") ? `[${device.management_ip}]` : device.management_ip;
  const defaultPort = protocol === "http" ? 80 : 443;
  const suffix = device.web_port != null && device.web_port !== defaultPort ? `:${device.web_port}` : "";
  return `${protocol}://${ip}${suffix}`;
}

export async function resolveManagementUrl(token: string, deviceId: string): Promise<AccessibilityResult> {
  return apiFetch<AccessibilityResult>(
    `/devices/${deviceId}/test-accessibility`,
    { method: "POST" },
    token,
  );
}

/**
 * Open a registered device's native management GUI without trusting its
 * inventory management_protocol as the web protocol.  A blank tab is opened
 * synchronously so browser popup blocking cannot race the HTTPS/HTTP probe;
 * the backend then resolves HTTPS first and HTTP only as a fallback.
 */
export async function openManagementGui(device: ManagementDevice, token?: string): Promise<boolean> {
  if (!device.management_ip) return false;
  if (!token || !device.id) {
    window.open(managementUrl(device), "_blank", "noopener,noreferrer");
    return true;
  }

  const tab = window.open("about:blank", "_blank");
  if (!tab) return false;
  try { tab.opener = null; } catch { /* best effort */ }
  try {
    tab.document.title = "Resolving device management GUI…";
    tab.document.body.textContent = "Resolving secure device management endpoint…";
  } catch { /* cross-browser best effort */ }

  try {
    const result = await resolveManagementUrl(token, device.id);
    if (!result.reachable || !result.url) {
      tab.close();
      return false;
    }
    tab.location.replace(result.url);
    return true;
  } catch (error) {
    tab.close();
    throw error;
  }
}

export async function copyToClipboard(value: string) {
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
  }
}
