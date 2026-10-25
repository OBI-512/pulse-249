import { apiFetch } from "../api/client";

type RemoteLaunch = {
  session_id: string;
  ticket: string;
  expires_at: string;
  websocket_path: string;
};

type ChildMessage = { type: "ready" } | { type: "received" };

function websocketUrl(path: string): string {
  const configured = (import.meta.env.VITE_REMOTE_ACCESS_WS_URL || "").trim();
  if (configured) {
    return configured.includes("{path}") ? configured.replace("{path}", path) : `${configured.replace(/\/$/, "")}${path}`;
  }
  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  if (window.location.port === "3000") return `${scheme}//${window.location.hostname}:8010${path}`;
  return `${scheme}//${window.location.host}/remote-access${path}`;
}

/**
 * Open a brokered Telnet session in the existing FTTW xterm terminal.
 * The one-time launch ticket is transferred only in memory over BroadcastChannel.
 */
export async function openWebTelnetWindow(token: string, deviceId: string, deviceName: string): Promise<void> {
  const channelId = crypto.randomUUID();
  const channelName = `fttw-remote-ssh-${channelId}`;
  const params = new URLSearchParams({ channel: channelId, device: deviceName, protocol: "TELNET" });
  const terminal = window.open(`/remote-ssh.html?${params.toString()}`, "_blank");
  if (!terminal) throw new Error("The browser blocked the Telnet terminal tab. Allow pop-ups for FTTW and try again.");

  const channel = new BroadcastChannel(channelName);
  let readyResolve: (() => void) | null = null;
  let receivedResolve: (() => void) | null = null;
  const ready = new Promise<void>((resolve) => { readyResolve = resolve; });
  const received = new Promise<void>((resolve) => { receivedResolve = resolve; });
  channel.onmessage = (event: MessageEvent<ChildMessage>) => {
    if (event.data?.type === "ready") readyResolve?.();
    if (event.data?.type === "received") receivedResolve?.();
  };
  const timeout = window.setTimeout(() => { readyResolve?.(); receivedResolve?.(); }, 10000);

  try {
    await ready;
    if (terminal.closed) throw new Error("The Telnet terminal tab was closed before the session started.");
    const launch = await apiFetch<RemoteLaunch>(
      `/devices/${deviceId}/remote-access/telnet-sessions`, { method: "POST" }, token,
    );
    channel.postMessage({
      type: "launch",
      session_id: launch.session_id,
      ticket: launch.ticket,
      expires_at: launch.expires_at,
      websocket_path: launch.websocket_path,
      websocket_url: websocketUrl(launch.websocket_path),
      device_id: deviceId,
      device_name: deviceName,
      protocol: "TELNET",
    });
    await received;
  } catch (error) {
    channel.postMessage({ type: "error", message: error instanceof Error ? error.message : "Unable to start Telnet." });
    throw error;
  } finally {
    window.clearTimeout(timeout);
    window.setTimeout(() => channel.close(), 1000);
  }
}
