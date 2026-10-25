import { apiFetch } from "../api/client";

type RemoteLaunch = {
  session_id: string;
  ticket: string;
  expires_at: string;
  websocket_path: string;
};

type WebRemoteLaunch = {
  session_id: string;
  ticket: string;
  expires_at: string;
};

type ChildMessage = { type: "ready" } | { type: "received" };

type WebGuiReadyMessage = {
  type: "fttw-web-gui-ready";
  channel: string;
};

function websocketUrl(path: string): string {
  const configured = (import.meta.env.VITE_REMOTE_ACCESS_WS_URL || "").trim();
  if (configured) {
    return configured.includes("{path}") ? configured.replace("{path}", path) : `${configured.replace(/\/$/, "")}${path}`;
  }
  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  if (window.location.port === "3000") return `${scheme}//${window.location.hostname}:8010${path}`;
  return `${scheme}//${window.location.host}/remote-access${path}`;
}

function terminalUrl(channelId: string, deviceName: string): string {
  const params = new URLSearchParams({ channel: channelId, device: deviceName });
  return `/remote-ssh.html?${params.toString()}`;
}

function installFttwSshAlertDialog(target: Window, deviceName: string): void {
  try {
    const doc = target.document;
    if (!doc || doc.getElementById("fttw-ssh-dialog-overlay")) return;

    const style = doc.createElement("style");
    style.id = "fttw-ssh-dialog-style";
    style.textContent = `
      #fttw-ssh-dialog-overlay { position: fixed; inset: 0; z-index: 2147483647; display: none; align-items: center; justify-content: center; background: rgba(15,23,42,.46); font-family: Inter, Segoe UI, Arial, sans-serif; }
      #fttw-ssh-dialog-box { width: min(480px, calc(100vw - 40px)); overflow: hidden; border: 1px solid #d8e2f0; border-radius: 14px; background: #fff; color: #253858; box-shadow: 0 20px 56px rgba(15,23,42,.28); }
      #fttw-ssh-dialog-head { padding: 16px 20px 10px; color: #17365d; font-size: 17px; font-weight: 700; }
      #fttw-ssh-dialog-message { padding: 4px 20px 18px; line-height: 1.5; white-space: pre-wrap; word-break: break-word; }
      #fttw-ssh-dialog-actions { display: flex; gap: 10px; justify-content: flex-end; padding: 12px 16px 16px; border-top: 1px solid #edf2f7; }
      #fttw-ssh-dialog-cancel, #fttw-ssh-dialog-confirm { min-width: 92px; border-radius: 8px; padding: 9px 18px; font-weight: 700; cursor: pointer; }
      #fttw-ssh-dialog-cancel { border: 1px solid #cbd5e1; background: #fff; color: #334155; }
      #fttw-ssh-dialog-confirm { border: 0; background: #2f80d0; color: #fff; }
      #fttw-ssh-dialog-confirm[data-danger="true"] { background: #b42318; }
      #fttw-ssh-dialog-cancel:focus, #fttw-ssh-dialog-confirm:focus { outline: 3px solid rgba(47,128,208,.25); outline-offset: 2px; }
    `;
    (doc.head || doc.documentElement).appendChild(style);

    const overlay = doc.createElement("div");
    overlay.id = "fttw-ssh-dialog-overlay";
    overlay.innerHTML = '<div id="fttw-ssh-dialog-box" role="dialog" aria-modal="true" aria-labelledby="fttw-ssh-dialog-head" aria-describedby="fttw-ssh-dialog-message"><div id="fttw-ssh-dialog-head">FTTW Remote Access</div><div id="fttw-ssh-dialog-message"></div><div id="fttw-ssh-dialog-actions"><button id="fttw-ssh-dialog-cancel" type="button">Cancel</button><button id="fttw-ssh-dialog-confirm" type="button">OK</button></div></div>';
    (doc.body || doc.documentElement).appendChild(overlay);

    const head = overlay.querySelector<HTMLElement>("#fttw-ssh-dialog-head");
    const message = overlay.querySelector<HTMLElement>("#fttw-ssh-dialog-message");
    const cancel = overlay.querySelector<HTMLButtonElement>("#fttw-ssh-dialog-cancel");
    const confirmButton = overlay.querySelector<HTMLButtonElement>("#fttw-ssh-dialog-confirm");

    type DialogRequest = {
      kind: "alert" | "confirm";
      title: string;
      message: string;
      confirmLabel: string;
      danger?: boolean;
      onConfirm?: () => void;
    };

    const queue: DialogRequest[] = [];
    let active: DialogRequest | null = null;
    let lastTrigger: HTMLElement | null = null;
    let bypassConfirmFor: HTMLElement | null = null;
    let bypassCloseFor: HTMLElement | null = null;

    const showNext = () => {
      if (active || queue.length === 0 || !head || !message || !cancel || !confirmButton) return;
      active = queue.shift() || null;
      if (!active) return;
      head.textContent = active.title;
      message.textContent = active.message;
      cancel.style.display = active.kind === "confirm" ? "inline-block" : "none";
      confirmButton.textContent = active.confirmLabel;
      confirmButton.dataset.danger = active.danger ? "true" : "false";
      overlay.style.display = "flex";
      target.setTimeout(() => (active?.kind === "confirm" ? cancel : confirmButton).focus(), 0);
    };

    const finish = (confirmed: boolean) => {
      const completed = active;
      active = null;
      overlay.style.display = "none";
      if (confirmed) completed?.onConfirm?.();
      showNext();
    };

    const enqueue = (request: DialogRequest) => { queue.push(request); showNext(); };
    cancel?.addEventListener("click", () => finish(false));
    confirmButton?.addEventListener("click", () => finish(true));

    const triggerFromEvent = (event: Event): HTMLElement | null => {
      const source = event.target as Element | null;
      const closest = source?.closest?.('button, [role="button"], a, input[type="button"], input[type="submit"]');
      return closest as HTMLElement | null;
    };

    const isCloseSessionControl = (control: HTMLElement): boolean => {
      const label = [control.textContent, control.getAttribute("aria-label"), control.getAttribute("title"), control.id]
        .filter(Boolean).join(" ").replace(/\s+/g, " ").trim().toLowerCase();
      return label.includes("close session") || label.includes("terminate session");
    };

    // Track the action that led to a synchronous native confirm(). The first
    // confirm call is cancelled and presented asynchronously in FTTW styling.
    // If approved, the same control is replayed once and only that replay is
    // allowed through confirm(), preserving the child page's original action.
    doc.addEventListener("click", (event) => {
      const control = triggerFromEvent(event);
      if (!control || overlay.contains(control)) return;
      lastTrigger = control;

      if (!isCloseSessionControl(control)) return;
      if (bypassCloseFor === control) {
        bypassCloseFor = null;
        return;
      }

      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();
      enqueue({
        kind: "confirm",
        title: "Terminate SSH session",
        message: `Terminate the active SSH session for ${deviceName}?\n\nAny unsaved terminal work will be lost.`,
        confirmLabel: "Terminate session",
        danger: true,
        onConfirm: () => {
          if (!control.isConnected) return;
          bypassCloseFor = control;
          bypassConfirmFor = control;
          control.click();
        },
      });
    }, true);

    target.alert = (value?: unknown) => {
      enqueue({
        kind: "alert",
        title: "FTTW Remote Access",
        message: String(value ?? ""),
        confirmLabel: "OK",
      });
    };

    target.confirm = (value?: unknown) => {
      const trigger = lastTrigger;
      if (trigger && bypassConfirmFor === trigger) {
        bypassConfirmFor = null;
        return true;
      }

      const text = String(value ?? "");
      const isPaste = /^\s*Paste\b/i.test(text);
      enqueue({
        kind: "confirm",
        title: isPaste ? "Confirm paste" : "Confirm action",
        message: text,
        confirmLabel: isPaste ? "Paste" : "Continue",
        onConfirm: () => {
          if (!trigger?.isConnected) return;
          bypassConfirmFor = trigger;
          trigger.click();
        },
      });
      return false;
    };
  } catch {
    // Same-origin Web SSH is expected; if browser policy changes, do not block
    // session launch merely because the presentation enhancement cannot install.
  }
}

export function webGuiGatewayOrigin(): string {
  const configured = (import.meta.env.VITE_REMOTE_ACCESS_WEB_ORIGIN || "").trim();
  if (configured) {
    const parsed = new URL(configured, window.location.href);
    return parsed.origin;
  }
  return `${window.location.protocol}//${window.location.hostname}:8010`;
}

/**
 * Open a brokered Web-SSH terminal in a standalone browser tab.
 * The one-time ticket is transferred only in memory over BroadcastChannel.
 */
export async function openWebSshWindow(
  token: string,
  deviceId: string,
  deviceName: string,
): Promise<void> {
  const channelId = crypto.randomUUID();
  const channelName = `fttw-remote-ssh-${channelId}`;
  const terminal = window.open(terminalUrl(channelId, deviceName), "_blank");
  if (!terminal) throw new Error("The browser blocked the Web SSH tab. Allow pop-ups for FTTW and try again.");

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
    if (terminal.closed) throw new Error("The Web SSH tab was closed before the session started.");
    installFttwSshAlertDialog(terminal, deviceName);
    const launch = await apiFetch<RemoteLaunch>(
      `/devices/${deviceId}/remote-access/ssh-sessions`, { method: "POST" }, token,
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
    });
    await received;
  } catch (error) {
    channel.postMessage({ type: "error", message: error instanceof Error ? error.message : "Unable to start Web SSH." });
    throw error;
  } finally {
    window.clearTimeout(timeout);
    window.setTimeout(() => channel.close(), 1000);
  }
}

/**
 * Open the native device GUI on the dedicated access-gateway browser origin.
 * Vendor HTML/JS never executes under the FTTW application origin. The
 * one-time launch ticket is sent to the gateway window with postMessage and is
 * never written to a URL, browser storage, or window name.
 */
export async function openSecureWebGuiWindow(
  token: string,
  deviceId: string,
  deviceName: string,
): Promise<void> {
  const channel = crypto.randomUUID();
  const gatewayOrigin = webGuiGatewayOrigin();
  const launchUrl = new URL("/web/launch", gatewayOrigin);
  launchUrl.searchParams.set("channel", channel);
  launchUrl.searchParams.set("device", deviceName);
  launchUrl.searchParams.set("opener_origin", window.location.origin);
  const popup = window.open(launchUrl.toString(), "_blank");
  if (!popup) throw new Error("The browser blocked the secure Web GUI tab. Allow pop-ups for FTTW and try again.");

  let readyResolve: (() => void) | null = null;
  let readyReject: ((error: Error) => void) | null = null;
  const ready = new Promise<void>((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const onMessage = (event: MessageEvent<WebGuiReadyMessage>) => {
    if (event.origin !== gatewayOrigin || event.source !== popup) return;
    if (event.data?.type !== "fttw-web-gui-ready" || event.data.channel !== channel) return;
    readyResolve?.();
  };
  window.addEventListener("message", onMessage);
  const timeout = window.setTimeout(() => readyReject?.(new Error("The secure Web GUI gateway did not become ready.")), 10000);

  try {
    await ready;
    if (popup.closed) throw new Error("The secure Web GUI tab was closed before the session started.");
    const launch = await apiFetch<WebRemoteLaunch>(
      `/devices/${deviceId}/remote-access/web-sessions`, { method: "POST" }, token,
    );
    popup.postMessage({
      type: "fttw-web-gui-launch",
      channel,
      session_id: launch.session_id,
      ticket: launch.ticket,
      expires_at: launch.expires_at,
    }, gatewayOrigin);
  } finally {
    window.clearTimeout(timeout);
    window.removeEventListener("message", onMessage);
  }
}
