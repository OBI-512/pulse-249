import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { WebglAddon } from "@xterm/addon-webgl";
import "../../remote-ssh.css";

type TerminalProtocol = "SSH" | "TELNET";
type LaunchMessage = {
  type: "launch";
  ticket: string;
  websocket_path?: string;
  websocket_url?: string;
};

type ChannelMessage = LaunchMessage | { type: "error"; message?: string };
type GatewayMessage =
  | { type: "ready"; compatibility_profile?: string; protocol?: TerminalProtocol; insecure_transport?: boolean }
  | { type: "output"; data?: string }
  | { type: "output_binary"; data?: string }
  | { type: "error"; code?: string };

const LEGACY_PROFILE = "LEGACY_SSH_RSA_DH1_CBC";
const MAX_PASTE_CHARS = 65536;
const APPEARANCE_STORAGE_KEY = "fttw.remoteSsh.appearance.v1";

type FontKey = "system" | "cascadia" | "consolas" | "menlo" | "courier";
type TerminalAppearance = {
  fontKey: FontKey;
  fontSize: number;
  foreground: string;
  background: string;
};

const FONT_FAMILIES: Record<FontKey, string> = {
  system: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace',
  cascadia: '"Cascadia Mono", "Cascadia Code", Consolas, monospace',
  consolas: 'Consolas, "Liberation Mono", monospace',
  menlo: 'Menlo, Monaco, "SFMono-Regular", monospace',
  courier: '"Courier New", Courier, monospace',
};

const DEFAULT_APPEARANCE: TerminalAppearance = {
  fontKey: "system",
  fontSize: 14,
  foreground: "#e7eef7",
  background: "#07101a",
};

const BASE_THEME = {
  cursor: "#8bc5ff",
  selectionBackground: "#285a89aa",
  selectionInactiveBackground: "#29445faa",
  black: "#101820",
  red: "#e06c75",
  green: "#98c379",
  yellow: "#e5c07b",
  blue: "#61afef",
  magenta: "#c678dd",
  cyan: "#56b6c2",
  white: "#d8dee9",
  brightBlack: "#5c6370",
  brightRed: "#ff7b86",
  brightGreen: "#b6e38c",
  brightYellow: "#f4d58d",
  brightBlue: "#78c2ff",
  brightMagenta: "#d994f0",
  brightCyan: "#77d5df",
  brightWhite: "#ffffff",
};

function isFontKey(value: unknown): value is FontKey {
  return typeof value === "string" && Object.prototype.hasOwnProperty.call(FONT_FAMILIES, value);
}

function isHexColor(value: unknown): value is string {
  return typeof value === "string" && /^#[0-9a-f]{6}$/i.test(value);
}

function loadAppearance(): TerminalAppearance {
  try {
    const parsed = JSON.parse(localStorage.getItem(APPEARANCE_STORAGE_KEY) || "null") as Partial<TerminalAppearance> | null;
    if (!parsed) return { ...DEFAULT_APPEARANCE };
    return {
      fontKey: isFontKey(parsed.fontKey) ? parsed.fontKey : DEFAULT_APPEARANCE.fontKey,
      fontSize: typeof parsed.fontSize === "number" && Number.isFinite(parsed.fontSize)
        ? Math.max(10, Math.min(28, Math.round(parsed.fontSize)))
        : DEFAULT_APPEARANCE.fontSize,
      foreground: isHexColor(parsed.foreground) ? parsed.foreground : DEFAULT_APPEARANCE.foreground,
      background: isHexColor(parsed.background) ? parsed.background : DEFAULT_APPEARANCE.background,
    };
  } catch {
    return { ...DEFAULT_APPEARANCE };
  }
}

function terminalTheme(value: TerminalAppearance) {
  return {
    ...BASE_THEME,
    background: value.background,
    foreground: value.foreground,
    cursorAccent: value.background,
  };
}

let appearance = loadAppearance();

function element<T extends HTMLElement>(id: string): T {
  const value = document.getElementById(id);
  if (!value) throw new Error(`Missing terminal element: ${id}`);
  return value as T;
}

try { window.opener = null; } catch { /* best effort */ }

const params = new URLSearchParams(window.location.search);
const channelId = params.get("channel") || "";
const deviceName = params.get("device") || "Device";
const protocol: TerminalProtocol = params.get("protocol")?.trim().toUpperCase() === "TELNET" ? "TELNET" : "SSH";
const protocolLabel = protocol === "TELNET" ? "Telnet" : "SSH";
const protocolFileLabel = protocol.toLowerCase();
const title = element<HTMLHeadingElement>("device-title");
const status = element<HTMLSpanElement>("connection-status");
const elapsed = element<HTMLSpanElement>("elapsed");
const connectionDot = element<HTMLSpanElement>("connection-dot");
const legacyBadge = element<HTMLSpanElement>("legacy-badge");
const terminalFrame = element<HTMLElement>("terminal-frame");
const terminalHost = element<HTMLDivElement>("terminal");
const overlay = element<HTMLDivElement>("terminal-overlay");
const searchPanel = element<HTMLElement>("search-panel");
const searchInput = element<HTMLInputElement>("search-input");
const searchCase = element<HTMLInputElement>("search-case");
const contextMenu = element<HTMLDivElement>("context-menu");
const settingsDialog = element<HTMLDialogElement>("settings-dialog");
const fontFamilySelect = element<HTMLSelectElement>("font-family");
const fontSizeInput = element<HTMLInputElement>("font-size");
const fontSizeValue = element<HTMLOutputElement>("font-size-value");
const fontColorInput = element<HTMLInputElement>("font-color");
const backgroundColorInput = element<HTMLInputElement>("background-color");
const helpDialog = element<HTMLDialogElement>("help-dialog");
const toast = element<HTMLDivElement>("toast");

title.textContent = deviceName;
document.title = `${deviceName} — ${protocolLabel} Terminal`;
terminalFrame.setAttribute("aria-label", `${protocolLabel} terminal`);
status.textContent = protocol === "TELNET" ? "Starting legacy Telnet session…" : "Starting secure SSH session…";
overlay.textContent = `Waiting for ${protocolLabel} session…`;
if (protocol === "TELNET") {
  legacyBadge.textContent = "Legacy Telnet — insecure";
  legacyBadge.hidden = false;
}
document.documentElement.style.setProperty("--terminal-bg", appearance.background);

let socket: WebSocket | null = null;
let channel: BroadcastChannel | null = null;
let launched = false;
let connectedAt: number | null = null;
let compatibilityProfile = "MODERN";
let toastTimer: number | null = null;
let selectionCopyTimer: number | null = null;
let fitTimer: number | null = null;

const fitAddon = new FitAddon();
const searchAddon = new SearchAddon();
const terminal = new Terminal({
  allowProposedApi: false,
  convertEol: false,
  cursorBlink: true,
  cursorStyle: "block",
  cursorInactiveStyle: "outline",
  disableStdin: false,
  drawBoldTextInBrightColors: true,
  fastScrollSensitivity: 5,
  fontFamily: FONT_FAMILIES[appearance.fontKey],
  fontSize: appearance.fontSize,
  fontWeight: "400",
  fontWeightBold: "700",
  letterSpacing: 0,
  lineHeight: 1.15,
  macOptionIsMeta: true,
  minimumContrastRatio: 4.5,
  logLevel: "off",
  rescaleOverlappingGlyphs: true,
  rightClickSelectsWord: false,
  screenReaderMode: false,
  scrollOnUserInput: true,
  scrollback: 10000,
  smoothScrollDuration: 80,
  tabStopWidth: 8,
  theme: terminalTheme(appearance),
});

terminal.loadAddon(fitAddon);
terminal.loadAddon(searchAddon);
terminal.loadAddon(new WebLinksAddon((_event, uri) => {
  try {
    const url = new URL(uri);
    if (url.protocol !== "http:" && url.protocol !== "https:") return;
    window.open(url.href, "_blank", "noopener,noreferrer");
  } catch { /* invalid/untrusted terminal link */ }
}));
terminal.open(terminalHost);

try {
  const webgl = new WebglAddon();
  webgl.onContextLoss(() => webgl.dispose());
  terminal.loadAddon(webgl);
} catch {
  // Canvas/DOM renderer remains available when WebGL2 is unavailable.
}

function setConnectionState(state: "waiting" | "connected" | "error", message: string): void {
  status.textContent = message;
  connectionDot.className = `connection-dot is-${state}`;
  if (state !== "connected") {
    connectedAt = null;
    elapsed.hidden = true;
  }
}

function showToast(message: string, duration = 1700): void {
  toast.textContent = message;
  toast.hidden = false;
  if (toastTimer !== null) window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => { toast.hidden = true; }, duration);
}

function websocketUrl(path: string): string {
  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  if (window.location.port === "3000") return `${scheme}//${window.location.hostname}:8010${path}`;
  return `${scheme}//${window.location.host}/remote-access${path}`;
}

function friendlyGatewayError(code: string): string {
  const common: Record<string, string> = {
    DEVICE_MANAGEMENT_IP_REQUIRED: "This device has no management address.",
    DEVICE_NOT_AVAILABLE: "This device is not available for remote access.",
    REMOTE_ACCESS_TICKET_EXPIRED: `The terminal launch expired. Close this tab and open ${protocolLabel} again.`,
    REMOTE_ACCESS_TICKET_ALREADY_USED: `This terminal launch has already been used. Close this tab and open ${protocolLabel} again.`,
    AUTH_SESSION_EXPIRED: "Your FTTW session has expired.",
    CONFIGURATION_CONFLICT: `Multiple equally preferred ${protocolLabel} Access Templates match this device.`,
  };
  const ssh: Record<string, string> = {
    REMOTE_ACCESS_NOT_CONFIGURED: "SSH access is not configured for this device.",
    SSH_HOST_KEY_MISMATCH: "Device identity verification failed.",
    SSH_HOST_KEY_SCAN_FAILED: "The device SSH service could not be verified.",
    SSH_AUTHENTICATION_FAILED: "The device rejected the configured SSH credentials.",
    AUTHENTICATION_FAILED: "The device rejected the configured SSH credentials.",
    REMOTE_ACCESS_SECRET_NOT_FOUND: "The configured SSH credential is unavailable.",
  };
  const telnet: Record<string, string> = {
    TELNET_ACCESS_DISABLED: "Legacy Telnet access is disabled on this FTTW installation.",
    TELNET_ACCESS_NOT_CONFIGURED: "Telnet access is not configured for this device.",
    TELNET_LOGIN_FAILED: "The device rejected the configured Telnet credentials.",
    TELNET_LOGIN_PROMPT_TIMEOUT: "The device did not present the expected Telnet login prompt in time.",
    TELNET_LOGIN_PROMPT_TOO_LARGE: "The Telnet login exchange exceeded the safe prompt limit.",
    TELNET_CONNECTION_CLOSED: "The device closed the Telnet connection during sign-in.",
    TELNET_CONNECTION_FAILED: "FTTW could not establish the Telnet connection.",
    TELNET_CREDENTIALS_REQUIRED: "The effective Telnet Access Template is incomplete.",
  };
  return common[code]
    || (protocol === "TELNET" ? telnet[code] : ssh[code])
    || `The ${protocolLabel} session could not be established.`;
}

function sendJson(payload: unknown): void {
  if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify(payload));
}

function sendInput(data: string): void {
  if (!data || socket?.readyState !== WebSocket.OPEN) return;
  // Keep individual websocket frames bounded while preserving xterm's exact key stream.
  for (let index = 0; index < data.length; index += 8192) {
    sendJson({ type: "input", data: data.slice(index, index + 8192) });
  }
}

function binaryStringToBase64(value: string): string {
  let raw = "";
  for (let i = 0; i < value.length; i += 1) raw += String.fromCharCode(value.charCodeAt(i) & 0xff);
  return btoa(raw);
}

function base64ToBytes(value: string): Uint8Array {
  const raw = atob(value);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) bytes[i] = raw.charCodeAt(i);
  return bytes;
}

function sendBinary(data: string): void {
  if (!data || socket?.readyState !== WebSocket.OPEN) return;
  sendJson({ type: "binary", data: binaryStringToBase64(data) });
}

terminal.onData(sendInput);
terminal.onBinary(sendBinary);
terminal.onResize(({ cols, rows }) => sendJson({ type: "resize", rows, cols }));

// xterm handles the complete VT keyboard map. The only explicit compatibility
// override is the older Ctrl-H backspace convention required by known legacy devices.
terminal.attachCustomKeyEventHandler((event) => {
  if (event.type !== "keydown") return true;

  const key = event.key.toLowerCase();
  if ((event.ctrlKey || event.metaKey) && event.shiftKey && !event.altKey && key === "f") {
    event.preventDefault();
    openSearch();
    return false;
  }
  if ((event.ctrlKey || event.metaKey) && event.shiftKey && key === "c") {
    event.preventDefault();
    void copySelection();
    return false;
  }
  if ((event.ctrlKey || event.metaKey) && event.shiftKey && key === "v") {
    event.preventDefault();
    void pasteClipboard();
    return false;
  }
  if (event.shiftKey && event.key === "Insert") {
    event.preventDefault();
    void pasteClipboard();
    return false;
  }
  if (event.key === "F3") {
    event.preventDefault();
    find(event.shiftKey ? "previous" : "next");
    return false;
  }
  return true;
});

function fitTerminalNow(): void {
  try {
    const rect = terminalFrame.getBoundingClientRect();
    if (rect.width < 40 || rect.height < 40) return;

    // FitAddon measures the computed size of the terminal element's direct
    // parent. Pin that parent to the flex viewport's actual pixel geometry so
    // percentage/absolute-layout ambiguity can never collapse the PTY to 1 row.
    terminalHost.style.width = `${Math.max(1, Math.floor(rect.width))}px`;
    terminalHost.style.height = `${Math.max(1, Math.floor(rect.height))}px`;

    const proposed = fitAddon.proposeDimensions();
    if (!proposed) return;
    if (terminal.cols !== proposed.cols || terminal.rows !== proposed.rows) {
      terminal.resize(proposed.cols, proposed.rows);
    }
    // Resend even when the xterm geometry did not change after the websocket
    // connected; a pre-connect resize event could not reach the remote terminal.
    sendJson({ type: "resize", rows: terminal.rows, cols: terminal.cols });
  } catch { /* terminal may be closing */ }
}

function scheduleFit(): void {
  if (fitTimer !== null) window.clearTimeout(fitTimer);
  fitTimer = window.setTimeout(() => {
    window.requestAnimationFrame(() => {
      fitTerminalNow();
      window.requestAnimationFrame(fitTerminalNow);
    });
  }, 20);
}

if (typeof ResizeObserver !== "undefined") new ResizeObserver(scheduleFit).observe(terminalFrame);
window.addEventListener("resize", scheduleFit);
document.addEventListener("fullscreenchange", scheduleFit);
if (document.fonts) void document.fonts.ready.then(scheduleFit).catch(() => undefined);
scheduleFit();

terminalFrame.addEventListener("pointerdown", (event) => {
  if (event.button !== 0) return;
  const target = event.target;
  if (target === terminalFrame || target === terminalHost) terminal.focus();
});

function fallbackCopy(text: string): boolean {
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  textarea.style.pointerEvents = "none";
  document.body.appendChild(textarea);
  textarea.select();
  let ok = false;
  try { ok = document.execCommand("copy"); } catch { ok = false; }
  textarea.remove();
  terminal.focus();
  return ok;
}

async function writeClipboard(text: string, quiet = false): Promise<boolean> {
  if (!text) return false;
  try {
    await navigator.clipboard.writeText(text);
    if (!quiet) showToast("Copied");
    return true;
  } catch {
    const ok = fallbackCopy(text);
    if (!quiet) showToast(ok ? "Copied" : "Clipboard access is unavailable.");
    return ok;
  }
}

async function copySelection(): Promise<void> {
  const text = terminal.hasSelection() ? terminal.getSelection() : "";
  if (!text) {
    showToast("Select text to copy.");
    terminal.focus();
    return;
  }
  await writeClipboard(text);
  terminal.focus();
}

terminal.onSelectionChange(() => {
  if (selectionCopyTimer !== null) window.clearTimeout(selectionCopyTimer);
  selectionCopyTimer = window.setTimeout(() => {
    if (terminal.hasSelection()) void writeClipboard(terminal.getSelection(), true);
  }, 120);
});

function pasteNeedsConfirmation(text: string): boolean {
  const lineBreaks = (text.match(/\r\n|\r|\n/g) || []).length;
  return lineBreaks > 0 || text.length > 512;
}

async function pasteClipboard(): Promise<void> {
  try {
    const text = await navigator.clipboard.readText();
    if (!text) return;
    if (text.length > MAX_PASTE_CHARS) {
      showToast(`Paste blocked: maximum ${MAX_PASTE_CHARS.toLocaleString()} characters.`);
      return;
    }
    if (pasteNeedsConfirmation(text)) {
      const lines = (text.match(/\r\n|\r|\n/g) || []).length + 1;
      if (!window.confirm(`Paste ${text.length.toLocaleString()} characters (${lines} lines) into the remote device?`)) return;
    }
    terminal.paste(text);
    terminal.focus();
  } catch {
    showToast("Clipboard paste requires browser permission.", 2600);
  }
}

function terminalBufferText(): string {
  const buffer = terminal.buffer.normal;
  const lines: string[] = [];
  for (let i = 0; i < buffer.length; i += 1) {
    lines.push(buffer.getLine(i)?.translateToString(true) || "");
  }
  while (lines.length && lines[lines.length - 1] === "") lines.pop();
  return lines.join("\n");
}

function downloadLog(): void {
  const body = terminalBufferText();
  const header = [
    `FTTW ${protocolLabel} Terminal Log`,
    `Device: ${deviceName}`,
    `Downloaded: ${new Date().toISOString()}`,
    "",
  ].join("\n");
  const blob = new Blob([header, body, "\n"], { type: "text/plain;charset=utf-8" });
  const anchor = document.createElement("a");
  anchor.href = URL.createObjectURL(blob);
  anchor.download = `fttw-${protocolFileLabel}-${deviceName.replace(/[^a-z0-9._-]+/gi, "_")}-${new Date().toISOString().replace(/[:.]/g, "-")}.log`;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(anchor.href), 1000);
  terminal.focus();
}

function openSearch(): void {
  searchPanel.hidden = false;
  searchInput.focus();
  searchInput.select();
}

function closeSearch(): void {
  searchPanel.hidden = true;
  terminal.focus();
}

function find(direction: "next" | "previous"): void {
  const query = searchInput.value;
  if (!query) return;
  const options = { caseSensitive: searchCase.checked, incremental: false };
  if (direction === "next") searchAddon.findNext(query, options);
  else searchAddon.findPrevious(query, options);
}

searchInput.addEventListener("input", () => {
  const query = searchInput.value;
  if (query) searchAddon.findNext(query, { caseSensitive: searchCase.checked, incremental: true });
});
searchInput.addEventListener("keydown", (event) => {
  if (event.key === "Escape") { event.preventDefault(); closeSearch(); }
  else if (event.key === "Enter") { event.preventDefault(); find(event.shiftKey ? "previous" : "next"); }
});
searchCase.addEventListener("change", () => find("next"));
element<HTMLButtonElement>("search-previous").onclick = () => find("previous");
element<HTMLButtonElement>("search-next").onclick = () => find("next");
element<HTMLButtonElement>("search-close").onclick = closeSearch;
element<HTMLButtonElement>("search-button").onclick = openSearch;

function syncAppearanceControls(): void {
  fontFamilySelect.value = appearance.fontKey;
  fontSizeInput.value = String(appearance.fontSize);
  fontSizeValue.value = `${appearance.fontSize} px`;
  fontSizeValue.textContent = `${appearance.fontSize} px`;
  fontColorInput.value = appearance.foreground;
  backgroundColorInput.value = appearance.background;
}

function persistAppearance(): void {
  try { localStorage.setItem(APPEARANCE_STORAGE_KEY, JSON.stringify(appearance)); } catch { /* browser storage is optional */ }
}

function applyAppearance(next: TerminalAppearance, persist = true): void {
  appearance = {
    fontKey: isFontKey(next.fontKey) ? next.fontKey : DEFAULT_APPEARANCE.fontKey,
    fontSize: Math.max(10, Math.min(28, Math.round(next.fontSize))),
    foreground: isHexColor(next.foreground) ? next.foreground : DEFAULT_APPEARANCE.foreground,
    background: isHexColor(next.background) ? next.background : DEFAULT_APPEARANCE.background,
  };
  terminal.options.fontFamily = FONT_FAMILIES[appearance.fontKey];
  terminal.options.fontSize = appearance.fontSize;
  terminal.options.theme = terminalTheme(appearance);
  document.documentElement.style.setProperty("--terminal-bg", appearance.background);
  syncAppearanceControls();
  if (persist) persistAppearance();
  scheduleFit();
}

function openAppearanceSettings(): void {
  syncAppearanceControls();
  settingsDialog.showModal();
}

function adjustFont(delta: number): void {
  const size = delta === 0 ? DEFAULT_APPEARANCE.fontSize : appearance.fontSize + delta;
  applyAppearance({ ...appearance, fontSize: size });
  terminal.focus();
}

syncAppearanceControls();
fontFamilySelect.addEventListener("change", () => {
  if (isFontKey(fontFamilySelect.value)) applyAppearance({ ...appearance, fontKey: fontFamilySelect.value });
});
fontSizeInput.addEventListener("input", () => {
  applyAppearance({ ...appearance, fontSize: Number(fontSizeInput.value) });
});
fontColorInput.addEventListener("input", () => {
  applyAppearance({ ...appearance, foreground: fontColorInput.value });
});
backgroundColorInput.addEventListener("input", () => {
  applyAppearance({ ...appearance, background: backgroundColorInput.value });
});
element<HTMLButtonElement>("settings-button").onclick = openAppearanceSettings;
element<HTMLButtonElement>("settings-close").onclick = () => settingsDialog.close();
element<HTMLButtonElement>("settings-reset").onclick = () => applyAppearance({ ...DEFAULT_APPEARANCE });
settingsDialog.addEventListener("close", () => { scheduleFit(); terminal.focus(); });

async function toggleFullscreen(): Promise<void> {
  try {
    if (!document.fullscreenElement) await document.documentElement.requestFullscreen();
    else await document.exitFullscreen();
  } catch { showToast("Fullscreen is unavailable."); }
  scheduleFit();
  terminal.focus();
}

function closeSession(): void {
  try { sendJson({ type: "close" }); socket?.close(1000, "User closed terminal."); } catch { /* no-op */ }
  window.setTimeout(() => window.close(), 80);
}

function showContextMenu(x: number, y: number): void {
  contextMenu.hidden = false;
  const width = contextMenu.offsetWidth || 220;
  const height = contextMenu.offsetHeight || 420;
  contextMenu.style.left = `${Math.max(6, Math.min(window.innerWidth - width - 6, x))}px`;
  contextMenu.style.top = `${Math.max(6, Math.min(window.innerHeight - height - 6, y))}px`;
}

function hideContextMenu(): void { contextMenu.hidden = true; }

terminalFrame.addEventListener("contextmenu", (event) => {
  event.preventDefault();
  showContextMenu(event.clientX, event.clientY);
});

document.addEventListener("pointerdown", (event) => {
  if (!contextMenu.hidden && !contextMenu.contains(event.target as Node) && event.target !== element("more-button")) hideContextMenu();
});

element<HTMLButtonElement>("more-button").onclick = (event) => {
  const rect = (event.currentTarget as HTMLElement).getBoundingClientRect();
  showContextMenu(rect.right - 220, rect.bottom + 5);
};

contextMenu.addEventListener("click", (event) => {
  const button = (event.target as HTMLElement).closest<HTMLButtonElement>("button[data-action]");
  if (!button) return;
  hideContextMenu();
  switch (button.dataset.action) {
    case "copy": void copySelection(); break;
    case "paste": void pasteClipboard(); break;
    case "select-all": terminal.selectAll(); break;
    case "search": openSearch(); break;
    case "clear-scrollback": terminal.clear(); terminal.focus(); break;
    case "clear-screen": sendInput("\x0c"); terminal.focus(); break;
    case "font-increase": adjustFont(1); break;
    case "font-decrease": adjustFont(-1); break;
    case "font-reset": adjustFont(0); break;
    case "settings": openAppearanceSettings(); break;
    case "download": downloadLog(); break;
    case "fullscreen": void toggleFullscreen(); break;
    case "help": helpDialog.showModal(); break;
  }
});

element<HTMLButtonElement>("paste-button").onclick = () => void pasteClipboard();
element<HTMLButtonElement>("download-button").onclick = downloadLog;
element<HTMLButtonElement>("fullscreen-button").onclick = () => void toggleFullscreen();
element<HTMLButtonElement>("close-button").onclick = closeSession;
element<HTMLButtonElement>("help-close").onclick = () => helpDialog.close();

setInterval(() => {
  if (!connectedAt) return;
  const total = Math.max(0, Math.floor((Date.now() - connectedAt) / 1000));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  elapsed.textContent = hours > 0
    ? `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`
    : `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}, 1000);

window.addEventListener("beforeunload", () => {
  try { socket?.close(1000, "Terminal tab closed."); } catch { /* no-op */ }
  try { channel?.close(); } catch { /* no-op */ }
  terminal.dispose();
});

if (!channelId || !/^[0-9a-f-]{36}$/i.test(channelId) || typeof BroadcastChannel === "undefined") {
  setConnectionState("error", "Unable to start terminal.");
  overlay.textContent = "Unable to initialize the terminal session.";
} else {
  // Keep the historical channel name for backward compatibility with the SSH
  // launcher; the same in-memory launch channel now serves SSH and Telnet.
  channel = new BroadcastChannel(`fttw-remote-ssh-${channelId}`);
  channel.onmessage = (event: MessageEvent<ChannelMessage>) => {
    const payload = event.data;
    if (payload?.type === "error") {
      setConnectionState("error", payload.message || `Unable to start ${protocolLabel}.`);
      overlay.textContent = payload.message || `Unable to start ${protocolLabel}.`;
      return;
    }
    if (payload?.type !== "launch" || launched) return;
    launched = true;
    channel?.postMessage({ type: "received" });

    const ticket = String(payload.ticket || "");
    const defaultPath = protocol === "TELNET" ? "/ws/telnet" : "/ws/ssh";
    const path = String(payload.websocket_path || defaultPath);
    const wsUrl = String(payload.websocket_url || websocketUrl(path));
    if (!ticket) {
      setConnectionState("error", "Unable to start terminal.");
      overlay.textContent = "A valid terminal launch was not received.";
      return;
    }

    setConnectionState("waiting", "Connecting…");
    socket = new WebSocket(wsUrl);
    socket.onopen = () => {
      setConnectionState("waiting", "Signing in…");
      sendJson({ type: "launch", ticket });
    };
    socket.onmessage = (message) => {
      let data: GatewayMessage;
      try { data = JSON.parse(String(message.data)) as GatewayMessage; }
      catch { data = { type: "output", data: String(message.data) }; }

      if (data.type === "ready") {
        compatibilityProfile = String(data.compatibility_profile || "MODERN");
        if (protocol === "TELNET") {
          legacyBadge.textContent = "Legacy Telnet — insecure";
          legacyBadge.hidden = false;
        } else {
          legacyBadge.textContent = "Legacy SSH";
          legacyBadge.hidden = compatibilityProfile !== LEGACY_PROFILE;
        }
        connectedAt = Date.now();
        elapsed.hidden = false;
        overlay.hidden = true;
        setConnectionState("connected", "Connected");
        scheduleFit();
        terminal.focus();
      } else if (data.type === "output_binary") {
        const encoded = String(data.data || "");
        if (encoded) {
          try { terminal.write(base64ToBytes(encoded)); } catch { /* ignore malformed gateway frame */ }
        }
      } else if (data.type === "output") {
        // Backward compatibility during a rolling gateway update.
        terminal.write(String(data.data || ""));
      } else if (data.type === "error") {
        const messageText = friendlyGatewayError(String(data.code || ""));
        setConnectionState("error", messageText);
        if (!connectedAt) overlay.textContent = messageText;
      }
    };
    socket.onclose = (event) => {
      overlay.hidden = false;
      if (event.code === 4003) {
        setConnectionState("error", "Session ended");
        overlay.textContent = `This ${protocolLabel} session has ended. Close this tab and open ${protocolLabel} again to start a new session.`;
      } else if (event.wasClean) {
        setConnectionState("waiting", "Disconnected");
        overlay.textContent = `${protocolLabel} session closed.`;
      } else {
        setConnectionState("error", "Connection lost");
        overlay.textContent = `The ${protocolLabel} connection was lost.`;
      }
    };
    socket.onerror = () => {
      setConnectionState("error", "Unable to connect");
      overlay.hidden = false;
      overlay.textContent = "FTTW could not connect to the remote-access gateway.";
    };

    channel?.close();
    channel = null;
  };
  channel.postMessage({ type: "ready" });
}
