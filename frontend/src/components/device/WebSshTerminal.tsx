import { useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { apiFetch } from "../../api/client";
import { Button } from "../../design-system/primitives";
import {
  DialogActions,
  DialogBackdrop,
  DialogBody,
  DialogCard,
  DialogHeader,
} from "../../design-system/composites/Dialog";
import styles from "./WebSshTerminal.module.css";

type Props = {
  token: string;
  deviceId: string;
  deviceName: string;
  sessionId: string;
  ticket: string;
  websocketPath: string;
  onClose: () => void;
};

function websocketUrl(path: string): string {
  const configured = (import.meta.env.VITE_REMOTE_ACCESS_WS_URL || "").trim();
  if (configured) return configured;
  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  if (window.location.port === "3000") {
    return `${scheme}//${window.location.hostname}:8010${path}`;
  }
  return `${scheme}//${window.location.host}/remote-access${path}`;
}

function cleanTerminalOutput(value: string): string {
  return value
    .replace(/\u001b\][^\u0007]*(?:\u0007|\u001b\\)/g, "")
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/\r(?!\n)/g, "\n");
}

function keyPayload(event: ReactKeyboardEvent<HTMLDivElement>): string | null {
  if (event.ctrlKey && event.key.length === 1) {
    const code = event.key.toUpperCase().charCodeAt(0);
    if (code >= 64 && code <= 95) return String.fromCharCode(code - 64);
  }
  const special: Record<string, string> = {
    Enter: "\r",
    Backspace: "\x7f",
    Tab: "\t",
    Escape: "\x1b",
    ArrowUp: "\x1b[A",
    ArrowDown: "\x1b[B",
    ArrowRight: "\x1b[C",
    ArrowLeft: "\x1b[D",
    Delete: "\x1b[3~",
    Home: "\x1b[H",
    End: "\x1b[F",
    PageUp: "\x1b[5~",
    PageDown: "\x1b[6~",
  };
  if (special[event.key]) return special[event.key];
  if (!event.ctrlKey && !event.altKey && !event.metaKey && event.key.length === 1) {
    return event.key;
  }
  return null;
}

export function WebSshTerminal(props: Props) {
  const [status, setStatus] = useState("Connecting...");
  const [output, setOutput] = useState("");
  const socketRef = useRef<WebSocket | null>(null);
  const terminalRef = useRef<HTMLDivElement | null>(null);
  const outputRef = useRef<HTMLPreElement | null>(null);
  const closingRef = useRef(false);
  const url = useMemo(
    () => websocketUrl(props.websocketPath),
    [props.websocketPath],
  );

  const revoke = async () => {
    if (closingRef.current) return;
    closingRef.current = true;
    try {
      socketRef.current?.send(JSON.stringify({ type: "close" }));
      socketRef.current?.close(1000, "User closed terminal.");
    } catch {
      // Connection may already be gone; server-side revoke remains authoritative.
    }
    try {
      await apiFetch(
        `/devices/${props.deviceId}/remote-access/sessions/${props.sessionId}`,
        { method: "DELETE" },
        props.token,
      );
    } catch {
      // Session may already be CLOSED/REVOKED. The backend/gateway expiration
      // path remains authoritative; closing the UI must never trap the user.
    }
    props.onClose();
  };

  useEffect(() => {
    const socket = new WebSocket(url);
    socketRef.current = socket;
    socket.onopen = () => {
      setStatus("Authenticating...");
      socket.send(JSON.stringify({ type: "launch", ticket: props.ticket }));
    };
    socket.onmessage = (event) => {
      let payload: any;
      try { payload = JSON.parse(String(event.data)); }
      catch { payload = { type: "output", data: String(event.data) }; }
      if (payload.type === "ready") {
        setStatus("Connected");
        window.setTimeout(() => terminalRef.current?.focus(), 0);
      } else if (payload.type === "output") {
        const text = cleanTerminalOutput(String(payload.data || ""));
        setOutput((current) => (current + text).slice(-200000));
      } else if (payload.type === "error") {
        setStatus(`Connection failed: ${String(payload.code || "UNKNOWN")}`);
      }
    };
    socket.onclose = (event) => {
      if (!closingRef.current) {
        setStatus(event.wasClean ? "Disconnected" : `Disconnected (${event.code})`);
      }
    };
    socket.onerror = () => setStatus("Remote gateway connection failed.");
    return () => {
      try { socket.close(1000, "Terminal component closed."); } catch { /* no-op */ }
    };
  }, [url]);

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [output]);

  const onKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    const data = keyPayload(event);
    if (data == null) return;
    event.preventDefault();
    const socket = socketRef.current;
    if (socket?.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: "input", data }));
    }
  };

  return (
    <DialogBackdrop role="presentation">
      <DialogCard wide role="dialog" aria-modal="true" className={styles.dialog}>
        <DialogHeader
          eyebrow="BROKERED REMOTE ACCESS"
          title={`Web SSH — ${props.deviceName}`}
          onClose={() => void revoke()}
        />
        <DialogBody className={styles.body}>
          <div className={styles.status}>{status}</div>
          <div
            ref={terminalRef}
            tabIndex={0}
            role="application"
            aria-label={`SSH terminal for ${props.deviceName}`}
            className={styles.terminal}
            onKeyDown={onKeyDown}
          >
            <pre ref={outputRef}>{output || "Waiting for SSH session...\n"}</pre>
          </div>
          <p className={styles.hint}>Click the terminal and type normally. Credentials remain inside the FTTW access gateway.</p>
        </DialogBody>
        <DialogActions>
          <Button unstyled className="secondary" onClick={() => void revoke()}>Close session</Button>
        </DialogActions>
      </DialogCard>
    </DialogBackdrop>
  );
}
