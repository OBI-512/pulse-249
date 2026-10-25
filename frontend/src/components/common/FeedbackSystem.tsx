import { createContext, type ReactNode, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { DialogActions, DialogBackdrop, DialogCard, DialogHeader, DialogMessage } from "../../design-system/composites/Dialog";
import { Button } from "../../design-system/primitives";

type FeedbackTone = "success" | "info" | "warning";
type Toast = { id: number; tone: FeedbackTone; title: string; message: string };
type ErrorNotice = { title: string; message: string } | null;
type FeedbackApi = {
  success: (message: string, title?: string) => void;
  info: (message: string, title?: string) => void;
  warning: (message: string, title?: string) => void;
  error: (message: string, title?: string) => void;
};

const FeedbackContext = createContext<FeedbackApi | null>(null);

function FeedbackIcon({ tone }: { tone: FeedbackTone }) {
  if (tone === "success") {
    return <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M5 12.5l4.2 4.2L19 7" /></svg>;
  }
  if (tone === "warning") {
    return <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M12 3.5 3.2 20h17.6L12 3.5Z" /><path d="M12 8.5v5.5" /><path d="M12 17.2h.01" /></svg>;
  }
  return <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M12 3.5 3.2 20h17.6L12 3.5Z" /><path d="M12 8.5v5.5" /><path d="M12 17.2h.01" /></svg>;
}

export function FeedbackProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [errorNotice, setErrorNotice] = useState<ErrorNotice>(null);
  const counter = useRef(0);

  const push = useCallback((tone: FeedbackTone, message: string, title: string) => {
    const id = ++counter.current;
    setToasts((items) => [...items.slice(-2), { id, tone, title, message }]);
    window.setTimeout(() => setToasts((items) => items.filter((item) => item.id !== id)), tone === "success" ? 3000 : 3500);
  }, []);

  const api = useMemo<FeedbackApi>(() => ({
    success: (message, title = "Completed") => push("success", message, title),
    info: (message, title = "Information") => push("info", message, title),
    warning: (message, title = "Attention") => push("warning", message, title),
    error: (message, title = "Unable to complete action") => setErrorNotice({ title, message }),
  }), [push]);

  useEffect(() => {
    if (!errorNotice) return;
    const close = (event: KeyboardEvent) => { if (event.key === "Escape" || event.key === "Enter") setErrorNotice(null); };
    document.addEventListener("keydown", close);
    return () => document.removeEventListener("keydown", close);
  }, [errorNotice]);

  return <FeedbackContext.Provider value={api}>
    {children}
    <div className="feedback-stack" aria-live="polite" aria-atomic="false">
      {toasts.map((toast) => <div key={toast.id} className={`feedback-toast feedback-${toast.tone}`}>
        <span className="feedback-icon" aria-hidden="true"><FeedbackIcon tone={toast.tone} /></span>
        <div><strong>{toast.title}</strong><span>{toast.message}</span></div>
      </div>)}
    </div>
    {errorNotice && <DialogBackdrop className="feedback-error-backdrop" role="presentation">
      <DialogCard className="feedback-error-card" role="alertdialog" aria-modal="true" aria-labelledby="feedback-error-title">
        <DialogHeader eyebrow="ACTION REQUIRED" title={errorNotice.title} titleId="feedback-error-title" />
        <div className="feedback-error-message-row"><span className="feedback-error-symbol" aria-hidden="true"><FeedbackIcon tone="warning" /></span><DialogMessage>{errorNotice.message}</DialogMessage></div>
        <DialogActions><Button unstyled autoFocus onClick={() => setErrorNotice(null)}>OK</Button></DialogActions>
      </DialogCard>
    </DialogBackdrop>}
  </FeedbackContext.Provider>;
}

export function useFeedback(): FeedbackApi {
  const context = useContext(FeedbackContext);
  if (!context) throw new Error("useFeedback must be used inside FeedbackProvider");
  return context;
}
