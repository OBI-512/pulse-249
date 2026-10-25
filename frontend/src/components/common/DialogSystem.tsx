import {
  createContext,
  type FormEvent,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  DialogActions,
  DialogBackdrop,
  DialogBody,
  DialogCard,
  DialogHeader,
  DialogMessage,
} from "../../design-system/composites/Dialog";
import { Button, Input } from "../../design-system/primitives";

type DialogTone = "default" | "danger";

type ConfirmOptions = {
  title?: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  tone?: DialogTone;
};

type PromptOptions = ConfirmOptions & {
  label?: string;
  defaultValue?: string;
  placeholder?: string;
  inputType?: "text" | "password" | "number";
  inputMode?: "text" | "numeric" | "decimal";
  maxLength?: number;
  pattern?: string;
  helperText?: string;
};

type ActiveDialog =
  | { kind: "confirm"; options: ConfirmOptions; resolve: (value: boolean) => void }
  | { kind: "prompt"; options: PromptOptions; resolve: (value: string | null) => void };

type DialogApi = {
  confirm: (options: ConfirmOptions | string) => Promise<boolean>;
  prompt: (options: PromptOptions | string) => Promise<string | null>;
};

const DialogContext = createContext<DialogApi | null>(null);

export function DialogProvider({ children }: { children: ReactNode }) {
  const [active, setActive] = useState<ActiveDialog | null>(null);
  const [value, setValue] = useState("");
  const inputRef = useRef<HTMLInputElement | null>(null);

  const closeAsCancel = useCallback(() => {
    setActive((current) => {
      if (!current) return null;
      if (current.kind === "confirm") current.resolve(false);
      else current.resolve(null);
      return null;
    });
  }, []);

  useEffect(() => {
    if (!active) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        closeAsCancel();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [active, closeAsCancel]);

  useEffect(() => {
    if (active?.kind === "prompt") {
      setValue(active.options.defaultValue ?? "");
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [active]);

  const api = useMemo<DialogApi>(() => ({
    confirm: (options) => new Promise<boolean>((resolve) => {
      const normalized = typeof options === "string" ? { message: options } : options;
      setActive({ kind: "confirm", options: normalized, resolve });
    }),
    prompt: (options) => new Promise<string | null>((resolve) => {
      const normalized = typeof options === "string" ? { message: options } : options;
      setActive({ kind: "prompt", options: normalized, resolve });
    }),
  }), []);

  const submit = (event?: FormEvent) => {
    event?.preventDefault();
    setActive((current) => {
      if (!current) return null;
      if (current.kind === "confirm") current.resolve(true);
      else current.resolve(value);
      return null;
    });
  };

  return (
    <DialogContext.Provider value={api}>
      {children}
      {active && (
        <DialogBackdrop role="presentation" onMouseDown={(event) => {
          if (event.currentTarget === event.target) closeAsCancel();
        }}>
          <DialogCard as="form" danger={active.options.tone === "danger"} role="dialog" aria-modal="true" onSubmit={submit}>
            <DialogHeader
              eyebrow="CONFIRMATION"
              title={active.options.title || (active.options.tone === "danger" ? "Confirm sensitive action" : "Confirm action")}
              onClose={closeAsCancel}
            />
            <DialogMessage>{active.options.message}</DialogMessage>
            {active.kind === "prompt" && (
              <label className="dialog-input-label">
                {active.options.label || "Value"}
                <Input unstyled
                  ref={inputRef}
                  type={active.options.inputType || "text"}
                  value={value}
                  placeholder={active.options.placeholder}
                  inputMode={active.options.inputMode}
                  maxLength={active.options.maxLength}
                  pattern={active.options.pattern}
                  onChange={(event) => setValue(event.target.value)}
                  autoComplete={active.options.inputType === "password" ? "new-password" : "off"}
                />
                {active.options.helperText && <span className="field-help">{active.options.helperText}</span>}
              </label>
            )}
            <DialogActions>
              <Button unstyled type="button" className="secondary" onClick={closeAsCancel}>{active.options.cancelLabel || "Cancel"}</Button>
              <Button unstyled type="submit" className={active.options.tone === "danger" ? "danger" : ""}>{active.options.confirmLabel || "Confirm"}</Button>
            </DialogActions>
          </DialogCard>
        </DialogBackdrop>
      )}
    </DialogContext.Provider>
  );
}

export function useDialog(): DialogApi {
  const context = useContext(DialogContext);
  if (!context) throw new Error("useDialog must be used inside DialogProvider");
  return context;
}

export function ModalShell({
  open,
  title,
  eyebrow = "EDIT",
  children,
  onClose,
  footer,
  wide = false,
}: {
  open: boolean;
  title: string;
  eyebrow?: string;
  children: ReactNode;
  onClose: () => void;
  footer?: ReactNode;
  wide?: boolean;
}) {
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <DialogBackdrop role="presentation" onMouseDown={(event) => {
      if (event.currentTarget === event.target) onClose();
    }}>
      <DialogCard wide={wide} role="dialog" aria-modal="true">
        <DialogHeader eyebrow={eyebrow} title={title} onClose={onClose} />
        <DialogBody>{children}</DialogBody>
        {footer && <DialogActions>{footer}</DialogActions>}
      </DialogCard>
    </DialogBackdrop>
  );
}
