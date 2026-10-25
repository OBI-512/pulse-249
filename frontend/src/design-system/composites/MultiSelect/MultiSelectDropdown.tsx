import { useEffect, useMemo, useRef, useState } from "react";
import styles from "./MultiSelect.module.css";

export type SelectOption = {
  value: string;
  label: string;
  description?: string | null;
};

export function MultiSelectDropdown({
  options,
  value,
  onChange,
  placeholder = "Select permissions",
  disabled = false,
}: {
  options: SelectOption[];
  value: string[];
  onChange: (value: string[]) => void;
  placeholder?: string;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const root = useRef<HTMLDivElement | null>(null);
  const selected = useMemo(() => new Set(value), [value]);
  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return options;
    return options.filter((option) => `${option.label} ${option.value} ${option.description || ""}`.toLowerCase().includes(needle));
  }, [options, search]);

  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);

  const toggle = (code: string) => {
    if (selected.has(code)) onChange(value.filter((item) => item !== code));
    else onChange([...value, code].sort());
  };

  return (
    <div className={styles.root} ref={root}>
      <button type="button" className={styles.trigger} disabled={disabled} onClick={() => setOpen((current) => !current)} aria-expanded={open}>
        <span>{value.length ? `${value.length} selected` : placeholder}</span><span aria-hidden="true">{"\u25BE"}</span>
      </button>
      {value.length > 0 && <div className={styles.chips}>{value.map((code) => <span className={styles.chip} key={code}>{code}<button type="button" aria-label={`Remove ${code}`} onClick={(event) => { event.stopPropagation(); toggle(code); }}>{"\u00D7"}</button></span>)}</div>}
      {open && (
        <div className={styles.menu}>
          <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search permissions" autoFocus />
          <div className={styles.options}>
            {filtered.map((option) => (
              <label className={styles.option} key={option.value}>
                <input type="checkbox" checked={selected.has(option.value)} onChange={() => toggle(option.value)} />
                <span><strong>{option.label}</strong><small>{option.value}{option.description ? ` \u00B7 ${option.description}` : ""}</small></span>
              </label>
            ))}
            {!filtered.length && <div className={styles.empty}>No matching permissions.</div>}
          </div>
        </div>
      )}
    </div>
  );
}
