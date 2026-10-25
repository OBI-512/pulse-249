import { useEffect, useId, useMemo, useRef, useState } from "react";
import { useDebouncedValue } from "../../../hooks/useDebouncedValue";
import type { ComboboxOption, ComboboxPage } from "./SearchableCombobox";
import styles from "./SearchableSelect.module.css";

export function SearchableMultiSelect<T = unknown>({
  value,
  onChange,
  loadPage,
  disabled = false,
  placeholder = "Select options...",
  emptyText = "No matching options found.",
  errorText = "Unable to load options.",
  pageSize = 50,
}: {
  value: ComboboxOption<T>[];
  onChange: (options: ComboboxOption<T>[]) => void;
  loadPage: (query: string, page: number, pageSize: number) => Promise<ComboboxPage<T>>;
  disabled?: boolean;
  placeholder?: string;
  emptyText?: string;
  errorText?: string;
  pageSize?: number;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [options, setOptions] = useState<ComboboxOption<T>[]>([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState("");
  const rootRef = useRef<HTMLDivElement | null>(null);
  const requestRef = useRef(0);
  const loaderRef = useRef(loadPage);
  const listboxId = useId();
  const debounced = useDebouncedValue(query, 280);
  loaderRef.current = loadPage;

  const selectedIds = useMemo(() => new Set(value.map((item) => item.id)), [value]);
  const mergedOptions = useMemo(() => {
    const seen = new Set<string>();
    return [...value, ...options].filter((option) => !seen.has(option.id) && seen.add(option.id));
  }, [value, options]);
  const hasMore = options.length < total;

  const runLoad = async (targetPage: number, append: boolean) => {
    if (disabled) return;
    const requestId = ++requestRef.current;
    append ? setLoadingMore(true) : setLoading(true);
    setError("");
    try {
      const result = await loaderRef.current(debounced.trim(), targetPage, pageSize);
      if (requestRef.current !== requestId) return;
      setPage(result.page);
      setTotal(result.total);
      setOptions((current) => {
        const rows = append ? [...current, ...result.items] : result.items;
        const seen = new Set<string>();
        return rows.filter((option) => !seen.has(option.id) && seen.add(option.id));
      });
    } catch {
      if (requestRef.current === requestId) {
        if (!append) setOptions([]);
        setError(errorText);
      }
    } finally {
      if (requestRef.current === requestId) {
        setLoading(false);
        setLoadingMore(false);
      }
    }
  };

  useEffect(() => {
    if (!open || disabled) return;
    setPage(1);
    void runLoad(1, false);
  }, [open, debounced, disabled, pageSize]);

  useEffect(() => {
    if (!open) return;
    const close = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("pointerdown", close);
    return () => document.removeEventListener("pointerdown", close);
  }, [open]);

  const toggle = (option: ComboboxOption<T>) => {
    if (selectedIds.has(option.id)) onChange(value.filter((item) => item.id !== option.id));
    else onChange([...value, option]);
  };

  const label = value.length === 0 ? placeholder : value.length === 1 ? value[0].label : `${value.length} selected`;

  return <div className={`${styles.multiRoot}${open ? ` ${styles.open}` : ""}`} ref={rootRef}>
    <button type="button" className={styles.multiTrigger} disabled={disabled} onClick={() => setOpen((current) => !current)} aria-expanded={open} aria-controls={listboxId}>
      <span>{label}</span>
      {loading ? <span className={styles.spinner} aria-label="Loading" /> : <span aria-hidden="true">{"\u25BE"}</span>}
    </button>
    {open && !disabled && <div className={styles.multiMenu} id={listboxId}>
      <div className={styles.multiSearch}><input autoFocus value={query} placeholder="Search..." onChange={(event) => setQuery(event.target.value)} /></div>
      {value.length > 0 && <div className={styles.multiActions}><button type="button" className="secondary small" onClick={() => onChange([])}>Clear selection</button></div>}
      <div className={styles.multiOptions} role="listbox" aria-multiselectable="true" onScroll={(event) => {
        const element = event.currentTarget;
        if (!loadingMore && !loading && hasMore && element.scrollTop + element.clientHeight >= element.scrollHeight - 36) void runLoad(page + 1, true);
      }}>
        {error && <div className={`${styles.state} ${styles.error}`}>{error}</div>}
        {!error && !loading && mergedOptions.length === 0 && <div className={styles.state}>{emptyText}</div>}
        {mergedOptions.map((option) => <label className={styles.multiOption} key={option.id}>
          <input type="checkbox" checked={selectedIds.has(option.id)} onChange={() => toggle(option)} />
          <span><strong>{option.label}</strong>{option.description && <small>{option.description}</small>}</span>
        </label>)}
        {loadingMore && <div className={styles.state}><span className={styles.spinner} /> Loading more…</div>}
      </div>
      {!loading && mergedOptions.length > 0 && <div className={styles.footer}>{Math.min(options.length, total)} of {total} matching option{total === 1 ? "" : "s"}</div>}
    </div>}
  </div>;
}
