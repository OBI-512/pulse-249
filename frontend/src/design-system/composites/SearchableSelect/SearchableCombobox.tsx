import { useEffect, useId, useMemo, useRef, useState } from "react";
import { useDebouncedValue } from "../../../hooks/useDebouncedValue";
import styles from "./SearchableSelect.module.css";

export type ComboboxOption<T = unknown> = {
  id: string;
  label: string;
  description?: string;
  data?: T;
};

export type ComboboxPage<T = unknown> = {
  items: ComboboxOption<T>[];
  total: number;
  page: number;
  page_size: number;
};

export function SearchableCombobox<T = unknown>({
  value,
  selectedOption,
  onChange,
  loadPage,
  disabled = false,
  placeholder = "Search or select...",
  emptyText = "No matching options found.",
  errorText = "Unable to load options.",
  pageSize = 50,
  ariaLabel,
  required = false,
  invalid = false,
}: {
  value: string;
  selectedOption?: ComboboxOption<T> | null;
  onChange: (option: ComboboxOption<T> | null) => void;
  loadPage: (query: string, page: number, pageSize: number) => Promise<ComboboxPage<T>>;
  disabled?: boolean;
  placeholder?: string;
  emptyText?: string;
  errorText?: string;
  pageSize?: number;
  ariaLabel?: string;
  required?: boolean;
  invalid?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [options, setOptions] = useState<ComboboxOption<T>[]>([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState("");
  const [highlighted, setHighlighted] = useState(-1);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const listboxId = useId();
  const requestRef = useRef(0);
  const loaderRef = useRef(loadPage);
  loaderRef.current = loadPage;
  const debounced = useDebouncedValue(query, 280);

  const selected = useMemo(() => {
    if (!value) return null;
    return options.find((option) => option.id === value) || (selectedOption?.id === value ? selectedOption : null);
  }, [value, selectedOption, options]);

  const displayValue = open ? query : (selected?.label || "");
  const hasMore = options.length < total;
  const showInvalid = invalid;

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
        const merged = append ? [...current, ...result.items] : result.items;
        const seen = new Set<string>();
        const unique = merged.filter((option) => !seen.has(option.id) && seen.add(option.id));
        if (selectedOption && value && selectedOption.id === value && !unique.some((option) => option.id === value)) {
          return [selectedOption, ...unique];
        }
        return unique;
      });
      setHighlighted(result.items.length > 0 ? 0 : -1);
    } catch {
      if (requestRef.current === requestId) {
        if (!append) setOptions(selectedOption && value ? [selectedOption] : []);
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
    if (!open) setQuery("");
  }, [value, open]);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    return () => document.removeEventListener("pointerdown", onPointerDown);
  }, [open]);

  const choose = (option: ComboboxOption<T> | null) => {
    onChange(option);
    setOpen(false);
    setQuery("");
    setHighlighted(-1);
  };

  return (
    <div
      className={`${styles.root}${open ? ` ${styles.open}` : ""}${showInvalid ? ` ${styles.invalid}` : ""}`}
      data-required={required ? "true" : undefined}
      data-empty={required && !value ? "true" : undefined}
      ref={rootRef}
    >
      <div className={styles.control}>
        <svg className={styles.searchIcon} viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6"/><path d="m16 16 4 4"/></svg>
        <input
          className={styles.input}
          role="combobox"
          aria-expanded={open}
          aria-controls={listboxId}
          aria-autocomplete="list"
          aria-label={ariaLabel || placeholder}
          aria-required={required || undefined}
          aria-invalid={showInvalid || undefined}
          disabled={disabled}
          value={displayValue}
          placeholder={placeholder}
          onFocus={() => { setOpen(true); setQuery(""); }}
          onClick={() => setOpen(true)}
          onChange={(event) => { setOpen(true); setQuery(event.target.value); setHighlighted(0); }}
          onKeyDown={(event) => {
            if (event.key === "ArrowDown") {
              event.preventDefault(); setOpen(true); setHighlighted((current) => Math.min(options.length - 1, Math.max(0, current + 1)));
            } else if (event.key === "ArrowUp") {
              event.preventDefault(); setHighlighted((current) => Math.max(0, current - 1));
            } else if (event.key === "Enter" && open && highlighted >= 0 && options[highlighted]) {
              event.preventDefault(); choose(options[highlighted]);
            } else if (event.key === "Escape") {
              setOpen(false); setQuery("");
            } else if ((event.key === "Backspace" || event.key === "Delete") && !open && value) {
              choose(null);
            }
          }}
        />
        {loading ? <span className={styles.spinner} aria-label="Loading" /> : value ? <button type="button" className={styles.clear} aria-label="Clear selection" disabled={disabled} onClick={(event) => { event.stopPropagation(); choose(null); }}>{"\u00D7"}</button> : <svg className={styles.chevron} viewBox="0 0 24 24" aria-hidden="true"><path d="m7 10 5 5 5-5"/></svg>}
      </div>
      {open && !disabled && <div className={styles.menu} role="listbox" id={listboxId} onScroll={(event) => {
        const element = event.currentTarget;
        if (!loadingMore && !loading && hasMore && element.scrollTop + element.clientHeight >= element.scrollHeight - 36) {
          void runLoad(page + 1, true);
        }
      }}>
        {error && <div className={`${styles.state} ${styles.error}`}>{error}</div>}
        {!error && !loading && options.length === 0 && <div className={styles.state}>{emptyText}</div>}
        {options.map((option, index) => <button
          key={option.id}
          type="button"
          role="option"
          aria-selected={option.id === value}
          className={`${styles.option}${index === highlighted ? ` ${styles.highlighted}` : ""}${option.id === value ? ` ${styles.selected}` : ""}`}
          onMouseEnter={() => setHighlighted(index)}
          onClick={() => choose(option)}
        >
          <span className={styles.optionCopy}><strong>{option.label}</strong>{option.description && <small>{option.description}</small>}</span>
          {option.id === value && <svg className={styles.check} viewBox="0 0 24 24" aria-hidden="true"><path d="m5 12 4 4L19 6"/></svg>}
        </button>)}
        {loadingMore && <div className={styles.state}><span className={styles.spinner} /> Loading more…</div>}
        {!loading && !loadingMore && options.length > 0 && <div className={styles.footer}>{Math.min(options.length, total)} of {total} eligible option{total === 1 ? "" : "s"}</div>}
      </div>}
    </div>
  );
}
