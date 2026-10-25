import { useEffect, useMemo, useRef, useState } from "react";
import type { Group } from "../../../types";
import styles from "./ChildGroupSelectors.module.css";
import { Button, Input } from "../../../design-system/primitives";

function useOutsideClose(open: boolean, onClose: () => void) {
  const root = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent) => {
      if (!root.current?.contains(event.target as Node)) onClose();
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open, onClose]);

  return root;
}

export function ChildGroupSelector({
  children,
  all,
  selected,
  onAll,
  onSelected,
}: {
  children: Group[];
  all: boolean;
  selected: string[];
  onAll: (value: boolean) => void;
  onSelected: (value: string[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const root = useOutsideClose(open, () => setOpen(false));
  const searchable = children.length > 10;
  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!searchable || !needle) return children;
    return children.filter((group) => `${group.name} ${group.code}`.toLowerCase().includes(needle));
  }, [children, search, searchable]);
  const selectedSet = useMemo(() => new Set(selected), [selected]);
  const toggle = (id: string) => onSelected(selectedSet.has(id) ? selected.filter((value) => value !== id) : [...selected, id]);
  const label = all
    ? `All child groups (${children.length})`
    : selected.length
      ? `${selected.length} child group${selected.length === 1 ? "" : "s"} selected`
      : "No child groups included";

  return (
    <div className={styles.root} ref={root}>
      <Button unstyled type="button" className={styles.trigger} onClick={() => setOpen((value) => !value)} aria-expanded={open}>
        <span>{label}</span><span aria-hidden="true">{"\u25BE"}</span>
      </Button>
      {open && (
        <div className={styles.menu}>
          <label className={styles.option}>
            <Input unstyled
              type="checkbox"
              checked={all}
              onChange={(event) => {
                onAll(event.target.checked);
                if (event.target.checked) onSelected([]);
              }}
            />
            <span><strong>Include all child groups</strong><small>Every direct child branch contributes its effective devices.</small></span>
          </label>
          {searchable && (
            <Input unstyled className={styles.search} value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search child groups..." autoFocus />
          )}
          <div className={styles.options}>
            {filtered.map((group) => (
              <label className={styles.option} key={group.id}>
                <Input unstyled
                  type="checkbox"
                  disabled={all}
                  checked={all || selectedSet.has(group.id)}
                  onChange={() => { if (!all) toggle(group.id); }}
                />
                <span><strong>{group.name}</strong><small>{group.code}</small></span>
              </label>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export function EditableChildGroupSelector({
  options,
  total,
  baseTotal,
  selected,
  search,
  onSearch,
  onSelected,
  loading,
  disabled,
}: {
  options: Group[];
  total: number;
  baseTotal: number;
  selected: string[];
  search: string;
  onSearch: (value: string) => void;
  onSelected: (value: string[]) => void;
  loading: boolean;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const root = useOutsideClose(open, () => setOpen(false));
  const searchable = baseTotal > 10;
  const selectedSet = useMemo(() => new Set(selected), [selected]);
  const toggle = (id: string) => onSelected(selectedSet.has(id) ? selected.filter((value) => value !== id) : [...selected, id]);
  const label = selected.length
    ? `${selected.length} child group${selected.length === 1 ? "" : "s"} selected`
    : baseTotal === 0 && !loading
      ? "No eligible child groups"
      : "Select child groups";
  const isDisabled = disabled || (baseTotal === 0 && selected.length === 0 && !loading);

  return (
    <div className={styles.root} ref={root}>
      <Button unstyled type="button" className={styles.trigger} disabled={isDisabled} onClick={() => setOpen((value) => !value)} aria-expanded={open}>
        <span>{loading ? "Loading eligible child groups..." : label}</span><span aria-hidden="true">{"\u25BE"}</span>
      </Button>
      {open && (
        <div className={styles.menu}>
          <div className={styles.info}><span><strong>Eligible Child Groups</strong><small>Only groups accepted by the current nesting rules are shown.</small></span></div>
          {searchable && (
            <Input unstyled className={styles.search} value={search} onChange={(event) => onSearch(event.target.value)} placeholder="Search eligible child groups..." autoFocus />
          )}
          <div className={styles.options}>
            {options.map((group) => (
              <label className={styles.option} key={group.id}>
                <Input unstyled type="checkbox" checked={selectedSet.has(group.id)} onChange={() => toggle(group.id)} />
                <span><strong>{group.name}</strong><small>{group.code} {"\u00B7"} {group.scope_type} {"\u00B7"} {group.device_scope || "ANY"}</small></span>
              </label>
            ))}
            {!loading && options.length === 0 && <div className={styles.info}><span><small>No eligible groups match the current criteria.</small></span></div>}
          </div>
          {total > options.length && <div className={styles.info}><span><small>Showing the first {options.length} matches. Refine the search to find additional groups.</small></span></div>}
        </div>
      )}
    </div>
  );
}
