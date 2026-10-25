import { useCallback, useMemo } from "react";
import { SearchableCombobox, type ComboboxOption, type ComboboxPage } from "./SearchableCombobox";

export type LocalComboboxOption<T = unknown> = ComboboxOption<T>;

export function LocalSearchableCombobox<T = unknown>({
  value,
  options,
  onChange,
  disabled = false,
  placeholder = "Search or select...",
  emptyText = "No matching options found.",
  pageSize = 50,
  ariaLabel,
  required = false,
  invalid = false,
}: {
  value: string;
  options: LocalComboboxOption<T>[];
  onChange: (option: LocalComboboxOption<T> | null) => void;
  disabled?: boolean;
  placeholder?: string;
  emptyText?: string;
  pageSize?: number;
  ariaLabel?: string;
  required?: boolean;
  invalid?: boolean;
}) {
  const normalized = useMemo(() => options.map((option) => ({ ...option })), [options]);
  const selectedOption = useMemo(
    () => normalized.find((option) => option.id === value) || null,
    [normalized, value],
  );

  const loadPage = useCallback(async (query: string, page: number, size: number): Promise<ComboboxPage<T>> => {
    const needle = query.trim().toLocaleLowerCase();
    const filtered = needle
      ? normalized.filter((option) => `${option.label} ${option.description || ""}`.toLocaleLowerCase().includes(needle))
      : normalized;
    const start = (page - 1) * size;
    return {
      items: filtered.slice(start, start + size),
      total: filtered.length,
      page,
      page_size: size,
    };
  }, [normalized]);

  return <SearchableCombobox<T>
    value={value}
    selectedOption={selectedOption}
    onChange={onChange}
    loadPage={loadPage}
    disabled={disabled}
    placeholder={placeholder}
    emptyText={emptyText}
    pageSize={pageSize}
    ariaLabel={ariaLabel}
    required={required}
    invalid={invalid}
  />;
}
