import { useCallback, useMemo } from "react";
import { apiFetch } from "../../api/client";
import type { PageResult } from "../../types";
import { SearchableCombobox, type ComboboxOption, type ComboboxPage } from "../../design-system/composites/SearchableSelect";

type AssignmentOption = {
  id: string;
  label: string;
  description?: string | null;
};

export function PhysicalSectorSearchSelect({
  token,
  value,
  onChange,
  networkId,
  cityId,
  locationId,
  disabled = false,
  placeholder = "Search physical sector...",
  selectedLabel,
}: {
  token: string;
  value: string;
  onChange: (value: string) => void;
  networkId?: string;
  cityId?: string;
  locationId?: string;
  disabled?: boolean;
  placeholder?: string;
  selectedLabel?: string | null;
}) {
  const loadPage = useCallback(async (query: string, page: number, pageSize: number): Promise<ComboboxPage<AssignmentOption>> => {
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
    if (query) params.set("search", query);
    if (value) params.set("selected_id", value);
    if (networkId) params.set("network_id", networkId);
    if (cityId) params.set("city_id", cityId);
    if (locationId) params.set("location_id", locationId);
    const result = await apiFetch<PageResult<AssignmentOption>>(`/assignment-options/physical-sectors?${params.toString()}`, {}, token);
    return {
      ...result,
      items: result.items.map((row) => ({ id: row.id, label: row.label, description: row.description || undefined, data: row })),
    };
  }, [token, value, networkId, cityId, locationId]);

  const selectedOption = useMemo<ComboboxOption<AssignmentOption> | null>(
    () => value ? { id: value, label: selectedLabel || "Current physical sector" } : null,
    [value, selectedLabel],
  );

  return <SearchableCombobox<AssignmentOption>
    value={value}
    selectedOption={selectedOption}
    onChange={(option) => onChange(option?.id || "")}
    loadPage={loadPage}
    disabled={disabled}
    placeholder={placeholder}
    emptyText="No physical sectors match the current scope."
  />;
}
