import { useCallback, useMemo } from "react";
import { apiFetch } from "../../api/client";
import type { PageResult } from "../../types";
import { SearchableCombobox, type ComboboxOption, type ComboboxPage } from "../../design-system/composites/SearchableSelect";

export type CandidatePlacementOption = {
  id: string;
  name: string;
  code: string;
  network_id: string;
  network_name: string;
  city_id: string;
  city_name: string;
  location_id: string;
  location_name: string;
  sector_id?: string | null;
  sector_name?: string | null;
  sector_role?: string | null;
  label: string;
};

type AssignmentRow = {
  id: string;
  label: string;
  description?: string | null;
  network_id?: string | null;
  network_name?: string | null;
  city_id?: string | null;
  city_name?: string | null;
  location_id?: string | null;
  location_name?: string | null;
  logical_sector_id?: string | null;
  logical_sector_name?: string | null;
  sector_role?: string | null;
};

export function placementFromAssignmentRow(
  row: AssignmentRow,
  kind: "locations" | "logical-sectors",
): CandidatePlacementOption {
  const isLogicalSector = kind === "logical-sectors";
  return {
    id: row.id,
    name: row.label,
    code: "",
    network_id: row.network_id || "",
    network_name: row.network_name || "",
    city_id: row.city_id || "",
    city_name: row.city_name || "",
    location_id: row.location_id || (isLogicalSector ? "" : row.id),
    location_name: row.location_name || row.label,
    sector_id: isLogicalSector ? (row.logical_sector_id || row.id) : null,
    sector_name: isLogicalSector ? (row.logical_sector_name || row.label) : null,
    sector_role: isLogicalSector ? (row.sector_role || null) : null,
    label: row.label,
  };
}

export function CandidatePlacementSearchSelect({
  token,
  kind,
  value,
  onChange,
  disabled = false,
  placeholder,
  currentSectorDeviceId,
  selectedLabel,
  required = false,
}: {
  token: string;
  kind: "locations" | "logical-sectors";
  value: string;
  onChange: (option: CandidatePlacementOption | null) => void;
  disabled?: boolean;
  placeholder: string;
  currentSectorDeviceId?: string;
  selectedLabel?: string | null;
  required?: boolean;
}) {
  const loadPage = useCallback(async (query: string, page: number, pageSize: number): Promise<ComboboxPage<CandidatePlacementOption>> => {
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
    if (query) params.set("search", query);
    if (value) params.set("selected_id", value);
    if (kind === "logical-sectors" && currentSectorDeviceId) params.set("current_sector_device_id", currentSectorDeviceId);
    const result = await apiFetch<PageResult<AssignmentRow>>(`/assignment-options/${kind}?${params.toString()}`, {}, token);
    return {
      ...result,
      items: result.items.map((row) => {
        const data = placementFromAssignmentRow(row, kind);
        return { id: row.id, label: row.label, description: row.description || undefined, data };
      }),
    };
  }, [token, kind, value, currentSectorDeviceId]);

  const selectedOption = useMemo<ComboboxOption<CandidatePlacementOption> | null>(() => {
    if (!value) return null;
    return { id: value, label: selectedLabel || "Current selection", data: undefined };
  }, [value, selectedLabel]);

  return <SearchableCombobox<CandidatePlacementOption>
    value={value}
    selectedOption={selectedOption}
    onChange={(option) => onChange(option?.data || null)}
    loadPage={loadPage}
    disabled={disabled}
    placeholder={placeholder}
    emptyText={kind === "logical-sectors" ? "No free logical sectors are available." : "No active locations match this search."}
    errorText="Unable to load assignment options."
    required={required}
  />;
}
