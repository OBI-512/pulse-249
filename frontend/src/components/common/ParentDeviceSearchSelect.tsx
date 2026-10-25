import { useCallback, useMemo } from "react";
import { apiFetch } from "../../api/client";
import type { DeviceManagementRow, PageResult } from "../../types";
import { SearchableCombobox, type ComboboxOption, type ComboboxPage } from "../../design-system/composites/SearchableSelect";

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
  physical_sector_device_id?: string | null;
  physical_sector_device_name?: string | null;
  management_ip?: string | null;
  device_type_code?: string | null;
};

function toManagementRow(row: AssignmentRow, deviceTypeId: string): DeviceManagementRow {
  return {
    id: row.id,
    device_type_id: deviceTypeId,
    device_type_code: row.device_type_code || "",
    display_name: row.label,
    management_ip: row.management_ip || null,
    lifecycle_state: "ACTIVE",
    operational_state: "UNKNOWN",
    network_id: row.network_id || null,
    network_name: row.network_name || null,
    city_id: row.city_id || null,
    city_name: row.city_name || null,
    location_id: row.location_id || null,
    location_name: row.location_name || null,
    sector_id: row.logical_sector_id || null,
    sector_name: row.logical_sector_name || null,
    sector_role: row.sector_role || null,
    physical_sector_device_id: row.physical_sector_device_id || null,
    physical_sector_device_name: row.physical_sector_device_name || null,
    parent_device_id: null,
    parent_device_name: null,
    customer_id: null,
    customer_name: null,
    service_vlan_id: null,
    customer_vlan_id: null,
    customer_vlan_start: null,
    customer_vlan_end: null,
  };
}

export function ParentDeviceSearchSelect({
  token,
  value,
  deviceTypeId,
  sectorRole,
  requireAvailableApParent = false,
  onChange,
  disabled = false,
  placeholder = "Search parent device...",
  currentChildDeviceId,
  selectedLabel,
  required = false,
}: {
  token: string;
  value: string;
  deviceTypeId: string;
  sectorRole?: "CUSTOMER_ACCESS" | "BACKHAUL";
  requireAvailableApParent?: boolean;
  onChange: (row: DeviceManagementRow | null) => void;
  disabled?: boolean;
  placeholder?: string;
  currentChildDeviceId?: string;
  selectedLabel?: string | null;
  required?: boolean;
}) {
  const childType = requireAvailableApParent ? "ACCESS_POINT" : "CPE";
  const loadPage = useCallback(async (query: string, page: number, pageSize: number): Promise<ComboboxPage<DeviceManagementRow>> => {
    const params = new URLSearchParams({ child_type: childType, page: String(page), page_size: String(pageSize) });
    if (query) params.set("search", query);
    if (value) params.set("selected_id", value);
    if (currentChildDeviceId) params.set("current_child_device_id", currentChildDeviceId);
    const result = await apiFetch<PageResult<AssignmentRow>>(`/assignment-options/parent-devices?${params.toString()}`, {}, token);
    return {
      ...result,
      items: result.items.map((row) => {
        const data = toManagementRow(row, deviceTypeId);
        return { id: row.id, label: row.label, description: row.description || undefined, data };
      }),
    };
  }, [token, childType, value, currentChildDeviceId, deviceTypeId]);

  const selectedOption = useMemo<ComboboxOption<DeviceManagementRow> | null>(() => value ? { id: value, label: selectedLabel || "Current parent" } : null, [value, selectedLabel]);

  return <SearchableCombobox<DeviceManagementRow>
    value={value}
    selectedOption={selectedOption}
    onChange={(option) => onChange(option?.data || null)}
    loadPage={loadPage}
    disabled={disabled || !deviceTypeId}
    placeholder={placeholder}
    emptyText={childType === "CPE" ? "No eligible customer-access SECTOR devices found." : "No eligible CPEs without an access point found."}
    errorText="Unable to load eligible parent devices."
    required={required}
  />;
}
