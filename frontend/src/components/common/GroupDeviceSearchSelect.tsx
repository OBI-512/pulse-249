import { useCallback } from "react";
import { apiFetch } from "../../api/client";
import type { Device, PageResult } from "../../types";
import { SearchableCombobox, type ComboboxPage } from "../../design-system/composites/SearchableSelect";

export function GroupDeviceSearchSelect(props: {
  token: string;
  groupId: string;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
}) {
  const loadPage = useCallback(async (query: string, page: number, pageSize: number): Promise<ComboboxPage<Device>> => {
    if (!props.groupId) return { items:[], total:0, page, page_size:pageSize };
    const params = new URLSearchParams({ page:String(page), page_size:String(pageSize) });
    if (query) params.set("search", query);
    const result = await apiFetch<PageResult<Device>>(`/device-groups/${props.groupId}/eligible-devices/page?${params.toString()}`, {}, props.token);
    return {
      ...result,
      items: result.items.map((device) => ({ id:device.id, label:device.display_name, description:[device.hostname, device.management_ip].filter(Boolean).join(" · "), data:device })),
    };
  }, [props.groupId, props.token]);

  return <SearchableCombobox<Device>
    value={props.value}
    onChange={(option)=>props.onChange(option?.id || "")}
    loadPage={loadPage}
    disabled={props.disabled || !props.groupId}
    placeholder="Search eligible devices..."
    emptyText="No eligible devices match this search."
  />;
}
