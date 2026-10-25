import { useCallback, useEffect, useRef, useState } from "react";
import { apiFetch } from "../../api/client";
import { useDialog } from "../../components/common/DialogSystem";
import { useDebouncedValue } from "../../hooks/useDebouncedValue";
import type { Device, DeviceInterface, DeviceIP, DeviceManagementRow, DeviceType, PageResult, SortState } from "../../types";
import { isValidIPv4 } from "../../utils/validation";

type Options = {
  token: string;
  permissions: string[];
  active: boolean;
  types: DeviceType[];
  recycleEntity: (entityType: string, id: string, label: string, deletePath: string) => Promise<boolean>;
  setBusy: (value: boolean) => void;
  clearAlerts: () => void;
  setError: (value: string) => void;
  setMessage: (value: string) => void;
  onError: (error: unknown, fallback: string) => void;
};

const blankDeviceForm = {
  display_name: "", device_type_id: "", management_ip: "", location_id: "", sector_id: "", parent_device_id: "",
  hostname: "", vendor: "", model: "", serial_number: "", description: "", lifecycle_state: "REGISTERED",
  operational_state: "UNKNOWN", manual_degraded_override: false, management_protocol: "", credential_reference: "",
};
const blankInterfaceForm = { interface_name: "", interface_index: "", mac_address: "", description: "", operational_status: "", administrative_status: "" };

export function useDeviceWorkspace(options: Options) {
  const optionsRef = useRef(options); optionsRef.current = options;
  const dialog = useDialog();
  const [section, setSection] = useState<"inventory" | "management">("inventory");
  const [devices, setDevices] = useState<Device[]>([]);
  const [deviceTotal, setDeviceTotal] = useState(0);
  const [devicePage, setDevicePage] = useState(1);
  const [devicePageSize, setDevicePageSize] = useState(50);
  const [deviceSort, setDeviceSort] = useState<SortState>({ key: "display_name", direction: "asc" });
  const [managementRows, setManagementRows] = useState<DeviceManagementRow[]>([]);
  const [managementTotal, setManagementTotal] = useState(0);
  const [managementPage, setManagementPage] = useState(1);
  const [managementPageSize, setManagementPageSize] = useState(50);
  const [managementSort, setManagementSort] = useState<SortState>({ key: "display_name", direction: "asc" });
  const [search, setSearch] = useState("");
  const [lifecycle, setLifecycle] = useState("");
  const [operational, setOperational] = useState("");
  const [deviceType, setDeviceType] = useState("");
  const [inventoryServiceVlan, setInventoryServiceVlan] = useState("");
  const [inventoryCustomerVlan, setInventoryCustomerVlan] = useState("");
  const [managementFilters, setManagementFilters] = useState({
    search: "", network_id: "", city_id: "", location_id: "", physical_sector_device_id: "", group_id: "",
    device_type_id: "", service_vlan_id: "", customer_vlan_id: "", lifecycle_state: "", operational_state: "",
  });
  const [selected, setSelected] = useState<Device | null>(null);
  const [ips, setIps] = useState<DeviceIP[]>([]);
  const [interfaces, setInterfaces] = useState<DeviceInterface[]>([]);
  const [placement, setPlacement] = useState<any | null>(null);
  const [domainContext, setDomainContext] = useState<DeviceManagementRow | null>(null);
  const [form, setForm] = useState({ ...blankDeviceForm });
  const [ipForm, setIpForm] = useState({ ip_address: "", is_management: true, is_primary: true, source: "MANUAL" });
  const [interfaceForm, setInterfaceForm] = useState({ ...blankInterfaceForm });
  const [statusForm, setStatusForm] = useState({ operational_state: "UNKNOWN", lifecycle_state: "" });
  const [placementForm, setPlacementForm] = useState({ network_id: "", city_id: "", location_id: "", sector_id: "" });
  const inventoryRequestRef = useRef(0);
  const managementRequestRef = useRef(0);
  const debouncedSearch = useDebouncedValue(search, 300);
  const debouncedManagementSearch = useDebouncedValue(managementFilters.search, 300);

  const loadDevices = useCallback(async () => {
    const requestId = ++inventoryRequestRef.current;
    const params = new URLSearchParams({
      page: String(devicePage), page_size: String(devicePageSize), sort_by: deviceSort.key, sort_direction: deviceSort.direction,
    });
    if (debouncedSearch.trim()) params.set("search", debouncedSearch.trim());
    if (lifecycle) params.set("lifecycle_state", lifecycle);
    if (operational) params.set("operational_state", operational);
    if (deviceType) params.set("device_type_id", deviceType);
    if (inventoryServiceVlan) params.set("service_vlan_id", inventoryServiceVlan);
    if (inventoryCustomerVlan) params.set("customer_vlan_id", inventoryCustomerVlan);
    const body = await apiFetch<PageResult<Device>>(`/devices/inventory/page?${params.toString()}`, {}, options.token);
    if (requestId !== inventoryRequestRef.current) return;
    setDevices(body.items || []); setDeviceTotal(body.total || 0);
  }, [debouncedSearch, devicePage, devicePageSize, deviceSort, deviceType, inventoryServiceVlan, inventoryCustomerVlan, lifecycle, operational, options.token]);

  const loadManagement = useCallback(async () => {
    const requestId = ++managementRequestRef.current;
    const params = new URLSearchParams({
      page: String(managementPage), page_size: String(managementPageSize), sort_by: managementSort.key, sort_direction: managementSort.direction,
    });
    for (const [key, value] of Object.entries(managementFilters) as Array<[string, string]>) {
      const resolved = key === "search" ? debouncedManagementSearch : value;
      if (resolved.trim()) params.set(key, resolved.trim());
    }
    const result = await apiFetch<PageResult<DeviceManagementRow>>(`/devices/management/page?${params.toString()}`, {}, options.token);
    if (requestId !== managementRequestRef.current) return;
    setManagementRows(result.items); setManagementTotal(result.total);
  }, [debouncedManagementSearch, managementFilters, managementPage, managementPageSize, managementSort, options.token]);

  useEffect(() => { setDevicePage(1); }, [debouncedSearch, lifecycle, operational, deviceType, inventoryServiceVlan, inventoryCustomerVlan]);
  useEffect(() => {
    if (!options.active || section !== "inventory" || !options.permissions.includes("device.read")) return;
    void loadDevices().catch((error) => optionsRef.current.onError(error, "Unable to load devices."));
  }, [loadDevices, options.active, options.permissions, section]);

  useEffect(() => { setManagementPage(1); }, [debouncedManagementSearch, managementFilters.network_id, managementFilters.city_id, managementFilters.location_id, managementFilters.physical_sector_device_id, managementFilters.group_id, managementFilters.device_type_id, managementFilters.service_vlan_id, managementFilters.customer_vlan_id, managementFilters.lifecycle_state, managementFilters.operational_state]);
  useEffect(() => {
    if (!options.active || section !== "management" || !options.permissions.includes("device.read")) return;
    void loadManagement().catch((error) => optionsRef.current.onError(error, "Unable to load device management data."));
  }, [loadManagement, options.active, options.permissions, section]);

  const startNew = useCallback(() => {
    const current = optionsRef.current;
    setSelected(null); setIps([]); setInterfaces([]); setPlacement(null); setDomainContext(null);
    setForm({
      ...blankDeviceForm,
      device_type_id: current.types.find((type) => type.code === "CPE")?.id || current.types[0]?.id || "",
    });
    setStatusForm({ operational_state: "UNKNOWN", lifecycle_state: "REGISTERED" });
    setIpForm({ ip_address: "", is_management: true, is_primary: true, source: "MANUAL" });
    setInterfaceForm({ ...blankInterfaceForm });
  }, []);

  const loadDetails = useCallback(async (device: Device) => {
    const current = optionsRef.current;
    setSelected(device);
    setForm({
      display_name: device.display_name, device_type_id: device.device_type_id, management_ip: device.management_ip || "",
      location_id: "", sector_id: "", parent_device_id: "", hostname: device.hostname || "", vendor: device.vendor || "",
      model: device.model || "", serial_number: device.serial_number || "", description: device.description || "",
      lifecycle_state: device.lifecycle_state, operational_state: device.operational_state, manual_degraded_override: Boolean(device.manual_degraded_override),
      management_protocol: device.management_protocol || "", credential_reference: device.credential_reference || "",
    });
    setStatusForm({ operational_state: device.operational_state, lifecycle_state: device.lifecycle_state });
    try {
      const [deviceIps, deviceInterfaces, contextPage] = await Promise.all([
        apiFetch<DeviceIP[]>(`/devices/${device.id}/ips`, {}, current.token),
        apiFetch<DeviceInterface[]>(`/devices/${device.id}/interfaces`, {}, current.token),
        apiFetch<PageResult<DeviceManagementRow>>(`/devices/management/page?page=1&page_size=1&device_id=${device.id}`, {}, current.token),
      ]);
      setIps(deviceIps); setInterfaces(deviceInterfaces);
      const managementIp = deviceIps.find((ip) => ip.is_management)?.ip_address || deviceIps.find((ip) => ip.is_primary)?.ip_address || deviceIps[0]?.ip_address || null;
      const context = contextPage.items[0] || null;
      const typeCode = current.types.find((type) => type.id === device.device_type_id)?.code || "";
      const hierarchyChild = typeCode === "CPE" || typeCode === "ACCESS_POINT";
      setSelected({ ...device, management_ip: managementIp }); setDomainContext(context);
      setForm((existing) => ({ ...existing,
        location_id: !hierarchyChild && typeCode !== "SECTOR" ? (context?.location_id || "") : "",
        sector_id: typeCode === "SECTOR" ? (context?.sector_id || "") : "",
        parent_device_id: hierarchyChild ? (context?.parent_device_id || "") : "",
      }));
      setPlacement(null);
      setPlacementForm({ network_id: context?.network_id || "", city_id: context?.city_id || "", location_id: context?.location_id || "", sector_id: context?.sector_id || "" });
    } catch (error) { current.onError(error, "Unable to load device details."); }
  }, []);

  const createDevice = useCallback(async () => {
    const current = optionsRef.current;
    if (!form.display_name.trim() || !form.device_type_id || !form.management_ip.trim()) { current.setError("Device name, device type and management IP are required."); return; }
    if (!isValidIPv4(form.management_ip)) { current.setError("Management IP must be a valid IPv4 address, for example 192.168.1.10."); return; }
    const selectedType = current.types.find((type) => type.id === form.device_type_id)?.code;
    if (selectedType === "SECTOR" && !form.sector_id) { current.setError("A SECTOR device must be bound to a logical sector."); return; }
    if ((selectedType === "CPE" || selectedType === "ACCESS_POINT") && !form.parent_device_id) { current.setError(`${selectedType} requires a parent device.`); return; }
    if (selectedType && !["SECTOR", "CPE", "ACCESS_POINT"].includes(selectedType) && !form.location_id) { current.setError(`${selectedType} requires an active location.`); return; }
    if (!await dialog.confirm({ message: `Create device ${form.display_name.trim()}?` })) return;
    current.setBusy(true); current.clearAlerts();
    try {
      const body = await apiFetch<Device>("/devices", { method: "POST", body: JSON.stringify({
        ...form, operational_state:"UNKNOWN", manual_degraded_override:false, display_name: form.display_name.trim(), management_ip: form.management_ip.trim(), location_id: form.location_id || null,
        sector_id: form.sector_id || null, parent_device_id: form.parent_device_id || null, hostname: form.hostname || null, vendor: form.vendor || null, model: form.model || null,
        serial_number: form.serial_number || null, description: form.description || null, management_protocol: form.management_protocol || null,
        credential_reference: form.credential_reference || null, metadata: {},
      }) }, current.token);
      await loadDevices(); await loadDetails(body); current.setMessage(`Device ${body.display_name} created.`);
    } catch (error) { current.onError(error, "Unable to create device."); }
    finally { current.setBusy(false); }
  }, [dialog, form, loadDetails, loadDevices]);

  const updateDevice = useCallback(async () => {
    const current = optionsRef.current; if (!selected) return;
    if (!await dialog.confirm({ message: `Save changes to ${selected.display_name}?` })) return;
    current.setBusy(true); current.clearAlerts();
    try {
      const body = await apiFetch<Device>(`/devices/${selected.id}`, { method: "PATCH", body: JSON.stringify({
        device_type_id: form.device_type_id, display_name: form.display_name.trim(), hostname: form.hostname || null, vendor: form.vendor || null,
        model: form.model || null, serial_number: form.serial_number || null, description: form.description || null,
        lifecycle_state: form.lifecycle_state, manual_degraded_override:Boolean(form.manual_degraded_override), management_protocol: form.management_protocol || null,
        credential_reference: form.credential_reference || null, location_id: form.location_id || null, sector_id: form.sector_id || null,
        parent_device_id: form.parent_device_id || null,
      }) }, current.token);
      await Promise.all([loadDevices(), loadDetails({ ...body, management_ip: selected.management_ip })]); current.setMessage("Device changes saved successfully.");
    } catch (error) { current.onError(error, "Unable to update device."); }
    finally { current.setBusy(false); }
  }, [dialog, form, loadDetails, loadDevices, selected]);

  const updateStatus = useCallback(async () => {
    const current = optionsRef.current; if (!selected) return;
    if (!await dialog.confirm({ message: `Apply lifecycle/manual degraded changes to ${selected.display_name}?` })) return;
    current.setBusy(true); current.clearAlerts();
    try {
      const body = await apiFetch<Device>(`/devices/${selected.id}/status`, { method: "PATCH", body: JSON.stringify({
        manual_degraded_override:Boolean(form.manual_degraded_override), lifecycle_state: form.lifecycle_state !== selected.lifecycle_state ? form.lifecycle_state : null,
      }) }, current.token);
      setSelected({ ...body, management_ip: selected.management_ip });
      setStatusForm({ operational_state: body.operational_state, lifecycle_state: body.lifecycle_state });
      setForm((existing) => ({ ...existing, operational_state: body.operational_state, manual_degraded_override:Boolean(body.manual_degraded_override), lifecycle_state: body.lifecycle_state }));
      await loadDevices(); current.setMessage("Device status updated.");
    } catch (error) { current.onError(error, "Unable to update device status."); }
    finally { current.setBusy(false); }
  }, [dialog, form.lifecycle_state, form.manual_degraded_override, loadDevices, selected]);

  const testAccessibility = useCallback(async (deviceId: string) => {
    const current = optionsRef.current; current.clearAlerts();
    try {
      const result = await apiFetch<{ reachable: boolean; url: string; status_code: number | null; response_time_ms: number | null; message: string }>(`/devices/${deviceId}/test-accessibility`, { method: "POST" }, current.token);
      current.setMessage(`${result.message}${result.response_time_ms != null ? ` Response time: ${result.response_time_ms} ms.` : ""}`);
    } catch (error) { current.onError(error, "Unable to test device accessibility."); }
  }, []);

  const decommission = useCallback(async () => {
    const current = optionsRef.current; if (!selected) return;
    if (!await dialog.confirm({ message: `Decommission ${selected.display_name}? You can reactivate it later until it is moved to the Recycle Bin.` })) return;
    current.setBusy(true); current.clearAlerts();
    try {
      const body = await apiFetch<Device>(`/devices/${selected.id}/decommission`, { method: "POST" }, current.token);
      setSelected({ ...body, management_ip: selected.management_ip }); setStatusForm({ operational_state: body.operational_state, lifecycle_state: body.lifecycle_state });
      setForm((existing) => ({ ...existing, operational_state: body.operational_state, manual_degraded_override:Boolean(body.manual_degraded_override), lifecycle_state: body.lifecycle_state }));
      await loadDevices(); current.setMessage("Device decommissioned.");
    } catch (error) { current.onError(error, "Unable to decommission device."); }
    finally { current.setBusy(false); }
  }, [dialog, loadDevices, selected]);

  const reactivate = useCallback(async () => {
    const current = optionsRef.current; if (!selected) return;
    if (!await dialog.confirm({ message: `Reactivate ${selected.display_name}? Its hierarchy will be validated before activation.` })) return;
    current.setBusy(true); current.clearAlerts();
    try {
      const body = await apiFetch<Device>(`/devices/${selected.id}/reactivate`, { method: "POST" }, current.token);
      await Promise.all([loadDevices(), loadDetails({ ...body, management_ip: selected.management_ip })]); current.setMessage("Device reactivated successfully.");
    } catch (error) { current.onError(error, "Unable to reactivate device."); }
    finally { current.setBusy(false); }
  }, [dialog, loadDetails, loadDevices, selected]);

  const deleteDevice = useCallback(async () => {
    const current = optionsRef.current; if (!selected) return;
    current.setBusy(true); current.clearAlerts();
    try {
      if (!await current.recycleEntity("DEVICE", selected.id, selected.display_name, `/devices/${selected.id}`)) return;
      setSelected(null); await loadDevices(); current.setMessage("Device moved to Recycle Bin.");
    } catch (error) { current.onError(error, "Unable to delete device."); }
    finally { current.setBusy(false); }
  }, [loadDevices, selected]);

  const addIp = useCallback(async () => {
    const current = optionsRef.current; if (!selected || !ipForm.ip_address.trim()) return;
    if (!isValidIPv4(ipForm.ip_address)) { current.setError("Additional IP must be a valid IPv4 address, for example 192.168.1.11."); return; }
    if (!await dialog.confirm({ message: `Add IP ${ipForm.ip_address.trim()} to ${selected.display_name}?` })) return;
    current.setBusy(true); current.clearAlerts();
    try {
      await apiFetch<DeviceIP>(`/devices/${selected.id}/ips`, { method: "POST", body: JSON.stringify({
        ip_address: ipForm.ip_address.trim(), is_management: ipForm.is_management, is_primary: ipForm.is_primary, source: ipForm.source || null,
      }) }, current.token);
      setIpForm({ ip_address: "", is_management: true, is_primary: false, source: "MANUAL" });
      await Promise.all([loadDetails(selected), loadDevices()]); current.setMessage("IP address added.");
    } catch (error) { current.onError(error, "Unable to add device IP."); }
    finally { current.setBusy(false); }
  }, [dialog, ipForm, loadDetails, loadDevices, selected]);

  const updateIp = useCallback(async (ip: DeviceIP) => {
    const current = optionsRef.current; if (!selected) return;
    if (!await dialog.confirm({ message: `Toggle management and primary flags for ${ip.ip_address}?` })) return;
    try {
      await apiFetch<DeviceIP>(`/devices/${selected.id}/ips/${ip.id}`, { method: "PATCH", body: JSON.stringify({ is_management: !ip.is_management, is_primary: !ip.is_primary }) }, current.token);
      await loadDetails(selected); current.setMessage("IP flags updated.");
    } catch (error) { current.onError(error, "Unable to update device IP."); }
  }, [dialog, loadDetails, selected]);

  const deleteIp = useCallback(async (ip: DeviceIP) => {
    const current = optionsRef.current; if (!selected) return;
    if (!await dialog.confirm({ message: `Delete IP ${ip.ip_address}?` })) return;
    try { await apiFetch<void>(`/devices/${selected.id}/ips/${ip.id}`, { method: "DELETE" }, current.token); await Promise.all([loadDetails(selected), loadDevices()]); current.setMessage("IP address removed."); }
    catch (error) { current.onError(error, "Unable to remove device IP."); }
  }, [dialog, loadDetails, loadDevices, selected]);

  const addInterface = useCallback(async () => {
    const current = optionsRef.current; if (!selected || !interfaceForm.interface_name.trim()) return;
    if (!await dialog.confirm({ message: `Add interface ${interfaceForm.interface_name.trim()}?` })) return;
    current.setBusy(true); current.clearAlerts();
    try {
      await apiFetch<DeviceInterface>(`/devices/${selected.id}/interfaces`, { method: "POST", body: JSON.stringify({
        interface_name: interfaceForm.interface_name.trim(), interface_index: interfaceForm.interface_index ? Number(interfaceForm.interface_index) : null,
        mac_address: interfaceForm.mac_address || null, description: interfaceForm.description || null,
        operational_status: interfaceForm.operational_status || null, administrative_status: interfaceForm.administrative_status || null, metadata: {},
      }) }, current.token);
      setInterfaceForm({ ...blankInterfaceForm }); await loadDetails(selected); current.setMessage("Interface added.");
    } catch (error) { current.onError(error, "Unable to add interface."); }
    finally { current.setBusy(false); }
  }, [dialog, interfaceForm, loadDetails, selected]);

  const deleteInterface = useCallback(async (item: DeviceInterface) => {
    const current = optionsRef.current; if (!selected) return;
    if (!await dialog.confirm({ message: `Delete interface ${item.interface_name}?` })) return;
    try { await apiFetch<void>(`/devices/${selected.id}/interfaces/${item.id}`, { method: "DELETE" }, current.token); await loadDetails(selected); current.setMessage("Interface removed."); }
    catch (error) { current.onError(error, "Unable to remove interface."); }
  }, [dialog, loadDetails, selected]);

  const updatePlacement = useCallback(async () => {
    const current = optionsRef.current; if (!selected) return;
    if (!await dialog.confirm({ message: `Save physical placement for ${selected.display_name}?` })) return;
    current.setBusy(true); current.clearAlerts();
    try {
      const body = await apiFetch<any>(`/devices/${selected.id}/placement`, { method: "PATCH", body: JSON.stringify({
        network_id: placementForm.network_id || null, city_id: placementForm.city_id || null, location_id: placementForm.location_id || null, sector_id: placementForm.sector_id || null,
      }) }, current.token);
      setPlacement(body); current.setMessage("Physical placement updated.");
    } catch (error) { current.onError(error, "Unable to update placement."); }
    finally { current.setBusy(false); }
  }, [dialog, placementForm, selected]);

  return {
    section, setSection, devices, deviceTotal, devicePage, setDevicePage, devicePageSize, setDevicePageSize, deviceSort, setDeviceSort,
    managementRows, managementTotal, managementPage, setManagementPage, managementPageSize, setManagementPageSize, managementSort, setManagementSort,
    managementFilters, setManagementFilters, search, setSearch, lifecycle, setLifecycle, operational, setOperational, deviceType, setDeviceType,
    inventoryServiceVlan, setInventoryServiceVlan, inventoryCustomerVlan, setInventoryCustomerVlan,
    selected, form, setForm, ips, interfaces, placement, domainContext, placementForm, setPlacementForm, statusForm, setStatusForm,
    ipForm, setIpForm, interfaceForm, setInterfaceForm, loadDevices, loadManagement, loadDetails, startNew, createDevice, updateDevice,
    updateStatus, testAccessibility, decommission, reactivate, deleteDevice, addIp, updateIp, deleteIp, addInterface, deleteInterface, updatePlacement,
  };
}

