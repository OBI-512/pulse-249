import { PageLayout } from "../design-system/layouts";
import { useCallback, useEffect, useState } from "react";
import type { City, Customer, Device, DeviceInterface, DeviceIP, DeviceType, Location, Network, Sector, SortState } from "../types";
import { EmptyState } from "../design-system/composites/AsyncState";
import { StatusBadge as Badge } from "../design-system/composites/Status";
import { nextSort } from "../utils/sorting";
import { copyToClipboard } from "../utils/management";
import { SortableDeviceIPs } from "../components/device/SortableDeviceIPs";
import { SortableInterfaces } from "../components/device/SortableInterfaces";
import { DeviceForm } from "../components/device/DeviceForm";
import { DeviceManagementPanel } from "../components/device/DeviceManagementPanel";
import { DeviceAccessActions } from "../components/device/DeviceAccessActions";
import { useDeviceAccessActions } from "../hooks/useDeviceAccessActions";
import { notifyDeviceAccessChanged } from "../utils/deviceAccess";
import { Tabs } from "../design-system/composites/Tabs";
import { SearchableCombobox, type ComboboxPage } from "../design-system/composites/SearchableSelect";
import { apiFetch } from "../api/client";

import { DataTable } from "../design-system/data/DataTable";
import { ServerPaginationRow } from "../design-system/data/Pagination";
import { SortHeader } from "../design-system/data/SortHeader";
import { TableExportButton } from "../design-system/data/TableExport";
import { ClearFiltersButton } from "../design-system/composites/FilterBar";
import { ContextMenuSurface } from "../design-system/composites/Menu";
import { Button, Input, Select } from "../design-system/primitives";

type InventoryVlanKind = "service" | "customer";
type InventoryVlanContext = {
  search: string;
  device_type_id: string;
  lifecycle_state: string;
  operational_state: string;
  service_vlan_id: string;
  customer_vlan_id: string;
};

function InventoryVlanFilterCombobox({
  token, kind, value, onChange, context, placeholder,
}: {
  token: string;
  kind: InventoryVlanKind;
  value: string;
  onChange: (value: string) => void;
  context: InventoryVlanContext;
  placeholder: string;
}) {
  const loadPage = useCallback(async (query: string, page: number, pageSize: number): Promise<ComboboxPage> => {
    const params = new URLSearchParams({ kind, page: String(page), page_size: String(pageSize) });
    if (query) params.set("search", query);
    if (context.search.trim()) params.set("management_search", context.search.trim());
    for (const key of ["device_type_id", "lifecycle_state", "operational_state"] as const) {
      const filterValue = context[key];
      if (filterValue) params.set(key, filterValue);
    }
    if (kind !== "service" && context.service_vlan_id) params.set("service_vlan_id", context.service_vlan_id);
    if (kind !== "customer" && context.customer_vlan_id) params.set("customer_vlan_id", context.customer_vlan_id);
    const result = await apiFetch<{items:Array<{id:string;label:string;description?:string|null}>;total:number;page:number;page_size:number}>(
      `/devices/management/vlan-options?${params.toString()}`, {}, token,
    );
    return {
      ...result,
      items: result.items.map((item) => ({ id: item.id, label: item.label, description: item.description || undefined })),
    };
  }, [context, kind, token]);

  return <SearchableCombobox
    value={value}
    selectedOption={value ? { id: value, label: value } : null}
    onChange={(option) => onChange(option?.id || "")}
    loadPage={loadPage}
    placeholder={placeholder}
    emptyText="No eligible VLANs."
  />;
}
type RemoteAccessStatus = {
  device_id: string;
  ssh_enabled: boolean;
  ssh_port: number;
  ssh_compatibility_profile: "MODERN" | "LEGACY_SSH_RSA_DH1_CBC";
  ssh_host_key_fingerprint: string | null;
  username_reference_configured: boolean;
  password_reference_configured: boolean;
  private_key_reference_configured: boolean;
  ready: boolean;
};

type WebRemoteAccessStatus = {
  device_id: string;
  web_enabled: boolean;
  web_scheme: "HTTP" | "HTTPS";
  web_port: number | null;
  effective_web_port: number;
  web_tls_mode: "SYSTEM" | "PRIVATE_CA" | "PINNED_CERT";
  web_tls_compat_profile: "MODERN" | "LEGACY_WEAK_CERT_KEY";
  tls_ca_reference_configured: boolean;
  tls_pinned_certificate_reference_configured: boolean;
  ready: boolean;
};

export function DevicePage(props: any) {
  const selected = props.selected;
  const permissions: string[] = props.permissions || [];
  const canCreate = permissions.includes("device.create");
  const canUpdate = permissions.includes("device.update");
  const canDelete = permissions.includes("device.delete");
  const canRemoteSsh = permissions.includes("device.remote_access.ssh");
  const canRemoteWeb = permissions.includes("device.remote_access.web");
  const deviceAccess = useDeviceAccessActions({ token: props.token, permissions });
  const decommissioned = selected?.lifecycle_state === "DECOMMISSIONED";
  const canEdit = canUpdate && !decommissioned;
  const selectedTypeCode = props.types.find((type: DeviceType) => type.id === selected?.device_type_id)?.code;
  const hierarchyManagedPlacement = selectedTypeCode === "CPE" || selectedTypeCode === "ACCESS_POINT" || selectedTypeCode === "SECTOR";
  const section = props.section as "inventory" | "management";
  const setSection = props.setSection as (section:"inventory"|"management")=>void;
  const [menu, setMenu] = useState<{ device: Device; x: number; y: number } | null>(null);
  const [createValidationAttempted, setCreateValidationAttempted] = useState(false);
  const [ipValidationAttempted, setIpValidationAttempted] = useState(false);
  const [interfaceValidationAttempted, setInterfaceValidationAttempted] = useState(false);
  const [remoteStatus, setRemoteStatus] = useState<RemoteAccessStatus | null>(null);
  const [webRemoteStatus, setWebRemoteStatus] = useState<WebRemoteAccessStatus | null>(null);
  const [remoteBusy, setRemoteBusy] = useState(false);
  const [remoteMessage, setRemoteMessage] = useState("");
  const [remoteForm, setRemoteForm] = useState({
    ssh_enabled: false,
    ssh_port: "22",
    ssh_compatibility_profile: "MODERN" as "MODERN" | "LEGACY_SSH_RSA_DH1_CBC",
    ssh_host_key_fingerprint: "",
    ssh_username_reference: "",
    ssh_password_reference: "",
    ssh_private_key_reference: "",
  });
  const [webRemoteForm, setWebRemoteForm] = useState({
    web_enabled: false,
    web_scheme: "HTTPS" as "HTTP" | "HTTPS",
    web_port: "",
    web_tls_mode: "SYSTEM" as "SYSTEM" | "PRIVATE_CA" | "PINNED_CERT",
    web_tls_compat_profile: "MODERN" as "MODERN" | "LEGACY_WEAK_CERT_KEY",
    web_tls_ca_reference: "",
    web_tls_pinned_certificate_reference: "",
  });
  useEffect(() => { setCreateValidationAttempted(false); setIpValidationAttempted(false); setInterfaceValidationAttempted(false); }, [selected?.id, section]);
  useEffect(() => { setIpValidationAttempted(false); }, [props.ips.length]);
  useEffect(() => { setInterfaceValidationAttempted(false); }, [props.interfaces.length]);
  const loadRemoteStatus = useCallback(async (deviceId: string) => {
    if (!canRemoteSsh) {
      setRemoteStatus(null);
      return;
    }
    try {
      const status = await apiFetch<RemoteAccessStatus>(`/devices/${deviceId}/remote-access`, {}, props.token);
      setRemoteStatus(status);
      setRemoteForm((current) => ({
        ...current,
        ssh_enabled: status.ssh_enabled,
        ssh_port: String(status.ssh_port || 22),
        ssh_compatibility_profile: status.ssh_compatibility_profile || "MODERN",
        ssh_host_key_fingerprint: status.ssh_host_key_fingerprint || "",
        ssh_username_reference: "",
        ssh_password_reference: "",
        ssh_private_key_reference: "",
      }));
      setRemoteMessage("");
    } catch (error) {
      setRemoteStatus(null);
      setRemoteMessage(error instanceof Error ? error.message : "Unable to load remote-access status.");
    }
  }, [canRemoteSsh, props.token]);

  const loadWebRemoteStatus = useCallback(async (deviceId: string) => {
    if (!canRemoteWeb) {
      setWebRemoteStatus(null);
      return;
    }
    try {
      const status = await apiFetch<WebRemoteAccessStatus>(`/devices/${deviceId}/remote-access/web`, {}, props.token);
      setWebRemoteStatus(status);
      setWebRemoteForm((current) => ({
        ...current,
        web_enabled: status.web_enabled,
        web_scheme: status.web_scheme || "HTTPS",
        web_port: status.web_port == null ? "" : String(status.web_port),
        web_tls_mode: status.web_tls_mode || "SYSTEM",
        web_tls_compat_profile: status.web_tls_compat_profile || "MODERN",
        web_tls_ca_reference: "",
        web_tls_pinned_certificate_reference: "",
      }));
      setRemoteMessage("");
    } catch (error) {
      setWebRemoteStatus(null);
      setRemoteMessage(error instanceof Error ? error.message : "Unable to load Web-GUI proxy status.");
    }
  }, [canRemoteWeb, props.token]);

  useEffect(() => {
    if (selected?.id && canRemoteSsh) void loadRemoteStatus(selected.id);
    else setRemoteStatus(null);
  }, [selected?.id, canRemoteSsh, loadRemoteStatus]);
  useEffect(() => {
    if (selected?.id && canRemoteWeb) void loadWebRemoteStatus(selected.id);
    else setWebRemoteStatus(null);
  }, [selected?.id, canRemoteWeb, loadWebRemoteStatus]);

  const saveRemoteAccess = async () => {
    if (!selected || !canRemoteSsh || !canUpdate) return;
    setRemoteBusy(true);
    setRemoteMessage("");
    try {
      const remote_access: Record<string, unknown> = {
        ssh_enabled: remoteForm.ssh_enabled,
        ssh_port: Number(remoteForm.ssh_port || "22"),
        ssh_compatibility_profile: remoteForm.ssh_compatibility_profile,
        ssh_host_key_fingerprint: remoteForm.ssh_host_key_fingerprint.trim() || null,
      };
      if (remoteForm.ssh_username_reference.trim()) remote_access.ssh_username_reference = remoteForm.ssh_username_reference.trim();
      if (remoteForm.ssh_password_reference.trim()) remote_access.ssh_password_reference = remoteForm.ssh_password_reference.trim();
      if (remoteForm.ssh_private_key_reference.trim()) remote_access.ssh_private_key_reference = remoteForm.ssh_private_key_reference.trim();
      await apiFetch(`/devices/${selected.id}`, {
        method: "PATCH",
        body: JSON.stringify({ remote_access }),
      }, props.token);
      await loadRemoteStatus(selected.id);
      notifyDeviceAccessChanged(selected.id);
      setRemoteMessage("SSH remote-access settings saved.");
    } catch (error) {
      setRemoteMessage(error instanceof Error ? error.message : "Unable to save remote-access settings.");
    } finally {
      setRemoteBusy(false);
    }
  };

  const saveWebRemoteAccess = async () => {
    if (!selected || !canRemoteWeb || !canUpdate) return;
    setRemoteBusy(true);
    setRemoteMessage("");
    try {
      const portText = webRemoteForm.web_port.trim();
      const port = portText === "" ? null : Number(portText);
      if (port !== null && (!Number.isInteger(port) || port < 1 || port > 65535)) {
        setRemoteMessage("Web GUI port must be blank or an integer between 1 and 65535.");
        return;
      }
      const remote_access: Record<string, unknown> = {
        web_enabled: webRemoteForm.web_enabled,
        web_scheme: webRemoteForm.web_scheme,
        web_port: port,
        web_tls_mode: webRemoteForm.web_scheme === "HTTP" ? "SYSTEM" : webRemoteForm.web_tls_mode,
        web_tls_compat_profile: webRemoteForm.web_scheme === "HTTP" ? "MODERN" : webRemoteForm.web_tls_compat_profile,
      };
      if (webRemoteForm.web_tls_ca_reference.trim()) remote_access.web_tls_ca_reference = webRemoteForm.web_tls_ca_reference.trim();
      if (webRemoteForm.web_tls_pinned_certificate_reference.trim()) remote_access.web_tls_pinned_certificate_reference = webRemoteForm.web_tls_pinned_certificate_reference.trim();
      await apiFetch(`/devices/${selected.id}`, { method: "PATCH", body: JSON.stringify({ remote_access }) }, props.token);
      await loadWebRemoteStatus(selected.id);
      notifyDeviceAccessChanged(selected.id);
      setRemoteMessage("Native Web-GUI proxy settings saved.");
    } catch (error) {
      setRemoteMessage(error instanceof Error ? error.message : "Unable to save Web-GUI proxy settings.");
    } finally {
      setRemoteBusy(false);
    }
  };

  const rows = props.devices as Device[];
  const menuDevice = menu?.device;
  const menuRemoteItems = menuDevice ? deviceAccess.menuItems(menuDevice) : [];
  const menuItems = menuDevice ? [
    ...menuRemoteItems,
    {
      id: "copy-management-ip",
      label: "Copy management IP",
      disabled: !menuDevice.management_ip,
      onClick: () => copyToClipboard(menuDevice.management_ip || ""),
    },
    {
      id: "test-accessibility",
      label: "Test accessibility",
      disabled: !menuDevice.management_ip,
      onClick: () => props.onTestAccessibility(menuDevice.id),
    },
    {
      id: "open-details",
      label: "Open details",
      onClick: () => props.onSelect(menuDevice),
    },
  ] : [];

  return (
    <PageLayout className="device-page">
      <div className="page-heading"><div><h2 className="hover-help-title" data-help="Inspect individual devices or manage filtered selections in batches.">Devices</h2></div></div>
      <Tabs<"inventory" | "management"> ariaLabel="Device workspace views" value={section} onChange={setSection} tabs={[{ id: "inventory", label: "Inventory & Details" }, { id: "management", label: "Device Management" }]} />
      {section === "management" ? <DeviceManagementPanel
        token={props.token}
        rows={props.managementRows || []}
        filters={props.managementFilters}
        setFilters={props.setManagementFilters}
        networks={props.creationNetworks || props.networks || []}
        cities={props.creationCities || []}
        locations={props.creationLocations || []}
        groups={props.groups || []}
        types={props.types || []}
        permissions={permissions}
        busy={props.busy}
        total={props.managementTotal}
        page={props.managementPage}
        pageSize={props.managementPageSize}
        sort={props.managementSort}
        setPage={props.setManagementPage}
        setPageSize={props.setManagementPageSize}
        setSort={props.setManagementSort}
        onReload={props.onReloadManagement}
      /> : <div className="device-layout">
        <section className="panel inventory-panel">
          <div className="panel-header"><div><h3>Inventory</h3><span>{props.deviceTotal} device(s)</span></div><div className="table-toolbar-actions"><TableExportButton token={props.token} tableId="device_inventory" filters={{search:props.search,device_type_id:props.deviceType,lifecycle_state:props.lifecycle,operational_state:props.operational,service_vlan_id:props.inventoryServiceVlan,customer_vlan_id:props.inventoryCustomerVlan,sort_by:props.deviceSort.key,sort_direction:props.deviceSort.direction}} />{canCreate && <Button unstyled className="secondary small" onClick={props.onNew}>New device</Button>}</div></div>
          <div className="filter-row compact">
            <Input unstyled value={props.search} onChange={(e) => { props.setSearch(e.target.value); props.setDevicePage(1); }} placeholder="Search name, hostname, IP, serial..." />
            <Select unstyled value={props.deviceType} onChange={(e) => { props.setDeviceType(e.target.value); props.setInventoryCustomerVlan(""); props.setDevicePage(1); }}><option value="">All device types</option>{props.types.map((t: DeviceType) => <option key={t.id} value={t.id}>{t.name}</option>)}</Select>
            <InventoryVlanFilterCombobox token={props.token} kind="service" value={props.inventoryServiceVlan} onChange={(value) => { props.setInventoryServiceVlan(value); props.setInventoryCustomerVlan(""); props.setDevicePage(1); }} context={{search:props.search,device_type_id:props.deviceType,lifecycle_state:props.lifecycle,operational_state:props.operational,service_vlan_id:props.inventoryServiceVlan,customer_vlan_id:props.inventoryCustomerVlan}} placeholder="All S-VLANs / search..." />
            <InventoryVlanFilterCombobox token={props.token} kind="customer" value={props.inventoryCustomerVlan} onChange={(value) => { props.setInventoryCustomerVlan(value); props.setDevicePage(1); }} context={{search:props.search,device_type_id:props.deviceType,lifecycle_state:props.lifecycle,operational_state:props.operational,service_vlan_id:props.inventoryServiceVlan,customer_vlan_id:props.inventoryCustomerVlan}} placeholder="All C-VLANs / search..." />
            <Select unstyled value={props.lifecycle} onChange={(e) => { props.setLifecycle(e.target.value); props.setDevicePage(1); }}><option value="">All lifecycle</option><option>REGISTERED</option><option>ACTIVE</option><option>MAINTENANCE</option><option>DECOMMISSIONED</option></Select>
            <Select unstyled value={props.operational} onChange={(e) => { props.setOperational(e.target.value); props.setDevicePage(1); }}><option value="">All operational</option><option>UNKNOWN</option><option>UP</option><option>DOWN</option><option>DEGRADED</option></Select>
            <ClearFiltersButton disabled={!props.search&&!props.deviceType&&!props.inventoryServiceVlan&&!props.inventoryCustomerVlan&&!props.lifecycle&&!props.operational} onClick={()=>{props.setSearch("");props.setDeviceType("");props.setInventoryServiceVlan("");props.setInventoryCustomerVlan("");props.setLifecycle("");props.setOperational("");props.setDevicePage(1)}}/>
          </div>
          <DataTable viewportClassName="table-wrap" className="clickable-table"><thead><tr><SortHeader label="Name" sortKey="display_name" sort={props.deviceSort} onSort={(key) => props.setDeviceSort((current:SortState) => nextSort(current, key))} /><SortHeader label="Type" sortKey="type" sort={props.deviceSort} onSort={(key) => props.setDeviceSort((current:SortState) => nextSort(current, key))} /><SortHeader label="IP address" sortKey="management_ip" sort={props.deviceSort} onSort={(key) => props.setDeviceSort((current:SortState) => nextSort(current, key))} /><SortHeader label="S-VLAN" sortKey="service_vlan_id" sort={props.deviceSort} onSort={(key) => props.setDeviceSort((current:SortState) => nextSort(current, key))} /><SortHeader label="C-VLAN" sortKey="customer_vlan_id" sort={props.deviceSort} onSort={(key) => props.setDeviceSort((current:SortState) => nextSort(current, key))} /><SortHeader label="Lifecycle" sortKey="lifecycle_state" sort={props.deviceSort} onSort={(key) => props.setDeviceSort((current:SortState) => nextSort(current, key))} /><SortHeader label="Operational" sortKey="operational_state" sort={props.deviceSort} onSort={(key) => props.setDeviceSort((current:SortState) => nextSort(current, key))} /><SortHeader label="Vendor" sortKey="vendor" sort={props.deviceSort} onSort={(key) => props.setDeviceSort((current:SortState) => nextSort(current, key))} /></tr></thead><tbody>{rows.map((device: Device) => <tr key={device.id} className={selected?.id === device.id ? "selected-row" : ""} onClick={() => { props.onSelect(device); void deviceAccess.prefetch(device.id); }} onPointerEnter={() => void deviceAccess.prefetch(device.id)} onPointerDown={() => void deviceAccess.prefetch(device.id)} onDoubleClick={() => deviceAccess.openSecureWebIfAvailable(device)} onContextMenu={(event) => { event.preventDefault(); event.stopPropagation(); void deviceAccess.prefetch(device.id); setMenu({ device, x: event.clientX, y: event.clientY }); }}><td>{device.display_name}</td><td>{props.types.find((t: DeviceType) => t.id === device.device_type_id)?.name || device.device_type_id}</td><td className="mono">{device.management_ip || "-"}</td><td>{device.service_vlan_id ?? "—"}</td><td>{device.customer_vlan_display || "—"}</td><td><Badge value={device.lifecycle_state} /></td><td><Badge value={device.operational_state} /></td><td>{device.vendor || "-"}</td></tr>)}<ServerPaginationRow colSpan={8} page={props.devicePage} pageSize={props.devicePageSize} total={props.deviceTotal} onPage={props.setDevicePage} onPageSize={(size)=>{props.setDevicePageSize(size);props.setDevicePage(1)}} itemLabel="devices" /></tbody></DataTable>{props.devices.length === 0 && <EmptyState text="No devices found." />}
          <ContextMenuSurface
            anchor={menu ? { x: menu.x, y: menu.y } : null}
            items={menuItems}
            onClose={() => setMenu(null)}
            ariaLabel={menuDevice ? `Device actions for ${menuDevice.display_name}` : "Device actions"}
          />
        </section>
        <section className={`panel${!selected && createValidationAttempted ? " validation-attempted" : ""}`}>{!selected ? (canCreate ? <><div className="panel-header"><div><h3 className="hover-help-title" data-help="Register a device directly into inventory.">Create device</h3></div></div><DeviceForm {...props} creationMode networks={props.creationNetworks || []} cities={props.creationCities || []} locations={props.creationLocations || []} sectors={props.creationSectors || []} /><div className="button-row"><Button unstyled onClick={() => { setCreateValidationAttempted(true); props.onCreate(); }} disabled={props.busy}>Create Device</Button></div></> : <EmptyState text="Select a device to view its details." />) : <><div className="panel-header"><div><h3>{selected.display_name}</h3></div><Badge value={selected.lifecycle_state} /></div><DeviceForm {...props} /><DeviceAccessActions token={props.token} device={selected} permissions={permissions} /><div className="button-row">{canEdit && <Button unstyled onClick={props.onUpdate} disabled={props.busy}>Save Changes</Button>}{canEdit && <Button unstyled className="secondary" onClick={props.onDecommission} disabled={props.busy}>Decommission</Button>}{canUpdate && decommissioned && <Button unstyled onClick={props.onReactivate} disabled={props.busy}>Reactivate</Button>}{canDelete && decommissioned && <Button unstyled className="danger" onClick={props.onDelete} disabled={props.busy}>Move to Recycle Bin</Button>}</div>
          {canRemoteSsh && <div className="panel-subsection">
            <h4>Brokered remote access</h4>
            <p className="field-help">
              Web SSH is brokered through the dedicated FTTW access gateway. Credential values remain gateway-side; FTTW stores only env:// references and a pinned SSH host-key fingerprint.
            </p>
            {remoteMessage && <div className="inline-status-message">{remoteMessage}</div>}
            <div className="inline-form">
              <label className="check-item">
                <Input unstyled type="checkbox" checked={remoteForm.ssh_enabled} disabled={!canUpdate || remoteBusy}
                  onChange={(e) => setRemoteForm({...remoteForm, ssh_enabled:e.target.checked})}/>
                SSH enabled
              </label>
              <Input unstyled type="number" min="1" max="65535" aria-label="SSH port" placeholder="SSH port"
                value={remoteForm.ssh_port} disabled={!canUpdate || remoteBusy}
                onChange={(e)=>setRemoteForm({...remoteForm,ssh_port:e.target.value})}/>
              <Select unstyled aria-label="SSH compatibility profile"
                value={remoteForm.ssh_compatibility_profile} disabled={!canUpdate || remoteBusy}
                onChange={(e)=>setRemoteForm({...remoteForm,ssh_compatibility_profile:e.target.value as "MODERN" | "LEGACY_SSH_RSA_DH1_CBC"})}>
                <option value="MODERN">Modern SSH (recommended)</option>
                <option value="LEGACY_SSH_RSA_DH1_CBC">Legacy RSA / DH1 / AES128-CBC (weak)</option>
              </Select>
              <Input unstyled aria-label="SSH host-key fingerprint" placeholder="SHA256: pinned host-key fingerprint"
                value={remoteForm.ssh_host_key_fingerprint} disabled={!canUpdate || remoteBusy}
                onChange={(e)=>setRemoteForm({...remoteForm,ssh_host_key_fingerprint:e.target.value})}/>
            </div>
            {canUpdate && <div className="inline-form">
              <Input unstyled aria-label="SSH username reference" placeholder={remoteStatus?.username_reference_configured ? "Username env:// reference configured — leave blank to keep" : "env://SSH_USERNAME"}
                value={remoteForm.ssh_username_reference} disabled={remoteBusy}
                onChange={(e)=>setRemoteForm({...remoteForm,ssh_username_reference:e.target.value})}/>
              <Input unstyled aria-label="SSH password reference" placeholder={remoteStatus?.password_reference_configured ? "Password env:// reference configured — leave blank to keep" : "env://SSH_PASSWORD"}
                value={remoteForm.ssh_password_reference} disabled={remoteBusy}
                onChange={(e)=>setRemoteForm({...remoteForm,ssh_password_reference:e.target.value})}/>
              <Input unstyled aria-label="SSH private key reference" placeholder={remoteStatus?.private_key_reference_configured ? "Private-key env:// reference configured — leave blank to keep" : "env://SSH_PRIVATE_KEY"}
                value={remoteForm.ssh_private_key_reference} disabled={remoteBusy}
                onChange={(e)=>setRemoteForm({...remoteForm,ssh_private_key_reference:e.target.value})}/>
              <Button unstyled className="secondary" onClick={()=>void saveRemoteAccess()} disabled={remoteBusy}>Save SSH settings</Button>
            </div>}
            <div className="field-help">
              Status: {remoteStatus?.ready ? "Ready" : "Not configured"}.
              {remoteStatus?.ready ? " A one-time launch ticket will be required for every terminal session." : ""}
              {remoteForm.ssh_compatibility_profile === "LEGACY_SSH_RSA_DH1_CBC"
                ? " Legacy mode enables weak SSH algorithms only for this device; upgrade the device SSH stack when possible."
                : ""}
            </div>
          </div>}
          {canRemoteWeb && <div className="panel-subsection">
            <h4>Native Web-GUI proxy</h4>
            <p className="field-help">
              The device's real GUI is proxied through the isolated access-gateway browser origin. Device destinations are resolved server-side; vendor cookies and TLS trust material remain gateway-side.
            </p>
            {remoteMessage && !canRemoteSsh && <div className="inline-status-message">{remoteMessage}</div>}
            <div className="inline-form">
              <label className="check-item">
                <Input unstyled type="checkbox" checked={webRemoteForm.web_enabled} disabled={!canUpdate || remoteBusy}
                  onChange={(e) => setWebRemoteForm({...webRemoteForm,web_enabled:e.target.checked})}/>
                Web GUI enabled
              </label>
              <Select unstyled aria-label="Web GUI scheme" value={webRemoteForm.web_scheme} disabled={!canUpdate || remoteBusy}
                onChange={(e)=>{const scheme=e.target.value as "HTTP"|"HTTPS";setWebRemoteForm({...webRemoteForm,web_scheme:scheme,web_tls_mode:scheme==="HTTP"?"SYSTEM":webRemoteForm.web_tls_mode,web_tls_compat_profile:scheme==="HTTP"?"MODERN":webRemoteForm.web_tls_compat_profile})}}>
                <option value="HTTPS">HTTPS</option><option value="HTTP">HTTP compatibility</option>
              </Select>
              <Input unstyled type="number" min="1" max="65535" step="1" aria-label="Web GUI port" placeholder={webRemoteForm.web_scheme==="HTTP"?"Default: 80":"Default: 443"}
                value={webRemoteForm.web_port} disabled={!canUpdate || remoteBusy}
                onChange={(e)=>setWebRemoteForm({...webRemoteForm,web_port:e.target.value})}/>
              <Select unstyled aria-label="Web GUI TLS trust mode" value={webRemoteForm.web_tls_mode}
                disabled={!canUpdate || remoteBusy || webRemoteForm.web_scheme==="HTTP"}
                onChange={(e)=>{const mode=e.target.value as "SYSTEM"|"PRIVATE_CA"|"PINNED_CERT";setWebRemoteForm({...webRemoteForm,web_tls_mode:mode,web_tls_compat_profile:mode==="PINNED_CERT"?webRemoteForm.web_tls_compat_profile:"MODERN"})}}>
                <option value="SYSTEM">System trust</option>
                <option value="PRIVATE_CA">Private CA</option>
                <option value="PINNED_CERT">Pinned certificate</option>
              </Select>
              <Select unstyled aria-label="Web GUI TLS compatibility profile" value={webRemoteForm.web_tls_compat_profile}
                disabled={!canUpdate || remoteBusy || webRemoteForm.web_scheme==="HTTP" || webRemoteForm.web_tls_mode!=="PINNED_CERT"}
                onChange={(e)=>setWebRemoteForm({...webRemoteForm,web_tls_compat_profile:e.target.value as "MODERN"|"LEGACY_WEAK_CERT_KEY"})}>
                <option value="MODERN">Modern TLS</option>
                <option value="LEGACY_WEAK_CERT_KEY">Legacy weak certificate key (pinned only)</option>
              </Select>
            </div>
            {canUpdate && webRemoteForm.web_scheme==="HTTPS" && <div className="inline-form">
              {webRemoteForm.web_tls_mode==="PRIVATE_CA" && <Input unstyled aria-label="Private CA reference"
                placeholder={webRemoteStatus?.tls_ca_reference_configured?"Private CA env:// reference configured — leave blank to keep":"env://DEVICE_WEB_CA_PEM"}
                value={webRemoteForm.web_tls_ca_reference} disabled={remoteBusy}
                onChange={(e)=>setWebRemoteForm({...webRemoteForm,web_tls_ca_reference:e.target.value})}/>}
              {webRemoteForm.web_tls_mode==="PINNED_CERT" && <Input unstyled aria-label="Pinned certificate reference"
                placeholder={webRemoteStatus?.tls_pinned_certificate_reference_configured?"Pinned certificate env:// reference configured — leave blank to keep":"env://DEVICE_WEB_CERT_PEM"}
                value={webRemoteForm.web_tls_pinned_certificate_reference} disabled={remoteBusy}
                onChange={(e)=>setWebRemoteForm({...webRemoteForm,web_tls_pinned_certificate_reference:e.target.value})}/>}
              <Button unstyled className="secondary" onClick={()=>void saveWebRemoteAccess()} disabled={remoteBusy}>Save Web GUI settings</Button>
            </div>}
            {canUpdate && webRemoteForm.web_scheme==="HTTP" && <div className="inline-form"><Button unstyled className="secondary" onClick={()=>void saveWebRemoteAccess()} disabled={remoteBusy}>Save Web GUI settings</Button></div>}
            <div className="field-help">Status: {webRemoteStatus?.ready?"Ready":"Not configured"}. Leave the port blank for {webRemoteForm.web_scheme==="HTTP"?"HTTP 80":"HTTPS 443"}. HTTP is never selected as an automatic HTTPS fallback.{webRemoteForm.web_tls_compat_profile==="LEGACY_WEAK_CERT_KEY" ? " Legacy certificate compatibility lowers the OpenSSL security level only for this device and only with its exact pinned certificate." : ""}</div>
          </div>}
          <div className="panel-subsection"><h4>IP addresses</h4>{canEdit && <div className={`inline-form${ipValidationAttempted ? " validation-attempted" : ""}`}><label className="inline-required-control"><span className="required-field-label">IPv4 address</span><Input unstyled required pattern="(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}" title="Enter a valid IPv4 address, for example 192.168.1.10." placeholder="IPv4 address" inputMode="decimal" value={props.ipForm.ip_address} onChange={(e) => props.setIpForm({ ...props.ipForm, ip_address: e.target.value })} /></label><label className="check-item"><Input unstyled type="checkbox" checked={props.ipForm.is_management} onChange={(e) => props.setIpForm({ ...props.ipForm, is_management: e.target.checked })} /> Management</label><label className="check-item"><Input unstyled type="checkbox" checked={props.ipForm.is_primary} onChange={(e) => props.setIpForm({ ...props.ipForm, is_primary: e.target.checked })} /> Primary</label><Button unstyled onClick={() => { setIpValidationAttempted(true); props.onAddIp(); }} disabled={props.busy}>Add IP</Button></div>}{props.ips.length === 0 ? <EmptyState text="No IP addresses." /> : <SortableDeviceIPs token={props.token} deviceId={selected.id} ips={props.ips} onUpdate={canEdit ? props.onUpdateIp : undefined} onDelete={canDelete ? props.onDeleteIp : undefined} />}</div>
          <div className="panel-subsection"><h4>Interfaces</h4>{canEdit && <div className={`inline-form${interfaceValidationAttempted ? " validation-attempted" : ""}`}><label className="inline-required-control"><span className="required-field-label">Interface name</span><Input unstyled required placeholder="Interface name" value={props.interfaceForm.interface_name} onChange={(e) => props.setInterfaceForm({ ...props.interfaceForm, interface_name: e.target.value })} /></label><Input unstyled placeholder="Index" value={props.interfaceForm.interface_index} onChange={(e) => props.setInterfaceForm({ ...props.interfaceForm, interface_index: e.target.value })} /><Button unstyled onClick={() => { setInterfaceValidationAttempted(true); props.onAddInterface(); }} disabled={props.busy}>Add Interface</Button></div>}{props.interfaces.length === 0 ? <EmptyState text="No interfaces." /> : <SortableInterfaces token={props.token} deviceId={selected.id} items={props.interfaces} onDelete={canDelete ? props.onDeleteInterface : undefined} />}</div>
        </>}</section>
      </div>}
    </PageLayout>
  );
}
