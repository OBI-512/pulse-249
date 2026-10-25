import { useEffect, useState } from "react";
import { Input, Select, Textarea } from "../../design-system/primitives";
import type { DeviceManagementRow, DeviceType } from "../../types";
import { CandidatePlacementSearchSelect, type CandidatePlacementOption } from "../common/CandidatePlacementSearchSelect";
import { ParentDeviceSearchSelect } from "../common/ParentDeviceSearchSelect";
import { DeviceAccessTemplatesPanel } from "./DeviceAccessTemplatesPanel";

const LOCATION_TYPES = new Set(["SWITCH", "ROUTER", "FIREWALL", "SERVER", "WIRELESS_BRIDGE", "NETWORK_DEVICE", "OTHER"]);

export function DeviceForm(props: any) {
  const type = props.types.find((t: DeviceType) => t.id === props.form.device_type_id)?.code || "";
  const selected = props.selected;
  const editing = Boolean(selected && !props.creationMode);
  const permissions: string[] = props.permissions || [];
  const canConfigure = props.creationMode ? permissions.includes("device.create") : permissions.includes("device.update");
  const decommissioned = selected?.lifecycle_state === "DECOMMISSIONED";
  const disabled = props.busy || decommissioned || !canConfigure;
  const isSector = type === "SECTOR";
  const isCpe = type === "CPE";
  const isAp = type === "ACCESS_POINT";
  const isLocationDevice = LOCATION_TYPES.has(type);
  const canMovePlacement = !editing || (
    (isSector && permissions.includes("physical_movement.sector")) ||
    (isCpe && permissions.includes("physical_movement.cpe")) ||
    (isAp && permissions.includes("physical_movement.access_point")) ||
    (isLocationDevice && permissions.includes("placement.update"))
  );
  const placementDisabled = disabled || !canMovePlacement;
  const sectorTypeId = props.types.find((t: DeviceType) => t.code === "SECTOR")?.id || "";
  const cpeTypeId = props.types.find((t: DeviceType) => t.code === "CPE")?.id || "";
  const [selectedParent, setSelectedParent] = useState<DeviceManagementRow | null>(null);
  const [selectedPlacement, setSelectedPlacement] = useState<CandidatePlacementOption | null>(null);

  useEffect(() => {
    setSelectedParent(null);
    setSelectedPlacement(null);
  }, [selected?.id, props.form.device_type_id]);

  const context = props.domainContext as DeviceManagementRow | null;
  const networkName = selectedParent?.network_name || selectedPlacement?.network_name || context?.network_name || "—";
  const cityName = selectedParent?.city_name || selectedPlacement?.city_name || context?.city_name || "—";
  const locationName = selectedParent?.location_name || selectedPlacement?.location_name || context?.location_name || "—";
  const sectorName = selectedParent?.sector_name || selectedPlacement?.sector_name || context?.sector_name || (isLocationDevice ? "Not applicable" : "—");
  const parentName = selectedParent?.display_name || context?.parent_device_name || "—";
  const physicalSectorName = selectedParent?.physical_sector_device_name || context?.physical_sector_device_name || (isCpe ? parentName : "—");

  const changeType = (value: string) => {
    props.setForm({ ...props.form, device_type_id: value, location_id: "", sector_id: "", parent_device_id: "" });
    setSelectedParent(null);
    setSelectedPlacement(null);
  };

  const choosePlacement = (option: CandidatePlacementOption | null) => {
    setSelectedPlacement(option);
    setSelectedParent(null);
    props.setForm({
      ...props.form,
      location_id: isLocationDevice ? (option?.location_id || "") : "",
      sector_id: isSector ? (option?.sector_id || option?.id || "") : "",
      parent_device_id: "",
    });
  };

  const chooseParent = (row: DeviceManagementRow | null) => {
    setSelectedParent(row);
    setSelectedPlacement(null);
    props.setForm({ ...props.form, parent_device_id: row?.id || "", location_id: "", sector_id: "" });
  };

  return (
    <>
      <fieldset disabled={disabled}>
        {decommissioned && <div className="review-guidance">This device is decommissioned and read-only. Reactivate it before making changes.</div>}
        {!decommissioned && !canConfigure && <div className="review-guidance">Your account has read-only access to this device.</div>}
        {editing && canConfigure && !canMovePlacement && <div className="review-guidance">You can edit this device, but you cannot change its location or parent assignment.</div>}
        <div className="form-grid two">
          <label><span className="required-field-label">Display name</span><Input unstyled required value={props.form.display_name} onChange={(e) => props.setForm({ ...props.form, display_name: e.target.value })} /></label>
          <label><span className={`required-field-label${!props.creationMode ? " hover-help-title" : ""}`} data-help={!props.creationMode ? "Manage this address from the IP Addresses section." : undefined}>Management IPv4</span><Input unstyled required pattern="(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}" title="Enter a valid IPv4 address, for example 192.168.1.10." value={props.form.management_ip} readOnly={!props.creationMode} aria-readonly={!props.creationMode} inputMode="decimal" placeholder="192.168.1.10" onChange={(e) => props.setForm({ ...props.form, management_ip: e.target.value })} /></label>
          <label><span className={`required-field-label${editing ? " hover-help-title" : ""}`} data-help={editing ? "Device type cannot be changed after registration." : undefined}>Device type</span>
            <Select unstyled required value={props.form.device_type_id} onChange={(e) => changeType(e.target.value)} disabled={disabled || editing}>
              <option value="">Select type</option>{props.types.map((t: DeviceType) => <option key={t.id} value={t.id}>{t.name}</option>)}
            </Select>
          </label>
        </div>

        {isLocationDevice && <div className="review-placement-card"><strong className="required-field-label">Location</strong><CandidatePlacementSearchSelect required token={props.token} kind="locations" value={props.form.location_id} selectedLabel={context?.location_name} onChange={choosePlacement} disabled={placementDisabled} placeholder="Search active location, city or network..." /></div>}
        {isSector && <div className="review-placement-card"><strong className="required-field-label">Logical Sector</strong><CandidatePlacementSearchSelect required token={props.token} kind="logical-sectors" value={props.form.sector_id} selectedLabel={context?.sector_name} onChange={choosePlacement} disabled={placementDisabled} placeholder="Search free logical sectors..." currentSectorDeviceId={editing ? selected?.id : undefined} /></div>}
        {isCpe && <div className="review-placement-card"><strong className="required-field-label">Parent SECTOR device</strong><ParentDeviceSearchSelect required token={props.token} value={props.form.parent_device_id} selectedLabel={context?.parent_device_name || context?.physical_sector_device_name} deviceTypeId={sectorTypeId} sectorRole="CUSTOMER_ACCESS" onChange={chooseParent} disabled={placementDisabled} placeholder="Search customer-access SECTOR name or IP..." /></div>}
        {isAp && <div className="review-placement-card"><strong className="required-field-label">Parent CPE</strong><ParentDeviceSearchSelect required token={props.token} value={props.form.parent_device_id} selectedLabel={context?.parent_device_name} deviceTypeId={cpeTypeId} requireAvailableApParent currentChildDeviceId={editing ? selected?.id : undefined} onChange={chooseParent} disabled={placementDisabled} placeholder="Search eligible CPE name or IP..." /></div>}

        {type && <div className="derived-context"><div><span>Network</span><strong>{networkName}</strong></div><div><span>City</span><strong>{cityName}</strong></div><div><span>Location</span><strong>{locationName}</strong></div><div><span>Sector</span><strong>{sectorName}</strong></div>{(isCpe || isAp) && <div><span>Physical SECTOR</span><strong>{physicalSectorName}</strong></div>}{isAp && <div><span>Parent CPE</span><strong>{parentName}</strong></div>}{editing && (isSector || isCpe || isAp) && <div><span>Service VLAN</span><strong>{context?.service_vlan_id ?? "—"}</strong></div>}{editing && isSector && <div><span>Customer VLAN Range</span><strong>{context?.customer_vlan_start != null && context?.customer_vlan_end != null ? `${context.customer_vlan_start}-${context.customer_vlan_end}` : "—"}</strong></div>}{editing && (isCpe || isAp) && <div><span>Customer VLAN</span><strong>{context?.customer_vlan_id ?? "—"}</strong></div>}{editing && (isCpe || isAp) && <div><span>Customer</span><strong>{context?.customer_name || "Unassigned"}</strong></div>}</div>}

        <div className="form-grid three"><label>Hostname<Input unstyled value={props.form.hostname} onChange={(e) => props.setForm({ ...props.form, hostname: e.target.value })} /></label><label>Vendor<Input unstyled value={props.form.vendor} onChange={(e) => props.setForm({ ...props.form, vendor: e.target.value })} /></label><label>Model<Input unstyled value={props.form.model} onChange={(e) => props.setForm({ ...props.form, model: e.target.value })} /></label></div>
        <div className="form-grid three"><label>Serial number<Input unstyled value={props.form.serial_number} onChange={(e) => props.setForm({ ...props.form, serial_number: e.target.value })} /></label><label>Management protocol<Input unstyled value={props.form.management_protocol} onChange={(e) => props.setForm({ ...props.form, management_protocol: e.target.value })} /></label><label>Credential reference<Input unstyled value={props.form.credential_reference} onChange={(e) => props.setForm({ ...props.form, credential_reference: e.target.value })} /></label></div>
        <label>Description<Textarea unstyled rows={3} value={props.form.description} onChange={(e) => props.setForm({ ...props.form, description: e.target.value })} /></label>
        <div className="form-grid two"><label>Lifecycle<Select unstyled value={props.form.lifecycle_state} onChange={(e) => props.setForm({ ...props.form, lifecycle_state: e.target.value })}>{decommissioned && <option>DECOMMISSIONED</option>}<option>REGISTERED</option><option>ACTIVE</option><option>MAINTENANCE</option></Select></label><label><span className="hover-help-title" data-help="UP, DOWN and UNKNOWN are synchronized automatically from server-authoritative availability. DEGRADED is a manual override while the device is online.">Operational (availability)</span><Input unstyled value={props.form.operational_state || "UNKNOWN"} readOnly aria-readonly="true" /></label></div>
        {editing && <label className="check-item"><Input unstyled type="checkbox" checked={Boolean(props.form.manual_degraded_override)} onChange={(e) => props.setForm({ ...props.form, manual_degraded_override:e.target.checked })} /> Manual DEGRADED override</label>}
      </fieldset>
      {editing && permissions.includes("access_template.read") && <DeviceAccessTemplatesPanel token={props.token} device={selected} permissions={permissions} />}
    </>
  );
}
