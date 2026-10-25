import { PageLayout } from "../design-system/layouts";
import { useState, type Dispatch, type SetStateAction } from "react";
import type { AuditEntry, Candidate, City, DeviceManagementRow, DeviceType, Location, Network, Sector, SortState } from "../types";
import { confidence, formatDate } from "../utils/formatting";
import { EmptyState } from "../design-system/composites/AsyncState";
import { StatusBadge as Badge } from "../design-system/composites/Status";
import { ParentDeviceSearchSelect } from "../components/common/ParentDeviceSearchSelect";
import { CandidatePlacementSearchSelect, type CandidatePlacementOption } from "../components/common/CandidatePlacementSearchSelect";
import { nextSort } from "../utils/sorting";
import { STATES } from "../constants";

import { Button, Input, Select, Textarea } from "../design-system/primitives";
import { DataTable } from "../design-system/data/DataTable";
import { PaginatedCollection, ServerPaginationRow } from "../design-system/data/Pagination";
import { SortHeader } from "../design-system/data/SortHeader";
import { TableExportButton } from "../design-system/data/TableExport";
import { ClearFiltersButton } from "../design-system/composites/FilterBar";
const LOCATION_TYPES = new Set(["SWITCH", "ROUTER", "FIREWALL", "SERVER", "WIRELESS_BRIDGE", "NETWORK_DEVICE", "OTHER"]);

type CandidatePageProps = {
  token: string;
  selected: Candidate | null;
  candidates: Candidate[];
  count: number;
  page: number;
  pageSize: number;
  setPage: (page: number) => void;
  setPageSize: (size: number) => void;
  sort: SortState;
  setSort: Dispatch<SetStateAction<SortState>>;
  filter: string;
  setFilter: (value: string) => void;
  search: string;
  setSearch: (value: string) => void;
  typeFilter: string;
  setTypeFilter: (value: string) => void;
  types: DeviceType[];
  networks: Network[];
  cities: City[];
  locations: Location[];
  sectors: Sector[];
  ip: string;
  setIp: (value: string) => void;
  name: string;
  setName: (value: string) => void;
  hostname: string;
  setHostname: (value: string) => void;
  vendorValue: string;
  setVendorValue: (value: string) => void;
  modelValue: string;
  setModelValue: (value: string) => void;
  serialNumber: string;
  setSerialNumber: (value: string) => void;
  managementProtocol: string;
  setManagementProtocol: (value: string) => void;
  typeId: string;
  setTypeId: (value: string) => void;
  note: string;
  setNote: (value: string) => void;
  networkId: string;
  setNetworkId: (value: string) => void;
  cityId: string;
  setCityId: (value: string) => void;
  locationId: string;
  setLocationId: (value: string) => void;
  sectorId: string;
  setSectorId: (value: string) => void;
  targetDeviceId: string;
  setTargetDeviceId: (value: string) => void;
  setRelationshipType: (value: string) => void;
  setRelationshipDirection: (value: string) => void;
  audit: AuditEntry[];
  onSelect: (candidate: Candidate) => void;
  onSave: () => void;
  onApprove: () => void;
  onReject: () => void;
  onReopen: () => void;
  onRegister: () => void;
  busy: boolean;
  permissions: string[];
};

export function CandidatePage(props: CandidatePageProps) {
  const selected = props.selected;
  const registered = selected?.state === "REGISTERED";
  const canReview = props.permissions.includes("candidate.review");
  const canRegister = props.permissions.includes("candidate.register");
  const reviewDisabled = registered || props.busy || !canReview;
  const isNew = selected?.state === "NEW";
  const isApproved = selected?.state === "APPROVED";
  const isRejected = selected?.state === "REJECTED";
  const discoveryMeta = selected?.metadata && typeof selected.metadata.discovery === "object" && selected.metadata.discovery !== null ? selected.metadata.discovery as Record<string, unknown> : {};
  const fieldSources = discoveryMeta.field_sources && typeof discoveryMeta.field_sources === "object" ? discoveryMeta.field_sources as Record<string, string> : {};
  const protocolStatus = discoveryMeta.protocol_status && typeof discoveryMeta.protocol_status === "object" ? discoveryMeta.protocol_status as Record<string, string> : {};
  const source = typeof selected?.metadata?.source === "string" ? selected.metadata.source : "";
  const discoveredIp = Boolean(selected?.discovery_result_id || source === "DISCOVERY" || selected?.metadata?.discovery);
  const typeCode = props.types.find((type) => type.id === props.typeId)?.code || "";
  const isHierarchyChild = typeCode === "CPE" || typeCode === "ACCESS_POINT";
  const isSectorDevice = typeCode === "SECTOR";
  const isLocationDevice = LOCATION_TYPES.has(typeCode);
  const [selectedParent, setSelectedParent] = useState<DeviceManagementRow | null>(null);
  const [validationAttempted, setValidationAttempted] = useState(false);
  const [selectedPlacement, setSelectedPlacement] = useState<CandidatePlacementOption | null>(null);

  const fallbackLocation = props.locations.find((item) => item.id === props.locationId) || null;
  const fallbackCity = props.cities.find((item) => item.id === (selectedPlacement?.city_id || fallbackLocation?.city_id)) || null;
  const fallbackNetwork = props.networks.find((item) => item.id === (selectedPlacement?.network_id || fallbackCity?.network_id)) || null;
  const fallbackSector = props.sectors.find((item) => item.id === props.sectorId) || null;
  const contextNetworkName = selectedParent?.network_name || selectedPlacement?.network_name || fallbackNetwork?.name || "—";
  const contextCityName = selectedParent?.city_name || selectedPlacement?.city_name || fallbackCity?.name || "—";
  const contextLocationName = selectedParent?.location_name || selectedPlacement?.location_name || fallbackLocation?.name || "—";
  const contextSectorName = selectedParent?.sector_name || selectedPlacement?.sector_name || fallbackSector?.name || (isLocationDevice ? "Not applicable" : "—");

  const sectorParentTypeId = props.types.find((type) => type.code === "SECTOR")?.id || "";
  const cpeParentTypeId = props.types.find((type) => type.code === "CPE")?.id || "";

  const clearPlacement = () => {
    setSelectedParent(null);
    setSelectedPlacement(null);
    props.setNetworkId("");
    props.setCityId("");
    props.setLocationId("");
    props.setSectorId("");
    props.setTargetDeviceId("");
    props.setRelationshipType("");
    props.setRelationshipDirection("DIRECTED");
  };

  const changeType = (value: string) => {
    props.setTypeId(value);
    clearPlacement();
    const code = props.types.find((type) => type.id === value)?.code;
  };

  const choosePlacement = (option: CandidatePlacementOption | null) => {
    setSelectedPlacement(option);
    props.setNetworkId(option?.network_id || "");
    props.setCityId(option?.city_id || "");
    props.setLocationId(option?.location_id || "");
    props.setSectorId(option?.sector_id || "");
    props.setTargetDeviceId("");
  };

  const chooseParent = (row: DeviceManagementRow | null) => {
    setSelectedParent(row);
    props.setTargetDeviceId(row?.id || "");
    props.setRelationshipType(row ? (typeCode === "CPE" ? "SECTOR_CPE" : "CPE_ACCESS_POINT") : "");
    props.setRelationshipDirection("DIRECTED");
    props.setSectorId(row?.sector_id || "");
    props.setLocationId(row?.location_id || "");
    props.setCityId(row?.city_id || "");
    props.setNetworkId(row?.network_id || "");
  };

  const workflowStep = registered ? 3 : isApproved ? 2 : 1;

  return <PageLayout className="candidate-page">
    <div className="page-heading"><div><h2 className="hover-help-title" data-help="Review discovered devices and complete their registration.">Candidate Review Queue</h2></div><div className="queue-count">{props.count} total</div></div>
    <section className="panel filter-panel"><div className="filter-row"><Input unstyled value={props.search} onChange={(e) => props.setSearch(e.target.value)} placeholder="Search IP, device name, type, hostname, vendor or model..." /><Select unstyled value={props.filter} onChange={(e) => props.setFilter(e.target.value)}><option value="ALL">All states</option>{STATES.filter((state) => state !== "ALL").map((state) => <option key={state} value={state}>{state}</option>)}</Select><Select unstyled value={props.typeFilter} onChange={(e) => props.setTypeFilter(e.target.value)}><option value="">All device types</option>{props.types.map((type) => <option key={type.id} value={type.id}>{type.name}</option>)}</Select><TableExportButton token={props.token} tableId="candidates" filters={{ search: props.search, state: props.filter === "ALL" ? "" : props.filter, device_type_id: props.typeFilter, sort_by: props.sort.key, sort_direction: props.sort.direction }}/><ClearFiltersButton disabled={!props.search&&props.filter==="ALL"&&!props.typeFilter} onClick={()=>{props.setSearch("");props.setFilter("ALL");props.setTypeFilter("");props.setPage(1)}}/></div></section>
    <div className="candidate-layout">
      <section className="panel queue-panel"><div className="panel-header"><div><h3 className="hover-help-title" data-help="Select a candidate to review it.">Review queue</h3></div></div>{props.candidates.length === 0 ? <EmptyState text="No candidates match the current filter." /> : <DataTable viewportClassName="table-wrap" className="clickable-table"><thead><tr><SortHeader label="IP" sortKey="ip_address" sort={props.sort} onSort={(key) => props.setSort((current: SortState) => nextSort(current, key))} /><SortHeader label="State" sortKey="state" sort={props.sort} onSort={(key) => props.setSort((current: SortState) => nextSort(current, key))} /><SortHeader label="Device name" sortKey="display_name" sort={props.sort} onSort={(key) => props.setSort((current: SortState) => nextSort(current, key))} /><SortHeader label="Device type" sortKey="device_type" sort={props.sort} onSort={(key) => props.setSort((current: SortState) => nextSort(current, key))} /><SortHeader label="Created" sortKey="created_at" sort={props.sort} onSort={(key) => props.setSort((current: SortState) => nextSort(current, key))} /></tr></thead><tbody>{props.candidates.map((candidate) => <tr key={candidate.id} className={selected?.id === candidate.id ? "selected-row" : ""} onClick={() => { setValidationAttempted(false); props.onSelect(candidate); }}><td>{candidate.ip_address}</td><td><Badge value={candidate.state} /></td><td>{candidate.display_name_suggestion || "—"}</td><td>{props.types.find((type) => type.id === candidate.suggested_device_type_id)?.name || "—"}</td><td>{formatDate(candidate.created_at)}</td></tr>)}<ServerPaginationRow colSpan={5} page={props.page} pageSize={props.pageSize} total={props.count} onPage={props.setPage} onPageSize={(size) => { props.setPageSize(size); props.setPage(1); }} itemLabel="candidates" /></tbody></DataTable>}</section>
      <section className={`panel review-panel${validationAttempted ? " validation-attempted" : ""}`}>{!selected ? <EmptyState text="Select a candidate from the queue." /> : <>
        <div className="panel-header"><div><h3>Engineer review</h3><span>{selected.ip_address}</span></div><Badge value={selected.state} /></div>
        <div className="candidate-workflow" aria-label="Candidate workflow"><div className={workflowStep >= 1 ? "active" : ""}><span>1</span><strong>Review</strong></div><i /><div className={workflowStep >= 2 ? "active" : ""}><span>2</span><strong>Approved</strong></div><i /><div className={workflowStep >= 3 ? "active" : ""}><span>3</span><strong>Registered</strong></div></div>
        <div className="evidence-grid"><div><span>Source IP</span><strong>{selected.ip_address}</strong></div><div><span>Confidence</span><strong>{confidence(selected.confidence)}</strong></div><div><span>Hostname</span><strong>{selected.hostname || "Unknown"}</strong><small>{fieldSources.hostname ? `Source: ${fieldSources.hostname}` : ""}</small></div><div><span>Vendor</span><strong>{selected.vendor || "Unknown"}</strong><small>{fieldSources.vendor ? `Source: ${fieldSources.vendor}` : ""}</small></div><div><span>Model</span><strong>{selected.model || "Unknown"}</strong><small>{fieldSources.model ? `Source: ${fieldSources.model}` : ""}</small></div><div><span>Serial</span><strong>{selected.serial_number || "Unknown"}</strong><small>{fieldSources.serial_number ? `Source: ${fieldSources.serial_number}` : ""}</small></div><div><span>Protocol</span><strong>{selected.management_protocol || "Unknown"}</strong></div><div><span>Source</span><strong>{discoveredIp ? "Discovery" : source || "Manual"}</strong></div></div>
        {Object.keys(protocolStatus).length > 0 && <div className="candidate-protocols"><span className="field-label">Correlated protocol evidence</span><div className="protocol-evidence-row">{Object.entries(protocolStatus).map(([method, status]) => <span className={`protocol-pill ${status === "DISCOVERED" ? "protocol-ok" : "protocol-fail"}`} key={method}>{method}: {status === "DISCOVERED" ? "UP" : "DOWN"}</span>)}</div></div>}
        <fieldset disabled={reviewDisabled} className="candidate-review-fieldset"><legend>Registration profile</legend>
          <div className="form-grid two"><label><span className="required-field-label">Device name</span><Input unstyled required value={props.name} onChange={(e) => props.setName(e.target.value)} /></label><label><span className={`required-field-label${discoveredIp ? " hover-help-title" : ""}`} data-help={discoveredIp ? "Discovery IP cannot be changed after discovery." : undefined}>Management IPv4</span><Input unstyled required pattern="(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}" title="Enter a valid IPv4 address, for example 192.168.1.10." value={props.ip} readOnly={discoveredIp} aria-readonly={discoveredIp} inputMode="decimal" placeholder="192.168.1.10" onChange={(e) => props.setIp(e.target.value)} /></label></div>
          <div className="form-grid two"><label><span className="required-field-label">Device type</span><Select unstyled required value={props.typeId} onChange={(e) => changeType(e.target.value)}><option value="">Select device type</option>{props.types.map((type) => <option key={type.id} value={type.id}>{type.name}</option>)}</Select></label></div>
          <div className="form-grid three"><label>Hostname<Input unstyled value={props.hostname} onChange={(e) => props.setHostname(e.target.value)} /></label><label>Vendor<Input unstyled value={props.vendorValue} onChange={(e) => props.setVendorValue(e.target.value)} /></label><label>Model<Input unstyled value={props.modelValue} onChange={(e) => props.setModelValue(e.target.value)} /></label></div>
          <div className="form-grid two"><label>Serial number<Input unstyled value={props.serialNumber} onChange={(e) => props.setSerialNumber(e.target.value)} /></label><label>Management protocol<Input unstyled value={props.managementProtocol} onChange={(e) => props.setManagementProtocol(e.target.value)} placeholder="ICMP, SNMP, HTTP..." /></label></div>
          {!typeCode && <div className="review-guidance">Select a device type to show only the placement fields that apply to that device.</div>}
          {isLocationDevice && <div className="review-placement-card"><div className="review-placement-title"><strong className="hover-help-title" data-help="Choose the Location for this device. Network and City are filled automatically.">Physical location</strong></div><label>Location<CandidatePlacementSearchSelect token={props.token} kind="locations" value={props.locationId} selectedLabel={fallbackLocation?.name} onChange={choosePlacement} disabled={reviewDisabled} placeholder="Search location, city or network..." /></label></div>}
          {isSectorDevice && <div className="review-placement-card"><div className="review-placement-title"><strong className="hover-help-title" data-help="Choose an available logical Sector for this device.">Logical Sector</strong></div><label>Logical Sector<CandidatePlacementSearchSelect token={props.token} kind="logical-sectors" value={props.sectorId} selectedLabel={fallbackSector?.name} onChange={choosePlacement} disabled={reviewDisabled} placeholder="Search free logical sectors..." /></label></div>}
          {typeCode === "CPE" && <div className="review-placement-card"><div className="review-placement-title"><strong className="hover-help-title" data-help="Choose the customer-access SECTOR device for this CPE. Location details are filled automatically.">Parent SECTOR device</strong></div><label><span className="required-field-label">Parent SECTOR device</span><ParentDeviceSearchSelect required token={props.token} value={props.targetDeviceId} deviceTypeId={sectorParentTypeId} sectorRole="CUSTOMER_ACCESS" onChange={chooseParent} disabled={reviewDisabled} placeholder="Search customer-access SECTOR name or IP..." /></label></div>}
          {typeCode === "ACCESS_POINT" && <div className="review-placement-card"><div className="review-placement-title"><strong className="hover-help-title" data-help="Choose the CPE for this Access Point. Location details are filled automatically.">Parent CPE</strong></div><label><span className="required-field-label">Parent CPE</span><ParentDeviceSearchSelect required token={props.token} value={props.targetDeviceId} deviceTypeId={cpeParentTypeId} requireAvailableApParent onChange={chooseParent} disabled={reviewDisabled} placeholder="Search eligible CPE name or management IP..." /></label></div>}
          {typeCode && <div className="derived-context"><div><span>Network</span><strong>{contextNetworkName}</strong></div><div><span>City</span><strong>{contextCityName}</strong></div><div><span>Location</span><strong>{contextLocationName}</strong></div><div><span>Sector</span><strong>{contextSectorName}</strong></div></div>}
          <label>Review note<Textarea unstyled rows={3} value={props.note} onChange={(e) => props.setNote(e.target.value)} placeholder="Optional engineering note" /></label>
        </fieldset>
        {registered ? <div className="terminal-note"><strong>Registered candidate.</strong><span>The review workflow is complete and read-only.</span></div> : (canReview || (canRegister && isApproved)) ? <div className="button-row candidate-actions">{canReview && <Button unstyled className="secondary" onClick={props.onSave} disabled={props.busy}>Save Review</Button>}{canReview && isNew && <Button unstyled onClick={() => { setValidationAttempted(true); props.onApprove(); }} disabled={props.busy}>Approve Candidate</Button>}{canRegister && isApproved && <Button unstyled onClick={() => { setValidationAttempted(true); props.onRegister(); }} disabled={props.busy}>Register Device</Button>}{canReview && (isNew || isApproved) && <Button unstyled className="danger" onClick={props.onReject} disabled={props.busy}>Reject Candidate</Button>}{canReview && isRejected && <Button unstyled onClick={props.onReopen} disabled={props.busy}>Reopen Candidate</Button>}</div> : null}
        <div className="panel-subsection"><h4>Workflow audit</h4>{props.audit.length === 0 ? <EmptyState text="No audit records returned." /> : <PaginatedCollection items={props.audit} itemLabel="audit entries" compact>{(pageAudit) => <div className="audit-list">{pageAudit.map((entry) => <div className="audit-row" key={entry.id}><div><strong>{entry.action}</strong><span>{entry.description}</span></div><time>{formatDate(entry.occurred_at)}</time></div>)}</div>}</PaginatedCollection>}</div>
      </>}</section>
    </div>
  </PageLayout>;
}
