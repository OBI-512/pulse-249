import { useCallback, useEffect, useRef, useState } from "react";
import { apiFetch } from "../../api/client";
import { useDialog } from "../../components/common/DialogSystem";
import { useDebouncedValue } from "../../hooks/useDebouncedValue";
import type { AuditEntry, Candidate, DeviceType, RegistrationResult, SortState } from "../../types";
import { isValidIPv4 } from "../../utils/validation";

type Options = {
  token: string;
  permissions: string[];
  active: boolean;
  types: DeviceType[];
  setBusy: (value: boolean) => void;
  clearAlerts: () => void;
  setError: (value: string) => void;
  setMessage: (value: string) => void;
  onError: (error: unknown, fallback: string) => void;
  onReferenceRefresh: () => Promise<void>;
  onDevicesChanged: () => Promise<void>;
};

export function useCandidateWorkspace(options: Options) {
  const optionsRef = useRef(options); optionsRef.current = options;
  const dialog = useDialog();
  const requestRef = useRef(0);
  const auditRequestRef = useRef(0);
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [count, setCount] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [sort, setSort] = useState<SortState>({ key: "created_at", direction: "desc" });
  const [filter, setFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [selected, setSelected] = useState<Candidate | null>(null);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [ip, setIp] = useState("");
  const [name, setName] = useState("");
  const [hostname, setHostname] = useState("");
  const [vendor, setVendor] = useState("");
  const [model, setModel] = useState("");
  const [serialNumber, setSerialNumber] = useState("");
  const [managementProtocol, setManagementProtocol] = useState("");
  const [dirty, setDirty] = useState(false);
  const [typeId, setTypeId] = useState("");
  const [note, setNote] = useState("");
  const [networkId, setNetworkId] = useState("");
  const [cityId, setCityId] = useState("");
  const [locationId, setLocationId] = useState("");
  const [sectorId, setSectorId] = useState("");
  const [targetDeviceId, setTargetDeviceId] = useState("");
  const [relationshipType, setRelationshipType] = useState("");
  const [relationshipDirection, setRelationshipDirection] = useState("DIRECTED");
  const debouncedSearch = useDebouncedValue(search, 300);
  const selectedRef = useRef(selected); selectedRef.current = selected;
  const dirtyRef = useRef(dirty); dirtyRef.current = dirty;
  const canReadCandidates = options.permissions.includes("candidate.read");

  const syncForm = useCallback((candidate: Candidate) => {
    setIp(candidate.ip_address || ""); setName(candidate.display_name_suggestion || `DEVICE-${candidate.ip_address}`);
    setHostname(candidate.hostname || ""); setVendor(candidate.vendor || ""); setModel(candidate.model || "");
    setSerialNumber(candidate.serial_number || ""); setManagementProtocol(candidate.management_protocol || "");
    setTypeId(candidate.suggested_device_type_id || ""); setNote(candidate.review_note || "");
    setNetworkId(candidate.network_id || ""); setCityId(candidate.city_id || ""); setLocationId(candidate.location_id || "");
    setSectorId(candidate.sector_id || "");
    setTargetDeviceId(candidate.relationship_target_device_id || ""); setRelationshipType(candidate.relationship_type || "");
    setRelationshipDirection(candidate.relationship_direction || "DIRECTED"); setDirty(false);
  }, []);

  const loadCandidates = useCallback(async () => {
    const requestId = ++requestRef.current;
    const params = new URLSearchParams({ limit: String(pageSize), offset: String((page - 1) * pageSize), sort_by: sort.key, sort_direction: sort.direction });
    if (filter !== "ALL") params.set("state", filter);
    if (debouncedSearch.trim()) params.set("search", debouncedSearch.trim());
    if (typeFilter) params.set("device_type_id", typeFilter);
    const body = await apiFetch<{ items: Candidate[]; count: number }>(`/device-candidates?${params.toString()}`, {}, options.token);
    if (requestId !== requestRef.current) return;
    setCandidates(body.items || []); setCount(body.count || 0);
    const currentSelection = selectedRef.current;
    if (currentSelection) {
      const refreshed = body.items?.find((item) => item.id === currentSelection.id);
      if (refreshed) { setSelected(refreshed); if (!dirtyRef.current) syncForm(refreshed); }
    }
  }, [debouncedSearch, filter, options.token, page, pageSize, sort, syncForm, typeFilter]);

  useEffect(() => { setPage(1); }, [filter, debouncedSearch, typeFilter]);
  useEffect(() => {
    if (!options.active || !canReadCandidates) return;
    void loadCandidates().catch((error) => optionsRef.current.onError(error, "Unable to load candidates."));
  }, [canReadCandidates, loadCandidates, options.active]);

  const selectCandidate = useCallback(async (candidate: Candidate) => {
    const current = optionsRef.current; const requestId = ++auditRequestRef.current;
    current.clearAlerts(); setSelected(candidate); syncForm(candidate); setAudit([]);
    try {
      const rows = await apiFetch<AuditEntry[]>(`/device-candidates/${candidate.id}/audit`, {}, current.token);
      if (requestId !== auditRequestRef.current) return; setAudit(rows);
    } catch (error) { if (requestId === auditRequestRef.current) current.onError(error, "Unable to load candidate details."); }
  }, [syncForm]);

  const saveReview = useCallback(async () => {
    const current = optionsRef.current; if (!selected) return;
    if (selected.state === "REGISTERED") { current.setError("Registered candidates are immutable."); return; }
    if (!name.trim()) { current.setError("Device name is required."); return; }
    if (!isValidIPv4(ip)) { current.setError("Management IP must be a valid IPv4 address, for example 192.168.1.10."); return; }
    if (!await dialog.confirm({ message: `Save the review changes for candidate ${selected.ip_address}?` })) return;
    const typeCode = current.types.find((type) => type.id === typeId)?.code;
    const hierarchyChild = typeCode === "CPE" || typeCode === "ACCESS_POINT";
    const expectedHierarchyType = typeCode === "CPE" ? "SECTOR_CPE" : typeCode === "ACCESS_POINT" ? "CPE_ACCESS_POINT" : null;
    current.setBusy(true); current.clearAlerts();
    try {
      const body = await apiFetch<Candidate>(`/device-candidates/${selected.id}`, { method: "PATCH", body: JSON.stringify({
        ip_address: ip.trim(), display_name_suggestion: name.trim(), hostname: hostname.trim() || null, vendor: vendor.trim() || null,
        model: model.trim() || null, serial_number: serialNumber.trim() || null, management_protocol: managementProtocol.trim() || null,
        suggested_device_type_id: typeId || null, review_note: note || null,
        network_id: hierarchyChild ? null : networkId || null, city_id: hierarchyChild ? null : cityId || null,
        location_id: hierarchyChild ? null : locationId || null, sector_id: hierarchyChild ? null : sectorId || null,
        relationship_target_device_id: hierarchyChild ? (targetDeviceId || null) : null,
        relationship_type: hierarchyChild ? expectedHierarchyType : null, relationship_direction: hierarchyChild ? "DIRECTED" : null,
      }) }, current.token);
      setSelected(body); syncForm(body); await Promise.all([loadCandidates(), current.onReferenceRefresh()]); current.setMessage("Candidate review saved.");
    } catch (error) { current.onError(error, "Unable to save candidate review."); }
    finally { current.setBusy(false); }
  }, [cityId, dialog, hostname, ip, loadCandidates, locationId, managementProtocol, model, name, networkId, note, sectorId, selected, serialNumber, syncForm, targetDeviceId, typeId, vendor]);

  const approve = useCallback(async () => {
    const current = optionsRef.current; if (!selected) return;
    if (selected.state !== "NEW") { current.setError(`Only NEW candidates can be approved. Current state: ${selected.state}.`); return; }
    if (!typeId) { current.setError("Select a device type before approval."); return; }
    if (!name.trim()) { current.setError("Device name is required before approval."); return; }
    if (!isValidIPv4(ip)) { current.setError("Management IP must be a valid IPv4 address, for example 192.168.1.10."); return; }
    const typeCode = current.types.find((type) => type.id === typeId)?.code;
    const hierarchyChild = typeCode === "CPE" || typeCode === "ACCESS_POINT";
    const expectedHierarchyType = typeCode === "CPE" ? "SECTOR_CPE" : typeCode === "ACCESS_POINT" ? "CPE_ACCESS_POINT" : null;
    if (hierarchyChild && !targetDeviceId) { current.setError(`${typeCode} candidates require a parent device.`); return; }
    if (typeCode === "SECTOR" && !sectorId) { current.setError("Select the logical sector represented by this SECTOR device."); return; }
    if (!["CPE", "ACCESS_POINT", "SECTOR"].includes(typeCode || "") && !locationId) { current.setError("Select the physical location for this device."); return; }
    if (!await dialog.confirm({ message: `Approve candidate ${selected.ip_address}? This will move it to APPROVED and make it eligible for registration.` })) return;
    current.setBusy(true); current.clearAlerts();
    try {
      const body = await apiFetch<Candidate>(`/device-candidates/${selected.id}/approve`, { method: "POST", body: JSON.stringify({
        ip_address: ip.trim(), suggested_device_type_id: typeId, display_name: name.trim(), hostname: hostname.trim() || null,
        vendor: vendor.trim() || null, model: model.trim() || null, serial_number: serialNumber.trim() || null,
        management_protocol: managementProtocol.trim() || null, review_note: note || null,
        network_id: hierarchyChild ? null : networkId || null, city_id: hierarchyChild ? null : cityId || null,
        location_id: hierarchyChild ? null : locationId || null, sector_id: hierarchyChild ? null : sectorId || null,
        relationship_target_device_id: hierarchyChild ? (targetDeviceId || null) : null,
        relationship_type: hierarchyChild ? expectedHierarchyType : null, relationship_direction: hierarchyChild ? "DIRECTED" : null,
      }) }, current.token);
      setSelected(body); syncForm(body); await loadCandidates(); current.setMessage("Candidate approved. It is ready for registration.");
    } catch (error) { current.onError(error, "Unable to approve candidate."); }
    finally { current.setBusy(false); }
  }, [cityId, dialog, hostname, ip, loadCandidates, locationId, managementProtocol, model, name, networkId, note, sectorId, selected, serialNumber, syncForm, targetDeviceId, typeId, vendor]);

  const reject = useCallback(async () => {
    const current = optionsRef.current; if (!selected) return;
    if (!["NEW", "APPROVED"].includes(selected.state)) { current.setError(`Candidate cannot be rejected from ${selected.state}.`); return; }
    if (!await dialog.confirm({ message: `Reject candidate ${selected.ip_address}?` })) return;
    current.setBusy(true); current.clearAlerts();
    try {
      const body = await apiFetch<Candidate>(`/device-candidates/${selected.id}/reject`, { method: "POST", body: JSON.stringify({ review_note: note || null }) }, current.token);
      setSelected(body); syncForm(body); await loadCandidates(); current.setMessage("Candidate rejected.");
    } catch (error) { current.onError(error, "Unable to reject candidate."); }
    finally { current.setBusy(false); }
  }, [dialog, loadCandidates, note, selected, syncForm]);

  const reopen = useCallback(async () => {
    const current = optionsRef.current; if (!selected) return;
    if (selected.state !== "REJECTED") { current.setError(`Only REJECTED candidates can be reopened. Current state: ${selected.state}.`); return; }
    if (!await dialog.confirm({ message: `Reopen candidate ${selected.ip_address} for review?` })) return;
    current.setBusy(true); current.clearAlerts();
    try {
      const body = await apiFetch<Candidate>(`/device-candidates/${selected.id}/reopen`, { method: "POST" }, current.token);
      setSelected(body); syncForm(body); await loadCandidates(); current.setMessage("Candidate reopened for review.");
    } catch (error) { current.onError(error, "Unable to reopen candidate."); }
    finally { current.setBusy(false); }
  }, [dialog, loadCandidates, selected, syncForm]);

  const register = useCallback(async () => {
    const current = optionsRef.current; if (!selected) return;
    if (selected.state !== "APPROVED") { current.setError("Only APPROVED candidates can be registered."); return; }
    if (!selected.suggested_device_type_id) { current.setError("A device type is required before registration."); return; }
    if (!await dialog.confirm({ message: `Register candidate ${selected.ip_address} as a device?` })) return;
    current.setBusy(true); current.clearAlerts();
    try {
      const result = await apiFetch<RegistrationResult>(`/device-candidates/${selected.id}/register`, { method: "POST" }, current.token);
      setSelected({ ...selected, state: result.state } as Candidate);
      await Promise.all([loadCandidates(), current.onDevicesChanged(), current.onReferenceRefresh()]);
      current.setMessage(result.idempotent ? "Existing registration returned." : "Device registered successfully.");
    } catch (error) { current.onError(error, "Unable to register device."); }
    finally { current.setBusy(false); }
  }, [dialog, loadCandidates, selected]);

  const dirtySetter = <T,>(setter: (value: T) => void) => (value: T) => { setter(value); setDirty(true); };

  return {
    candidates, count, page, setPage, pageSize, setPageSize, sort, setSort, filter, setFilter, search, setSearch, typeFilter, setTypeFilter,
    selected, audit, ip, setIp: dirtySetter(setIp), name, setName: dirtySetter(setName), hostname, setHostname: dirtySetter(setHostname),
    vendor, setVendor: dirtySetter(setVendor), model, setModel: dirtySetter(setModel), serialNumber, setSerialNumber: dirtySetter(setSerialNumber),
    managementProtocol, setManagementProtocol: dirtySetter(setManagementProtocol), typeId, setTypeId: dirtySetter(setTypeId), note, setNote: dirtySetter(setNote),
    networkId, setNetworkId: dirtySetter(setNetworkId), cityId, setCityId: dirtySetter(setCityId), locationId, setLocationId: dirtySetter(setLocationId),
    sectorId, setSectorId: dirtySetter(setSectorId), targetDeviceId, setTargetDeviceId: dirtySetter(setTargetDeviceId),
    relationshipType, setRelationshipType: dirtySetter(setRelationshipType), relationshipDirection, setRelationshipDirection: dirtySetter(setRelationshipDirection),
    loadCandidates, selectCandidate, saveReview, approve, reject, reopen, register,
  };
}
