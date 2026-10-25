import { useCallback, useEffect, useMemo, useState } from "react";
import { ApiError, apiFetch } from "../api/client";
import { useDialog } from "../components/common/DialogSystem";
import { useFeedback } from "../components/common/FeedbackSystem";
import { DataTable } from "../design-system/data/DataTable";
import { PageLayout } from "../design-system/layouts";
import { Button, Input, Select, Textarea } from "../design-system/primitives";
import { ConfigurationTemplateLifecyclePanel } from "../features/configuration/ConfigurationTemplateLifecyclePanel";
import type { Device, PageResult } from "../types";
import { friendlyError } from "../utils/feedback";
import {
  canRestoreSnapshot,
  coerceParameterValue,
  findVersionEntry,
  isActiveConfigurationOperation,
  parameterDefinitions,
  publishedVersions,
  type ConfigurationFunction,
  type ConfigurationSnapshot,
  type ConfigurationTemplateDetail,
  type ConfigurationVersion,
  type ParameterDefinition,
} from "../features/configuration/model";

type TemplateSummary = ConfigurationTemplateDetail["template"];
type Binding = {
  id: string; device_id: string; template_version_id: string; credential_source: string;
  credential_reference_configured: boolean; connection_overrides: Record<string, unknown>; enabled: boolean; bound_at: string;
};
type ConfigState = {
  device_id: string; last_known_good_snapshot_id: string | null; last_verified_snapshot_id: string | null;
  last_operation_id: string | null; drift_status: string; last_verified_at: string | null;
};
type Operation = {
  id: string; device_id: string; template_version_id: string | null; actor_user_id: string | null;
  operation_type: string; status: string; pre_change_snapshot_id: string | null; candidate_snapshot_id: string | null;
  result_snapshot_id: string | null; rollback_snapshot_id: string | null; verification_summary: Record<string, unknown>;
  failure_stage: string | null; failure_code: string | null; failure_message: string | null;
  started_at: string | null; finished_at: string | null; created_at: string; updated_at: string;
};
type OperationDetail = { operation: Operation; steps: Array<{ id:string; step_order:number; function_name_snapshot:string; status:string; failure_code:string|null; failure_message:string|null; verification_summary:Record<string,unknown> }> };
type DiffResult = { from_snapshot_id: string; to_snapshot_id: string; diff: string; truncated: boolean };
type Queued = { operation_id: string; status: string };

type Props = { token: string; permissions: string[]; refreshKey?: number };

const shortId = (value: string | null | undefined) => value ? `${value.slice(0, 8)}…` : "-";
const stamp = (value: string | null | undefined) => value ? new Date(value).toLocaleString() : "-";
const idempotency = (kind: string) => `ui-${kind}-${crypto.randomUUID()}`;

function parameterInitial(definition: ParameterDefinition) {
  if (definition.default === undefined || definition.default === null) return "";
  return String(definition.default);
}

export function ConfigurationPage({ token, permissions, refreshKey = 0 }: Props) {
  const feedback = useFeedback();
  const dialog = useDialog();
  const canTemplateRead = permissions.includes("device.configuration.template.read");
  const canTemplateManage = permissions.includes("device.configuration.template.manage");
  const canCapture = permissions.includes("device.configuration.capture");
  const canApply = permissions.includes("device.configuration.apply");
  const canRestore = permissions.includes("device.configuration.restore");

  const [devices, setDevices] = useState<Device[]>([]);
  const [deviceId, setDeviceId] = useState("");
  const [templates, setTemplates] = useState<TemplateSummary[]>([]);
  const [catalog, setCatalog] = useState<ConfigurationTemplateDetail[]>([]);
  const [catalogNotice, setCatalogNotice] = useState("");
  const [binding, setBinding] = useState<Binding | null>(null);
  const [state, setState] = useState<ConfigState | null>(null);
  const [snapshots, setSnapshots] = useState<ConfigurationSnapshot[]>([]);
  const [operations, setOperations] = useState<Operation[]>([]);
  const [operationDetail, setOperationDetail] = useState<OperationDetail | null>(null);
  const [busy, setBusy] = useState(false);

  const [bindTemplateId, setBindTemplateId] = useState("");
  const [bindVersionId, setBindVersionId] = useState("");
  const [credentialSource, setCredentialSource] = useState("ACCESS_TEMPLATE");
  const [credentialReference, setCredentialReference] = useState("");

  const [fromSnapshotId, setFromSnapshotId] = useState("");
  const [toSnapshotId, setToSnapshotId] = useState("");
  const [diff, setDiff] = useState<DiffResult | null>(null);
  const [applyFunctionId, setApplyFunctionId] = useState("");
  const [applyValues, setApplyValues] = useState<Record<string, string>>({});

  const bound = useMemo(() => findVersionEntry(catalog, binding?.template_version_id), [catalog, binding?.template_version_id]);
  const boundVersion = bound?.entry.version || null;
  const boundFunctions = useMemo(
    () => (bound?.entry.functions || []).filter((fn) => fn.enabled),
    [bound],
  );
  const selectedApplyFunction = useMemo(
    () => boundFunctions.find((fn) => fn.id === applyFunctionId) || null,
    [boundFunctions, applyFunctionId],
  );
  const applyParameters = useMemo(() => parameterDefinitions(selectedApplyFunction), [selectedApplyFunction]);
  const bindingTemplate = useMemo(() => catalog.find((item) => item.template.id === bindTemplateId) || null, [catalog, bindTemplateId]);
  const bindingVersions = useMemo(() => publishedVersions(bindingTemplate), [bindingTemplate]);

  const loadCatalog = useCallback(async () => {
    if (!canTemplateRead) { setTemplates([]); setCatalog([]); return; }
    try {
      const rows = await apiFetch<TemplateSummary[]>("/configuration-templates?active_only=false&limit=500", {}, token);
      setTemplates(rows.filter((row) => row.is_active));
      const settled = await Promise.allSettled(rows.map((row) => apiFetch<ConfigurationTemplateDetail>(`/configuration-templates/${row.id}`, {}, token)));
      const details = settled.filter((item): item is PromiseFulfilledResult<ConfigurationTemplateDetail> => item.status === "fulfilled").map((item) => item.value);
      setCatalog(details);
      setCatalogNotice(details.length === rows.length ? "" : "Some template details are outside the current request scope.");
    } catch (error) {
      setTemplates([]); setCatalog([]);
      setCatalogNotice(error instanceof ApiError && error.status === 403 ? "Template catalog is outside the current global request scope." : friendlyError(error, "Unable to load configuration templates"));
    }
  }, [canTemplateRead, token]);

  const loadDevices = useCallback(async () => {
    const result = await apiFetch<PageResult<Device>>("/devices/inventory/page?page=1&page_size=200&sort_by=display_name&sort_direction=asc", {}, token);
    setDevices(result.items || []);
    setDeviceId((current) => current || result.items?.[0]?.id || "");
  }, [token]);

  const loadDevice = useCallback(async (targetId: string) => {
    if (!targetId) return;
    const bindingRequest = apiFetch<Binding>(`/devices/${targetId}/configuration/binding`, {}, token)
      .catch((error) => {
        if (error instanceof ApiError && error.status === 404) return null;
        throw error;
      });
    const [nextBinding, nextState, nextSnapshots, nextOperations] = await Promise.all([
      bindingRequest,
      apiFetch<ConfigState>(`/devices/${targetId}/configuration/state`, {}, token),
      apiFetch<ConfigurationSnapshot[]>(`/devices/${targetId}/configuration/snapshots?limit=100`, {}, token),
      apiFetch<Operation[]>(`/devices/${targetId}/configuration/operations?limit=100`, {}, token),
    ]);
    setBinding(nextBinding);
    setState(nextState);
    setSnapshots(nextSnapshots);
    setOperations(nextOperations);
    if (nextSnapshots.length >= 2) {
      setFromSnapshotId((current) => current || nextSnapshots[1].id);
      setToSnapshotId((current) => current || nextSnapshots[0].id);
    } else if (nextSnapshots.length === 1) {
      setFromSnapshotId(nextSnapshots[0].id);
      setToSnapshotId(nextSnapshots[0].id);
    } else {
      setFromSnapshotId(""); setToSnapshotId("");
    }
  }, [token]);

  const refresh = useCallback(async () => {
    setBusy(true);
    try {
      await Promise.all([loadDevices(), loadCatalog()]);
      if (deviceId) await loadDevice(deviceId);
    } catch (error) { feedback.error(friendlyError(error, "Unable to load configuration management")); }
    finally { setBusy(false); }
  }, [deviceId, feedback, loadCatalog, loadDevice, loadDevices]);

  useEffect(() => { void Promise.all([loadDevices(), loadCatalog()]).catch((error) => feedback.error(friendlyError(error, "Unable to load configuration workspace"))); }, [loadCatalog, loadDevices, refreshKey]);
  useEffect(() => { if (deviceId) void loadDevice(deviceId).catch((error) => feedback.error(friendlyError(error, "Unable to load device configuration"))); }, [deviceId, loadDevice, refreshKey]);

  useEffect(() => {
    if (!binding) { setBindTemplateId(""); setBindVersionId(""); return; }
    const match = findVersionEntry(catalog, binding.template_version_id);
    if (match) {
      setBindTemplateId(match.detail.template.id);
      setBindVersionId(binding.template_version_id);
    }
    setCredentialSource(binding.credential_source || "ACCESS_TEMPLATE");
  }, [binding, catalog]);

  useEffect(() => {
    if (!boundFunctions.some((fn) => fn.id === applyFunctionId)) {
      setApplyFunctionId(boundFunctions[0]?.id || "");
    }
  }, [applyFunctionId, boundFunctions]);

  useEffect(() => {
    const values: Record<string, string> = {};
    for (const definition of applyParameters) values[definition.name] = parameterInitial(definition);
    setApplyValues(values);
  }, [selectedApplyFunction?.id]);

  useEffect(() => {
    if (!deviceId || !operations.some((operation) => isActiveConfigurationOperation(operation.status))) return;
    const timer = window.setInterval(() => { void loadDevice(deviceId).catch(() => undefined); }, 2500);
    return () => window.clearInterval(timer);
  }, [deviceId, loadDevice, operations]);

  const queue = async (path: string, payload: Record<string, unknown>, label: string) => {
    if (!deviceId) return;
    setBusy(true);
    try {
      const queued = await apiFetch<Queued>(`/devices/${deviceId}/configuration/${path}`, { method: "POST", body: JSON.stringify(payload) }, token);
      feedback.info(`${label} queued as operation ${queued.operation_id}. This operation will not be automatically replayed.`, `${label} queued`);
      await loadDevice(deviceId);
    } catch (error) { feedback.error(friendlyError(error, `${label} was not queued`)); }
    finally { setBusy(false); }
  };

  const capture = async () => {
    await queue("capture", { idempotency_key: idempotency("capture") }, "Configuration capture");
  };

  const restore = async (snapshot: ConfigurationSnapshot) => {
    if (!canRestoreSnapshot(snapshot, binding?.template_version_id)) {
      feedback.error("The selected snapshot is not READY/restorable for the currently bound template version.", "Restore blocked"); return;
    }
    const typed = await dialog.prompt({
      title: "Restore device configuration",
      message: `This can change the device and may interrupt management access.\n\nSnapshot: ${snapshot.id}\n\nThe operation is one-time and will never be automatically replayed.`,
      label: "Type the snapshot ID exactly",
      confirmLabel: "Queue restore",
      tone: "danger",
    });
    if (typed === null) return;
    if (typed.trim() !== snapshot.id) { feedback.error("Snapshot ID does not match. No restore was queued.", "Restore not started"); return; }
    await queue("restore", { snapshot_id: snapshot.id, idempotency_key: idempotency("restore") }, "Configuration restore");
  };

  const apply = async () => {
    if (!selectedApplyFunction || !boundVersion?.capabilities.includes("APPLY")) return;
    const parameters: Record<string, unknown> = {};
    try {
      for (const definition of applyParameters) {
        const raw = applyValues[definition.name] ?? "";
        if (definition.required !== false && !raw.trim() && definition.value_type !== "BOOLEAN") throw new Error(`${definition.label || definition.name} is required.`);
        if (!raw.trim() && definition.required === false) continue;
        parameters[definition.name] = coerceParameterValue(definition, raw);
      }
    } catch (error) { feedback.error(error instanceof Error ? error.message : "Invalid function parameters.", "Apply not started"); return; }
    if (!await dialog.confirm({ title: "Apply configuration function", message: `Queue ${selectedApplyFunction.name} for the selected device?\n\nThe backend will capture PRE_CHANGE state, verify the result, and attempt rollback on failure.\nThis operation will not be automatically replayed.`, confirmLabel: "Queue apply", tone: "danger" })) return;
    await queue("apply", { steps: [{ function_id: selectedApplyFunction.id, parameters }], idempotency_key: idempotency("apply") }, "Configuration apply");
  };

  const saveBinding = async () => {
    if (!deviceId || !bindVersionId) return;
    if (!await dialog.confirm({ title: "Bind configuration template", message: "Bind this exact published template version to the selected device? Executable configuration actions will use this immutable version until deliberately rebound.", confirmLabel: "Bind version" })) return;
    setBusy(true);
    try {
      const payload = {
        template_version_id: bindVersionId,
        credential_source: credentialSource,
        credential_reference: credentialSource === "ENV_REFERENCE" ? credentialReference.trim() || null : null,
        connection_overrides: {}, enabled: true,
      };
      const next = await apiFetch<Binding>(`/devices/${deviceId}/configuration/binding`, { method: "PUT", body: JSON.stringify(payload) }, token);
      setBinding(next); feedback.success("Exact published configuration template version bound to device.");
      await loadDevice(deviceId);
    } catch (error) { feedback.error(friendlyError(error, "Unable to bind configuration template")); }
    finally { setBusy(false); }
  };

  const loadDiff = async () => {
    if (!deviceId || !fromSnapshotId || !toSnapshotId || fromSnapshotId === toSnapshotId) { feedback.error("Choose two different snapshots.", "Diff not loaded"); return; }
    setBusy(true);
    try {
      const params = new URLSearchParams({ from_snapshot_id: fromSnapshotId, to_snapshot_id: toSnapshotId });
      setDiff(await apiFetch<DiffResult>(`/devices/${deviceId}/configuration/diff?${params.toString()}`, {}, token));
    } catch (error) { setDiff(null); feedback.error(friendlyError(error, "Safe configuration diff is unavailable")); }
    finally { setBusy(false); }
  };

  const showOperation = async (operation: Operation) => {
    setBusy(true);
    try { setOperationDetail(await apiFetch<OperationDetail>(`/devices/${operation.device_id}/configuration/operations/${operation.id}`, {}, token)); }
    catch (error) { feedback.error(friendlyError(error, "Unable to load operation details")); }
    finally { setBusy(false); }
  };

  const onBindingTemplate = (next: string) => {
    setBindTemplateId(next);
    const detail = catalog.find((item) => item.template.id === next);
    setBindVersionId(publishedVersions(detail)[0]?.version.id || "");
  };

  const renderParameter = (definition: ParameterDefinition) => {
    const value = applyValues[definition.name] ?? "";
    const setValue = (next: string) => setApplyValues((current) => ({ ...current, [definition.name]: next }));
    const kind = String(definition.value_type || "STRING").toUpperCase();
    if (kind === "BOOLEAN") return <Select unstyled value={value || "false"} onChange={(event) => setValue(event.target.value)}><option value="false">False</option><option value="true">True</option></Select>;
    if (kind === "ENUM" && definition.choices?.length) return <Select unstyled value={value} onChange={(event) => setValue(event.target.value)}><option value="">Select…</option>{definition.choices.map((choice) => <option key={choice} value={choice}>{choice}</option>)}</Select>;
    return <Input unstyled type={definition.sensitive ? "password" : (["INTEGER", "NUMBER", "VLAN_ID"].includes(kind) ? "number" : "text")} value={value} onChange={(event) => setValue(event.target.value)} />;
  };

  return <PageLayout className="page">
    <div className="page-heading"><div><h2 className="hover-help-title" data-help="Guarded single-device configuration lifecycle, history and rollback evidence.">Configuration Management</h2><p className="muted">Versioned templates, encrypted snapshots, guarded actions and operation evidence.</p></div><Button unstyled className="secondary" disabled={busy} onClick={() => void refresh()}>Refresh</Button></div>

    {canTemplateRead && <ConfigurationTemplateLifecyclePanel token={token} catalog={catalog} canManage={canTemplateManage} onCatalogChanged={loadCatalog} />}

    <section className="panel"><h3>Device workspace</h3><div className="form-grid two"><label>Device<Select unstyled value={deviceId} onChange={(event) => { setDeviceId(event.target.value); setDiff(null); setOperationDetail(null); }}><option value="">Select device…</option>{devices.map((device) => <option key={device.id} value={device.id}>{device.display_name}{device.management_ip ? ` — ${device.management_ip}` : ""}</option>)}</Select></label><label>Configuration state<Input unstyled readOnly value={state?.drift_status || "UNKNOWN"} /></label></div>{deviceId && <div className="actions">{canCapture && <Button unstyled disabled={busy || !binding} onClick={() => void capture()}>Capture configuration</Button>}<span className="muted">LKG: {shortId(state?.last_known_good_snapshot_id)} · Last verified: {stamp(state?.last_verified_at)}</span></div>}</section>

    <section className="panel"><h3>Template binding</h3>{catalogNotice && <div className="inline-warning">{catalogNotice}</div>}<div className="form-grid two"><label>Current version<Input unstyled readOnly value={binding ? `${bound?.detail.template.code || "template"} / ${binding.template_version_id}` : "Not bound"} /></label><label>Credential source<Input unstyled readOnly value={binding?.credential_source || "-"} /></label></div>{canTemplateManage && <><div className="form-grid two"><label>Template<Select unstyled value={bindTemplateId} onChange={(event) => onBindingTemplate(event.target.value)}><option value="">Select template…</option>{templates.map((template) => <option key={template.id} value={template.id}>{template.code} — {template.vendor} {template.model || ""}</option>)}</Select></label><label>Published version<Select unstyled value={bindVersionId} onChange={(event) => setBindVersionId(event.target.value)}><option value="">Select version…</option>{bindingVersions.map(({ version }) => <option key={version.id} value={version.id}>v{version.version_number} · {version.adapter_key} · {version.capabilities.join(", ")}</option>)}</Select></label><label>Credential source<Select unstyled value={credentialSource} onChange={(event) => setCredentialSource(event.target.value)}><option value="ACCESS_TEMPLATE">Access Template</option><option value="REMOTE_ACCESS_PROFILE">Remote Access Profile</option><option value="ENV_REFERENCE">Environment reference</option></Select></label>{credentialSource === "ENV_REFERENCE" && <label>Environment reference<Input unstyled value={credentialReference} onChange={(event) => setCredentialReference(event.target.value)} placeholder="env://DEVICE_CREDENTIAL" /></label>}</div><Button unstyled disabled={busy || !deviceId || !bindVersionId} onClick={() => void saveBinding()}>Bind exact version</Button></>}</section>

    {boundVersion && <section className="panel"><h3>Bound execution contract</h3><DataTable viewportClassName="table-wrap"><thead><tr><th>Version</th><th>Adapter</th><th>Transport</th><th>Capabilities</th><th>Functions</th></tr></thead><tbody><tr><td>v{boundVersion.version_number}</td><td>{boundVersion.adapter_key}</td><td>{boundVersion.transport}</td><td>{boundVersion.capabilities.join(", ")}</td><td>{boundFunctions.length}</td></tr></tbody></DataTable>{canApply && boundVersion.capabilities.includes("APPLY") && <div className="panel"><h3>Apply one versioned function</h3><div className="form-grid two"><label>Function<Select unstyled value={applyFunctionId} onChange={(event) => setApplyFunctionId(event.target.value)}><option value="">Select function…</option>{boundFunctions.map((fn) => <option key={fn.id} value={fn.id}>{fn.name}{fn.is_destructive ? " · destructive" : ""}</option>)}</Select></label>{applyParameters.map((definition) => <label key={definition.name}>{definition.label || definition.name}{definition.required !== false ? " *" : ""}{renderParameter(definition)}{definition.description && <span className="muted">{definition.description}</span>}</label>)}</div><Button unstyled className="danger" disabled={busy || !selectedApplyFunction} onClick={() => void apply()}>Queue guarded apply</Button></div>}</section>}

    <section className="panel"><h3>Snapshot history</h3><DataTable viewportClassName="table-wrap"><thead><tr><th>Created</th><th>Kind</th><th>Status</th><th>Size</th><th>Restorable</th><th>SHA256</th><th>Actions</th></tr></thead><tbody>{snapshots.map((snapshot) => <tr key={snapshot.id}><td>{stamp(snapshot.created_at)}</td><td>{snapshot.snapshot_kind}</td><td>{snapshot.artifact_status}</td><td>{snapshot.artifact_size_bytes ?? "-"}</td><td>{snapshot.is_restorable ? "YES" : "NO"}</td><td title={snapshot.normalized_sha256 || ""}>{snapshot.normalized_sha256 ? `${snapshot.normalized_sha256.slice(0, 12)}…` : "-"}</td><td><div className="actions">{canRestore && <Button unstyled className="small danger" disabled={busy || !canRestoreSnapshot(snapshot, binding?.template_version_id)} onClick={() => void restore(snapshot)}>Restore</Button>}</div></td></tr>)}{!snapshots.length && <tr><td colSpan={7}>No configuration snapshots exist for this device.</td></tr>}</tbody></DataTable></section>

    <section className="panel"><h3>Safe snapshot diff</h3><div className="form-grid two"><label>From<Select unstyled value={fromSnapshotId} onChange={(event) => setFromSnapshotId(event.target.value)}><option value="">Select snapshot…</option>{snapshots.map((snapshot) => <option key={snapshot.id} value={snapshot.id}>{stamp(snapshot.created_at)} · {snapshot.snapshot_kind} · {shortId(snapshot.id)}</option>)}</Select></label><label>To<Select unstyled value={toSnapshotId} onChange={(event) => setToSnapshotId(event.target.value)}><option value="">Select snapshot…</option>{snapshots.map((snapshot) => <option key={snapshot.id} value={snapshot.id}>{stamp(snapshot.created_at)} · {snapshot.snapshot_kind} · {shortId(snapshot.id)}</option>)}</Select></label></div><Button unstyled disabled={busy || !fromSnapshotId || !toSnapshotId || fromSnapshotId === toSnapshotId} onClick={() => void loadDiff()}>Load safe diff</Button>{diff && <><p className="muted">{diff.truncated ? "Diff truncated by the server safety limit." : "Server-sanitized diff."}</p><Textarea unstyled readOnly rows={18} value={diff.diff || "No differences."} /></>}</section>

    <section className="panel"><h3>Operation history</h3><DataTable viewportClassName="table-wrap"><thead><tr><th>Created</th><th>Type</th><th>Status</th><th>Failure</th><th>PRE_CHANGE</th><th>Result</th><th>Rollback</th><th>Details</th></tr></thead><tbody>{operations.map((operation) => <tr key={operation.id}><td>{stamp(operation.created_at)}</td><td>{operation.operation_type}</td><td>{operation.status}</td><td>{operation.failure_code ? `${operation.failure_stage || ""}: ${operation.failure_code}` : "-"}</td><td>{shortId(operation.pre_change_snapshot_id)}</td><td>{shortId(operation.result_snapshot_id)}</td><td>{shortId(operation.rollback_snapshot_id)}</td><td><Button unstyled className="small" disabled={busy} onClick={() => void showOperation(operation)}>Open</Button></td></tr>)}{!operations.length && <tr><td colSpan={8}>No configuration operations exist for this device.</td></tr>}</tbody></DataTable>{operationDetail && <div className="panel"><div className="page-heading"><h3>Operation {operationDetail.operation.id}</h3><Button unstyled className="secondary small" onClick={() => setOperationDetail(null)}>Close</Button></div><p>Status: <strong>{operationDetail.operation.status}</strong> · Type: {operationDetail.operation.operation_type}</p>{operationDetail.operation.failure_code && <div className="inline-warning">{operationDetail.operation.failure_stage}: {operationDetail.operation.failure_code}{operationDetail.operation.failure_message ? ` — ${operationDetail.operation.failure_message}` : ""}</div>}<DataTable viewportClassName="table-wrap"><thead><tr><th>Order</th><th>Function</th><th>Status</th><th>Failure</th></tr></thead><tbody>{operationDetail.steps.map((step) => <tr key={step.id}><td>{step.step_order}</td><td>{step.function_name_snapshot}</td><td>{step.status}</td><td>{step.failure_code || "-"}</td></tr>)}{!operationDetail.steps.length && <tr><td colSpan={4}>No function steps (capture/restore/verify operations do not require APPLY steps).</td></tr>}</tbody></DataTable></div>}</section>

    {canTemplateRead && <section className="panel"><h3>Template catalog</h3><DataTable viewportClassName="table-wrap"><thead><tr><th>Code</th><th>Vendor / Model</th><th>Published versions</th><th>Latest capabilities</th></tr></thead><tbody>{catalog.map((detail) => { const versions = publishedVersions(detail); const latest: ConfigurationVersion | null = versions[0]?.version || null; return <tr key={detail.template.id}><td>{detail.template.code}</td><td>{detail.template.vendor} {detail.template.model || ""}</td><td>{versions.length}</td><td>{latest?.capabilities.join(", ") || "-"}</td></tr>; })}{!catalog.length && <tr><td colSpan={4}>No configuration templates are visible in the current global request scope.</td></tr>}</tbody></DataTable></section>}
  </PageLayout>;
}
