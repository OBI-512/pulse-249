import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "../../api/client";
import { useDialog } from "../../components/common/DialogSystem";
import { useFeedback } from "../../components/common/FeedbackSystem";
import { DataTable } from "../../design-system/data/DataTable";
import { Button, Input, Select, Textarea } from "../../design-system/primitives";
import type { DeviceType } from "../../types";
import { friendlyError } from "../../utils/feedback";
import {
  configurationDefinition,
  sortedVersions,
  type ConfigurationTemplateDetail,
  type ConfigurationVersion,
} from "./model";

type Props = {
  token: string;
  catalog: ConfigurationTemplateDetail[];
  canManage: boolean;
  onCatalogChanged: () => Promise<void> | void;
};

type FamilyCloneRead = {
  template_id: string;
  version_id: string;
  version_number: number;
  status: string;
  source_version_id: string;
};

type NewFamilyDraft = {
  code: string;
  name: string;
  vendor: string;
  model: string;
  series: string;
  device_type_id: string;
  description: string;
  definition: string;
};

const EMPTY_DEFINITION = JSON.stringify({
  adapter_key: "",
  transport: "SSH_CLI",
  capabilities: [],
  parameters: [],
  transport_parameters: {},
  functions: [],
}, null, 2);

const emptyFamily = (): NewFamilyDraft => ({
  code: "",
  name: "",
  vendor: "",
  model: "",
  series: "",
  device_type_id: "",
  description: "",
  definition: EMPTY_DEFINITION,
});

const stamp = (value: string | null | undefined) => value ? new Date(value).toLocaleString() : "-";
const shortHash = (value: string | null | undefined) => value ? `${value.slice(0, 12)}…` : "-";

function parseDefinition(raw: string): Record<string, unknown> {
  const value = JSON.parse(raw) as unknown;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Definition must be a JSON object.");
  const definition = value as Record<string, unknown>;
  if (typeof definition.adapter_key !== "string" || !definition.adapter_key.trim()) throw new Error("Definition adapter_key is required.");
  return definition;
}

export function ConfigurationTemplateLifecyclePanel({ token, catalog, canManage, onCatalogChanged }: Props) {
  const feedback = useFeedback();
  const dialog = useDialog();
  const [templateId, setTemplateId] = useState("");
  const [versionId, setVersionId] = useState("");
  const [definitionText, setDefinitionText] = useState(EMPTY_DEFINITION);
  const [changeNote, setChangeNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [deviceTypes, setDeviceTypes] = useState<DeviceType[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [familyDraft, setFamilyDraft] = useState<NewFamilyDraft>(emptyFamily);

  const selected = useMemo(
    () => catalog.find((detail) => detail.template.id === templateId) || null,
    [catalog, templateId],
  );
  const versions = useMemo(() => sortedVersions(selected), [selected]);
  const selectedEntry = useMemo(
    () => versions.find((entry) => entry.version.id === versionId) || null,
    [versionId, versions],
  );
  const selectedVersion = selectedEntry?.version || null;

  useEffect(() => {
    if (!catalog.length) { setTemplateId(""); setVersionId(""); return; }
    if (!catalog.some((detail) => detail.template.id === templateId)) setTemplateId(catalog[0].template.id);
  }, [catalog, templateId]);

  useEffect(() => {
    if (!selected) return;
    if (!versions.some((entry) => entry.version.id === versionId)) setVersionId(versions[0]?.version.id || "");
  }, [selected, versionId, versions]);

  useEffect(() => {
    if (!selectedEntry) return;
    setDefinitionText(JSON.stringify(configurationDefinition(selectedEntry), null, 2));
    setChangeNote(selectedEntry.version.change_note || "");
  }, [selectedEntry]);

  useEffect(() => {
    if (!canManage) return;
    void apiFetch<DeviceType[]>("/devices/types", {}, token)
      .then(setDeviceTypes)
      .catch(() => setDeviceTypes([]));
  }, [canManage, token]);

  const refresh = async () => {
    await onCatalogChanged();
  };

  const lifecycleAction = async (action: "test" | "approve" | "activate", success: string) => {
    if (!selected || !selectedVersion) return;
    if (action === "approve") {
      if (!await dialog.confirm({
        title: "Approve configuration template version",
        message: `Approve ${selected.template.code} v${selectedVersion.version_number} using its current successful Test evidence?`,
        confirmLabel: "Approve version",
      })) return;
    }
    if (action === "activate") {
      if (!await dialog.confirm({
        title: "Publish configuration template version",
        message: `Publish ${selected.template.code} v${selectedVersion.version_number}?\n\nThis publishes the immutable template definition only. It does not bind a device, connect to a device, or execute configuration. Any previous Published version in this family becomes Retired.`,
        confirmLabel: "Publish version",
      })) return;
    }
    setBusy(true);
    try {
      await apiFetch<unknown>(
        `/configuration-templates/${selected.template.id}/versions/${selectedVersion.id}/${action}`,
        { method: "POST" },
        token,
      );
      feedback.success(success);
      await refresh();
    } catch (error) {
      feedback.error(friendlyError(error, `Unable to ${action} configuration template version`));
    } finally {
      setBusy(false);
    }
  };

  const saveDefinition = async () => {
    if (!selected || !selectedVersion) return;
    let definition: Record<string, unknown>;
    try { definition = parseDefinition(definitionText); }
    catch (error) { feedback.error(error instanceof Error ? error.message : "Definition JSON is invalid.", "Definition not saved"); return; }

    if (["TESTED", "APPROVED"].includes(selectedVersion.status)) {
      if (!await dialog.confirm({
        title: "Invalidate lifecycle evidence",
        message: `Editing a ${selectedVersion.status} version clears its Test/Approval evidence and returns it to Draft. Continue?`,
        confirmLabel: "Save as Draft",
      })) return;
    }
    setBusy(true);
    try {
      await apiFetch<ConfigurationVersion>(
        `/configuration-templates/${selected.template.id}/versions/${selectedVersion.id}`,
        { method: "PUT", body: JSON.stringify({ definition, change_note: changeNote.trim() || null }) },
        token,
      );
      feedback.success("Configuration template definition saved. Lifecycle state is Draft.");
      await refresh();
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to save configuration template definition"));
    } finally {
      setBusy(false);
    }
  };

  const cloneVersion = async () => {
    if (!selected || !selectedVersion) return;
    const note = await dialog.prompt({
      title: "New Draft revision",
      message: `Create a new Draft revision from exact source v${selectedVersion.version_number}?`,
      label: "Change note (optional)",
      defaultValue: `Cloned from version ${selectedVersion.version_number}`,
      confirmLabel: "Create Draft revision",
      maxLength: 1000,
    });
    if (note === null) return;
    setBusy(true);
    try {
      await apiFetch<ConfigurationVersion>(
        `/configuration-templates/${selected.template.id}/versions/${selectedVersion.id}/clone`,
        { method: "POST", body: JSON.stringify({ change_note: note.trim() || null }) },
        token,
      );
      setVersionId("");
      feedback.success("New Draft revision created from the selected exact version.");
      await refresh();
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to create Draft revision"));
    } finally {
      setBusy(false);
    }
  };

  const cloneFamily = async () => {
    if (!selected || !selectedVersion) return;
    const code = await dialog.prompt({
      title: "Clone configuration template family",
      message: `Clone ${selected.template.code} v${selectedVersion.version_number} into a new family and Draft lineage.`,
      label: "New family code",
      confirmLabel: "Continue",
      maxLength: 80,
    });
    if (code === null || !code.trim()) return;
    const name = await dialog.prompt({
      title: "Clone configuration template family",
      message: "Enter the new family display name.",
      label: "New family name",
      defaultValue: `${selected.template.name} Copy`,
      confirmLabel: "Clone family",
      maxLength: 160,
    });
    if (name === null || !name.trim()) return;
    setBusy(true);
    try {
      const result = await apiFetch<FamilyCloneRead>(
        `/configuration-templates/${selected.template.id}/versions/${selectedVersion.id}/clone-family`,
        {
          method: "POST",
          body: JSON.stringify({
            code: code.trim(),
            name: name.trim(),
            description: selected.template.description,
            change_note: `Family cloned from ${selected.template.code} v${selectedVersion.version_number}`,
          }),
        },
        token,
      );
      setTemplateId(result.template_id);
      setVersionId(result.version_id);
      feedback.success("Configuration template family cloned with explicit source lineage.");
      await refresh();
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to clone configuration template family"));
    } finally {
      setBusy(false);
    }
  };

  const createFamily = async () => {
    let definition: Record<string, unknown>;
    try { definition = parseDefinition(familyDraft.definition); }
    catch (error) { feedback.error(error instanceof Error ? error.message : "Definition JSON is invalid.", "Template family not created"); return; }
    if (!familyDraft.code.trim() || !familyDraft.name.trim() || !familyDraft.vendor.trim() || !familyDraft.device_type_id) {
      feedback.error("Code, name, vendor, and device type are required.", "Template family not created"); return;
    }
    setBusy(true);
    try {
      const created = await apiFetch<ConfigurationTemplateDetail>(
        "/configuration-templates",
        {
          method: "POST",
          body: JSON.stringify({
            code: familyDraft.code.trim(),
            name: familyDraft.name.trim(),
            vendor: familyDraft.vendor.trim(),
            model: familyDraft.model.trim() || null,
            series: familyDraft.series.trim() || null,
            device_type_id: familyDraft.device_type_id,
            description: familyDraft.description.trim() || null,
            definition,
          }),
        },
        token,
      );
      setTemplateId(created.template.id);
      setVersionId(created.versions[0]?.version.id || "");
      setFamilyDraft(emptyFamily());
      setShowCreate(false);
      feedback.success("Configuration template family created with initial Draft version.");
      await refresh();
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to create configuration template family"));
    } finally {
      setBusy(false);
    }
  };

  const useSelectedDefinitionForCreate = () => {
    if (!selectedEntry) return;
    setFamilyDraft((current) => ({ ...current, definition: JSON.stringify(configurationDefinition(selectedEntry), null, 2) }));
  };

  const editable = Boolean(selectedVersion && ["DRAFT", "TESTED", "APPROVED"].includes(selectedVersion.status));
  const testable = Boolean(selectedVersion && ["DRAFT", "TESTED"].includes(selectedVersion.status));
  const approvable = selectedVersion?.status === "TESTED";
  const publishable = selectedVersion?.status === "APPROVED" && selected?.template.is_active === true;

  return <section className="panel">
    <div className="page-heading">
      <div>
        <h3>Configuration template lifecycle</h3>
        <p className="muted">Authoring is definition-only: Draft → Tested → Approved → Published. No test runs automatically, and lifecycle actions never connect to or configure a device.</p>
      </div>
      {canManage && <Button unstyled className="secondary" disabled={busy} onClick={() => setShowCreate((value) => !value)}>{showCreate ? "Close new family" : "Create template family"}</Button>}
    </div>

    {showCreate && canManage && <div className="panel">
      <h3>New template family</h3>
      <div className="form-grid two">
        <label>Code<Input unstyled value={familyDraft.code} onChange={(event) => setFamilyDraft((current) => ({ ...current, code: event.target.value }))} /></label>
        <label>Name<Input unstyled value={familyDraft.name} onChange={(event) => setFamilyDraft((current) => ({ ...current, name: event.target.value }))} /></label>
        <label>Vendor<Input unstyled value={familyDraft.vendor} onChange={(event) => setFamilyDraft((current) => ({ ...current, vendor: event.target.value }))} /></label>
        <label>Model<Input unstyled value={familyDraft.model} onChange={(event) => setFamilyDraft((current) => ({ ...current, model: event.target.value }))} /></label>
        <label>Series<Input unstyled value={familyDraft.series} onChange={(event) => setFamilyDraft((current) => ({ ...current, series: event.target.value }))} /></label>
        <label>Device type<Select unstyled value={familyDraft.device_type_id} onChange={(event) => setFamilyDraft((current) => ({ ...current, device_type_id: event.target.value }))}><option value="">Select device type…</option>{deviceTypes.map((item) => <option key={item.id} value={item.id}>{item.name} ({item.code})</option>)}</Select></label>
      </div>
      <label>Description<Textarea unstyled rows={3} value={familyDraft.description} onChange={(event) => setFamilyDraft((current) => ({ ...current, description: event.target.value }))} /></label>
      <label>Initial Draft definition JSON<Textarea unstyled rows={16} value={familyDraft.definition} onChange={(event) => setFamilyDraft((current) => ({ ...current, definition: event.target.value }))} /></label>
      <div className="actions">
        {selectedEntry && <Button unstyled className="secondary" disabled={busy} onClick={useSelectedDefinitionForCreate}>Use selected version definition</Button>}
        <Button unstyled disabled={busy} onClick={() => void createFamily()}>Create Draft family</Button>
      </div>
    </div>}

    <div className="form-grid two">
      <label>Template family<Select unstyled value={templateId} onChange={(event) => { setTemplateId(event.target.value); setVersionId(""); }}><option value="">Select template…</option>{catalog.map((detail) => <option key={detail.template.id} value={detail.template.id}>{detail.template.code} — {detail.template.name}</option>)}</Select></label>
      <label>Version<Select unstyled value={versionId} onChange={(event) => setVersionId(event.target.value)}><option value="">Select version…</option>{versions.map(({ version }) => <option key={version.id} value={version.id}>v{version.version_number} · {version.status}</option>)}</Select></label>
    </div>

    {selected && <p className="muted">Family: <strong>{selected.template.is_active ? "ACTIVE" : "INACTIVE"}</strong> · Vendor/model: {selected.template.vendor} {selected.template.model || ""} · Device type: {selected.template.device_type_id}</p>}

    {selectedVersion && <>
      <DataTable viewportClassName="table-wrap"><thead><tr><th>Version</th><th>Status</th><th>Source</th><th>Tested</th><th>Approved</th><th>Published</th><th>Definition hash</th><th>Action</th></tr></thead><tbody>{versions.map(({ version }) => <tr key={version.id}><td>v{version.version_number}</td><td>{version.status}</td><td>{version.source_version_id ? shortHash(version.source_version_id) : "Initial"}</td><td>{stamp(version.tested_at)}</td><td>{stamp(version.approved_at)}</td><td>{stamp(version.published_at)}</td><td title={version.tested_definition_sha256 || version.content_sha256 || ""}>{shortHash(version.tested_definition_sha256 || version.content_sha256)}</td><td><Button unstyled className="small secondary" disabled={busy || version.id === selectedVersion.id} onClick={() => setVersionId(version.id)}>Open</Button></td></tr>)}</tbody></DataTable>

      <div className="panel">
        <h3>Version v{selectedVersion.version_number} · {selectedVersion.status}</h3>
        <p className="muted">Lineage source: {selectedVersion.source_version_id || "Initial family version"} · Tested by: {selectedVersion.tested_by_user_id || "-"} · Approved by: {selectedVersion.approved_by_user_id || "-"} · Published by: {selectedVersion.published_by_user_id || "-"}</p>
        {selectedVersion.status === "PUBLISHED" && <div className="inline-warning">Published versions are immutable runtime contracts. Create a new Draft revision to change the definition.</div>}
        {selectedVersion.status === "RETIRED" && <div className="inline-warning">Retired versions remain visible for auditability and exact-version lineage. They cannot be edited in place.</div>}
        {["TESTED", "APPROVED"].includes(selectedVersion.status) && <div className="inline-warning">Editing this version is allowed only by invalidating its current Test/Approval evidence; the backend will return it to Draft.</div>}
        <label>Definition JSON<Textarea unstyled rows={20} readOnly={!editable || !canManage} value={definitionText} onChange={(event) => setDefinitionText(event.target.value)} /></label>
        {canManage && editable && <label>Change note<Input unstyled value={changeNote} maxLength={1000} onChange={(event) => setChangeNote(event.target.value)} /></label>}
        {canManage && <div className="actions">
          {editable && <Button unstyled disabled={busy} onClick={() => void saveDefinition()}>{selectedVersion.status === "DRAFT" ? "Save Draft definition" : "Save definition as Draft"}</Button>}
          <Button unstyled className="secondary" disabled={busy} onClick={() => void cloneVersion()}>New Draft revision from selected</Button>
          <Button unstyled className="secondary" disabled={busy} onClick={() => void cloneFamily()}>Clone family from selected</Button>
          {testable && <Button unstyled disabled={busy} onClick={() => void lifecycleAction("test", "Configuration template version passed definition/adapter Test without a device connection.")}>Test definition (no device connection)</Button>}
          {approvable && <Button unstyled disabled={busy} onClick={() => void lifecycleAction("approve", "Configuration template version approved.")}>Approve version</Button>}
          {publishable && <Button unstyled disabled={busy} onClick={() => void lifecycleAction("activate", "Configuration template version published; any previous Published version is now Retired.")}>Publish version</Button>}
        </div>}
        {selectedVersion.status === "APPROVED" && selected?.template.is_active === false && <p className="muted">Publication is blocked because this template family is inactive.</p>}
      </div>
    </>}

    {!catalog.length && <p className="muted">No configuration template families are visible in the current global request scope.</p>}
  </section>;
}
