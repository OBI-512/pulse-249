import { useCallback, useEffect, useMemo, useState } from "react";
import { apiFetch } from "../../api/client";
import { useDialog } from "../common/DialogSystem";
import { useFeedback } from "../common/FeedbackSystem";
import { Button, Input, Select } from "../../design-system/primitives";
import type { Device } from "../../types";
import { friendlyError } from "../../utils/feedback";
import { notifyDeviceAccessChanged } from "../../utils/deviceAccess";

type Protocol = "SNMP" | "SSH" | "TELNET" | "WEB";
type ScopeType = "DEVICE" | "DEVICE_GROUP" | "LOGICAL_SECTOR" | "LOCATION" | "NETWORK" | "CITY";

type AccessTemplate = {
  id: string;
  name: string;
  protocol: Protocol;
  protocol_variant: string | null;
  visibility: "PRIVATE" | "SHARED";
  is_active: boolean;
};

type EffectiveAccess = {
  device_id: string;
  protocol: Protocol;
  status: "RESOLVED" | "NONE" | "CONFLICT";
  template_id?: string | null;
  template_name?: string | null;
  assignment_id?: string | null;
  scope_type?: ScopeType | null;
  priority?: number | null;
};

type TestResult = {
  id: string;
  template_id: string;
  device_id: string;
  status: "SUCCESS" | "FAILED";
  failure_code: string | null;
  sanitized_message: string | null;
  latency_ms: number | null;
  tested_at: string;
};

type SSHHostKeyAction = {
  action: "DISCOVER_HOST_KEY";
  device_id: string;
  template_id: string;
  template_name: string;
  fingerprint: string;
  key_type: string;
  port: number;
  compatibility_profile: string;
  pinned_fingerprint: string | null;
  trust_state: "NEW" | "MATCH" | "MISMATCH";
};

const PROTOCOLS: Protocol[] = ["SNMP", "SSH", "TELNET", "WEB"];

function scopeLabel(scope: ScopeType | null | undefined): string {
  if (!scope) return "";
  return {
    DEVICE: "Device",
    DEVICE_GROUP: "Device group",
    LOGICAL_SECTOR: "Logical sector",
    LOCATION: "Location",
    NETWORK: "Network",
    CITY: "City",
  }[scope];
}

function effectiveSummary(value: EffectiveAccess | undefined): string {
  if (!value || value.status === "NONE") return "No effective template";
  if (value.status === "CONFLICT") return "CONFLICT — multiple equally preferred templates";
  const source = value.scope_type ? ` via ${scopeLabel(value.scope_type)}` : "";
  const priority = value.priority != null ? `, priority ${value.priority}` : "";
  return `${value.template_name || "Resolved template"}${source}${priority}`;
}

export function DeviceAccessTemplatesPanel({
  token,
  device,
  permissions,
  onChanged,
}: {
  token: string;
  device: Pick<Device, "id" | "display_name" | "management_ip">;
  permissions: string[];
  onChanged?: () => void | Promise<void>;
}) {
  const dialog = useDialog();
  const feedback = useFeedback();
  const canRead = permissions.includes("access_template.read");
  const canManage = permissions.includes("access_template.manage");
  const canTest = permissions.includes("access_template.test");
  const [templates, setTemplates] = useState<AccessTemplate[]>([]);
  const [effective, setEffective] = useState<Partial<Record<Protocol, EffectiveAccess>>>({});
  const [testResults, setTestResults] = useState<Partial<Record<Protocol, TestResult>>>({});
  const [testingProtocol, setTestingProtocol] = useState<Protocol | null>(null);
  const [assignProtocol, setAssignProtocol] = useState<Protocol>("SSH");
  const [templateId, setTemplateId] = useState("");
  const [priority, setPriority] = useState("0");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!canRead) return;
    const [visibleTemplates, snmp, ssh, telnet, web] = await Promise.all([
      apiFetch<AccessTemplate[]>("/access-templates", {}, token),
      apiFetch<EffectiveAccess>(`/access-templates/effective/${device.id}/SNMP`, {}, token),
      apiFetch<EffectiveAccess>(`/access-templates/effective/${device.id}/SSH`, {}, token),
      apiFetch<EffectiveAccess>(`/access-templates/effective/${device.id}/TELNET`, {}, token),
      apiFetch<EffectiveAccess>(`/access-templates/effective/${device.id}/WEB`, {}, token),
    ]);
    setTemplates(visibleTemplates.filter((item) => item.is_active));
    setEffective({ SNMP: snmp, SSH: ssh, TELNET: telnet, WEB: web });
  }, [canRead, device.id, token]);

  useEffect(() => {
    if (!canRead) return;
    void load().catch((error) => feedback.error(friendlyError(error, "Unable to resolve device Access Templates.")));
  }, [canRead, load, feedback]);

  const protocolTemplates = useMemo(
    () => templates.filter((item) => item.protocol === assignProtocol),
    [templates, assignProtocol],
  );

  useEffect(() => {
    if (templateId && protocolTemplates.some((item) => item.id === templateId)) return;
    setTemplateId(protocolTemplates[0]?.id || "");
  }, [protocolTemplates, templateId]);

  if (!canRead) return null;

  const assignDirect = async () => {
    if (!canManage || !templateId) return;
    setBusy(true);
    try {
      await apiFetch(`/access-templates/${templateId}/assignments`, {
        method: "POST",
        body: JSON.stringify({
          scope_type: "DEVICE",
          scope_id: device.id,
          priority: Number(priority || 0),
          enabled: true,
        }),
      }, token);
      await load();
      await onChanged?.();
      notifyDeviceAccessChanged(device.id);
      feedback.success(`${assignProtocol} Access Template assigned directly to ${device.display_name}.`);
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to assign the Access Template."));
    } finally {
      setBusy(false);
    }
  };

  const removeDirect = async (value: EffectiveAccess) => {
    if (!canManage || value.status !== "RESOLVED" || value.scope_type !== "DEVICE" || !value.template_id || !value.assignment_id) return;
    if (!await dialog.confirm({ message: `Remove the direct ${value.protocol} Access Template assignment from ${device.display_name}?` })) return;
    setBusy(true);
    try {
      await apiFetch(`/access-templates/${value.template_id}/assignments/${value.assignment_id}`, { method: "DELETE" }, token);
      await load();
      await onChanged?.();
      notifyDeviceAccessChanged(device.id);
      feedback.success(`Direct ${value.protocol} Access Template assignment removed.`);
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to remove the direct Access Template assignment."));
    } finally {
      setBusy(false);
    }
  };

  const testEffective = async (value: EffectiveAccess) => {
    if (!canTest || value.status !== "RESOLVED" || !value.template_id) return;
    const protocol = value.protocol;
    setTestingProtocol(protocol);
    setTestResults((current) => ({ ...current, [protocol]: undefined }));
    try {
      let result = await apiFetch<TestResult | SSHHostKeyAction>(`/access-templates/${value.template_id}/test`, {
        method: "POST",
        body: JSON.stringify({ device_id: device.id }),
      }, token);

      if ("action" in result) {
        const replacing = result.trust_state === "MISMATCH";
        const message = replacing
          ? `The ${protocol} host key changed. Expected ${result.pinned_fingerprint || "no previous pin"}; observed ${result.fingerprint}. Trust the replacement and continue the test?`
          : `First-use SSH host key: ${result.fingerprint}. Trust this device-specific key and continue the test?`;
        if (!await dialog.confirm({ message })) return;
        result = await apiFetch<TestResult | SSHHostKeyAction>(`/access-templates/${value.template_id}/test`, {
          method: "POST",
          body: JSON.stringify({
            device_id: device.id,
            trust_host_key: true,
            expected_fingerprint: result.fingerprint,
            replace_existing: replacing,
          }),
        }, token);
        if ("action" in result) throw new Error("SSH host-key confirmation did not complete.");
      }

      const finalResult = result as TestResult;
      setTestResults((current) => ({ ...current, [protocol]: finalResult }));
      if (finalResult.status === "SUCCESS") feedback.success(`${protocol} Access Template test passed for ${device.display_name}.`);
      else feedback.error(`${finalResult.failure_code || `${protocol}_TEST_FAILED`} — ${finalResult.sanitized_message || "Access Template test failed."}`);
    } catch (error) {
      feedback.error(friendlyError(error, `Unable to test the effective ${protocol} Access Template.`));
    } finally {
      setTestingProtocol(null);
    }
  };

  return <div className="panel-subsection">
    <h4>Access Templates</h4>
    <p className="field-help">Effective credentials are resolved by protocol. Direct device assignments override group and geographic assignments. Secret values remain server-side.</p>
    <div className="stats-grid">
      {PROTOCOLS.map((protocol) => {
        const value = effective[protocol];
        const result = testResults[protocol];
        return <div key={protocol}>
          <strong>{protocol}</strong>
          <div className={value?.status === "CONFLICT" ? "inline-status-message" : "field-help"}>{effectiveSummary(value)}</div>
          {value?.status === "RESOLVED" && canTest && <Button unstyled className="small secondary" disabled={testingProtocol !== null || busy} onClick={() => void testEffective(value)}>{testingProtocol === protocol ? "Testing..." : "Test access"}</Button>}
          {value?.status === "RESOLVED" && value.scope_type === "DEVICE" && canManage && <Button unstyled className="small secondary" disabled={busy || testingProtocol !== null} onClick={() => void removeDirect(value)}>Remove direct assignment</Button>}
          {result && <div className={result.status === "SUCCESS" ? "field-help" : "inline-status-message"}><strong>{result.status}</strong>{result.failure_code ? ` — ${result.failure_code}` : ""}{result.sanitized_message ? ` — ${result.sanitized_message}` : ""}{result.latency_ms != null ? ` (${result.latency_ms} ms)` : ""}</div>}
          {protocol === "TELNET" && <div className="field-help">Legacy/insecure plaintext transport.</div>}
          {protocol === "WEB" && <div className="field-help">Gateway-side GUI authentication; credentials are never sent to the browser.</div>}
        </div>;
      })}
    </div>

    {canManage && <div className="inline-form">
      <Select unstyled aria-label="Access Template protocol" value={assignProtocol} onChange={(event) => setAssignProtocol(event.target.value as Protocol)}><option>SSH</option><option>SNMP</option><option>TELNET</option><option>WEB</option></Select>
      <Select unstyled aria-label="Access Template" value={templateId} onChange={(event) => setTemplateId(event.target.value)}><option value="">Select template...</option>{protocolTemplates.map((item) => <option key={item.id} value={item.id}>{item.name}{item.protocol_variant ? ` / ${item.protocol_variant}` : ""}</option>)}</Select>
      <Input unstyled type="number" min="-100000" max="100000" aria-label="Direct assignment priority" value={priority} onChange={(event) => setPriority(event.target.value)} />
      <Button unstyled className="secondary" disabled={busy || testingProtocol !== null || !templateId} onClick={() => void assignDirect()}>Assign directly</Button>
    </div>}

    <p className="field-help">Use the unified Remote access section for Secure GUI, SSH and Telnet launch actions.</p>
  </div>;
}
