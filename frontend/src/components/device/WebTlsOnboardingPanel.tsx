import { useCallback, useEffect, useMemo, useState } from "react";
import { apiFetch } from "../../api/client";
import { Button, Input, Select } from "../../design-system/primitives";
import type { Device } from "../../types";
import { useDialog } from "../common/DialogSystem";
import { useFeedback } from "../common/FeedbackSystem";
import { friendlyError } from "../../utils/feedback";
import { notifyDeviceAccessChanged } from "../../utils/deviceAccess";

type WebTemplate = {
  id: string;
  name: string;
  protocol: "WEB";
  protocol_variant: string | null;
  is_active: boolean;
};

type WebStatus = {
  web_enabled: boolean;
  web_scheme: "HTTP" | "HTTPS";
  web_port: number | null;
  effective_web_port: number;
  web_tls_mode: "SYSTEM" | "PRIVATE_CA" | "PINNED_CERT";
  web_tls_compat_profile: "MODERN" | "LEGACY_WEAK_CERT_KEY";
  internal_tls_trust_configured: boolean;
  internal_tls_trust_fingerprint: string | null;
  ready: boolean;
};

type Inspection = {
  device_id: string;
  device_name: string;
  management_ip: string;
  port: number;
  compatibility_profile: "MODERN" | "LEGACY_WEAK_CERT_KEY";
  certificate_sha256: string;
  subject: string;
  issuer: string;
  serial_number: string;
  not_valid_before: string;
  not_valid_after: string;
  san_dns: string[];
  san_ip: string[];
  self_signed: boolean;
  validity_state: "VALID" | "EXPIRED" | "NOT_YET_VALID";
  current_trusted_certificate_sha256: string | null;
  trust_relation: "UNTRUSTED" | "MATCH" | "MISMATCH";
  credentials_sent: false;
  application_data_sent: false;
  observed_at: string;
};

type TestResult = {
  id: string;
  status: "SUCCESS" | "FAILED";
  failure_code: string | null;
  sanitized_message: string | null;
  latency_ms: number | null;
};

function shortFingerprint(value: string | null | undefined): string {
  if (!value) return "—";
  return `${value.slice(0, 16)}…${value.slice(-16)}`;
}

export function WebTlsOnboardingPanel({
  token,
  device,
  permissions,
}: {
  token: string;
  device: Pick<Device, "id" | "display_name" | "management_ip" | "lifecycle_state">;
  permissions: string[];
}) {
  const dialog = useDialog();
  const feedback = useFeedback();
  const canWeb = permissions.includes("device.remote_access.web");
  const canTrust = permissions.includes("device.remote_access.web.trust");
  const canReadTemplates = permissions.includes("access_template.read");
  const canTest = permissions.includes("access_template.test");
  const canAssign = permissions.includes("access_template.manage");

  const [templates, setTemplates] = useState<WebTemplate[]>([]);
  const [templateId, setTemplateId] = useState("");
  const [port, setPort] = useState("443");
  const [compatibility, setCompatibility] = useState<"MODERN" | "LEGACY_WEAK_CERT_KEY">("MODERN");
  const [inspection, setInspection] = useState<Inspection | null>(null);
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [trusted, setTrusted] = useState(false);
  const [busy, setBusy] = useState<"LOAD" | "INSPECT" | "TRUST" | "TEST" | "ASSIGN" | null>(null);

  const selectedTemplate = useMemo(
    () => templates.find((item) => item.id === templateId) || null,
    [templates, templateId],
  );

  const load = useCallback(async () => {
    if (!canWeb || !canReadTemplates) return;
    setBusy("LOAD");
    try {
      const [visible, status] = await Promise.all([
        apiFetch<WebTemplate[]>("/access-templates?protocol=WEB", {}, token),
        apiFetch<WebStatus>(`/devices/${device.id}/remote-access/web`, {}, token),
      ]);
      const active = visible.filter((item) => item.protocol === "WEB" && item.is_active);
      setTemplates(active);
      setTemplateId((current) => active.some((item) => item.id === current) ? current : (active[0]?.id || ""));
      setPort(String(status.effective_web_port || 443));
      setCompatibility(status.web_tls_compat_profile || "MODERN");
      setTrusted(Boolean(status.internal_tls_trust_configured && status.internal_tls_trust_fingerprint));
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to load Secure Web onboarding prerequisites."));
    } finally {
      setBusy(null);
    }
  }, [canReadTemplates, canWeb, device.id, feedback, token]);

  useEffect(() => {
    setInspection(null);
    setTestResult(null);
    setTrusted(false);
    void load();
  }, [device.id, load]);

  if (!canWeb || !canReadTemplates) return null;

  const parsedPort = Number(port);
  const portValid = Number.isInteger(parsedPort) && parsedPort >= 1 && parsedPort <= 65535;
  const readyToInspect = Boolean(selectedTemplate && portValid && device.lifecycle_state !== "DECOMMISSIONED");

  const inspect = async () => {
    if (!readyToInspect) return;
    setBusy("INSPECT");
    setInspection(null);
    setTestResult(null);
    try {
      const result = await apiFetch<Inspection>(`/devices/${device.id}/remote-access/web/tls/inspect`, {
        method: "POST",
        body: JSON.stringify({ port: parsedPort, compatibility_profile: compatibility }),
      }, token);
      setInspection(result);
      setTrusted(result.trust_relation === "MATCH");
      if (result.trust_relation === "MATCH") feedback.success("The observed HTTPS certificate matches this device's current trust.");
      else if (result.trust_relation === "MISMATCH") feedback.error("The observed HTTPS certificate differs from the currently trusted certificate. Explicit replacement is required.");
      else feedback.success("Certificate inspected without sending device credentials. Review it before trusting.");
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to inspect the device HTTPS certificate."));
    } finally {
      setBusy(null);
    }
  };

  const trustOrReplace = async () => {
    if (!inspection || !canTrust || inspection.validity_state !== "VALID") return;
    const replacing = inspection.trust_relation === "MISMATCH";
    const confirmed = await dialog.confirm({
      title: replacing ? "Replace trusted HTTPS certificate" : "Trust HTTPS certificate",
      message: replacing
        ? `The device certificate changed. Current: ${shortFingerprint(inspection.current_trusted_certificate_sha256)}. Observed: ${shortFingerprint(inspection.certificate_sha256)}. Replace trust only if you independently expect this device certificate change.`
        : `Trust the observed certificate for ${device.display_name}? SHA-256: ${inspection.certificate_sha256}. FTTW will re-observe the certificate before committing trust.`,
      confirmLabel: replacing ? "Replace trusted certificate" : "Trust & Continue",
      tone: replacing ? "danger" : "default",
    });
    if (!confirmed) return;
    setBusy("TRUST");
    try {
      if (replacing) {
        await apiFetch(`/devices/${device.id}/remote-access/web/tls/replace`, {
          method: "POST",
          body: JSON.stringify({
            port: parsedPort,
            compatibility_profile: compatibility,
            current_certificate_sha256: inspection.current_trusted_certificate_sha256,
            expected_new_certificate_sha256: inspection.certificate_sha256,
            acknowledge_certificate_change: true,
          }),
        }, token);
      } else {
        await apiFetch(`/devices/${device.id}/remote-access/web/tls/trust`, {
          method: "POST",
          body: JSON.stringify({
            port: parsedPort,
            compatibility_profile: compatibility,
            expected_certificate_sha256: inspection.certificate_sha256,
          }),
        }, token);
      }
      setTrusted(true);
      setInspection({ ...inspection, trust_relation: "MATCH", current_trusted_certificate_sha256: inspection.certificate_sha256 });
      notifyDeviceAccessChanged(device.id);
      feedback.success(replacing ? "HTTPS certificate trust replaced explicitly." : "HTTPS certificate trusted for this device.");
    } catch (error) {
      feedback.error(friendlyError(error, replacing ? "Unable to replace the trusted certificate." : "Unable to trust the certificate."));
    } finally {
      setBusy(null);
    }
  };

  const testTemplate = async () => {
    if (!trusted || !templateId || !canTest) return;
    setBusy("TEST");
    setTestResult(null);
    try {
      const result = await apiFetch<TestResult>(`/access-templates/${templateId}/test`, {
        method: "POST",
        body: JSON.stringify({ device_id: device.id }),
      }, token);
      setTestResult(result);
      if (result.status === "SUCCESS") feedback.success(`WEB Access Template test passed for ${device.display_name}.`);
      else feedback.error(`${result.failure_code || "WEB_TEST_FAILED"} — ${result.sanitized_message || "WEB Access Template test failed."}`);
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to test the selected WEB Access Template."));
    } finally {
      setBusy(null);
    }
  };

  const assignTemplate = async () => {
    if (testResult?.status !== "SUCCESS" || !templateId || !canAssign) return;
    if (!await dialog.confirm({
      title: "Assign WEB Access Template",
      message: `Assign ${selectedTemplate?.name || "the selected WEB template"} directly to ${device.display_name}? This changes template resolution only; it does not execute device configuration.`,
      confirmLabel: "Assign template",
    })) return;
    setBusy("ASSIGN");
    try {
      await apiFetch(`/access-templates/${templateId}/assignments`, {
        method: "POST",
        body: JSON.stringify({ scope_type: "DEVICE", scope_id: device.id, priority: 0, enabled: true }),
      }, token);
      notifyDeviceAccessChanged(device.id);
      feedback.success(`WEB Access Template assigned directly to ${device.display_name}.`);
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to assign the selected WEB Access Template."));
    } finally {
      setBusy(null);
    }
  };

  return <div className="panel-subsection">
    <h4>Secure Web onboarding</h4>
    <p className="field-help">Device-specific TLS trust is separate from reusable WEB credentials. Certificate inspection performs only a TLS handshake and sends no device credentials or HTTP application data.</p>
    <div className="inline-form">
      <Select unstyled aria-label="Approved WEB Access Template" value={templateId} disabled={busy !== null} onChange={(event) => { setTemplateId(event.target.value); setTestResult(null); }}>
        <option value="">Select active WEB template...</option>
        {templates.map((item) => <option key={item.id} value={item.id}>{item.name}{item.protocol_variant ? ` / ${item.protocol_variant}` : ""}</option>)}
      </Select>
      <Input unstyled type="number" min="1" max="65535" aria-label="HTTPS port" value={port} disabled={busy !== null} onChange={(event) => { setPort(event.target.value); setInspection(null); setTrusted(false); setTestResult(null); }} />
      <Select unstyled aria-label="TLS compatibility" value={compatibility} disabled={busy !== null} onChange={(event) => { setCompatibility(event.target.value as "MODERN" | "LEGACY_WEAK_CERT_KEY"); setInspection(null); setTrusted(false); setTestResult(null); }}>
        <option value="MODERN">Modern TLS</option>
        <option value="LEGACY_WEAK_CERT_KEY">Legacy weak certificate key</option>
      </Select>
      <Button unstyled className="secondary" disabled={!readyToInspect || busy !== null} onClick={() => void inspect()}>{busy === "INSPECT" ? "Inspecting..." : "Inspect certificate"}</Button>
    </div>
    {inspection && <div className={inspection.trust_relation === "MISMATCH" ? "inline-status-message" : "field-help"}>
      <strong>{inspection.trust_relation === "MATCH" ? "Trusted certificate match" : inspection.trust_relation === "MISMATCH" ? "Certificate mismatch" : "Certificate not yet trusted"}</strong>
      {` — SHA-256 ${inspection.certificate_sha256}. Subject: ${inspection.subject || "(empty)"}. Issuer: ${inspection.issuer || "(empty)"}. Valid ${new Date(inspection.not_valid_before).toLocaleString()} to ${new Date(inspection.not_valid_after).toLocaleString()}. `}
      {inspection.self_signed ? "Self-signed. " : ""}
      {`Inspection sent credentials: ${inspection.credentials_sent ? "yes" : "no"}; application data: ${inspection.application_data_sent ? "yes" : "no"}.`}
    </div>}
    {inspection && !trusted && canTrust && <div className="button-row">
      <Button unstyled className={inspection.trust_relation === "MISMATCH" ? "danger" : "secondary"} disabled={busy !== null || inspection.validity_state !== "VALID"} onClick={() => void trustOrReplace()}>
        {busy === "TRUST" ? "Confirming..." : inspection.trust_relation === "MISMATCH" ? "Replace trusted certificate" : "Trust & Continue"}
      </Button>
    </div>}
    {trusted && <div className="button-row">
      {canTest && <Button unstyled className="secondary" disabled={busy !== null || !templateId} onClick={() => void testTemplate()}>{busy === "TEST" ? "Testing..." : "Test WEB template"}</Button>}
      {canAssign && <Button unstyled className="secondary" disabled={busy !== null || testResult?.status !== "SUCCESS"} onClick={() => void assignTemplate()}>{busy === "ASSIGN" ? "Assigning..." : "Assign directly"}</Button>}
    </div>}
    {testResult && <div className={testResult.status === "SUCCESS" ? "field-help" : "inline-status-message"}><strong>{testResult.status}</strong>{testResult.failure_code ? ` — ${testResult.failure_code}` : ""}{testResult.sanitized_message ? ` — ${testResult.sanitized_message}` : ""}{testResult.latency_ms != null ? ` (${testResult.latency_ms} ms)` : ""}</div>}
    {!templates.length && busy !== "LOAD" && <div className="field-help">No active WEB Access Template is visible. Create, test, approve and activate a WEB template before onboarding this device.</div>}
  </div>;
}
