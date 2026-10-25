import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../../api/client";
import { Button, Checkbox, Input, Select, Textarea } from "../../design-system/primitives";
import { useDialog } from "../../components/common/DialogSystem";
import { useFeedback } from "../../components/common/FeedbackSystem";
import { friendlyError } from "../../utils/feedback";
import { openWebTemplateWizardPreview } from "./webTemplateWizardRemoteAccess";


type CredentialMode = "USERNAME_PASSWORD" | "PASSWORD_ONLY";
type Visibility = "PRIVATE" | "SHARED";
type Protocol = "SNMP" | "SSH" | "TELNET" | "WEB";
type DiscoveryMode = "AUTO" | "MANUAL";
type ManualAuthMode = "FORM_POST" | "HTTP_BASIC" | "HTTP_DIGEST";

type WizardTemplate = {
  id: string;
  name: string;
  protocol: "WEB";
  protocol_variant: string | null;
  visibility: Visibility;
  is_active: boolean;
  settings: Record<string, unknown>;
};

type DeletedTemplate = {
  id: string;
  name: string;
  protocol: Protocol;
  protocol_variant: string | null;
  visibility: Visibility;
  is_active: boolean;
};

type Discovery = {
  device_id: string;
  device_name: string;
  vendor: string | null;
  model: string | null;
  management_ip: string;
  scheme: "HTTP" | "HTTPS";
  port: number;
  auth_mode: "FORM_POST" | "HTTP_BASIC" | "HTTP_DIGEST";
  credential_mode: CredentialMode;
  settings: Record<string, unknown>;
  landing_path: string;
  form_encoding: string | null;
  username_field: string | null;
  password_field: string | null;
  confidence: "HIGH" | "MEDIUM" | "LOW";
  reference_transport_applied: boolean;
};

type WizardStart = {
  template: WizardTemplate;
  discovery: Discovery;
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

function authModeLabel(value: Discovery["auth_mode"]): string {
  return {
    FORM_POST: "HTML form login",
    HTTP_BASIC: "HTTP Basic",
    HTTP_DIGEST: "HTTP Digest",
  }[value];
}

function credentialModeLabel(value: CredentialMode): string {
  return value === "PASSWORD_ONLY" ? "Password only" : "Username + password";
}

export function WebTemplateWizard({
  token,
  permissions,
  onCompleted,
}: {
  token: string;
  permissions: string[];
  onCompleted?: () => void | Promise<void>;
}) {
  const dialog = useDialog();
  const feedback = useFeedback();
  const canManage = permissions.includes("access_template.manage");
  const canTest = permissions.includes("access_template.test");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [visibility, setVisibility] = useState<Visibility>("PRIVATE");
  const [managementIp, setManagementIp] = useState("");
  const [credentialMode, setCredentialMode] = useState<CredentialMode>("USERNAME_PASSWORD");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [timeoutSeconds, setTimeoutSeconds] = useState("10");
  const [applyReferenceTransport, setApplyReferenceTransport] = useState(true);
  const [discoveryMode, setDiscoveryMode] = useState<DiscoveryMode>("AUTO");
  const [autoDiscoveryFailed, setAutoDiscoveryFailed] = useState(false);
  const [manualScheme, setManualScheme] = useState<"HTTP" | "HTTPS">("HTTPS");
  const [manualPort, setManualPort] = useState("443");
  const [manualAuthMode, setManualAuthMode] = useState<ManualAuthMode>("FORM_POST");
  const [manualLoginPagePath, setManualLoginPagePath] = useState("/");
  const [manualLoginSubmitPath, setManualLoginSubmitPath] = useState("/");
  const [manualUsernameField, setManualUsernameField] = useState("username");
  const [manualPasswordField, setManualPasswordField] = useState("password");
  const [manualCaptureHiddenFields, setManualCaptureHiddenFields] = useState(true);
  const [manualSuccessPathPrefix, setManualSuccessPathPrefix] = useState("");
  const [manualSuccessText, setManualSuccessText] = useState("");
  const [manualFailureText, setManualFailureText] = useState("");
  const [result, setResult] = useState<WizardStart | null>(null);
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [previewSessionId, setPreviewSessionId] = useState<string | null>(null);
  const [previewConfirmed, setPreviewConfirmed] = useState(false);
  const [assignReferenceDevice, setAssignReferenceDevice] = useState(false);
  const [busy, setBusy] = useState(false);
  const [deletedTemplates, setDeletedTemplates] = useState<DeletedTemplate[]>([]);
  const [recycleBusy, setRecycleBusy] = useState(false);

  const loadDeletedTemplates = useCallback(async () => {
    if (!canManage) return;
    setDeletedTemplates(await apiFetch<DeletedTemplate[]>("/access-templates/deleted", {}, token));
  }, [canManage, token]);

  useEffect(() => {
    if (!canManage) return;
    void loadDeletedTemplates().catch((error) => feedback.error(friendlyError(error, "Unable to load deleted Access Templates.")));
  }, [canManage, loadDeletedTemplates, feedback]);

  if (!canManage) return null;

  const reset = () => {
    setName("");
    setDescription("");
    setVisibility("PRIVATE");
    setManagementIp("");
    setCredentialMode("USERNAME_PASSWORD");
    setUsername("");
    setPassword("");
    setTimeoutSeconds("10");
    setApplyReferenceTransport(true);
    setDiscoveryMode("AUTO");
    setAutoDiscoveryFailed(false);
    setManualScheme("HTTPS");
    setManualPort("443");
    setManualAuthMode("FORM_POST");
    setManualLoginPagePath("/");
    setManualLoginSubmitPath("/");
    setManualUsernameField("username");
    setManualPasswordField("password");
    setManualCaptureHiddenFields(true);
    setManualSuccessPathPrefix("");
    setManualSuccessText("");
    setManualFailureText("");
    setResult(null);
    setTestResult(null);
    setPreviewSessionId(null);
    setPreviewConfirmed(false);
    setAssignReferenceDevice(false);
  };

  const selectManualAuthMode = (mode: ManualAuthMode) => {
    setManualAuthMode(mode);
    if (mode !== "FORM_POST") setCredentialMode("USERNAME_PASSWORD");
  };

  const selectManualScheme = (scheme: "HTTP" | "HTTPS") => {
    setManualScheme(scheme);
    setManualPort(scheme === "HTTPS" ? "443" : "80");
  };

  const discover = async () => {
    if (!name.trim() || !managementIp.trim() || !password) {
      feedback.error("Template name, reference management IP, and password are required.");
      return;
    }
    if (credentialMode === "USERNAME_PASSWORD" && !username) {
      feedback.error("Username is required for a username + password device.");
      return;
    }
    if (discoveryMode === "MANUAL") {
      const port = Number(manualPort);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        feedback.error("Manual Web port must be an integer between 1 and 65535.");
        return;
      }
      if (manualAuthMode === "FORM_POST" && !manualPasswordField.trim()) {
        feedback.error("Password field is required for manual form authentication.");
        return;
      }
      if (manualAuthMode === "FORM_POST" && credentialMode === "USERNAME_PASSWORD" && !manualUsernameField.trim()) {
        feedback.error("Username field is required for this manual form login.");
        return;
      }
    }
    setBusy(true);
    setResult(null);
    setTestResult(null);
    setPreviewSessionId(null);
    setPreviewConfirmed(false);
    try {
      const created = await apiFetch<WizardStart>(
        "/access-templates/web-wizard/start",
        {
          method: "POST",
          body: JSON.stringify({
            name: name.trim(),
            description: description.trim() || null,
            visibility,
            management_ip: managementIp.trim(),
            credential_mode: credentialMode,
            ...(credentialMode === "USERNAME_PASSWORD" ? { username } : {}),
            password,
            timeout_seconds: Number(timeoutSeconds || 10),
            apply_reference_transport: applyReferenceTransport,
            discovery_mode: discoveryMode,
            ...(discoveryMode === "MANUAL" ? {
              manual_scheme: manualScheme,
              manual_port: Number(manualPort),
              manual_auth_mode: manualAuthMode,
              manual_login_page_path: manualLoginPagePath.trim() || "/",
              manual_login_submit_path: manualLoginSubmitPath.trim() || "/",
              manual_username_field: manualUsernameField.trim() || "username",
              manual_password_field: manualPasswordField.trim() || "password",
              manual_capture_hidden_fields: manualCaptureHiddenFields,
              manual_success_path_prefix: manualSuccessPathPrefix.trim() || null,
              manual_success_text: manualSuccessText.trim() || null,
              manual_failure_text: manualFailureText.trim() || null,
            } : {}),
          }),
        },
        token,
      );
      setResult(created);
      setAutoDiscoveryFailed(false);
      setUsername("");
      setPassword("");
      feedback.success(discoveryMode === "MANUAL"
        ? "Manual Web login contract verified. An inactive, unassigned draft was created with encrypted credentials."
        : "Secure Web blueprint discovered. An inactive, unassigned draft was created with encrypted credentials.");
    } catch (error) {
      if (discoveryMode === "AUTO") setAutoDiscoveryFailed(true);
      feedback.error(friendlyError(error, discoveryMode === "MANUAL"
        ? "Unable to verify the manual Web login contract."
        : "Unable to discover the reference device Web login."));
    } finally {
      setBusy(false);
    }
  };

  const runTest = async () => {
    if (!result || !canTest) return;
    setBusy(true);
    setTestResult(null);
    setPreviewSessionId(null);
    setPreviewConfirmed(false);
    try {
      const tested = await apiFetch<TestResult>(
        `/access-templates/web-wizard/${result.template.id}/test`,
        {
          method: "POST",
          body: JSON.stringify({ device_id: result.discovery.device_id }),
        },
        token,
      );
      setTestResult(tested);
      if (tested.status === "SUCCESS") feedback.success("Draft connection test passed.");
      else feedback.error(`${tested.failure_code || "WEB_TEST_FAILED"} — ${tested.sanitized_message || "The draft connection test failed."}`);
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to test the discovered Secure Web template."));
    } finally {
      setBusy(false);
    }
  };

  const openPreview = async () => {
    if (!result || testResult?.status !== "SUCCESS" || !canTest) return;
    setBusy(true);
    setPreviewSessionId(null);
    setPreviewConfirmed(false);
    try {
      const sessionId = await openWebTemplateWizardPreview(
        token,
        result.template.id,
        result.discovery.device_id,
        result.discovery.device_name,
      );
      setPreviewSessionId(sessionId);
      feedback.success("Secure GUI preview opened. Verify that the device GUI is already authenticated, then confirm below.");
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to open the authenticated Secure GUI preview."));
    } finally {
      setBusy(false);
    }
  };

  const confirmTemplate = async () => {
    if (!result || !previewSessionId || !previewConfirmed) return;
    setBusy(true);
    try {
      await apiFetch<WizardTemplate>(
        `/access-templates/web-wizard/${result.template.id}/confirm`,
        {
          method: "POST",
          body: JSON.stringify({
            device_id: result.discovery.device_id,
            preview_session_id: previewSessionId,
            assign_reference_device: assignReferenceDevice,
          }),
        },
        token,
      );
      feedback.success("Secure Web Access Template activated and is ready for reuse.");
      await onCompleted?.();
      reset();
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to activate the Secure Web Access Template."));
    } finally {
      setBusy(false);
    }
  };

  const restoreTemplate = async (template: DeletedTemplate) => {
    if (!await dialog.confirm({ message: `Restore ${template.name} as an inactive Access Template? Previous assignments will remain disabled.` })) return;
    setRecycleBusy(true);
    try {
      await apiFetch(`/access-templates/${template.id}/restore`, { method: "POST" }, token);
      await loadDeletedTemplates();
      await onCompleted?.();
      feedback.success(`${template.name} restored as inactive. Assignments remain disabled until explicitly recreated or enabled through normal management.`);
    } catch (error) {
      feedback.error(friendlyError(error, "Unable to restore the Access Template."));
    } finally {
      setRecycleBusy(false);
    }
  };

  return <>
    <section className="panel settings-web-template-wizard">
      <div className="panel-header">
        <div>
          <h3>Secure Web Template Wizard</h3>
          <span>Build a reusable Web-GUI login template from one known-good reference device. Automatic discovery is preferred; manual fallback is server-verified before any draft is created.</span>
        </div>
        {result && <Button unstyled className="secondary" disabled={busy} onClick={reset}>Start over</Button>}
      </div>

      {!result ? <>
        <div className="inline-status-message">
          The reference IP must already be registered as a management IP in FTTW. Discovery is restricted to that device and never becomes a general network scanner.
        </div>
        <div className="form-grid three">
          <label>Template name<Input unstyled value={name} disabled={busy} placeholder="Example: AirOS M2 Web login" onChange={(event) => setName(event.target.value)} /></label>
          <label>Reference management IP<Input unstyled value={managementIp} disabled={busy} placeholder="192.168.0.1" onChange={(event) => setManagementIp(event.target.value)} /></label>
          <label>Visibility<Select unstyled value={visibility} disabled={busy} onChange={(event) => setVisibility(event.target.value as Visibility)}><option value="PRIVATE">Private</option><option value="SHARED">Shared</option></Select></label>
        </div>
        <label>Description<Textarea unstyled rows={2} value={description} disabled={busy} placeholder="Optional device family / firmware notes" onChange={(event) => setDescription(event.target.value)} /></label>
        <div className="form-grid three">
          <label>Discovery mode<Select unstyled value={discoveryMode} disabled={busy} onChange={(event) => { setDiscoveryMode(event.target.value as DiscoveryMode); setAutoDiscoveryFailed(false); }}><option value="AUTO">Automatic discovery</option><option value="MANUAL">Manual fallback (server verified)</option></Select></label>
          <label>Device login requirement<Select unstyled value={credentialMode} disabled={busy || (discoveryMode === "MANUAL" && manualAuthMode !== "FORM_POST")} onChange={(event) => { setCredentialMode(event.target.value as CredentialMode); setUsername(""); }}><option value="USERNAME_PASSWORD">Username + password</option><option value="PASSWORD_ONLY">Password only</option></Select></label>
          {credentialMode === "USERNAME_PASSWORD" && <label>Reference username<Input unstyled value={username} disabled={busy} autoComplete="off" onChange={(event) => setUsername(event.target.value)} /></label>}
          <label>Reference password<Input unstyled type="password" value={password} disabled={busy} autoComplete="new-password" onChange={(event) => setPassword(event.target.value)} /></label>
          <label>Discovery timeout (seconds)<Input unstyled type="number" min="1" max="30" value={timeoutSeconds} disabled={busy} onChange={(event) => setTimeoutSeconds(event.target.value)} /></label>
        </div>

        {autoDiscoveryFailed && discoveryMode === "AUTO" && <div className="inline-status-message">
          Automatic discovery did not produce a usable login contract. If you know the device's login behavior, use the manual fallback; FTTW will verify it server-side before creating a draft.
          <div className="button-row"><Button unstyled className="secondary" disabled={busy} onClick={() => setDiscoveryMode("MANUAL")}>Use manual fallback</Button></div>
        </div>}

        {discoveryMode === "MANUAL" && <div className="panel-subsection">
          <h4>Manual Secure-Web fallback</h4>
          <p className="field-help">Use this only when automatic discovery cannot identify the login contract. Paths must be target-relative. FTTW authenticates with these values on the server first; a failed manual contract creates no Access Template draft.</p>
          <div className="form-grid three">
            <label>Scheme<Select unstyled value={manualScheme} disabled={busy} onChange={(event) => selectManualScheme(event.target.value as "HTTP" | "HTTPS")}><option value="HTTPS">HTTPS</option><option value="HTTP">HTTP</option></Select></label>
            <label>Port<Input unstyled type="number" min="1" max="65535" value={manualPort} disabled={busy} onChange={(event) => setManualPort(event.target.value)} /></label>
            <label>Authentication<Select unstyled value={manualAuthMode} disabled={busy} onChange={(event) => selectManualAuthMode(event.target.value as ManualAuthMode)}><option value="FORM_POST">HTML form (POST)</option><option value="HTTP_BASIC">HTTP Basic</option><option value="HTTP_DIGEST">HTTP Digest</option></Select></label>
          </div>
          {manualAuthMode === "FORM_POST" && <>
            <div className="form-grid two">
              <label>Login page path<Input unstyled value={manualLoginPagePath} disabled={busy} placeholder="/" onChange={(event) => setManualLoginPagePath(event.target.value)} /><span className="muted">Target-relative path only.</span></label>
              <label>Login submit path<Input unstyled value={manualLoginSubmitPath} disabled={busy} placeholder="/login" onChange={(event) => setManualLoginSubmitPath(event.target.value)} /><span className="muted">Target-relative POST path only.</span></label>
              {credentialMode === "USERNAME_PASSWORD" && <label>Username field<Input unstyled value={manualUsernameField} disabled={busy} placeholder="username" onChange={(event) => setManualUsernameField(event.target.value)} /></label>}
              <label>Password field<Input unstyled value={manualPasswordField} disabled={busy} placeholder="password" onChange={(event) => setManualPasswordField(event.target.value)} /></label>
              <label>Success path prefix<Input unstyled value={manualSuccessPathPrefix} disabled={busy} placeholder="Optional: /index" onChange={(event) => setManualSuccessPathPrefix(event.target.value)} /></label>
              <label>Success text<Input unstyled value={manualSuccessText} disabled={busy} placeholder="Optional authenticated-page marker" onChange={(event) => setManualSuccessText(event.target.value)} /></label>
              <label>Failure text<Input unstyled value={manualFailureText} disabled={busy} placeholder="Optional login-failure marker" onChange={(event) => setManualFailureText(event.target.value)} /></label>
            </div>
            <label className="check-item"><Checkbox unstyled checked={manualCaptureHiddenFields} disabled={busy} onChange={(event) => setManualCaptureHiddenFields(event.target.checked)} />Preserve hidden login fields such as CSRF tokens</label>
          </>}
        </div>}

        <label className="check-item"><Checkbox unstyled checked={applyReferenceTransport} disabled={busy} onChange={(event) => setApplyReferenceTransport(event.target.checked)} />Apply the {discoveryMode === "MANUAL" ? "verified" : "detected"} HTTP/HTTPS scheme and port to this reference device after successful discovery</label>
        <p className="field-help">The username/password are used only by the server-side discovery flow. On success they are stored using Access Template encrypted secret storage; they are never returned to the browser.</p>
        <div className="button-row"><Button unstyled disabled={busy} onClick={() => void discover()}>{busy ? "Working..." : discoveryMode === "MANUAL" ? "Verify Manual Contract & Build Draft" : "Discover & Build Draft"}</Button>{discoveryMode === "MANUAL" && <Button unstyled className="secondary" disabled={busy} onClick={() => { setDiscoveryMode("AUTO"); setAutoDiscoveryFailed(false); }}>Back to automatic</Button>}</div>
      </> : <>
        <div className="inline-status-message">Step 1 complete — {discoveryMode === "MANUAL" ? "manual contract verification" : "discovery"} succeeded. The template is still <strong>inactive and unassigned</strong>.</div>
        <div className="stats-grid">
          <div><span>Reference device</span><strong>{result.discovery.device_name}</strong><small>{result.discovery.management_ip}</small></div>
          <div><span>Transport</span><strong>{result.discovery.scheme} / {result.discovery.port}</strong><small>{result.discovery.reference_transport_applied ? "Applied to reference device" : "Reference profile unchanged"}</small></div>
          <div><span>Authentication</span><strong>{authModeLabel(result.discovery.auth_mode)}</strong><small>{credentialModeLabel(result.discovery.credential_mode)}</small></div>
          <div><span>Confidence</span><strong>{result.discovery.confidence}</strong><small>{discoveryMode === "MANUAL" ? "server-verified manual contract" : "authenticated discovery"}</small></div>
        </div>

        <h4>{discoveryMode === "MANUAL" ? "Verified blueprint" : "Discovered blueprint"}</h4>
        <div className="form-grid three">
          <label>Login page<Input unstyled readOnly value={String(result.discovery.settings.login_page_path || "Not applicable")} /></label>
          <label>Submit path<Input unstyled readOnly value={String(result.discovery.settings.login_submit_path || "Not applicable")} /></label>
          <label>Form encoding<Input unstyled readOnly value={result.discovery.form_encoding || "Not applicable"} /></label>
          {result.discovery.credential_mode === "USERNAME_PASSWORD" && <label>Username field<Input unstyled readOnly value={result.discovery.username_field || "HTTP authentication"} /></label>}
          <label>Password field<Input unstyled readOnly value={result.discovery.password_field || "HTTP authentication"} /></label>
          <label>Authenticated landing path<Input unstyled readOnly value={result.discovery.landing_path} /></label>
        </div>
        <p className="field-help">Advanced values remain visible for troubleshooting. Manual fallback values reached this stage only after successful server-side authentication.</p>

        <div className="panel-subsection">
          <h4>Step 2 — Automated connection test</h4>
          <p className="field-help">FTTW replays the saved draft against the reference device using only server-side credentials. Editing the draft afterwards invalidates this test and requires a new pass.</p>
          <Button unstyled className="secondary" disabled={busy || !canTest} onClick={() => void runTest()}>Run connection test</Button>
          {testResult && <div className={testResult.status === "SUCCESS" ? "field-help" : "inline-status-message"}>
            <strong>{testResult.status}</strong>{testResult.failure_code ? ` — ${testResult.failure_code}` : ""} — {testResult.sanitized_message || "No message"}{testResult.latency_ms != null ? ` (${testResult.latency_ms} ms)` : ""}
          </div>}
        </div>

        <div className="panel-subsection">
          <h4>Step 3 — Human Secure GUI acceptance</h4>
          <p className="field-help">Open the GUI through the same broker used in production. Confirm visually that you land inside the device already authenticated. The preview must follow the current successful test.</p>
          <Button unstyled className="secondary" disabled={busy || testResult?.status !== "SUCCESS" || !canTest} onClick={() => void openPreview()}>Open authenticated Secure GUI preview</Button>
          {previewSessionId && <>
            <label className="check-item"><Checkbox unstyled checked={previewConfirmed} disabled={busy} onChange={(event) => setPreviewConfirmed(event.target.checked)} />I confirmed that the reference device GUI opened successfully and was already authenticated.</label>
            <label className="check-item"><Checkbox unstyled checked={assignReferenceDevice} disabled={busy} onChange={(event) => setAssignReferenceDevice(event.target.checked)} />Also assign this new template directly to the reference device when activating it</label>
            <div className="button-row"><Button unstyled disabled={busy || !previewConfirmed} onClick={() => void confirmTemplate()}>Confirm & Activate Template</Button></div>
          </>}
        </div>
      </>}
    </section>

    <section className="panel settings-access-template-recovery">
      <div className="panel-header">
        <div>
          <h3>Deleted Access Templates</h3>
          <span>Recover an owned template without making it effective again automatically.</span>
        </div>
        <Button unstyled className="secondary" disabled={recycleBusy} onClick={() => void loadDeletedTemplates()}>Refresh</Button>
      </div>
      <p className="field-help">A restored template remains inactive and all previous assignments remain disabled. Review and explicitly activate/reassign it through normal Access Template management.</p>
      {deletedTemplates.length === 0 ? <div className="field-help">No deleted Access Templates.</div> : <div className="stats-grid">
        {deletedTemplates.map((template) => <div key={template.id}>
          <strong>{template.name}</strong>
          <div className="field-help">{template.protocol}{template.protocol_variant ? ` / ${template.protocol_variant}` : ""} — {template.visibility}</div>
          <Button unstyled className="small secondary" disabled={recycleBusy} onClick={() => void restoreTemplate(template)}>Restore inactive</Button>
        </div>)}
      </div>}
    </section>
  </>;
}
