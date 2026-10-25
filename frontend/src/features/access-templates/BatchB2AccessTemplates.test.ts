import { describe, expect, it } from "vitest";
import appSource from "../../App.tsx?raw";
import discoveryPageSource from "../../pages/DiscoveryPage.tsx?raw";
import discoveryWorkspaceSource from "../discovery/useDiscoveryWorkspace.ts?raw";
import wizardSource from "./WebTemplateWizard.tsx?raw";


describe("Batch B2 discovery and Secure Web fallback", () => {
  it("uses active SNMP Access Templates as reusable discovery credentials", () => {
    expect(discoveryWorkspaceSource).toContain('/access-templates?include_inactive=false');
    expect(discoveryWorkspaceSource).toContain('row.protocol === "SNMP" && row.is_active');
    expect(discoveryWorkspaceSource).toContain('snmpCredentialSource === "ACCESS_TEMPLATE"');
    expect(discoveryWorkspaceSource).toContain("access_template_id: usingTemplate ? snmpAccessTemplateId : null");
    expect(discoveryWorkspaceSource).toContain('access_template_id: methods.includes("SNMP") ? snmpAccessTemplateId : null');
    expect(discoveryWorkspaceSource).not.toContain("SNMP batch discovery is intentionally disabled");
  });

  it("shows the reusable credential boundary in single and batch discovery UX", () => {
    expect(discoveryPageSource).toContain("Credential source");
    expect(discoveryPageSource).toContain("SNMP Access Template");
    expect(discoveryPageSource).toContain("only the selected Access Template ID");
    expect(discoveryPageSource).toContain("Only the template ID is queued");
    expect(discoveryPageSource).toContain('permissions?.includes("access_template.read")');
  });

  it("wires the SNMP Access Template controls through the application", () => {
    expect(appSource).toContain("snmpCredentialSource={discovery.snmpCredentialSource}");
    expect(appSource).toContain("snmpAccessTemplateId={discovery.snmpAccessTemplateId}");
    expect(appSource).toContain("snmpAccessTemplates={discovery.snmpAccessTemplates}");
    expect(appSource).toContain("token={token}");
  });

  it("exposes manual Web fallback only as an explicit server-verified path", () => {
    expect(wizardSource).toContain('type DiscoveryMode = "AUTO" | "MANUAL"');
    expect(wizardSource).toContain("Manual fallback (server verified)");
    expect(wizardSource).toContain("Use manual fallback");
    expect(wizardSource).toContain("Verify Manual Contract & Build Draft");
    expect(wizardSource).toContain("manual_login_page_path");
    expect(wizardSource).toContain("manual_login_submit_path");
    expect(wizardSource).toContain("a failed manual contract creates no Access Template draft");
    expect(wizardSource).toContain("Run connection test");
    expect(wizardSource).toContain("Open authenticated Secure GUI preview");
    expect(wizardSource).toContain("Confirm & Activate Template");
  });
});
