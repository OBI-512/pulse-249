import { describe, expect, it } from "vitest";
import wizardSource from "./WebTemplateWizard.tsx?raw";
import previewSource from "./webTemplateWizardRemoteAccess.ts?raw";


describe("Secure Web Template Wizard", () => {
  it("keeps automatic discovery as the default while exposing an explicit manual fallback", () => {
    expect(wizardSource).toContain("Reference management IP");
    expect(wizardSource).toContain("Username + password");
    expect(wizardSource).toContain("Password only");
    expect(wizardSource).toContain("Discover & Build Draft");
    expect(wizardSource).toContain("Manual fallback (server verified)");
    expect(wizardSource).toContain("Use manual fallback");
    expect(wizardSource).toContain("/access-templates/web-wizard/start");
  });

  it("keeps automatic contract values informational and requires server verification for manual values", () => {
    expect(wizardSource).toContain("Discovered blueprint");
    expect(wizardSource).toContain("Verified blueprint");
    expect(wizardSource).toContain("Login page");
    expect(wizardSource).toContain("Submit path");
    expect(wizardSource).toContain("Form encoding");
    expect(wizardSource).toContain("a failed manual contract creates no Access Template draft");
    expect(wizardSource).toContain("Manual fallback values reached this stage only after successful server-side authentication");
  });

  it("requires automated test, authenticated preview and explicit human acceptance before activation", () => {
    expect(wizardSource).toContain("Run connection test");
    expect(wizardSource).toContain("Open authenticated Secure GUI preview");
    expect(wizardSource).toContain("I confirmed that the reference device GUI opened successfully and was already authenticated.");
    expect(wizardSource).toContain("Confirm & Activate Template");
    expect(wizardSource).toContain("preview_session_id");
  });

  it("uses the dedicated access-gateway popup and memory-only ticket handoff for draft preview", () => {
    expect(previewSource).toContain("webGuiGatewayOrigin");
    expect(previewSource).toContain("/web/launch");
    expect(previewSource).toContain("fttw-web-gui-launch");
    expect(previewSource).toContain("/access-templates/web-wizard/${templateId}/preview");
    expect(previewSource).not.toContain("localStorage");
    expect(previewSource).not.toContain("sessionStorage");
  });
});
