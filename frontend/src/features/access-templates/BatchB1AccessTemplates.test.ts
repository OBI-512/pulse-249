import { describe, expect, it } from "vitest";
import devicePanelSource from "../../components/device/DeviceAccessTemplatesPanel.tsx?raw";
import wizardSource from "./WebTemplateWizard.tsx?raw";


describe("Batch B1 Access Template lifecycle", () => {
  it("exposes device-level Test access only through the existing Access Template test endpoint", () => {
    expect(devicePanelSource).toContain('permissions.includes("access_template.test")');
    expect(devicePanelSource).toContain('value?.status === "RESOLVED" && canTest');
    expect(devicePanelSource).toContain("Test access");
    expect(devicePanelSource).toContain("/access-templates/${value.template_id}/test");
    expect(devicePanelSource).toContain("device_id: device.id");
  });

  it("preserves explicit SSH host-key trust during device-level testing", () => {
    expect(devicePanelSource).toContain('result.trust_state === "MISMATCH"');
    expect(devicePanelSource).toContain("trust_host_key: true");
    expect(devicePanelSource).toContain("expected_fingerprint: result.fingerprint");
    expect(devicePanelSource).toContain("replace_existing: replacing");
  });

  it("exposes deleted-template recovery without automatic effectiveness", () => {
    expect(wizardSource).toContain("Deleted Access Templates");
    expect(wizardSource).toContain('apiFetch<DeletedTemplate[]>("/access-templates/deleted"');
    expect(wizardSource).toContain("/access-templates/${template.id}/restore");
    expect(wizardSource).toContain("Restore inactive");
    expect(wizardSource).toContain("all previous assignments remain disabled");
  });

  it("communicates that edits invalidate wizard acceptance evidence", () => {
    expect(wizardSource).toContain("Editing the draft afterwards invalidates this test");
    expect(wizardSource).toContain("The preview must follow the current successful test");
  });
});
