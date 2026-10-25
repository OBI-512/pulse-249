import { describe, expect, it } from "vitest";
import lifecycleSource from "./ConfigurationTemplateLifecyclePanel.tsx?raw";
import pageSource from "../../pages/ConfigurationPage.tsx?raw";
import modelSource from "./model.ts?raw";


describe("TP1 Package 4 Configuration Template lifecycle UI", () => {
  it("loads complete lifecycle families while preserving active-only binding choices", () => {
    expect(pageSource).toContain('"/configuration-templates?active_only=false&limit=500"');
    expect(pageSource).toContain("setTemplates(rows.filter((row) => row.is_active));");
    expect(pageSource).toContain("publishedVersions(bindingTemplate)");
    expect(pageSource).toContain("Bind exact version");
  });

  it("exposes Draft -> Tested -> Approved -> Published lifecycle actions", () => {
    expect(lifecycleSource).toContain('action: "test" | "approve" | "activate"');
    expect(lifecycleSource).toContain('/${action}`');
    expect(lifecycleSource).toContain("Test definition (no device connection)");
    expect(lifecycleSource).toContain("Approve version");
    expect(lifecycleSource).toContain("Publish version");
    expect(lifecycleSource).toContain('selectedVersion?.status === "TESTED"');
    expect(lifecycleSource).toContain('selectedVersion?.status === "APPROVED"');
    expect(lifecycleSource).toContain("No test runs automatically");
  });

  it("keeps lifecycle editing fail-closed for terminal versions and invalidates stale evidence", () => {
    expect(lifecycleSource).toContain('["DRAFT", "TESTED", "APPROVED"].includes(selectedVersion.status)');
    expect(lifecycleSource).toContain("Editing a ${selectedVersion.status} version clears its Test/Approval evidence and returns it to Draft.");
    expect(lifecycleSource).toContain("Published versions are immutable runtime contracts");
    expect(lifecycleSource).toContain("Retired versions remain visible for auditability and exact-version lineage");
  });

  it("supports lifecycle-native family creation, exact-version cloning, and lineage visibility", () => {
    expect(lifecycleSource).toContain('"/configuration-templates"');
    expect(lifecycleSource).toContain('`/configuration-templates/${selected.template.id}/versions/${selectedVersion.id}/clone`');
    expect(lifecycleSource).toContain('`/configuration-templates/${selected.template.id}/versions/${selectedVersion.id}/clone-family`');
    expect(lifecycleSource).toContain("source_version_id");
    expect(lifecycleSource).toContain("Create Draft family");
    expect(lifecycleSource).toContain("New Draft revision from selected");
  });

  it("reconstructs the exact editable definition from version and function data", () => {
    expect(modelSource).toContain("export function configurationDefinition");
    expect(modelSource).toContain("adapter_key: entry.version.adapter_key");
    expect(modelSource).toContain("transport_parameters: entry.version.transport_parameters");
    expect(modelSource).toContain("functions: entry.functions.map");
    expect(modelSource).toContain("required_capabilities: fn.required_capabilities");
  });

  it("does not introduce configuration execution into lifecycle authoring", () => {
    expect(lifecycleSource).not.toContain("/configuration/apply");
    expect(lifecycleSource).not.toContain("/configuration/capture");
    expect(lifecycleSource).not.toContain("/configuration/restore");
    expect(lifecycleSource).not.toContain("ConfigurationOperation");
    expect(lifecycleSource).toContain("lifecycle actions never connect to or configure a device");
  });
});
