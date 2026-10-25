import { describe, expect, it } from "vitest";
import dialogSource from "./TemplateAssignmentBulkDialog.tsx?raw";
import panelSource from "./DeviceManagementPanel.tsx?raw";


describe("TP4 bulk template assignment UI contract", () => {
  it("uses only the six frozen TP4 assignment APIs", () => {
    expect(dialogSource).toContain("/template-assignment-options/access?");
    expect(dialogSource).toContain("/template-assignment-options/configuration?");
    expect(dialogSource).toContain('"/template-assignment-batches/preview"');
    expect(dialogSource).toContain("`/template-assignment-batches/${preview.batch.id}/apply`");
    expect(dialogSource).not.toContain("/configuration-batches");
    expect(dialogSource).not.toContain("/configuration/apply");
    expect(dialogSource).not.toContain("/configuration/capture");
  });

  it("binds apply to the exact preview request fingerprint", () => {
    expect(dialogSource).toContain("expected_request_fingerprint:preview.batch.request_fingerprint");
    expect(dialogSource).toContain("Preview fingerprint:");
  });

  it("keeps target selection explicit and bounded to 500 devices", () => {
    expect(dialogSource).toContain("device_ids:props.devices.map(device=>device.id)");
    expect(dialogSource).toContain("if(selectedCount>500)");
    expect(dialogSource).toContain("limited to 500 explicit devices");
    expect(panelSource).toContain("selectedRows.length>500");
  });

  it("requires the frozen compound permissions before exposing each family", () => {
    expect(dialogSource).toContain('props.permissions.includes("access_template.read")&&props.permissions.includes("access_template.manage")');
    expect(dialogSource).toContain('props.permissions.includes("device.configuration.template.read")&&props.permissions.includes("device.configuration.template.manage")&&props.permissions.includes("device.configuration.read")');
    expect(panelSource).toContain('props.permissions.includes("device.read")&&');
  });

  it("states and preserves the no-execution boundary", () => {
    expect(dialogSource).toContain("This does not execute device configuration.");
    expect(dialogSource).toContain("No configuration was executed.");
    expect(panelSource).toContain("Assignment never executes configuration.");
    for (const forbidden of ["queue_operation", "send_task", "celery", "ConfigurationOperation("]) {
      expect(dialogSource).not.toContain(forbidden);
    }
  });

  it("supports cross-page row retention while clearing hidden stale selections on filter or sort changes", () => {
    expect(panelSource).toContain("selectedById");
    expect(panelSource).toContain("selected across pages");
    expect(panelSource).toContain("Selection is preserved while paging. Filter or sort changes clear it");
    const clearEffect = panelSource.split("useEffect(()=>{clearSelection()}", 2)[1]?.split("]);", 1)[0] || "";
    expect(clearEffect).not.toContain("props.page,");
    expect(clearEffect).not.toContain("props.pageSize");
    expect(clearEffect).toContain("props.sort.key");
    expect(clearEffect).toContain("props.filters.search");
  });

  it("keeps configuration replacement, credentials and staged enablement explicit", () => {
    expect(dialogSource).toContain("replace_existing:replaceConfiguration");
    expect(dialogSource).toContain("credential_mode:credentialMode");
    expect(dialogSource).toContain("enabled:configurationEnabled");
    expect(dialogSource).toContain("PRESERVE_EXISTING");
    expect(dialogSource).toContain("REMOTE_ACCESS_PROFILE");
    expect(dialogSource).toContain("ACCESS_TEMPLATE");
  });

  it("shows per-device preview/apply outcomes and blockers instead of hiding partial failure", () => {
    expect(dialogSource).toContain("preview_status");
    expect(dialogSource).toContain("apply_status");
    expect(dialogSource).toContain("target.blockers.map");
    expect(dialogSource).toContain("target.failure_code");
    expect(dialogSource).toContain('result.batch.status==="PARTIAL"');
  });

  it("uses the canonical DataTable shell for operator outcomes", () => {
    expect(dialogSource).toContain('import { DataTable } from "../../design-system/data/DataTable"');
    expect(dialogSource).toContain('<DataTable viewportClassName="table-wrap" className="management-table">');
    expect(dialogSource).not.toContain("<table");
  });
});
