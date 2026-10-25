import { describe, expect, it } from "vitest";
import source from "./AccessTemplatesPanel.tsx?raw";


describe("TP1 Package 4 Access Template lifecycle UI", () => {
  it("creates new families through the lifecycle-native bootstrap", () => {
    expect(source).toContain('apiFetch<LifecycleCreateRead>("/access-templates/families"');
    expect(source).toContain("is_active: false");
    expect(source).toContain("Create Draft family");
    expect(source).not.toContain('method: "POST",\n            body: JSON.stringify({ ...common, protocol: draft.protocol })');
  });

  it("uses revision-native editing and preserves immutable lifecycle states", () => {
    expect(source).toContain('selectedRevision?.lifecycle_status === "DRAFT"');
    expect(source).toContain('`/access-templates/${selected.id}/revisions/${selectedRevision.id}`');
    expect(source).toContain("Save Draft revision");
    expect(source).toContain("This revision is read-only in the definition editor. Create a new Draft revision to change it.");
    expect(source).not.toContain("Active template");
  });

  it("exposes lineage, duplicate, and new-revision workflows", () => {
    expect(source).toContain("Revision history");
    expect(source).toContain("source_revision_id");
    expect(source).toContain("New revision from selected");
    expect(source).toContain('`/access-templates/${selected.id}/revisions`');
    expect(source).toContain('`/access-templates/${selected.id}/clone`');
    expect(source).toContain("credentials are intentionally not copied");
  });

  it("enforces Test -> Approve -> Activate operator actions", () => {
    expect(source).toContain('`/access-templates/${selected.id}/revisions/${selectedRevision.id}/test`');
    expect(source).toContain('`/access-templates/${selected.id}/revisions/${selectedRevision.id}/approve`');
    expect(source).toContain('`/access-templates/${selected.id}/revisions/${selectedRevision.id}/activate`');
    expect(source).toContain('selectedRevision.lifecycle_status === "TESTED"');
    expect(source).toContain('selectedRevision.lifecycle_status === "APPROVED"');
    expect(source).toContain("No test runs automatically.");
  });

  it("keeps active and retired revisions visible instead of editing them in place", () => {
    expect(source).toContain('type LifecycleStatus = "DRAFT" | "TESTED" | "APPROVED" | "ACTIVE" | "RETIRED"');
    expect(source).toContain("superseded Active revisions become Retired");
    expect(source).toContain("This is the current runtime projection. It cannot be edited in place.");
    expect(source).toContain("Retired revisions remain visible for auditability and lineage.");
  });
});
