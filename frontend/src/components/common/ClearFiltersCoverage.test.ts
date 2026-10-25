import { describe, expect, it } from "vitest";

const sources = import.meta.glob("../../**/*.tsx", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

describe("universal Clear Filters contract",()=>{
  it("uses the shared ClearFiltersButton in every view containing a filter group",()=>{
    const pattern=/className=\"[^\"]*(?:filter-row|filter-grid|filter-panel|permission-toolbar|filters-grid|management-filter-row)[^\"]*\"/;
    const missing=Object.entries(sources)
      .filter(([,source])=>pattern.test(source)&&!source.includes("ClearFiltersButton"))
      .map(([path])=>path.replace(/^\.\.\/\.\.\//,""))
      .sort();
    expect(missing).toEqual([]);
  });
});
