import { describe, expect, it } from "vitest";

const sources = import.meta.glob("../../**/*.tsx", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

function isNonOperatorSource(path: string): boolean {
  return (
    path.includes("/design-system/") ||
    path.endsWith(".test.tsx") ||
    path.endsWith(".stories.tsx")
  );
}

describe("universal table export contract", () => {
  it("places the shared TableExportButton in every operator view that renders a table", () => {
    const missing = Object.entries(sources)
      .filter(([path, source]) => {
        if (path.endsWith(".bak") || isNonOperatorSource(path)) return false;

        const rendersOperatorTable = source.includes("<table") || source.includes("<DataTable");
        return rendersOperatorTable && !source.includes("TableExportButton");
      })
      .map(([path]) => path.replace(/^\.\.\/\.\.\//, ""))
      .sort();

    expect(missing).toEqual([]);
  });
});
