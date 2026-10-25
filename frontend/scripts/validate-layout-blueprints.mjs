import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const required = [
  "src/design-system/layouts/PageLayout/PageLayout.tsx",
  "src/design-system/layouts/PageLayout/PageLayout.module.css",
  "src/design-system/layouts/ViewLayouts/ViewLayouts.tsx",
  "src/design-system/layouts/ViewLayouts/ViewLayouts.module.css",
  "src/design-system/layouts/Headers/Headers.tsx",
  "src/design-system/layouts/Headers/Headers.module.css",
  "src/design-system/layouts/Surface/Surface.tsx",
  "src/design-system/layouts/Surface/Surface.module.css",
  "src/design-system/layouts/LayoutBlueprints.test.tsx",
  "architecture/FR5_LAYOUT_VIEW_BLUEPRINT_STANDARD.md",
];
for (const rel of required) if (!fs.existsSync(path.join(root, rel))) throw new Error(`[FR5] missing layout blueprint: ${rel}`);

const pageLayoutCss = fs.readFileSync(path.join(root, "src/design-system/layouts/PageLayout/PageLayout.module.css"), "utf8");
const rootRule = pageLayoutCss.match(/\.root\s*\{([^}]*)\}/)?.[1] || "";
if (/\bdisplay\s*:/.test(rootRule)) throw new Error("[FR5] PageLayout root must not override feature-owned display model.");

const moduleFiles = required.filter((x) => x.endsWith(".module.css"));
const hardColor = /#[0-9a-fA-F]{3,8}\b|rgba?\s*\(|hsla?\s*\(/;
for (const rel of moduleFiles) {
  const text = fs.readFileSync(path.join(root, rel), "utf8");
  if (hardColor.test(text)) throw new Error(`[FR5] hard-coded color in layout CSS Module: ${rel}`);
  if (/!important/.test(text)) throw new Error(`[FR5] !important prohibited in layout CSS Module: ${rel}`);
}
console.log("[PASS] FR5 layout/view blueprint ownership guard.");
