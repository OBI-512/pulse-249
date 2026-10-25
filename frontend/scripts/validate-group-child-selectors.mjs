import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const required = [
  "src/features/groups/components/ChildGroupSelectors.tsx",
  "src/features/groups/components/ChildGroupSelectors.module.css",
  "src/features/groups/components/index.ts",
  "architecture/FR6C3_GROUP_CHILD_SELECTOR_STANDARD.md",
];
for (const rel of required) {
  if (!fs.existsSync(path.join(root, rel))) {
    console.error(`[FR6-C3 group selectors] FAIL - missing ${rel}`);
    process.exit(1);
  }
}

const groupPage = fs.readFileSync(path.join(root, "src/pages/GroupPage.tsx"), "utf8");
if (!groupPage.includes('from "../features/groups/components"')) {
  console.error("[FR6-C3 group selectors] FAIL - GroupPage is not delegated to the feature selector owner.");
  process.exit(1);
}
for (const forbidden of ["function ChildGroupSelector(", "function EditableChildGroupSelector(", 'className="multi-select-', 'className="child-group-']) {
  if (groupPage.includes(forbidden)) {
    console.error(`[FR6-C3 group selectors] FAIL - legacy GroupPage selector ownership remains: ${forbidden}`);
    process.exit(1);
  }
}

const sourceRoots = [path.join(root, "src")];
function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? walk(full) : [full];
  });
}
const sourceFiles = sourceRoots.flatMap(walk).filter((file) => /\.(ts|tsx|css)$/.test(file) && !file.endsWith(".module.css"));
const forbiddenGlobal = [
  /\.multi-select(?:-|\s|\{|\.)/,
  /\.selection-chip(?:s)?(?:\s|\{|\.)/,
  /\.child-group-selector(?:\s|\{|\.)/,
  /\.child-group-menu(?:\s|\{|\.)/,
];
const violations = [];
for (const file of sourceFiles) {
  const text = fs.readFileSync(file, "utf8");
  for (const pattern of forbiddenGlobal) {
    if (pattern.test(text)) violations.push(path.relative(root, file).replaceAll("\\", "/"));
  }
}
if (violations.length) {
  console.error("[FR6-C3 group selectors] FAIL - retired global selector families remain:");
  for (const file of [...new Set(violations)].sort()) console.error(`- ${file}`);
  process.exit(1);
}

const owner = fs.readFileSync(path.join(root, "src/features/groups/components/ChildGroupSelectors.tsx"), "utf8");
for (const escaped of ['{"\\u25BE"}', '{"\\u00B7"}']) {
  if (!owner.includes(escaped)) {
    console.error(`[FR6-C3 group selectors] FAIL - encoding-safe glyph missing: ${escaped}`);
    process.exit(1);
  }
}
console.log("[PASS] FR6-C3 group child selector ownership/retirement guard.");
