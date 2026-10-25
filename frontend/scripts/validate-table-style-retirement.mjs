import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = path.resolve(process.cwd());
const srcRoot = path.join(root, "src");

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? walk(full) : [full];
  });
}

const retiredLegacyClasses = [
  "table-sort",
  "sort-indicator",
  "sort-triangle",
  "pagination-viewport",
  "pagination-center-track",
  "pagination-bar",
  "pagination-size",
  "pagination-icon",
  "pagination-current",
  "server-pagination",
  "table-export-control",
  "table-export-trigger",
  "table-export-chevron",
  "table-export-menu",
];

const globalCss = walk(srcRoot).filter((file) => file.endsWith(".css") && !file.endsWith(".module.css"));
const sourceFiles = walk(srcRoot).filter((file) => /\.(?:tsx?|jsx?)$/.test(file));
const failures = [];

for (const className of retiredLegacyClasses) {
  const classPattern = new RegExp(`\\.${className.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&")}(?![A-Za-z0-9_-])`);
  for (const file of globalCss) {
    const text = fs.readFileSync(file, "utf8");
    if (classPattern.test(text)) failures.push(`retired global selector .${className} remains in ${path.relative(root, file).replaceAll("\\\\", "/")}`);
  }
  const sourcePattern = new RegExp(`(?:className\\s*=|[\\"'` + "`" + `])[^\\n]{0,180}\\b${className}\\b`);
  for (const file of sourceFiles) {
    const text = fs.readFileSync(file, "utf8");
    if (sourcePattern.test(text)) failures.push(`retired legacy class ${className} is referenced by ${path.relative(root, file).replaceAll("\\\\", "/")}`);
  }
}

const canonicalOwners = [
  "src/design-system/data/DataTable/DataTable.module.css",
  "src/design-system/data/SortHeader/SortHeader.module.css",
  "src/design-system/data/Pagination/Pagination.module.css",
  "src/design-system/data/TableExport/TableExport.module.css",
];
for (const relative of canonicalOwners) {
  if (!fs.existsSync(path.join(root, relative))) failures.push(`canonical table style owner missing: ${relative}`);
}

const activeCompatibility = [
  ["src/pages/RecycleBinPage.tsx", "pagination-table-row"],
  ["src/pages/DevicePage.tsx", "table-toolbar-actions"],
];
for (const [relative, token] of activeCompatibility) {
  const file = path.join(root, relative);
  if (!fs.existsSync(file) || !fs.readFileSync(file, "utf8").includes(token)) failures.push(`expected active compatibility token ${token} missing from ${relative}`);
}

const style50 = fs.readFileSync(path.join(srcRoot, "styles/50-scale-management-workspaces.css"), "utf8");
if (!style50.includes(".pagination-table-row > td")) failures.push("active Recycle Bin pagination-table-row compatibility rule was removed");
const style98 = fs.readFileSync(path.join(srcRoot, "styles/98-operations-ui-refinement.css"), "utf8");
if (!style98.includes(".table-toolbar-actions")) failures.push("active Device table-toolbar-actions compatibility rule was removed");

if (failures.length) {
  console.error("[FAIL] FR6-B4 legacy table-style retirement guard.");
  for (const failure of [...new Set(failures)].sort()) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`[PASS] FR6-B4 legacy table-style retirement guard: ${retiredLegacyClasses.length} legacy class families retired; canonical CSS-Module owners present; active compatibility rules preserved.`);
