import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = path.resolve(process.cwd());
const srcRoot = path.join(root, "src");
const problems = [];
const operatorFiles = [];

function walk(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) { walk(absolute); continue; }
    if (!entry.name.endsWith(".tsx")) continue;
    const rel = path.relative(root, absolute).replaceAll(path.sep, "/");
    if (rel.startsWith("src/design-system/") || /(?:\.test|\.spec|\.stories)\.tsx$/.test(rel)) continue;
    operatorFiles.push([rel, fs.readFileSync(absolute, "utf8")]);
  }
}
walk(srcRoot);

for (const [rel, source] of operatorFiles) {
  if (/from\s+["'][^"']*(?:components\/common|common)\/(?:Pagination|ServerPagination)["']/.test(source)) {
    problems.push(`${rel} still imports pagination through a compatibility facade`);
  }
  const uiImports = [...source.matchAll(/import\s*\{([^}]*)\}\s*from\s*["'][^"']*common\/Ui["']/g)];
  for (const match of uiImports) {
    const names = match[1].split(",").map((value) => value.replace(/^\s*type\s+/, "").trim());
    if (names.includes("SortHeader")) problems.push(`${rel} still imports SortHeader through common/Ui`);
    if (names.includes("TableExportButton")) problems.push(`${rel} still imports TableExportButton through common/Ui`);
  }
}

const owners = {
  "src/design-system/data/SortHeader/SortHeader.tsx": ["styles.triangle", "onSort"],
  "src/design-system/data/Pagination/Pagination.tsx": ["PAGE_SIZE_OPTIONS", "PaginationControls", "ServerPaginationRow"],
  "src/design-system/data/TableExport/TableExportButton.tsx": ["TableExportButton", 'format: "CSV" | "XLSX"', "closeOnOutsideClick"],
  "src/design-system/data/DataTable/DataTable.tsx": ["DataTable", "TableToolbar"],
};
for (const [rel, markers] of Object.entries(owners)) {
  const source = fs.readFileSync(path.join(root, rel), "utf8");
  for (const marker of markers) if (!source.includes(marker)) problems.push(`${rel} missing canonical marker ${marker}`);
}

const paginationSource = fs.readFileSync(path.join(root, "src/design-system/data/Pagination/Pagination.tsx"), "utf8");
if (!paginationSource.includes("[50, 100, 200, 300, 400, 500]")) problems.push("Locked pagination sizes changed");

const exportSource = fs.readFileSync(path.join(root, "src/design-system/data/TableExport/TableExportButton.tsx"), "utf8");
if (exportSource.includes('run("JSON")')) problems.push("Operator table export must remain CSV/XLSX only");
if (!exportSource.includes('entity_type: "table"')) problems.push("Table export must retain complete filtered table backend contract");
if (!exportSource.includes("closeOnOutsideClick")) problems.push("Table export outside-click closing behavior was lost");

const inventoryPath = path.join(root, "architecture/fr6b3-legacy-table-style-inventory.json");
if (!fs.existsSync(inventoryPath)) problems.push("Legacy table style retirement inventory is missing");
else {
  const inventory = JSON.parse(fs.readFileSync(inventoryPath, "utf8"));
  if (inventory.phase !== "FR6-B3") problems.push("Legacy style inventory phase marker is invalid");
  if (!Array.isArray(inventory.files) || inventory.files.length === 0) problems.push("Legacy style inventory is empty");
}

if (problems.length) {
  console.error("[FR6-B3 table tools ownership] FAIL");
  for (const problem of problems) console.error(`- ${problem}`);
  process.exit(1);
}
console.log(`[PASS] FR6-B3 table tools ownership guard: ${operatorFiles.length} operator TSX files use canonical table-tool ownership.`);
