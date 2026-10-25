import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = path.resolve(process.cwd());
const read = (rel) => fs.readFileSync(path.join(root, rel), "utf8");
const problems = [];

const ownerPath = "src/design-system/data/DataTable/DataTable.tsx";
const owner = read(ownerPath);
for (const marker of ["viewportClassName", "<table", "styles.viewport", "styles.table"]) {
  if (!owner.includes(marker)) problems.push(`DataTable owner missing ${marker}`);
}
if (!owner.includes(".module.css")) problems.push("DataTable must remain CSS-Module owned");

// Universal export, sorting and pagination remain view/toolbar concerns.
if (owner.includes("TableExportButton") || owner.includes("apiDownload")) problems.push("DataTable must not own export behavior");
if (owner.includes("SortHeader") || owner.includes("PaginationControls") || owner.includes("ServerPaginationRow")) problems.push("DataTable must not own sorting or pagination behavior");

const css = read("src/design-system/data/DataTable/DataTable.module.css");
if (/#[0-9a-fA-F]{3,8}\b|rgba?\s*\(|hsla?\s*\(|!important\b/.test(css)) {
  problems.push("DataTable.module.css must remain token/structure-only with no hard-coded color or !important debt");
}

const operatorRoot = path.join(root, "src");
const rawTableOwners = [];
const dataTableUsers = [];

function walk(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      walk(absolute);
      continue;
    }
    if (!entry.name.endsWith(".tsx")) continue;

    const rel = path.relative(root, absolute).replaceAll(path.sep, "/");
    if (rel === ownerPath || /(?:\.test|\.spec|\.stories)\.tsx$/.test(rel)) continue;

    const source = fs.readFileSync(absolute, "utf8");
    if (/<table\b/.test(source)) rawTableOwners.push(rel);
    if (/<DataTable\b/.test(source)) dataTableUsers.push(rel);
  }
}
walk(operatorRoot);

for (const rel of rawTableOwners) problems.push(`${rel} still owns a raw <table>; operator table shells must use canonical DataTable`);

const expectedMigrated = [
  "src/components/device/DeviceManagementPanel.tsx",
  "src/components/device/SortableDeviceIPs.tsx",
  "src/components/device/SortableInterfaces.tsx",
  "src/pages/AccountPage.tsx",
  "src/pages/AlarmPage.tsx",
  "src/pages/CandidatePage.tsx",
  "src/pages/CustomerPage.tsx",
  "src/pages/DataReportingPage.tsx",
  "src/pages/DevicePage.tsx",
  "src/pages/DiscoveryPage.tsx",
  "src/pages/DiscoveryResults.tsx",
  "src/pages/GroupPage.tsx",
  "src/pages/LogsPage.tsx",
  "src/pages/MaintenancePage.tsx",
  "src/pages/NetworkPage.tsx",
  "src/pages/RecycleBinPage.tsx",
  "src/pages/RestorePointsPage.tsx",
  "src/pages/SettingsPage.tsx",
  "src/pages/UserManagementPage.tsx",
];
for (const rel of expectedMigrated) {
  const source = read(rel);
  if (!source.includes("<DataTable")) problems.push(`${rel} is not migrated to canonical DataTable`);
}

if (dataTableUsers.length < expectedMigrated.length) {
  problems.push(`Expected at least ${expectedMigrated.length} canonical DataTable owners/users; found ${dataTableUsers.length}`);
}

if (problems.length) {
  console.error("[FR6-B2 table migration] FAIL");
  for (const problem of problems) console.error(`- ${problem}`);
  process.exit(1);
}
console.log(`[PASS] FR6-B2 canonical DataTable migration guard: ${dataTableUsers.length} operator source files, 0 raw operator <table> owners.`);
