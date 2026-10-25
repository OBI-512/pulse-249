import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = path.resolve(process.cwd());
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const problems = [];
const tabsSource = read("src/design-system/composites/Tabs/Tabs.tsx");
const tabsCss = read("src/design-system/composites/Tabs/Tabs.module.css");

for (const token of ["role=\"tablist\"", "role=\"tab\"", "aria-selected", "styles.tab", "styles.active"]) {
  if (!tabsSource.includes(token)) problems.push(`Tabs blueprint missing ${token}`);
}
for (const token of ['html[data-theme="light"]', '.tab::before', '.tab::after']) {
  if (!tabsCss.includes(token)) problems.push(`Tabs theme contract missing ${token}`);
}
if (/#[0-9a-fA-F]{3,8}\b|rgba?\s*\(|!important\b/.test(tabsCss)) {
  problems.push("Tabs.module.css must remain semantic-token driven and must not introduce hard-coded colors or !important");
}

const pageDir = path.join(root, "src/pages");
const pageFiles = fs.readdirSync(pageDir).filter((name) => name.endsWith(".tsx") && !name.endsWith(".test.tsx"));
const legacy = /(?:view-tabs|management-tabs|device-workspace-tabs|log-tabs|settings-view-tabs)/;
for (const name of pageFiles) {
  const source = fs.readFileSync(path.join(pageDir, name), "utf8");
  if (legacy.test(source)) problems.push(`${name} still references a legacy global tab class`);
  if (source.includes('role="tablist"')) problems.push(`${name} still owns tablist markup instead of canonical Tabs`);
}

const required = {
  "NetworkPage.tsx": "<Tabs<Tab>",
  "DataReportingPage.tsx": "<WorkspaceTabs<Tab>",
  "TopologyPage.tsx": "<Tabs<ViewMode>",
  "DevicePage.tsx": '<Tabs<"inventory" | "management">',
  "GroupPage.tsx": "<Tabs<Tab>",
  "SettingsPage.tsx": "<Tabs<SettingsTab>",
  "LogsPage.tsx": '<Tabs<"audit" | "operational">',
  "UserManagementPage.tsx": "<Tabs<Tab>",
};
for (const [name, marker] of Object.entries(required)) {
  const source = fs.readFileSync(path.join(pageDir, name), "utf8");
  if (!source.includes(marker)) problems.push(`${name} is not migrated to canonical Tabs`);
}

if (problems.length) {
  console.error("[FR6-A2 tabs migration] FAIL");
  for (const problem of problems) console.error(`- ${problem}`);
  process.exit(1);
}
console.log("[PASS] FR6-A2 theme-aware canonical Tabs and remaining operator-surface migration guard.");
