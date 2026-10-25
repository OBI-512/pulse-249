import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const src = path.join(root, "src");
const required = [
  "src/design-system/composites/Status/StatusBadge.tsx",
  "src/design-system/composites/Metric/StatCard.tsx",
  "src/design-system/visualizations/Dashboard/DashboardIcon.tsx",
  "src/design-system/visualizations/Dashboard/MetricCard.tsx",
  "src/design-system/visualizations/Dashboard/AvailabilityGauge.tsx",
  "src/design-system/visualizations/Dashboard/StateBar.tsx",
];
for (const rel of required) if (!fs.existsSync(path.join(root, rel))) throw new Error(`CP3 missing canonical owner: ${rel}`);

const files = [];
function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (/\.tsx?$/.test(entry.name) && !/\.test\./.test(entry.name)) files.push(full);
  }
}
walk(src);
const violations = [];
for (const file of files) {
  const rel = path.relative(root, file).replaceAll(path.sep, "/");
  const text = fs.readFileSync(file, "utf8");
  if (/components\/common\/Ui|\.\.\/common\/Ui/.test(text)) violations.push(`${rel}: legacy common/Ui import`);
  if (/components\/common\/WorkspacePatterns/.test(text)) violations.push(`${rel}: legacy WorkspacePatterns import`);
}
const overview = fs.readFileSync(path.join(src, "pages/OverviewPage.tsx"), "utf8");
for (const name of ["DashboardIcon", "AnimatedNumber", "MetricCard", "AvailabilityGauge", "StateBar"]) {
  if (new RegExp(`function\\s+${name}\\s*\\(`).test(overview)) violations.push(`OverviewPage.tsx still owns ${name}`);
}
if (!overview.includes('from "../design-system/visualizations"')) violations.push("OverviewPage.tsx does not use canonical visualization owners");
const reporting = fs.readFileSync(path.join(src, "pages/DataReportingPage.tsx"), "utf8");
if (!reporting.includes('design-system/composites/Metric')) violations.push("DataReportingPage does not use canonical StatCard owner");
if (!reporting.includes('design-system/composites/Status')) violations.push("DataReportingPage does not use canonical StatusBadge owner");
const settings = fs.readFileSync(path.join(src, "pages/SettingsPage.tsx"), "utf8");
if (!settings.includes('design-system/composites/Metric')) violations.push("SettingsPage does not use canonical StatCard owner");
if (violations.length) throw new Error(`CP3 feature ownership guard FAILED:\n${violations.join("\n")}`);
console.log("[PASS] CP3 dashboard/state/final-feature ownership guard.");
console.log(`- active legacy common/Ui consumers: 0`);
console.log(`- active WorkspacePatterns consumers: 0`);
console.log(`- Overview dashboard visualization helpers: canonical design-system ownership`);
