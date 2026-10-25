import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
const fail = (m) => { console.error(`[FAIL] CP2 style/layout guard: ${m}`); process.exit(1); };

const pageFiles = [
  "AccountPage.tsx","AlarmPage.tsx","CandidatePage.tsx","CustomerPage.tsx","DataReportingPage.tsx",
  "DevicePage.tsx","DiscoveryPage.tsx","GroupPage.tsx","LogsPage.tsx","MaintenancePage.tsx","NetworkPage.tsx",
  "OverviewPage.tsx","RecycleBinPage.tsx","RestorePointsPage.tsx","SettingsPage.tsx","TopologyPage.tsx","UserManagementPage.tsx",
];
for (const file of pageFiles) {
  const source = read(`src/pages/${file}`);
  if (!source.includes("PageLayout")) fail(`${file} is not migrated to canonical PageLayout ownership.`);
}

const pageLayoutCss = read("src/design-system/layouts/PageLayout/PageLayout.module.css");
const pageRootRule = pageLayoutCss.match(/\.root\s*\{([^}]*)\}/)?.[1] || "";
if (/\bdisplay\s*:/.test(pageRootRule)) fail("PageLayout root must not override feature-owned display model.");

const dialog = read("src/design-system/composites/Dialog/Dialog.tsx");
if (!dialog.includes('Dialog.module.css')) fail("Dialog visual ownership is not CSS-Module isolated.");
const unstyledContracts = {
  Button: 'className={className}',
  Input: 'unstyled ? className :',
  Select: 'unstyled ? className :',
  Textarea: 'unstyled ? className :',
};
for (const [primitive, expected] of Object.entries(unstyledContracts)) {
  const source = read(`src/design-system/primitives/${primitive}/${primitive}.tsx`);
  if (source.includes("styles.compat")) fail(`${primitive} unstyled path must not inject design-system compatibility presentation.`);
  if (!source.includes(expected)) fail(`${primitive} unstyled path does not preserve caller-owned class presentation.`);
}
const complete = read("scripts/validate-form-primitive-migration-complete.mjs");
if (!complete.includes("Raw application/shared")) fail("CP1 complete form-control guard missing.");
console.log("[PASS] CP2 form/dialog style ownership + page layout migration guard.");
