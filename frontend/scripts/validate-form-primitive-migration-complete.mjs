import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const srcRoot = path.join(root, "src");
const rawControl = /<(?:button|input|select|textarea)\b/g;
const allowedPrefixes = [
  path.join(srcRoot, "design-system") + path.sep,
];

function walk(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else if (entry.isFile() && entry.name.endsWith(".tsx") && !entry.name.includes(".test.") && !entry.name.includes(".spec.")) out.push(full);
  }
  return out;
}

const violations = [];
for (const full of walk(srcRoot)) {
  if (allowedPrefixes.some((prefix) => full.startsWith(prefix))) continue;
  const text = fs.readFileSync(full, "utf8");
  const hits = [...text.matchAll(rawControl)];
  if (hits.length) {
    violations.push({
      file: path.relative(root, full).replaceAll(path.sep, "/"),
      count: hits.length,
    });
  }
}

if (violations.length) {
  const detail = violations.map((item) => `${item.file}: ${item.count}`).join("\n");
  throw new Error(`Application/shared source still owns raw form controls outside canonical design-system owners:\n${detail}`);
}

const requiredTargets = [
  "src/pages/DevicePage.tsx",
  "src/pages/GroupPage.tsx",
  "src/pages/DataReportingPage.tsx",
  "src/pages/OverviewPage.tsx",
  "src/pages/TopologyPage.tsx",
  "src/components/common/AppChrome.tsx",
  "src/components/common/AuthorizedUseNotice.tsx",
  "src/components/common/DialogSystem.tsx",
  "src/components/common/FeedbackSystem.tsx",
  "src/components/device/DeviceManagementPanel.tsx",
  "src/components/device/SortableDeviceIPs.tsx",
  "src/components/device/SortableInterfaces.tsx",
  "src/components/topology/LazyTopologyHierarchy.tsx",
  "src/features/groups/components/ChildGroupSelectors.tsx",
];

for (const rel of requiredTargets) {
  const full = path.join(root, rel);
  if (!fs.existsSync(full)) throw new Error(`Consolidated D7/D8 target missing: ${rel}`);
  const text = fs.readFileSync(full, "utf8");
  if (!/design-system\/primitives/.test(text)) {
    throw new Error(`${rel} does not import canonical primitives directly`);
  }
}

console.log("[PASS] FR6-D7/D8 complete application form/control ownership guard.");
console.log("[PASS] Raw application/shared button/input/select/textarea owners outside design-system: 0.");
