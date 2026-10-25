import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const targets = [
  "src/pages/AccountPage.tsx",
  "src/pages/MaintenancePage.tsx",
  "src/pages/RestorePointsPage.tsx",
];
const raw = /<(?:button|input|select|textarea)\b/g;
const primitiveImport = /from\s+["']\.\.\/design-system\/primitives["']/;

for (const rel of targets) {
  const full = path.join(root, rel);
  if (!fs.existsSync(full)) throw new Error(`FR6-D3 target missing: ${rel}`);
  const text = fs.readFileSync(full, "utf8");
  const hits = [...text.matchAll(raw)];
  if (hits.length) throw new Error(`${rel} still owns ${hits.length} raw form control(s)`);
  if (!primitiveImport.test(text)) throw new Error(`${rel} does not import canonical primitives directly`);
  if (!text.includes("<Button unstyled") && !text.includes("<Input unstyled") && !text.includes("<Select unstyled")) {
    throw new Error(`${rel} does not use the compatibility-preserving primitive bridge`);
  }
}

console.log("[PASS] FR6-D3 page-level form primitive migration guard.");
